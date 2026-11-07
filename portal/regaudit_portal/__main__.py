"""``regaudit-portal serve``, ``check-config`` and ``demo-setup``. Only the administrator, or a launcher, uses these.

``serve`` without ``--config`` looks for the configuration in the standard per-user folder. If there is none it starts in
welcome mode, where the bundled samples work and your own reports are not set up. It never creates that folder or
anything in it. ``--port 0`` takes any free port, and the line ``portal-listening url=... mode=...`` tells a launcher
where the portal is.

The engine is checked before anything that imports it is loaded. If the check fails, ``serve`` starts the
"verification unavailable" application instead, and the other commands stop with exit code 3. What failed and where is
printed in this terminal. It is never sent to a browser.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import shlex
import shutil
import signal
import socket
import sys
import threading
from collections.abc import Callable

# Standard library only, so it is safe to import when the engine is missing or damaged.
from . import STOP_DEADLINE_SECONDS, STOPPED, _leave_now, _stop_while_starting
from .engine import REINSTALL, check_engine
from .paths import default_config_path, display_path

HOST = "127.0.0.1"  # local only: this first version has no sign-in, so it must not be reachable from a network


def listening_line(port: int, mode: str) -> str:
    """One line a launcher can read: where the portal is and which mode it is in.

    ``mode`` is ``ready`` (your own reports can be checked), ``welcome`` (no configuration: the samples work),
    ``needs-attention`` (a configuration that cannot be used: the samples work) or ``unavailable`` (the engine check
    failed: only a page saying so is served).
    """
    return f"portal-listening url=http://{HOST}:{port}/ mode={mode}"


def started_message(mode: str, port: int) -> str:
    """What to tell the person at the terminal once the portal is listening. Not before, and not if it never started."""
    opening = f"open http://{HOST}:{port} in a browser."
    if mode == "welcome":
        return (
            f"{opening} The samples work. Your own reports are not set up yet: an administrator has to set up trust "
            "first (the page says how). Press Ctrl-C to stop."
        )
    if mode == "needs-attention":
        return (
            f"{opening} The samples work, but your own reports cannot be checked until the configuration is fixed. "
            "Run check-config with the same --config to see why. Press Ctrl-C to stop."
        )
    return f"{opening} Press Ctrl-C to stop."


def _bind_loopback(port: int) -> socket.socket:
    """Listen on this computer only. Port 0 takes any free port, which the caller reads back from the socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, port))
    except OSError:
        sock.close()
        raise
    return sock


def _configuration(given: str | None) -> str | None:
    """The configuration to use: ``--config`` if given, else the standard per-user file if one is there, else none.

    ``None`` is welcome mode. This only looks. It creates nothing.
    """
    if given is not None:
        return given
    try:
        standard = default_config_path()
    except RuntimeError:  # no home folder to look in
        return None
    return str(standard) if os.path.lexists(standard) else None


def unavailable_message(reason: str, detail: str) -> str:
    """For the administrator's terminal. It names what failed and where, so it must never reach a browser."""
    return (
        f"not usable: verification unavailable: {reason}: {detail}. Reinstall with: {REINSTALL}\n"
    )


GRACEFUL_SHUTDOWN_SECONDS = 3


_stop_requested = False
_serving = False  # set when the portal starts to serve; before that, the package's own handler takes the stop
# How the server that is running, or about to run, is asked to finish: set just before it starts. Until then a stop is
# only recorded, and the portal does not start to serve.
_ask_server_to_stop: Callable[[], None] | None = None


def _stop_like_ctrl_c(_signum: int, _frame: object) -> None:
    """One stop is enough. A second request while the first is being handled (a signal, and then the launcher's input
    closing) changes nothing.

    While the portal serves, the stop is recorded and the server is asked to finish, which it does at its next safe
    point: it stops taking requests, lets those in progress end (for at most GRACEFUL_SHUTDOWN_SECONDS), closes, and
    the program returns normally, so the private folder is removed on the way out. Nothing is raised here: a signal's
    handler can run inside any Python code, a garbage collector's weakref callback included, and an exception raised
    there is printed as "Exception ignored" and dropped, so the stop would be lost. If the portal has still not gone
    after STOP_DEADLINE_SECONDS, a timer ends it. Any other command has nothing to finish and stops at once, as Ctrl-C
    does."""
    global _stop_requested
    if _stop_requested:
        return
    _stop_requested = True
    if not _serving:
        raise KeyboardInterrupt
    deadline = threading.Timer(STOP_DEADLINE_SECONDS, _leave_now)
    deadline.daemon = True
    deadline.start()
    ask = _ask_server_to_stop
    if ask is not None:
        ask()


def _leaving() -> None:
    """A stop has begun. From here until the process is gone, further stop requests change nothing: a second one (a
    signal, and then the launcher's input closing) must not interrupt the clean-up, which includes removing the
    private bytecode folder when the interpreter exits."""
    global _stop_requested
    _stop_requested = True
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)


class _DropCancelledRequests(logging.Filter):
    """uvicorn logs a traceback for each request, and for the lifespan task, that it had to cancel because the portal
    was asked to stop (and again for a second request). That is the stop working as intended, so only those records are
    dropped; any other error is still shown. Starlette hands the lifespan failure on as a text, so that one is
    recognised by its text."""

    def filter(self, record: logging.LogRecord) -> bool:
        error = record.exc_info[1] if record.exc_info else None
        if isinstance(error, asyncio.CancelledError):
            return False
        text = record.msg if isinstance(record.msg, str) else ""
        cancelled_lifespan = (
            text.lstrip().startswith("Traceback (most recent call last)")
            and "uvicorn/lifespan/on.py" in text
            and text.rstrip().endswith("asyncio.exceptions.CancelledError")
        )
        return not cancelled_lifespan


def _hand_over_from_the_early_stop(serving: bool) -> None:
    """The package's early handler covers the program from its first line to here, and it never raises: it removes the
    private folder and ends the process. From here on a stop is a KeyboardInterrupt, taken by ``main`` (or by uvicorn
    when it is serving). The portal hands over just before it starts to serve; any other command hands over as soon
    as its arguments are read. Handlers that are not the early one (an inherited "ignore", or one a command sets for
    itself) are left alone."""
    global _serving
    _serving = serving or _serving
    if signal.getsignal(signal.SIGINT) == _stop_while_starting:
        # The portal takes Ctrl-C the way it takes SIGTERM: recorded and handled at a safe point (see
        # _stop_like_ctrl_c). Any other command stops with a KeyboardInterrupt, as before.
        signal.signal(signal.SIGINT, _stop_like_ctrl_c if _serving else signal.default_int_handler)
    if signal.getsignal(signal.SIGTERM) == _stop_while_starting:
        signal.signal(signal.SIGTERM, _stop_like_ctrl_c)


def _stop_when_input_closes() -> None:
    """For a launcher: stop like Ctrl-C when the other end of standard input closes.

    A launcher that holds the write end of a pipe on the portal's standard input closes it when it quits, crashes or is
    killed, even by SIGKILL. The portal then stops cleanly instead of running on with nothing to stop it.
    """
    # A portal started with this option is one that a launcher must always be able to stop, and the watcher below stops
    # it by signalling itself: so SIGTERM is taken even if the parent had it ignored. The package's early handler stays.
    if signal.getsignal(signal.SIGTERM) in (signal.SIG_DFL, signal.SIG_IGN):
        signal.signal(signal.SIGTERM, _stop_while_starting)

    def watch() -> None:
        # Read the descriptor itself, never sys.stdin. A daemon thread waiting inside the buffered reader holds its
        # lock, and when the interpreter shuts down and cannot take that lock to close the stream, Python aborts.
        try:
            while os.read(0, 4096):
                pass
        except OSError:
            pass  # the descriptor is gone: the same signal to stop as an end of input
        os.kill(os.getpid(), signal.SIGTERM)

    threading.Thread(target=watch, name="launcher-watch", daemon=True).start()


def _run(app: object, sock: socket.socket, mode: str) -> None:
    """Serve until Ctrl-C or SIGTERM (what ``kill`` sends), then stop cleanly with one line.

    uvicorn shuts down gracefully, puts back the handlers that were in place before it started, and then raises the
    signal again. With the default handlers that would be a traceback for Ctrl-C and a death without cleanup for SIGTERM,
    so a handler is installed first that turns both into KeyboardInterrupt. Returning normally lets the exit hooks run,
    which removes the private bytecode folder.
    """
    import uvicorn

    _hand_over_from_the_early_stop(True)

    class Announcing(uvicorn.Server):
        async def startup(self, sockets: list | None = None) -> None:
            await super().startup(sockets=sockets)
            if self.started:  # only after the socket was taken up; a failed start exits before this
                print(listening_line(port, mode), flush=True)
                print(started_message(mode, port), flush=True)

    port = sock.getsockname()[1]
    # A request still arriving when the portal is asked to stop (a slow upload) gets three seconds. The macOS launcher
    # gives up after six and kills the portal, which would leave its private folder behind.
    config = uvicorn.Config(
        app,
        access_log=False,
        server_header=False,
        log_level="warning",
        timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS,
    )
    signal.signal(signal.SIGTERM, _stop_like_ctrl_c)
    logging.getLogger("uvicorn.error").addFilter(_DropCancelledRequests())
    server = Announcing(config)
    _ask_server_to_stop_with(lambda: setattr(server, "should_exit", True))
    # uvicorn takes SIGINT and SIGTERM itself while it serves, and gives them back to _stop_like_ctrl_c when it has
    # finished. A stop that came before this point was recorded: then the portal does not start to serve at all. One
    # that comes between here and uvicorn taking the signals sets should_exit, which uvicorn checks before it serves.
    if not _stop_requested:
        # A KeyboardInterrupt can still come from a Ctrl-C handler this program did not set.
        with contextlib.suppress(KeyboardInterrupt):
            server.run(sockets=[sock])
    _leaving()
    print(STOPPED, flush=True)  # a start that failed raised SystemExit above and does not get here


def _ask_server_to_stop_with(ask: Callable[[], None]) -> None:
    """Say how the server is asked to finish. A stop recorded before this is passed on at once."""
    global _ask_server_to_stop
    _ask_server_to_stop = ask
    if _stop_requested:
        ask()


def portal_command(argv0: str, python: str) -> str:
    """The command that started this run, written so that it works when typed from any folder.

    Started as ``python -m regaudit_portal``, ``argv0`` is the module's own file, so the command is the interpreter
    with ``-m``. Started as the installed program, it is that program's full path.
    """
    if os.path.basename(argv0) == "__main__.py":
        return f"{shlex.quote(python)} -m regaudit_portal"
    if os.sep not in argv0:
        argv0 = shutil.which(argv0) or argv0
    return shlex.quote(os.path.abspath(argv0))


def _serve_unavailable(port: int, reason: str, detail: str) -> int:
    """No engine, or an engine that failed its check: serve only the page that says so. Nothing is verified."""
    from .fallback import make_server

    sys.stderr.write(unavailable_message(reason, detail))
    try:
        server = make_server(port)
    except OSError as exc:
        sys.stderr.write(f"cannot listen on {HOST}:{port}: {exc.strerror or exc}\n")
        return 1
    port = server.server_address[1]  # the real port, also when 0 asked for any free one
    # Hand over from the package's early stop handler BEFORE the listening line is printed: whoever waits for that line
    # (a test, a launcher) may stop the portal the moment it appears. SIGTERM ends the page the way Ctrl-C does, so the
    # private bytecode folder is removed on the way out.
    _hand_over_from_the_early_stop(True)
    signal.signal(signal.SIGTERM, _stop_like_ctrl_c)
    # serve_forever ends at its next poll once shutdown() is called. shutdown() waits for that, so it is called from a
    # thread of its own and never from the handler, which runs in the serving thread.
    _ask_server_to_stop_with(lambda: threading.Thread(target=server.shutdown, daemon=True).start())
    try:
        print(listening_line(port, "unavailable"), flush=True)
        print(
            f"open http://{HOST}:{port} in a browser. It will say that verification is unavailable. "
            "Press Ctrl-C to stop.",
            flush=True,
        )
        server.serve_forever()
        _leaving()
        print(STOPPED, flush=True)
    except KeyboardInterrupt:  # a Ctrl-C handler this program did not set, if any
        _leaving()
        print(STOPPED, flush=True)
    finally:
        server.server_close()
    return 3


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except KeyboardInterrupt:
        _leaving()
        # A stop asked for after the early handler was handed over. The portal says so and ends with status 0. Any
        # other command (demo-setup, check-config) stops with status 1, so that a script never takes it for success.
        if _serving or sys.argv[1:2] == ["serve"]:
            print(STOPPED, flush=True)
            return 0
        print("stopped.", flush=True)
        return 1


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="regaudit-portal")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Start the portal on this computer only.")
    serve.add_argument(
        "--config",
        help="The configuration file. Without it, the standard per-user location is used if a file is there.",
    )
    serve.add_argument(
        "--port", type=int, default=8765, help="The port on this computer. 0 takes any free port."
    )
    serve.add_argument(
        "--exit-when-input-closes",
        action="store_true",
        help="For a launcher: stop when standard input is closed, for example because the launcher was killed.",
    )
    check = commands.add_parser(
        "check-config", help="Say whether a configuration can be used, and why not."
    )
    check.add_argument(
        "--config", help="The configuration file. Without it, the standard per-user location."
    )
    demo = commands.add_parser(
        "demo-setup", help="Create a synthetic trust store, configuration and sample reports."
    )
    demo.add_argument("directory")
    args = parser.parse_args(argv)
    if args.command != "serve":
        _hand_over_from_the_early_stop(False)
    if args.command == "serve" and args.exit_when_input_closes:
        _stop_when_input_closes()

    # Before anything imports the engine: only the recognised release may be loaded and used.
    identity = check_engine()
    if not identity.ok:
        if args.command == "serve":
            return _serve_unavailable(args.port, identity.reason, identity.detail)
        sys.stderr.write(unavailable_message(identity.reason, identity.detail))
        return 3

    if args.command == "demo-setup":
        try:
            from .demo import create
        except Exception as exc:  # a library the engine needs is missing: the same plain message
            sys.stderr.write(
                unavailable_message("ENGINE_UNLOADABLE", f"{type(exc).__name__}: {exc}")
            )
            return 3

        try:
            root = create(args.directory)
        except FileExistsError:
            sys.stderr.write(f"{args.directory} already exists; choose a new directory\n")
            return 2
        print(f"created {root}")
        command = portal_command(sys.argv[0], sys.executable)
        print(f"next: {command} serve --config {shlex.quote(str(root / 'portal-config.json'))}")
        print("then open http://127.0.0.1:8765 and try the files in sample-reports")
        return 0

    try:
        from .config import ConfigProblem, approved_entries, load_portal
    except Exception as exc:  # a library the engine needs is missing: the same plain message
        reason, detail = "ENGINE_UNLOADABLE", f"{type(exc).__name__}: {exc}"
        if args.command == "serve":
            return _serve_unavailable(args.port, reason, detail)
        sys.stderr.write(unavailable_message(reason, detail))
        return 3

    if args.command == "check-config":
        configured = _configuration(args.config)
        if configured is None:
            sys.stderr.write(
                f"not usable: there is no configuration at {display_path(default_config_path())}\n"
            )
            return 3
        try:
            portal = load_portal(configured)
        except ConfigProblem as exc:
            sys.stderr.write(f"not usable: {exc}\n")
            return 3
        print(
            f"usable: profile {portal.profile}, {approved_entries(portal.approved_count)}, "
            f"replay mode {portal.replay_mode}"
        )
        print(f"engine: {portal.engine['summary']}")
        return 0

    try:
        import uvicorn  # noqa: F401 - checked here so a missing library is explained, not a traceback

        from .app import build_app
    except Exception as exc:  # a library the portal needs is missing: serve the page that says so
        return _serve_unavailable(args.port, "ENGINE_UNLOADABLE", f"{type(exc).__name__}: {exc}")

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        sock = _bind_loopback(args.port)
    except OSError as exc:
        sys.stderr.write(f"cannot listen on {HOST}:{args.port}: {exc.strerror or exc}\n")
        return 1
    configured = _configuration(args.config)
    app = build_app(configured, port=sock.getsockname()[1])
    print(f"engine: {identity.engine['summary'] if identity.engine else ''}", flush=True)
    _run(app, sock, app.state.mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
