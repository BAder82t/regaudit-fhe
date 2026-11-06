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
import contextlib
import logging
import os
import shlex
import shutil
import signal
import socket
import sys
import threading

# Standard library only, so it is safe to import when the engine is missing or damaged.
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


STOPPED = "the portal has stopped."


def _stop_like_ctrl_c(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def _stop_when_input_closes() -> None:
    """For a launcher: stop like Ctrl-C when the other end of standard input closes.

    A launcher that holds the write end of a pipe on the portal's standard input closes it when it quits, crashes or is
    killed, even by SIGKILL. The portal then stops cleanly instead of running on with nothing to stop it.
    """
    signal.signal(signal.SIGTERM, _stop_like_ctrl_c)

    def watch() -> None:
        try:
            while sys.stdin.buffer.read(4096):
                pass
        except (OSError, ValueError):
            pass
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

    class Announcing(uvicorn.Server):
        async def startup(self, sockets: list | None = None) -> None:
            await super().startup(sockets=sockets)
            if self.started:  # only after the socket was taken up; a failed start exits before this
                print(listening_line(port, mode), flush=True)
                print(started_message(mode, port), flush=True)

    port = sock.getsockname()[1]
    config = uvicorn.Config(app, access_log=False, server_header=False, log_level="warning")
    signal.signal(signal.SIGTERM, _stop_like_ctrl_c)
    with contextlib.suppress(KeyboardInterrupt):
        Announcing(config).run(sockets=[sock])
    print(STOPPED, flush=True)  # a start that failed raised SystemExit above and does not get here


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
    print(listening_line(port, "unavailable"), flush=True)
    print(
        f"open http://{HOST}:{port} in a browser. It will say that verification is unavailable. "
        "Press Ctrl-C to stop.",
        flush=True,
    )
    # SIGTERM ends the page the way Ctrl-C does, so the private bytecode folder is removed on the way out.
    signal.signal(signal.SIGTERM, _stop_like_ctrl_c)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(STOPPED, flush=True)
    finally:
        server.server_close()
    return 3


def main(argv: list[str] | None = None) -> int:
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
