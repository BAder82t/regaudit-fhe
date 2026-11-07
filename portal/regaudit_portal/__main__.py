"""``regaudit-portal serve``, ``check-config`` and ``demo-setup``. Only the administrator uses these.

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
import sys

# Standard library only, so it is safe to import when the engine is missing or damaged.
from .engine import REINSTALL, check_engine

HOST = "127.0.0.1"  # local only: this first version has no sign-in, so it must not be reachable from a network


def started_message(ready: bool, port: int) -> str:
    """What to tell the administrator once the portal is listening. Not before, and not if it never started."""
    if ready:
        return f"open http://{HOST}:{port} in a browser. Press Ctrl-C to stop."
    return (
        "the portal is running but NOT ready, so it gives no verdicts. "
        "Run check-config with the same --config to see why. Press Ctrl-C to stop."
    )


def unavailable_message(reason: str, detail: str) -> str:
    """For the administrator's terminal. It names what failed and where, so it must never reach a browser."""
    return (
        f"not usable: verification unavailable: {reason}: {detail}. Reinstall with: {REINSTALL}\n"
    )


STOPPED = "the portal has stopped."


def _stop_like_ctrl_c(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def _run(app: object, port: int, ready: bool) -> None:
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
            if self.started:  # only after the port was bound; a failed start exits before this
                print(started_message(ready, port), flush=True)

    config = uvicorn.Config(
        app, host=HOST, port=port, access_log=False, server_header=False, log_level="warning"
    )
    signal.signal(signal.SIGTERM, _stop_like_ctrl_c)
    with contextlib.suppress(KeyboardInterrupt):
        Announcing(config).run()
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
    serve.add_argument("--config", required=True)
    serve.add_argument("--port", type=int, default=8765)
    check = commands.add_parser(
        "check-config", help="Say whether a configuration can be used, and why not."
    )
    check.add_argument("--config", required=True)
    demo = commands.add_parser(
        "demo-setup", help="Create a synthetic trust store, configuration and sample reports."
    )
    demo.add_argument("directory")
    args = parser.parse_args(argv)

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
        try:
            portal = load_portal(args.config)
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
    app = build_app(args.config, port=args.port)
    print(f"engine: {identity.engine['summary'] if identity.engine else ''}", flush=True)
    _run(app, args.port, app.state.ready)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
