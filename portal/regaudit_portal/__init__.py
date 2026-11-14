"""A local browser interface for checking signed regaudit-fhe reports.

It calls the published verifier and shows what it returns. It contains no cryptography of its own.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

# This comes first, before any module of this package or of the engine is imported. The engine check hashes the
# engine's source files, but Python can run a compiled ``.pyc`` file next to them without looking at the source (an
# unchecked-hash file, or one whose recorded time and size match). Pointing the bytecode cache at a fresh private
# folder means no ``.pyc`` file inside the engine's folder, or anywhere else, is ever loaded: modules imported from now
# on are compiled from their source files, which are the files that were checked. The folder is created with mode
# 0700 when the package is first imported and removed, best effort, when the process exits. Modules that were
# already imported before this package was are not affected.
#
# A stop request that arrives while the portal is still starting (SIGTERM, which is what a launcher sends when the
# application quits, or SIGINT) must neither leave that folder behind nor end in a traceback, and it must not be lost.
# While the portal is starting, nothing is being served, so a stop is handled here without raising anything: the
# handler removes the folder and ends the process at once. (Raising KeyboardInterrupt in the middle of the engine's
# libraries is not safe: pydantic, for one, catches it and turns it into a SchemaError, and the portal then carried on
# instead of stopping.) When this package is the program itself (``python -m regaudit_portal``, or the
# ``regaudit-portal`` script), the handler is put in place as the first thing, before the folder is made and before
# anything but ``os``, ``signal`` and ``sys`` is imported, so there is no moment when the folder exists and a stop would
# skip removing it. The portal replaces the handler just before it starts to serve. A program that merely imports this
# package keeps its own signal handling.
import os
import signal
import sys

STOPPED = "the portal has stopped."

# Once the portal is serving, a stop is a KeyboardInterrupt (or uvicorn's own graceful shutdown). If the portal has not
# gone this many seconds after the first stop request, whatever swallowed it is bypassed and the portal leaves at once.
# This is less than the six seconds the macOS launcher waits before it kills the portal.
STOP_DEADLINE_SECONDS = 5.0

_folder: str | None = None

# What a command other than the portal says when a stop ends it. Until the command starts to change anything it is true
# that nothing was changed; a command that goes on to write files says something else from then on.
_stop_words: str | None = None


def _say_when_stopped(words: str) -> None:
    global _stop_words
    _stop_words = words


_rmtree = None  # shutil.rmtree, once shutil has been imported; the handler must not import anything itself


def _leave_now() -> None:
    """Remove the private folder, say so and end the process at once. Safe in a signal handler or a timer thread.

    It imports nothing: a stop can arrive while a module is half imported, and importing it again from here would find
    it only partly made. The portal itself stops with status 0 and says so. Any other command (check-config,
    demo-setup, the administrator commands) has not done anything yet when this runs, so it says that, and leaves with
    status 1: a script that runs it must never take a stop for success.

    The words are written to the output's descriptor itself, not with print or a flush: a signal's handler can run
    while the program is inside print, holding the output stream's lock (Python runs pending handlers between the
    pieces of a write), and print would then fail with "reentrant call" and say nothing. From the deadline's timer
    thread, taking that lock could wait for ever on a write that is stuck. The portal prints its own lines with
    flush, so nothing of its own is left waiting in the stream.
    """
    folder, rmtree = _folder, _rmtree
    if folder is not None and rmtree is not None:
        try:  # noqa: SIM105 - contextlib is not imported here: nothing may be imported by this handler
            rmtree(folder, ignore_errors=True)
        except Exception:  # noqa: S110 - nothing may get in the way of leaving
            pass
    serving = sys.argv[1:2] == ["serve"]
    words = (STOPPED if serving else (_stop_words or "stopped: Nothing was changed.")) + "\n"
    stream = sys.stdout
    if stream is not None:
        try:  # noqa: SIM105 - contextlib is not imported here: nothing may be imported by this handler
            os.write(stream.fileno(), words.encode())
        except Exception:  # noqa: S110 - nothing may get in the way of leaving
            pass
    os._exit(0 if serving else 1)


def _stop_while_starting(_signum: int, _frame: object) -> None:
    _leave_now()


def _is_the_program() -> bool:
    first = sys.argv[0] if sys.argv else ""
    return first == "-m" or os.path.basename(first) in ("regaudit-portal", "regaudit-portal.exe")


def _is_an_administrator_command() -> bool:
    """The two commands that change a trust list on disk. A hang-up (SIGHUP) in their first moments is handled like a stop,
    so that nothing is left half done. The portal itself is not one of them and keeps its own behaviour."""
    return sys.argv[1:2] in (["admin-describe"], ["admin-apply"])


def _stop_quietly_while_starting() -> None:
    if not _is_the_program():  # never a program that merely imports this package
        return
    # The launcher's option says this portal must always be stoppable, so it takes SIGTERM even if its parent had it
    # ignored. Without the option an inherited "ignore" is left as it is.
    launcher = "--exit-when-input-closes" in sys.argv
    try:
        term = signal.getsignal(signal.SIGTERM)
        if term == signal.SIG_DFL or (launcher and term == signal.SIG_IGN):
            signal.signal(signal.SIGTERM, _stop_while_starting)
        if signal.getsignal(signal.SIGINT) is signal.default_int_handler:
            signal.signal(signal.SIGINT, _stop_while_starting)
        hangup = getattr(signal, "SIGHUP", None)
        if (
            hangup is not None
            and _is_an_administrator_command()
            and signal.getsignal(hangup) == signal.SIG_DFL
        ):
            signal.signal(hangup, _stop_while_starting)
    except ValueError:  # not the main thread: signals cannot be set from here
        pass


def _use_a_private_bytecode_cache() -> str:
    global _folder, _rmtree
    _stop_quietly_while_starting()  # first, before the heavier imports below
    import atexit
    import shutil
    import tempfile

    _rmtree = shutil.rmtree

    # A stop that arrives between making the folder and remembering it would leave it behind: hold such a request
    # over those few steps. It is delivered, and handled with the folder known, when they are done.
    held = {signal.SIGTERM, signal.SIGINT}
    if _is_an_administrator_command() and hasattr(signal, "SIGHUP"):
        held.add(signal.SIGHUP)
    program = _is_the_program()
    before = (
        signal.pthread_sigmask(signal.SIG_BLOCK, held)
        if hasattr(signal, "pthread_sigmask")
        else None
    )
    try:
        folder = tempfile.mkdtemp(
            prefix="regaudit-portal-pyc-"
        )  # a new, empty folder, readable by this account only
        _folder = folder
        os.chmod(folder, 0o700)
        sys.pycache_prefix = folder
        atexit.register(shutil.rmtree, folder, ignore_errors=True)
    finally:
        if before is not None:
            # A program that merely imports this package may have a stop request held on purpose (a command that wants
            # to take it later does), so the mask is put back exactly as it was. The portal itself is a server that must
            # always be stoppable: if its parent started it with these two blocked, it unblocks them, or nothing but
            # SIGKILL could end it.
            signal.pthread_sigmask(signal.SIG_SETMASK, (before - held) if program else before)
    return folder


PRIVATE_BYTECODE_CACHE = _use_a_private_bytecode_cache()

__version__ = "0.0.1"
