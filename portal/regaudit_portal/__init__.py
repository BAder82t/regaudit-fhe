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
# application quits, or SIGINT) must neither leave that folder behind nor end in a traceback. When this package is the
# program itself (``python -m regaudit_portal``), the handler below is put in place before the folder is made, so there
# is no moment when the folder exists and a stop would skip removing it. The portal replaces the handler with its own
# once it is serving. A program that merely imports this package keeps its own signal handling.
import atexit
import contextlib
import os
import shutil
import signal
import sys
import tempfile

STOPPED = "the portal has stopped."

_folder: str | None = None


def _stop_while_starting(_signum: int, _frame: object) -> None:
    """Nothing is being served and nothing is half-written: remove the private folder, say so and leave with status 0."""
    if _folder is not None:
        shutil.rmtree(_folder, ignore_errors=True)
    with contextlib.suppress(Exception):  # nothing may get in the way of leaving
        print(STOPPED, flush=True)
    os._exit(0)


def _stop_quietly_while_starting() -> None:
    if (
        not sys.argv or sys.argv[0] != "-m"
    ):  # only the program itself, never a program that imports this package
        return
    try:
        if (
            signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
        ):  # an inherited "ignore" is left as it is
            signal.signal(signal.SIGTERM, _stop_while_starting)
        if signal.getsignal(signal.SIGINT) is signal.default_int_handler:
            signal.signal(signal.SIGINT, _stop_while_starting)
    except ValueError:  # not the main thread: signals cannot be set from here
        pass


def _use_a_private_bytecode_cache() -> str:
    global _folder
    _stop_quietly_while_starting()
    # A stop that arrives between making the folder and remembering it would leave it behind: hold such a request
    # over those few steps. It is delivered, and handled with the folder known, when they are done.
    held = {signal.SIGTERM, signal.SIGINT}
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, held)
    try:
        folder = tempfile.mkdtemp(
            prefix="regaudit-portal-pyc-"
        )  # a new, empty folder, readable by this account only
        _folder = folder
        os.chmod(folder, 0o700)
        sys.pycache_prefix = folder
        atexit.register(shutil.rmtree, folder, ignore_errors=True)
    finally:
        if hasattr(signal, "pthread_sigmask"):
            signal.pthread_sigmask(signal.SIG_UNBLOCK, held)
    return folder


PRIVATE_BYTECODE_CACHE = _use_a_private_bytecode_cache()

__version__ = "0.0.1"
