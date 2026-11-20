"""Local file helpers for writing a trust store: an advisory lock and a durable atomic replace.

The lock is ``flock`` on the directory that holds the store, so no lock file is created and the store's on-disk format is
unchanged. It is advisory: it orders cooperating ``regaudit-fhe`` processes on one local filesystem. It does not stop
another program, the same account or an administrator, and ``flock`` may not be honoured on a network filesystem.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import contextlib
import os
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

NEW_STORE_MODE = 0o600


@contextlib.contextmanager
def store_lock(path: str | Path) -> Iterator[None]:
    """Hold an exclusive advisory lock on the store's directory for the read-modify-write.

    A directory that does not exist is not locked here; the caller's own checks refuse it. Any other failure to lock
    raises ``OSError`` so the caller refuses to write.
    """
    try:
        import fcntl
    except ImportError:  # pragma: no cover - the supported platforms have it
        yield
        return
    directory = os.path.dirname(os.path.abspath(path))
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except (FileNotFoundError, NotADirectoryError):
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)  # closing releases the lock


def write_store_atomic(path: str | Path, data: bytes) -> None:
    """Replace ``path`` with ``data``: temp file in the same directory, fsync, mode, ``os.replace``, directory fsync.

    A new store is created with mode 0600 whatever the umask. An existing store keeps the permission bits it has; they
    are neither widened nor narrowed. Any failure before ``os.replace`` leaves the old file as it was and removes the
    temp file.
    """
    target = Path(path)
    directory = target.parent if str(target.parent) else Path(".")
    try:
        mode = stat.S_IMODE(target.stat().st_mode)
    except FileNotFoundError:
        mode = NEW_STORE_MODE
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".trust-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    dir_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
