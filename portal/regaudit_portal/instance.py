"""One running portal for each account and configuration folder (F-022).

Two portals on the same configuration folder would read and write the same trust list and replay file at the same
time. This module lets ``serve`` take an operating-system lock on a small file that belongs to this account and this
folder. The lock is ``flock``: it is taken atomically, so two starts at the same moment cannot both win, and it is
released by the system when the holder exits for any reason, including a crash or ``kill -9``. Nothing here checks a
process list or a port, because either can be wrong; and nothing here stops the portal that already holds the lock.

The lock files live in a private folder made for this account (not in the configuration folder, so that checking a
report or setting up an account still writes nothing there). The folder and each file are opened without following
links and are refused unless they are ours, regular, and closed to everyone else.

Only ``serve`` takes the lock. The other commands (check-config, demo-setup, admin-describe, admin-apply) do not, so
they work while a portal runs.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path

# The status ``serve`` ends with when another portal already holds the lock (sysexits EX_TEMPFAIL). A launcher shows a
# message for it instead of "the portal stopped".
ALREADY_RUNNING_STATUS = 75

_FOLDER_PREFIX = "regaudit-portal-instance-"
_INFO_LIMIT = 1024


class InstanceProblem(Exception):
    """The place for the lock cannot be made safe. The portal does not start without the lock."""


class AlreadyRunning(Exception):
    """Another portal holds the lock for this account and configuration folder."""

    def __init__(self, pid: int | None, url: str | None) -> None:
        self.pid = pid
        self.url = url
        who = f"process {pid}" if pid else "another process"
        where = f" at {url}" if url else ""
        super().__init__(
            f"The Evidence Verification Portal is already running for this account and configuration folder "
            f"({who}{where}). Open that address, or quit that portal first. Nothing was stopped."
        )


def _darwin_user_temp() -> str:
    """macOS's own per-account temporary folder (confstr _CS_DARWIN_USER_TEMP_DIR). Unlike $TMPDIR it cannot be changed from
    outside, so two portals started from shells with different TMPDIR still meet at the same lock."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    buffer = ctypes.create_string_buffer(1024)
    if libc.confstr(65537, buffer, ctypes.c_size_t(len(buffer))) == 0:
        return ""
    return buffer.value.decode("utf-8", "surrogateescape")


def _base_folder() -> Path:
    """A per-account place that no environment variable can move: the system's own on macOS, the account's runtime folder or
    /tmp elsewhere. (The lock folder inside it is made private and checked; see ``_private_folder``.)"""
    if sys.platform == "darwin":
        try:
            found = _darwin_user_temp()
        except (OSError, AttributeError, ValueError):
            found = ""
        if found and os.path.isabs(found):
            return Path(found)
    runtime = Path(
        f"/run/user/{os.geteuid()}"
    )  # Linux: the account's runtime folder, when there is one and it is ours
    try:
        info = runtime.lstat()
        if (
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid()
            and not stat.S_IMODE(info.st_mode) & 0o022
        ):
            return runtime
    except OSError:
        pass  # no runtime folder for this account (not Linux, or none made): the shared place below is used instead
    return Path("/tmp")  # noqa: S108 - a fixed shared place; the folder made inside it is checked to be ours and private


def instance_folder() -> Path:
    return _base_folder() / f"{_FOLDER_PREFIX}{os.geteuid()}"


def root_key(config_root: str | os.PathLike[str]) -> str:
    """A name for a configuration folder. The folder need not exist yet (a first run has none)."""
    resolved = os.path.realpath(os.path.abspath(os.fspath(config_root)))
    return hashlib.sha256(resolved.encode("utf-8", "surrogateescape")).hexdigest()[:32]


def _private_folder(path: Path) -> int:
    """Open the folder, making it (mode 0700) if it is missing, and return a descriptor. Refuse an unsafe one."""
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass  # made by an earlier start: its owner and mode are checked right below, so nothing is trusted unchecked
    except OSError as exc:
        raise InstanceProblem(f"cannot make {path}: {exc.strerror or exc}") from exc
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        reason = (
            "it is a link"
            if exc.errno in (errno.ELOOP, errno.ENOTDIR)
            else exc.strerror or str(exc)
        )
        raise InstanceProblem(f"cannot use {path}: {reason}") from exc
    info = os.fstat(fd)
    if info.st_uid != os.geteuid():
        os.close(fd)
        raise InstanceProblem(f"{path} belongs to another account")
    if stat.S_IMODE(info.st_mode) & 0o077:
        os.close(fd)
        raise InstanceProblem(f"{path} can be used by group or others")
    return fd


def _open_lock(folder_fd: int, name: str) -> int:
    # Several starts at the same instant all try to create the file. macOS can answer one of them "no such file" in that
    # moment although the file is being made, so a few more tries are made. Each try still refuses a link.
    fd = -1
    for attempt in range(100):
        try:
            fd = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=folder_fd,
            )
            break
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.EEXIST) and attempt < 99:
                time.sleep(0.01)
                continue
            reason = "it is a link" if exc.errno == errno.ELOOP else exc.strerror or str(exc)
            raise InstanceProblem(f"cannot open the instance lock {name}: {reason}") from exc
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        os.close(fd)
        raise InstanceProblem(
            f"the instance lock {name} is not a private regular file of this account"
        )
    return fd


def _holder(fd: int) -> tuple[int | None, str | None]:
    """What the holder wrote, for the message. It is only a hint: the lock itself is what counts."""
    try:
        raw = os.pread(fd, _INFO_LIMIT, 0)
        data = json.loads(raw.decode("utf-8")) if raw else {}
    except (OSError, ValueError):
        return None, None
    pid = data.get("pid") if isinstance(data, dict) else None
    url = data.get("url") if isinstance(data, dict) else None
    return (
        pid if isinstance(pid, int) and not isinstance(pid, bool) else None,
        url if isinstance(url, str) and url.startswith("http://127.0.0.1:") else None,
    )


class InstanceLock:
    """The lock, held until this object is closed or the process ends."""

    def __init__(self, fd: int) -> None:
        self._fd: int | None = fd

    def publish(self, url: str | None = None) -> None:
        """Write who holds the lock, so that a second start can say so. The lock does not depend on it."""
        if self._fd is None:
            return
        data = json.dumps({"pid": os.getpid(), "url": url}).encode("utf-8")
        try:
            os.ftruncate(self._fd, 0)
            os.pwrite(self._fd, data, 0)
        except OSError:
            pass  # a hint only

    def close(self) -> None:
        if self._fd is not None:
            fd, self._fd = self._fd, None
            os.close(fd)  # closing the descriptor releases the lock


def acquire(
    config_root: str | os.PathLike[str],
    *,
    wait: float = 0.0,
    folder: Path | None = None,
) -> InstanceLock:
    """Take the lock for this account and configuration folder, or raise ``AlreadyRunning``.

    ``wait`` is how many seconds to keep trying, for a portal that is being restarted and whose predecessor is still
    stopping. The lock file is never deleted: removing it would let two holders each have a different file.
    """
    place = folder if folder is not None else instance_folder()
    folder_fd = _private_folder(place)
    try:
        fd = _open_lock(folder_fd, root_key(config_root) + ".lock")
    finally:
        os.close(folder_fd)
    end = time.monotonic() + max(0.0, wait)
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno not in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                    raise InstanceProblem(
                        f"cannot lock the instance file: {exc.strerror or exc}"
                    ) from exc
                if time.monotonic() < end:
                    time.sleep(0.05)
                    continue
                pid, url = _holder(fd)
                raise AlreadyRunning(pid, url) from None
            lock = InstanceLock(fd)
            lock.publish(None)
            return lock
    except BaseException:
        os.close(
            fd
        )  # a refusal, a problem or an interrupt: the descriptor is not kept, and no lock is held
        raise
