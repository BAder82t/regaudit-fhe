"""Can another unprivileged local account change this file? Used for the trust store and the replay file.

These checks keep out other accounts. They say nothing about the same account, an administrator or a restored backup.
Supported on Linux and macOS. Anything that cannot be established is reported as a problem, so a caller fails closed.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
from collections.abc import Collection

_ACL_TYPE_EXTENDED = 0x00000100
# Rights an ACL can allow without letting anyone change the object. Anything else counts as write access.
_ACL_READ_ONLY_RIGHTS = frozenset(
    {
        "read",
        "execute",
        "search",
        "list",
        "readattr",
        "readextattr",
        "readsecurity",
    }
)
_ACL_FLAGS = frozenset(
    {"inherited", "file_inherit", "directory_inherit", "limit_inherit", "only_inherit"}
)
_MAX_LINKS = 40


def platform_problem() -> str | None:
    if (
        not sys.platform.startswith(("linux", "darwin"))
        or not hasattr(os, "geteuid")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        return "this platform cannot establish the owner and permissions of the file"
    return None


def _acl_text_problem(text: str, what: str) -> str | None:
    """A macOS ACL: an allow entry with any right beyond reading, for anyone but us or root, is refused."""
    lines = [line for line in text.splitlines() if line and not line.startswith("!#acl")]
    euid = os.geteuid()
    for line in lines:
        fields = line.rsplit(":", 3)
        if len(fields) != 4 or ":" not in fields[0]:
            return f"the ACL on {what} cannot be read reliably"
        principal, identifier, kind, rights = fields
        kind, *flags = kind.split(",")  # for example allow,inherited or allow,file_inherit
        if set(flags) - _ACL_FLAGS or kind not in ("allow", "deny"):
            return f"the ACL on {what} cannot be read reliably"
        if kind == "deny":
            continue
        if principal.startswith("user:") and identifier in (str(euid), "0"):
            continue
        if set(rights.split(",")) - _ACL_READ_ONLY_RIGHTS:
            return f"an ACL on {what} lets another principal write it"
    return None


def _macos_acl_problem(what: str, fd: int | None, path: str | None) -> str | None:
    """``fd`` for an opened file. ``path`` for a directory, without following a link."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.acl_get_fd_np.restype = ctypes.c_void_p
        libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
        libc.acl_get_link_np.restype = ctypes.c_void_p
        libc.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
        libc.acl_to_text.restype = ctypes.c_void_p
        libc.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
        libc.acl_free.argtypes = [ctypes.c_void_p]
    except (OSError, AttributeError):
        return f"the ACL on {what} cannot be read on this system"
    ctypes.set_errno(0)
    if fd is not None:
        acl = libc.acl_get_fd_np(fd, _ACL_TYPE_EXTENDED)
    else:
        assert path is not None
        acl = libc.acl_get_link_np(os.fsencode(path), _ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:  # how macOS says there is no ACL
            return None
        return f"the ACL on {what} cannot be read reliably"
    try:
        size = ctypes.c_ssize_t(0)
        text = libc.acl_to_text(acl, ctypes.byref(size))
        if not text:
            return f"the ACL on {what} cannot be read reliably"
        try:
            return _acl_text_problem(ctypes.string_at(text, size.value).decode("utf-8"), what)
        except UnicodeDecodeError:
            return f"the ACL on {what} cannot be read reliably"
        finally:
            libc.acl_free(text)
    finally:
        libc.acl_free(acl)


def acl_problem(what: str, *, fd: int | None = None, path: str | None = None) -> str | None:
    """On Linux a POSIX ACL entry that grants write shows in the group bits, so the mode check already refuses it."""
    if sys.platform != "darwin":
        return None
    return _macos_acl_problem(what, fd, path)


def _directory_entry_problem(
    path: str, info: os.stat_result, *, sticky_allowed: bool
) -> str | None:
    if not stat.S_ISDIR(info.st_mode):
        return f"{path!r} is not a directory"
    if stat.S_IMODE(info.st_mode) & 0o022 and not (sticky_allowed and info.st_mode & stat.S_ISVTX):
        return f"{path!r} is writable by group or others"
    return acl_problem(repr(path), path=path)


def resolve_directory(directory: str) -> tuple[str | None, str]:
    """Walk ``directory`` one component at a time, as the kernel does, and check everything on the way.

    Whoever can change a directory on the way to the file can replace what is under it. So each directory, and the
    directory holding each symbolic link, must belong to us or to root and not be writable by group or others. ``..``
    goes up from where a link really led, not from how the path is written. A sticky directory above the parent is
    allowed, because others cannot rename what they do not own. The parent itself may not be sticky, because anyone
    could create the file first. Returns the problem, if any, and the directory the walk ended in.
    """
    euid = os.geteuid()
    try:
        start = directory if os.path.isabs(directory) else os.path.join(os.getcwd(), directory)
    except OSError as exc:
        return f"cannot inspect the working directory: {exc}", directory
    pending = list(reversed(start.split("/")))
    current = "/"
    links = 0
    try:
        problem = _directory_entry_problem("/", os.lstat("/"), sticky_allowed=True)
    except OSError as exc:
        return f"cannot inspect '/': {exc}", current
    if problem is not None:
        return problem, current
    while pending:
        part = pending.pop()
        if part in ("", "."):
            continue
        if part == "..":
            current = os.path.dirname(current)
            continue
        candidate = os.path.join(current, part)
        try:
            info = os.lstat(candidate)
            if info.st_uid not in (euid, 0):
                return f"{candidate!r} belongs to another account", candidate
            if stat.S_ISLNK(info.st_mode):
                links += 1
                if links > _MAX_LINKS:
                    return f"too many symbolic links on the way to {directory!r}", candidate
                target = os.readlink(candidate)
                if target.startswith("/"):
                    current = "/"
                pending.extend(reversed(target.split("/")))
                continue
        except OSError as exc:
            return f"cannot inspect {candidate!r}: {exc}", candidate
        problem = _directory_entry_problem(candidate, info, sticky_allowed=True)
        if problem is not None:
            return problem, candidate
        current = candidate
    try:
        return _directory_entry_problem(current, os.lstat(current), sticky_allowed=False), current
    except OSError as exc:
        return f"cannot inspect {current!r}: {exc}", current


def directory_problem(directory: str) -> str | None:
    return resolve_directory(directory)[0]


def resolve_file(path: str) -> tuple[str | None, str]:
    """Follow a final symbolic link one hop at a time, and check every directory and link on the way.

    A chain of links can pass through a directory that neither the path as written nor the file's real location shows,
    and whoever can write there can point the chain at another file. Returns the problem, if any, and where the chain
    ended, which need not exist.
    """
    euid = os.geteuid()
    current = path
    for _ in range(_MAX_LINKS + 1):
        head, tail = os.path.split(current)
        problem, directory = resolve_directory(head or ".")
        if problem is not None:
            return problem, current
        target = os.path.join(directory, tail)
        try:
            info = os.lstat(target)
            if not stat.S_ISLNK(info.st_mode):
                return None, target
            if info.st_uid not in (euid, 0):
                return f"{target!r} belongs to another account", target
            current = os.path.join(directory, os.readlink(target))
        except FileNotFoundError:
            return None, target
        except OSError as exc:
            return f"cannot inspect {target!r}: {exc}", target
    return f"too many symbolic links on the way to {path!r}", current


def file_problem(info: os.stat_result, *, owners: Collection[int] | None = None) -> str | None:
    """``info`` comes from the opened file. By default only we may own it."""
    if not stat.S_ISREG(info.st_mode):
        return "it is not a regular file"
    if info.st_uid not in (owners if owners is not None else (os.geteuid(),)):
        return "it belongs to another account"
    if stat.S_IMODE(info.st_mode) & 0o022:
        # No trusted group can be declared yet, so a group-writable mode cannot be judged and is refused.
        return f"mode {stat.S_IMODE(info.st_mode):04o} lets group or others write it"
    if info.st_nlink != 1:
        return "it has more than one name"
    return None
