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
        "file_inherit",
        "directory_inherit",
        "limit_inherit",
        "only_inherit",
    }
)


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
        if kind == "deny":
            continue
        if kind != "allow":
            return f"the ACL on {what} cannot be read reliably"
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


def directory_problem(directory: str) -> str | None:
    """Whoever can change a directory on the way to the file can replace what is under it.

    Each directory, as written and resolved, must belong to us or to root and not be writable by group or others.
    A sticky directory above the parent is allowed, because others cannot rename what they do not own. The parent
    itself may not be sticky, because anyone could create the file first.
    """
    euid = os.geteuid()
    real = os.path.realpath(directory)
    for chain in (directory, real):
        current = chain
        while True:
            try:
                info = os.lstat(current)
            except OSError as exc:
                return f"cannot inspect {current!r}: {exc}"
            if info.st_uid not in (euid, 0):
                return f"{current!r} belongs to another account"
            if not stat.S_ISLNK(info.st_mode):
                if not stat.S_ISDIR(info.st_mode):
                    return f"{current!r} is not a directory"
                sticky_above = current != real and bool(info.st_mode & stat.S_ISVTX)
                if stat.S_IMODE(info.st_mode) & 0o022 and not sticky_above:
                    return f"{current!r} is writable by group or others"
                problem = acl_problem(repr(current), path=current)
                if problem is not None:
                    return problem
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
    return None


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
