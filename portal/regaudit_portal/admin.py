"""Applying an administrator setup plan: ``regaudit-portal admin-describe PLAN`` and ``regaudit-portal admin-apply PLAN``.

This is the only part of the portal that writes the administrator's configuration and trust list. The portal process
never imports it, so no page, route or request can reach it. A person runs it, in Terminal or through the application's
Administrator setup menu. It can do nothing that person could not already do by hand with ``regaudit-fhe trust add``
and a text editor: it adds no privilege.

What it holds to:

* The installed engine must pass the strict identity check, before anything is read and again just before anything is
  written.
* For every issuer, the person must type the fingerprint they received from that issuer by another route, and it must
  equal the fingerprint the engine computes from the key in the plan. The plan holds no fingerprint of its own, and
  there is no option, setting or file that skips this.
* Keys are enrolled by the engine's own ``trust add`` code, so the fingerprint check and the file format are exactly
  those of ``regaudit-fhe trust add``. What it wrote is then compared byte for byte with what was shown beforehand.
* A plan never names a destination. It is the standard folder for this account, or the folder given on the command line
  with ``--config-folder`` by the person running it.
* Every folder on the way is opened one at a time without following a symbolic link. A link anywhere is refused, and so
  is a folder or file that belongs to another account or can be changed by group or others.
* A first setup refuses to replace an existing configuration or trust list. Adding issuers only adds entries to an
  existing trust list. Nothing is removed, revoked or replaced.
* The folder is made with mode 0700 and the files with mode 0600. They are written in a new private folder next to their
  destination, synced to disk, checked with the portal's own readers, and then moved into place. If anything fails
  before that move, nothing has changed. Only one apply can run at a time for a folder.

It never reads standard input: the questions, when there is no ``--expect-fingerprint``, are asked on the terminal.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import fcntl
import hashlib
import io
import json
import os
import secrets
import signal
import stat
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from regaudit_fhe import (
    cli,
)  # the code behind regaudit-fhe trust add, loaded here and never by the portal
from regaudit_fhe.canonical import CanonicalError, loads_strict
from regaudit_fhe.trust import MAX_TRUST_STORE_BYTES, TrustStore, TrustStoreError

from .config import (
    CUSTOMER,
    ConfigProblem,
    Settings,
    legacy_warnings,
    read_settings,
    read_trust_store,
    trust_mode_of,
)
from .engine import REINSTALL, check_engine
from .paths import CONFIG_NAME, default_config_folder, finder_steps
from .plan import (
    ADD_ISSUERS,
    FIRST_SETUP,
    MAX_PLAN_BYTES,
    TRUST_LIST_NAME,
    Plan,
    PlanProblem,
    body_lines,
    fingerprints_match,
    notices,
    quoted,
    read_plan,
    shown,
    top_lines,
    typed_fingerprint,
)

EXIT_DONE, EXIT_FAILED, EXIT_REFUSED, EXIT_ENGINE, EXIT_DONE_BUT = 0, 1, 2, 3, 4
STAGING_PREFIX = ".regaudit-admin-"
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_RESTART = (
    "A running portal reads its configuration only when it starts. Restart it to use this configuration. The "
    "application's Administrator setup does this for you."
)
UNCHANGED = "Nothing was changed."
COMPLETE = "The change is complete: the new files are in place."
_STOPS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class Refused(Exception):
    """The plan, the fingerprints or the destination cannot be used. Nothing was changed."""


class Failed(Exception):
    """Something went wrong while writing. The message says what state the files are in."""


class Progress:
    """Whether the step that puts the new files in place has happened. Set in the same breath as that step."""

    committed = False


class _Stops:
    """A stop asked for while files are being put in place waits until they are. Python runs signal handlers in the
    main thread only, so this works whichever thread the signal reached."""

    holding = False
    pending = False
    # The command's result is final: the files are in place and checked, or the answer is given. A stop from then on
    # changes nothing, so it is not taken: it would only make the words and the status wrong.
    finished = False


def _stop_like_ctrl_c(_signum: int, _frame: object) -> None:
    if _Stops.finished:
        return
    if _Stops.holding:
        _Stops.pending = True
        return
    raise KeyboardInterrupt


@contextlib.contextmanager
def _held_signals() -> Iterator[None]:
    """Hold Ctrl-C, SIGTERM and SIGHUP for the few calls that put files in place, so that a stop lands before them or
    after them and never between them. A held stop takes effect as soon as this ends. SIGKILL and a power cut cannot
    be held."""
    _Stops.holding, _Stops.pending = True, False
    try:
        yield
    finally:
        _Stops.holding = False
        stop, _Stops.pending = _Stops.pending, False
    if stop:
        raise KeyboardInterrupt


def _sync(fd: int) -> None:
    """Flush a file or folder to the disk itself. On macOS fsync stops at the drive's cache, F_FULLFSYNC does not."""
    if hasattr(fcntl, "F_FULLFSYNC"):
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return
        except OSError:
            pass
    os.fsync(fd)


def _flush_committed(fd: int) -> None:
    """After the change is in place: flush the folder that now holds it, before a stop can be taken.

    It runs while stops are held, so a stop is taken only once the change is on the disk itself. If the flush fails,
    the words say exactly that: the files are in place, but may not survive a power cut.
    """
    try:
        _sync(fd)
    except OSError as exc:
        raise Failed(
            f"The new files are in place, but flushing them to the disk failed ({exc.strerror}). If the computer "
            "loses power before it writes them out, the change may be lost. Restart the portal, and run check-config."
        ) from exc


# ----------------------------------------------------------------------------- output


def _out(text: str, err: bool = False) -> bool:
    """Print text, on standard output or (``err``) standard error, with every control or invisible character made
    visible, line by line. Says whether it was printed.

    Printing never changes what happens to the files. A stream that was closed when the command started is not there
    at all (Python sets it to ``None``): nothing is printed and the command carries on. If nobody reads the output any
    more, for example because the launcher that started this command has quit, the rest of that output goes nowhere
    and the command carries on.
    """
    target = sys.stderr if err else sys.stdout
    if target is None:
        return False
    try:
        target.write("\n".join(shown(line, 100_000) for line in text.split("\n")) + "\n")
        target.flush()
        return True
    except (OSError, ValueError):
        with contextlib.suppress(OSError, ValueError, AttributeError):
            nowhere = os.open(os.devnull, os.O_WRONLY)
            os.dup2(nowhere, target.fileno())
            os.close(nowhere)
        return False


def _reserve_standard_descriptors() -> None:
    """Put the null device on standard input, output or error if one was closed when the command started.

    Otherwise the next file this command opens would get that number, and anything written to "standard error" by a
    library would land in it: in a trust list, say. Python has already set a closed stream to ``None``, so nothing is
    printed to the null device either: :func:`_out` skips it.
    """
    for number in (0, 1, 2):
        try:
            os.fstat(number)
        except OSError:
            with contextlib.suppress(OSError):
                fd = os.open(os.devnull, os.O_RDWR)
                if fd != number:
                    os.dup2(fd, number)
                    os.close(fd)


# ----------------------------------------------------------------------------- the plan file and the fingerprints


def _read_plan_file(path: str) -> bytes:
    """The plan's bytes: a regular file of at most the plan size limit. A pipe or a device is refused unread."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise Refused(f"The plan file cannot be opened: {exc.strerror}.") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refused("The plan is not a regular file.")
        data = bytearray()
        while chunk := os.read(fd, 65536):
            data += chunk
            if len(data) > MAX_PLAN_BYTES:
                raise Refused(
                    f"The plan file is larger than {MAX_PLAN_BYTES // 1024} KB, far more than a plan needs."
                )
        return bytes(data)
    finally:
        os.close(fd)


def _load_plan(path: str) -> Plan:
    try:
        return read_plan(_read_plan_file(path))
    except PlanProblem as exc:
        raise Refused(f"The plan cannot be used. {exc}") from exc


def _given_fingerprints(plan: Plan, given: list[str]) -> dict[str, str]:
    """``--expect-fingerprint KEY_ID=FINGERPRINT`` values: exactly one for each issuer in the plan, nothing else."""
    wanted = {issuer.key_id for issuer in plan.issuers}
    found: dict[str, str] = {}
    for item in given:
        key_id, sep, value = item.partition("=")
        if not sep or key_id not in wanted:
            raise Refused(
                "Each --expect-fingerprint must be KEY_ID=FINGERPRINT, with the key id of an issuer in the plan. "
                "One of them is not."
            )
        if key_id in found:
            raise Refused(f"Two fingerprints were given for key id {key_id}.")
        found[key_id] = value
    missing = [issuer for issuer in plan.issuers if issuer.key_id not in found]
    if missing:
        names = ", ".join(f"{quoted(i.issuer)} (key id {i.key_id})" for i in missing)
        raise Refused(
            f"No fingerprint was given for {names}. Give one --expect-fingerprint for each issuer."
        )
    return found


def ask_on_terminal(question: str) -> str:
    """Ask on the terminal itself, never through standard input. Raises ``OSError`` when there is no terminal."""
    fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    try:
        raw = io.FileIO(fd, "w+")
    except BaseException:
        os.close(fd)  # the descriptor is not owned by anything yet
        raise
    # A terminal cannot seek, so it is read and written through one unbuffered file, as getpass does.
    with raw, io.TextIOWrapper(raw, encoding="utf-8", errors="replace") as tty:
        tty.write(question)
        tty.flush()
        return tty.readline(1024)


def _asked_fingerprints(plan: Plan) -> dict[str, str]:
    found = {}
    for number, issuer in enumerate(plan.issuers, start=1):
        question = (
            f"Fingerprint for issuer {number}, {quoted(issuer.issuer)} (key id {issuer.key_id}), as the issuer "
            "gave it to you by another route: "
        )
        try:
            found[issuer.key_id] = ask_on_terminal(question)
        except OSError as exc:
            raise Refused(
                "There is no terminal to ask in. Give each fingerprint with --expect-fingerprint KEY_ID=FINGERPRINT."
            ) from exc
    return found


def _check_fingerprints(plan: Plan, typed: dict[str, str]) -> dict[str, str]:
    """Each typed fingerprint, normalised, if every one matches its key. The computed fingerprint is never shown."""
    checked, wrong = {}, []
    for number, issuer in enumerate(plan.issuers, start=1):
        where = f"issuer {number} ({quoted(issuer.issuer)}, key id {issuer.key_id})"
        try:
            value = typed_fingerprint(typed[issuer.key_id], where)
        except PlanProblem as exc:
            raise Refused(f"{exc} {UNCHANGED}") from exc
        if not fingerprints_match(value, issuer.fingerprint):
            wrong.append(where)
        checked[issuer.key_id] = value
    if wrong:
        raise Refused(
            f"The fingerprint typed for {', '.join(wrong)} does not match the key in the plan. {UNCHANGED} Check the "
            "fingerprint with the issuer by a call or another route. If it is right, the plan does not hold that "
            "issuer's key: do not apply it."
        )
    return checked


# ----------------------------------------------------------------------------- the destination


def destination(given: str | None) -> tuple[Path, bool]:
    """The folder to write to, and whether it is this account's standard folder. A plan never decides this."""
    if given is None:
        try:
            place, standard = default_config_folder(), True
        except RuntimeError as exc:
            raise Refused(
                "This account has no home folder, so there is no standard folder to use."
            ) from exc
    else:
        if "\x00" in given or not given:
            raise Refused("The folder given with --config-folder is not a usable path.")
        place, standard = Path.cwd() / given, False
    if not place.is_absolute() or ".." in place.parts:
        raise Refused(
            f"The configuration folder must be a full path without '..' in it, not {quoted(str(place))}."
        )
    place = Path(os.path.normpath(place))
    if place == Path(place.anchor):
        raise Refused("The configuration folder cannot be the root folder.")
    return place, standard


def _refuse_entry(path: Path, info: os.stat_result, *, folder: bool) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise Refused(
            f"{path} is a symbolic link. Links are not followed. Give the real folder instead."
        )
    if folder and not stat.S_ISDIR(info.st_mode):
        raise Refused(f"{path} is not a folder.")


def _check_ancestor(fd: int, path: Path) -> None:
    info = os.fstat(fd)
    if info.st_uid not in (os.geteuid(), 0):
        raise Refused(f"{path} belongs to another account.")
    if stat.S_IMODE(info.st_mode) & 0o022 and not info.st_mode & stat.S_ISVTX:
        raise Refused(f"{path} can be changed by group or others.")


def _check_own(info: os.stat_result, path: Path) -> None:
    if info.st_uid != os.geteuid():
        raise Refused(f"{path} belongs to another account.")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise Refused(f"{path} can be changed by group or others.")


def _open_parent(folder: Path) -> int:
    """Open the folder that holds ``folder``, one step at a time from the root, never following a link."""
    fd = os.open(folder.anchor or "/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    here = Path(folder.anchor or "/")
    try:
        _check_ancestor(fd, here)
        for name in folder.parent.parts[1:]:
            here = here / name
            try:
                next_fd = os.open(name, _DIR, dir_fd=fd)
            except FileNotFoundError as exc:
                raise Refused(
                    f"{here} does not exist. Make it first, or give another --config-folder."
                ) from exc
            except OSError as exc:
                with contextlib.suppress(OSError):
                    _refuse_entry(
                        here, os.stat(name, dir_fd=fd, follow_symlinks=False), folder=True
                    )
                raise Refused(f"{here} cannot be opened: {exc.strerror}.") from exc
            os.close(fd)
            fd = next_fd
            _check_ancestor(fd, here)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _entry(dir_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


@dataclasses.dataclass
class Existing:
    """What an add-issuers plan starts from: the configuration's settings and the trust list as it is now."""

    settings: Settings
    store_name: str
    data: bytes
    payload: dict[str, Any]
    identity: tuple[
        int, int, int, int
    ]  # device, inode, size and change time of the trust list read


class Destination:
    """The destination folder, opened without following links and checked. Writes only through :meth:`apply`."""

    def __init__(self, folder: Path) -> None:
        self.folder = folder
        self.parent_fd = -1
        self.folder_fd: int | None = None

    def __enter__(self) -> Destination:
        if os.geteuid() == 0:
            raise Refused("Run this as the account that runs the portal, not as root.")
        try:
            self.parent_fd = _open_parent(self.folder)
            info = _entry(self.parent_fd, self.folder.name)
            if info is not None:
                _refuse_entry(self.folder, info, folder=True)
                fd = os.open(self.folder.name, _DIR, dir_fd=self.parent_fd)
                self.folder_fd = fd
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise Refused(f"{self.folder} changed while it was being checked.")
                _check_own(opened, self.folder)
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *_exc: object) -> None:
        for fd in (self.folder_fd, self.parent_fd):
            if fd is not None and fd >= 0:
                os.close(fd)
        self.folder_fd, self.parent_fd = None, -1

    def lock(self) -> None:
        """Only one apply at a time for this folder. The lock goes when this process ends, however it ends."""
        try:
            fcntl.flock(self.parent_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused(
                f"Another administrator setup is running for {self.folder}. {UNCHANGED}"
            ) from exc

    def leftovers(self) -> list[str]:
        """Private folders left by an apply that was stopped before it finished. They are never used by the portal."""
        found = []
        for fd, place in ((self.folder_fd, self.folder), (self.parent_fd, self.folder.parent)):
            if fd is not None and fd >= 0:
                found += [
                    str(place / n) for n in sorted(os.listdir(fd)) if n.startswith(STAGING_PREFIX)
                ]
        return found

    def check_first_setup(self) -> None:
        if self.folder_fd is None:
            return
        config = _entry(self.folder_fd, CONFIG_NAME)
        store = _entry(self.folder_fd, TRUST_LIST_NAME)
        if config is not None:
            raise Refused(
                f"There is already a configuration in {self.folder}. This first version never replaces one. "
                'To add issuers to it, prepare an "Add issuers" plan instead. To start again, move the '
                "folder's files somewhere else first." + finder_steps(self.folder)
            )
        if store is not None:
            raise Refused(
                f"There is already a trust list in {self.folder} but no configuration. An administrator setup that "
                "was stopped part-way can leave this. The portal does not use a trust list without a configuration. "
                f"Look at {TRUST_LIST_NAME}, and move it away if you want to start again."
                + finder_steps(self.folder)
                + f" {UNCHANGED}"
            )

    def read_existing(self) -> Existing:
        """For adding issuers: the configuration and the trust list it names, read with the portal's own checks."""
        if self.folder_fd is None:
            raise Refused(
                f"{self.folder} does not exist, so there is no trust list to add to. Use a first-setup plan."
            )
        if _entry(self.folder_fd, CONFIG_NAME) is None:
            raise Refused(
                f"There is no configuration in {self.folder} to add issuers to. Use a first-setup plan."
            )
        try:
            settings = read_settings(self.folder / CONFIG_NAME)
        except ConfigProblem as exc:
            raise Refused(f"The existing configuration cannot be used: {exc}") from exc
        name = settings.store_path.name
        if (
            settings.store_path != self.folder / name
            or name in ("", ".", "..")
            or name.startswith(STAGING_PREFIX)
        ):
            raise Refused(
                "The existing configuration names a trust list outside its own folder. Adding issuers to it is refused."
            )
        try:
            store = read_trust_store(settings)
        except ConfigProblem as exc:
            raise Refused(f"The existing trust list cannot be used: {exc}") from exc
        try:
            mode, reason = trust_mode_of(settings, store)
        except (
            ConfigProblem
        ) as exc:  # the bundled demonstration key, without "trust_mode": "demonstration"
            raise Refused(
                f"The existing configuration cannot be used: {exc}. Real issuers are not added to it. Move it and "
                "the trust list away, then apply a first-setup plan." + finder_steps(self.folder)
            ) from exc
        if mode != CUSTOMER:
            raise Refused(
                f"The existing configuration is a demonstration ({reason}). Real issuers are not added to "
                "demonstration trust. Move it and the trust list away, then apply a first-setup plan."
                + finder_steps(self.folder)
            )
        data, identity = self._read_store(name)
        try:
            payload = loads_strict(data, max_bytes=MAX_TRUST_STORE_BYTES)
            again = TrustStore.from_dict(payload)
        except (CanonicalError, RecursionError, TrustStoreError) as exc:
            raise Refused(f"The existing trust list cannot be used: {shown(str(exc))}") from exc
        if dict(again.keys) != dict(store.keys):
            raise Refused(f"The trust list changed while it was being read. {UNCHANGED}")
        return Existing(settings, name, data, payload, identity)

    def _read_store(self, name: str) -> tuple[bytes, tuple[int, int, int, int]]:
        assert self.folder_fd is not None
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.folder_fd)
        except OSError as exc:
            raise Refused(
                f"The trust list {self.folder / name} cannot be opened: {exc.strerror}."
            ) from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise Refused(f"{self.folder / name} is not a regular file.")
            _check_own(info, self.folder / name)
            data = bytearray()
            while chunk := os.read(fd, 65536):
                data += chunk
                if len(data) > MAX_TRUST_STORE_BYTES:
                    raise Refused("The existing trust list is larger than the engine accepts.")
            return bytes(data), (info.st_dev, info.st_ino, info.st_size, info.st_ctime_ns)
        finally:
            os.close(fd)


# ----------------------------------------------------------------------------- writing


def _write_new(dir_fd: int, name: str, data: bytes) -> None:
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=dir_fd,
    )
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        _sync(fd)
    finally:
        os.close(fd)


def _seal(dir_fd: int, name: str) -> bytes:
    """Make a file the enrolment code wrote private (0600), sync it, and return its bytes."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise Refused(f"The enrolment code did not leave a private regular file. {UNCHANGED}")
        os.fchmod(fd, 0o600)
        data = bytearray()
        while chunk := os.read(fd, 65536):
            data += chunk
        _sync(fd)
        return bytes(data)
    finally:
        os.close(fd)


@contextlib.contextmanager
def _staging(dir_fd: int, place: Path) -> Iterator[tuple[str, int, Path]]:
    """A new private folder (0700) in ``place``. It is removed afterwards unless it was moved into place."""
    name = STAGING_PREFIX + secrets.token_hex(8)
    os.mkdir(name, 0o700, dir_fd=dir_fd)
    fd = os.open(name, _DIR, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid():
            raise Refused(f"The temporary folder does not belong to this account. {UNCHANGED}")
        os.fchmod(fd, 0o700)
        yield name, fd, place / name
    finally:
        try:
            if _entry(dir_fd, name) is not None:
                for leftover in os.listdir(fd):
                    os.unlink(leftover, dir_fd=fd)
                os.rmdir(name, dir_fd=dir_fd)
        except OSError as exc:
            _out(
                f"Note: the temporary folder {place / name} could not be removed ({exc.strerror}). The portal does "
                "not use it, and it can be deleted.",
                err=True,
            )
        os.close(fd)


def _enrol(
    plan: Plan, typed: dict[str, str], staging_fd: int, staging_path: Path, store_name: str
) -> None:
    """Enrol each key with the engine's own ``regaudit-fhe trust add`` code, in the private folder.

    The same command a person types, with the same fingerprint check and the same file format. Its own fingerprint
    check runs again here, on the value the person typed.
    """
    for number, issuer in enumerate(plan.issuers, start=1):
        key_file = f"issuer-{number}.pub"
        _write_new(staging_fd, key_file, issuer.public_key_pem.encode("ascii"))
        said, problems = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(said), contextlib.redirect_stderr(problems):
                code = cli.main(
                    [
                        "trust",
                        "add",
                        f"--store={staging_path / store_name}",
                        f"--key-id={issuer.key_id}",
                        f"--issuer={issuer.issuer}",
                        f"--public-key={staging_path / key_file}",
                        f"--fingerprint={typed[issuer.key_id]}",
                    ]
                )
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else EXIT_REFUSED
        finally:
            os.unlink(key_file, dir_fd=staging_fd)
        if code != 0:
            reason = problems.getvalue().strip()
            if "fingerprint" in reason.lower():
                reason = "the fingerprint does not match the key"
            raise Refused(
                f"The trust add enrolment code refused issuer {number}: {shown(reason)}. {UNCHANGED}"
            )


def _expect_only(dir_fd: int, names: set[str]) -> None:
    present = set(os.listdir(dir_fd))
    if present != names:
        raise Refused(f"The temporary folder does not hold exactly the files expected. {UNCHANGED}")


def _same_trust_list(dir_fd: int, name: str, existing: Existing) -> None:
    """Has the trust list changed since it was read? Then adding to it would lose that change, so refuse."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError as exc:
        raise Refused(
            f"The trust list cannot be opened again: {exc.strerror}. {UNCHANGED}"
        ) from exc
    try:
        info = os.fstat(fd)
        data = bytearray()
        while chunk := os.read(fd, 65536):
            data += chunk
    finally:
        os.close(fd)
    if (info.st_dev, info.st_ino, info.st_size, info.st_ctime_ns) != existing.identity or bytes(
        data
    ) != existing.data:
        raise Refused(f"The trust list changed while this ran. {UNCHANGED}")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _written(name: str, data: bytes) -> str:
    return f"Wrote {name} (mode 0600, {len(data)} bytes, SHA-256 {_sha(data)}):\n{data.decode('utf-8').rstrip()}"


def _apply_first_setup(
    place: Destination, plan: Plan, typed: dict[str, str], progress: Progress
) -> list[str]:
    place.check_first_setup()
    config_text = (plan.configuration_text() or "").encode("utf-8")
    expected_store = plan.trust_list_text().encode("utf-8")
    fresh = place.folder_fd is None
    where_fd = place.parent_fd if fresh else place.folder_fd
    where = place.folder.parent if fresh else place.folder
    assert where_fd is not None
    with _staging(where_fd, where) as (name, staging_fd, staging_path):
        _enrol(plan, typed, staging_fd, staging_path, TRUST_LIST_NAME)
        store_data = _seal(staging_fd, TRUST_LIST_NAME)
        if store_data != expected_store:
            raise Refused(
                f"The trust list the enrolment code wrote is not the one that was shown. {UNCHANGED}"
            )
        _write_new(staging_fd, CONFIG_NAME, config_text)
        _check_staged_first_setup(staging_path, plan)
        _expect_only(staging_fd, {CONFIG_NAME, TRUST_LIST_NAME})
        _sync(staging_fd)
        _engine_still_recognised()
        if fresh:
            # The whole folder appears at once, holding both files, or not at all.
            with _held_signals():
                try:
                    os.rename(
                        name,
                        place.folder.name,
                        src_dir_fd=place.parent_fd,
                        dst_dir_fd=place.parent_fd,
                    )
                except OSError as exc:
                    raise Refused(
                        f"{place.folder} could not be created: {exc.strerror}. Something else may have made it "
                        f"meanwhile. {UNCHANGED}"
                    ) from exc
                progress.committed = True
                _flush_committed(place.parent_fd)
        else:
            _link_both(place, staging_fd, progress)
    made = (
        f"Created {place.folder}, readable and writable by this account only (mode 0700)."
        if fresh
        else None
    )
    return [line for line in (made,) if line] + [
        _written(CONFIG_NAME, config_text),
        _written(TRUST_LIST_NAME, store_data),
    ]


def _link_both(place: Destination, staging_fd: int, progress: Progress) -> None:
    """Into an existing folder: the trust list, then the configuration, each refusing to replace anything.

    The configuration is what the portal reads, so until it is in place the setup is not in use. If putting it there
    fails, the trust list just added is taken away again, so nothing has changed. Stops are held for these steps. Only
    SIGKILL or a power cut at the exact moment between the two can leave the trust list without the configuration:
    the portal does not use it, and the next apply says so.
    """
    assert place.folder_fd is not None
    staged = os.stat(TRUST_LIST_NAME, dir_fd=staging_fd, follow_symlinks=False)
    with _held_signals():
        _link_both_held(place, staging_fd, staged, progress)
        _flush_committed(place.folder_fd)


def _link_both_held(
    place: Destination, staging_fd: int, staged: os.stat_result, progress: Progress
) -> None:
    assert place.folder_fd is not None
    try:
        os.link(
            TRUST_LIST_NAME,
            TRUST_LIST_NAME,
            src_dir_fd=staging_fd,
            dst_dir_fd=place.folder_fd,
            follow_symlinks=False,
        )
    except FileExistsError as exc:
        raise Refused(
            f"A trust list appeared in {place.folder} while this ran. {UNCHANGED}"
        ) from exc
    try:
        os.link(
            CONFIG_NAME,
            CONFIG_NAME,
            src_dir_fd=staging_fd,
            dst_dir_fd=place.folder_fd,
            follow_symlinks=False,
        )
    except BaseException as exc:
        try:
            now = os.stat(TRUST_LIST_NAME, dir_fd=place.folder_fd, follow_symlinks=False)
            if (now.st_dev, now.st_ino) == (staged.st_dev, staged.st_ino):
                os.unlink(TRUST_LIST_NAME, dir_fd=place.folder_fd)
            _sync(place.folder_fd)
        except OSError as undo:
            raise Failed(
                f"The trust list was written to {place.folder} but the configuration was not, and taking the trust "
                f"list away again failed ({undo.strerror}). The portal does not use a trust list without a "
                f"configuration. Move {place.folder / TRUST_LIST_NAME} away before trying again."
            ) from exc
        if isinstance(exc, FileExistsError):
            raise Refused(
                f"A configuration appeared in {place.folder} while this ran. {UNCHANGED}"
            ) from exc
        if isinstance(exc, OSError):
            raise Refused(
                f"The configuration could not be written: {exc.strerror}. {UNCHANGED}"
            ) from exc
        raise
    progress.committed = True


def _check_staged_first_setup(staging_path: Path, plan: Plan) -> None:
    """Read the new files back with the portal's own readers, the ones it uses when it starts."""
    try:
        settings = read_settings(staging_path / CONFIG_NAME)
        store = read_trust_store(settings)
        mode = trust_mode_of(settings, store)[0]
    except ConfigProblem as exc:
        raise Refused(
            f"The new files do not pass the portal's own check: {exc}. {UNCHANGED}"
        ) from exc
    wanted = (plan.profile, plan.verifier_id, plan.max_age_days, plan.replay_mode, False, CUSTOMER)
    found = (
        settings.profile,
        settings.verifier_id,
        settings.max_age_days,
        settings.replay_mode,
        settings.allow_self_signed,
        # What the file itself says, not only what the portal makes of it: a new configuration must say "customer"
        # in so many words. One without the setting would be read as customer trust too, but only as a legacy one.
        settings.trust_mode if mode == CUSTOMER else mode,
    )
    if found != wanted or settings.store_path != staging_path / TRUST_LIST_NAME:
        raise Refused(f"The new configuration does not say what the plan says. {UNCHANGED}")
    if set(store.entries) != {i.key_id for i in plan.issuers}:
        raise Refused(f"The new trust list does not hold exactly the plan's issuers. {UNCHANGED}")


def _apply_add_issuers(
    place: Destination, plan: Plan, typed: dict[str, str], progress: Progress
) -> list[str]:
    existing = place.read_existing()
    already = [i for i in plan.issuers if i.key_id in existing.payload["entries"]]
    if already:
        names = ", ".join(i.key_id for i in already)
        raise Refused(
            f"Key id {names} is already in the trust list. Existing entries are never replaced. {UNCHANGED}"
        )
    expected = plan.trust_list_text(existing.payload).encode("utf-8")
    try:  # the engine's own rules for a trust list, before anything is written
        TrustStore.from_dict(json.loads(expected))
    except TrustStoreError as exc:
        raise Refused(
            f"The engine refuses the trust list this would make: {shown(str(exc))}. {UNCHANGED}"
        ) from exc
    assert place.folder_fd is not None
    with _staging(place.folder_fd, place.folder) as (_name, staging_fd, staging_path):
        _write_new(staging_fd, existing.store_name, existing.data)
        _enrol(plan, typed, staging_fd, staging_path, existing.store_name)
        store_data = _seal(staging_fd, existing.store_name)
        if store_data != expected:
            raise Refused(
                f"The trust list the enrolment code wrote is not the one that was shown. {UNCHANGED}"
            )
        try:
            store = read_trust_store(
                dataclasses.replace(
                    existing.settings, store_path=staging_path / existing.store_name
                )
            )
        except ConfigProblem as exc:
            raise Refused(
                f"The new trust list does not pass the portal's own check: {exc}. {UNCHANGED}"
            ) from exc
        before = TrustStore.from_dict(existing.payload)
        if any(store.entries.get(k) != e for k, e in before.entries.items()) or set(
            store.entries
        ) != set(before.entries) | {i.key_id for i in plan.issuers}:
            raise Refused(f"The new trust list would change an existing entry. {UNCHANGED}")
        _expect_only(staging_fd, {existing.store_name})
        _sync(staging_fd)
        _engine_still_recognised()
        with _held_signals():
            _same_trust_list(place.folder_fd, existing.store_name, existing)
            # One step: the old trust list or the new one, never half of either.
            os.rename(
                existing.store_name,
                existing.store_name,
                src_dir_fd=staging_fd,
                dst_dir_fd=place.folder_fd,
            )
            progress.committed = True
            _flush_committed(place.folder_fd)
    added = len(plan.issuers)
    return [
        f"Added {added} issuer{'' if added == 1 else 's'} to the trust list. The configuration was not changed.",
        _written(existing.store_name, store_data),
        *legacy_warnings(existing.settings, CUSTOMER),
    ]


def _engine_still_recognised() -> None:
    identity = check_engine()
    if not identity.ok:
        raise Refused(
            f"The verification engine no longer passes its check: {identity.reason}. {UNCHANGED}"
        )


def _final_check(folder: Path, plan: Plan) -> None:
    """After the move: the portal's own start-up readers accept the result."""
    try:
        store = read_trust_store(read_settings(folder / CONFIG_NAME))
    except ConfigProblem as exc:
        raise Failed(
            f"The change is complete, but the portal's own check of the result fails: {exc}. Run check-config."
        ) from exc
    if not {i.key_id for i in plan.issuers} <= set(store.entries):
        raise Failed(
            "The change is complete, but the trust list does not hold every issuer of the plan. Run check-config."
        )


# ----------------------------------------------------------------------------- the two commands


def _engine_or_refuse() -> None:
    identity = check_engine()
    if not identity.ok:
        raise Refused(
            f"verification unavailable: {identity.reason}: {identity.detail}. Reinstall with: {REINSTALL}"
        )


def _describe_destination(folder: Path, plan: Plan) -> tuple[str | None, list[str], list[str]]:
    """Would applying the plan here be refused, and why, and which folders did a stopped apply leave? Read-only: it
    opens folders and reads files, nothing else. The leftovers are listed with any answer, a refusal included, once the
    folders could be opened and checked."""
    leftovers: list[str] = []
    warnings: list[str] = []
    try:
        with Destination(folder) as place:
            leftovers = place.leftovers()
            if plan.mode == FIRST_SETUP:
                place.check_first_setup()
            else:
                existing = place.read_existing()
                warnings = list(legacy_warnings(existing.settings, CUSTOMER))
                already = [
                    i.key_id for i in plan.issuers if i.key_id in existing.payload["entries"]
                ]
                if already:
                    raise Refused(f"Key id {', '.join(already)} is already in the trust list.")
                TrustStore.from_dict(json.loads(plan.trust_list_text(existing.payload)))
            return None, leftovers, warnings
    except Refused as exc:
        return str(exc), leftovers, warnings
    except TrustStoreError as exc:
        return (
            f"The engine refuses the trust list it would make: {shown(str(exc))}",
            leftovers,
            warnings,
        )
    except OSError as exc:
        return f"{folder} cannot be checked: {exc.strerror}.", leftovers, warnings


def describe(args: Any) -> int:
    """Print what a plan would do, computed from its content, and whether it could be applied here. Writes nothing."""
    return _stoppable(lambda _progress: _describe(args))


def _describe(args: Any) -> int:
    try:
        _engine_or_refuse()
        plan = _load_plan(args.plan)
        folder, standard = destination(args.config_folder)
    except Refused as exc:
        if args.json:
            _out(json.dumps({"ok": False, "problem": str(exc)}, ensure_ascii=True))
        else:
            _out(f"refused: {exc}", err=True)
        return EXIT_REFUSED
    problem, leftovers, warnings = _describe_destination(folder, plan)
    origin = "the standard folder for this account" if standard else "given with --config-folder"
    lines = [
        *top_lines(plan),
        f"Setup plan, content checksum (SHA-256) {plan.content_sha256}. The checksum matches the content. It shows "
        "only that the file is intact, not who made it.",
        *body_lines(plan),
        f"Destination folder: {folder} ({origin}). The plan cannot choose it.",
        "Destination check: it can be applied here."
        if problem is None
        else f"Destination check: applying it here is refused. {problem}",
    ]
    lines += [
        f"Left by an apply that was stopped: {item}. The portal does not use it."
        for item in leftovers
    ]
    lines += warnings  # about the existing configuration, word for word
    if args.json:
        body = {
            "ok": problem is None,
            "problem": None if problem is None else shown(problem, 4000),
            "plan_sha256": plan.content_sha256,
            "mode": plan.mode,
            "notices": [shown(line, 4000) for line in notices(plan)],
            "summary": "\n".join(shown(line, 4000) for line in lines),
            "issuers": [
                {"number": n, "issuer": i.issuer, "key_id": i.key_id}
                for n, i in enumerate(plan.issuers, 1)
            ],
        }
        _out(json.dumps(body, ensure_ascii=True))
    else:
        _out("\n".join(lines))
    return EXIT_DONE if problem is None else EXIT_REFUSED


@contextlib.contextmanager
def _own_signal_handling(stop: Any) -> Iterator[None]:
    """Decide what Ctrl-C, SIGTERM and SIGHUP do here, whatever this process was started with. A launcher that
    ignores them would otherwise pass that on, and then could not stop this command."""
    previous = {sig: signal.getsignal(sig) for sig in _STOPS}
    for sig in _STOPS:
        signal.signal(sig, stop)
    # The entry point held these while the engine's libraries started their threads. Only this thread takes them.
    mask = signal.pthread_sigmask(signal.SIG_UNBLOCK, _STOPS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        for sig, handler in previous.items():
            signal.signal(sig, handler if handler is not None else signal.SIG_DFL)


def apply(args: Any) -> int:
    """Apply a plan, after every typed fingerprint matches. Says exactly what was written, or why nothing was.

    Exit status: 0 applied; 2 refused, nothing changed; 3 the engine is not the recognised release; 1 failed or
    stopped before the change, nothing changed (unless the message says otherwise); 4 applied, but a step after the
    change did not finish (the message says which).
    """
    return _stoppable(lambda progress: _apply(args, progress))


def _stoppable(command: Any) -> int:
    """Run a command so that a stop ends it plainly, with what state the files are in, from its very first moment.

    The entry point holds stops while the engine loads, so one sent then is taken as soon as the handlers are in
    place, which is inside this ``try``.
    """
    progress = Progress()
    _Stops.finished = False
    try:
        with _own_signal_handling(_stop_like_ctrl_c):
            return int(command(progress))
    except KeyboardInterrupt:
        code, said = _after(progress, "")
        _out(f"stopped: {said}", err=True)
        return code
    finally:
        _Stops.finished = False


def _is_this_program() -> bool:
    """Is this process the regaudit-portal command itself, rather than a program that calls it (the tests do)?"""
    first = sys.argv[0] if sys.argv else ""
    main = getattr(sys.modules.get("__main__"), "__spec__", None)
    return os.path.basename(first) in ("regaudit-portal", "regaudit-portal.exe") or (
        main is not None and main.name == "regaudit_portal.__main__"
    )


def _leave_the_result_as_it_is() -> None:
    """After the command has finished, as the program: a stop until the process ends is ignored.

    The result and its words are final by now. The entry point lets held stops through again once this returns, and
    the handlers it had before would turn a late stop into a "stopped" with status 1, or a death by SIGHUP, after a
    command that had finished. Ignoring them for the few moments before the process ends keeps the status exact. A
    program that merely calls this keeps its own handling.
    """
    if not _is_this_program():
        return
    for sig in _STOPS:
        with contextlib.suppress(ValueError, OSError):
            signal.signal(sig, signal.SIG_IGN)


def _after(progress: Progress, what: str) -> tuple[int, str]:
    """The exit status, and the words for what state the files are in after a stop or failure."""
    if progress.committed:
        state = f"{COMPLETE} Restart the portal, and run check-config."
        return EXIT_DONE_BUT, " ".join(part for part in (what, state) if part)
    return EXIT_FAILED, " ".join(part for part in (what, UNCHANGED) if part)


def _apply(args: Any, progress: Progress) -> int:
    try:
        _engine_or_refuse()
        plan = _load_plan(args.plan)
        if (
            args.expect_plan_sha256 is not None
            and args.expect_plan_sha256.strip().lower() != plan.content_sha256
        ):
            raise Refused(f"The plan file changed since it was described. {UNCHANGED}")
        folder, _standard = destination(args.config_folder)
        typed = (
            _given_fingerprints(plan, args.expect_fingerprint)
            if args.expect_fingerprint
            else _asked_fingerprints(plan)
        )
        checked = _check_fingerprints(plan, typed)
        with Destination(folder) as place:
            place.lock()
            if plan.mode == ADD_ISSUERS:
                report = _apply_add_issuers(place, plan, checked, progress)
            else:
                report = _apply_first_setup(place, plan, checked, progress)
        _final_check(folder, plan)
        _Stops.finished = (
            True  # in place, flushed and accepted by the portal's own readers: the result stands
        )
    except Refused as exc:
        _out(f"refused: {exc}", err=True)
        return EXIT_DONE_BUT if progress.committed else EXIT_REFUSED
    except Failed as exc:
        _out(f"failed: {exc}", err=True)
        return EXIT_DONE_BUT if progress.committed else EXIT_FAILED
    except KeyboardInterrupt:
        code, said = _after(progress, "")
        _out(f"stopped: {said}", err=True)
        return code
    except OSError as exc:
        code, said = _after(
            progress, f"{exc.strerror or exc} ({errno.errorcode.get(exc.errno or 0, 'error')})."
        )
        _out(f"failed: {said}", err=True)
        return code
    except (
        Exception
    ) as exc:  # only the kind is printed: the text of an unexpected error is not shown
        code, said = _after(progress, f"An unexpected {type(exc).__name__}.")
        _out(f"failed: {said}", err=True)
        return code
    enrolled = [
        # Name and key id only: the fingerprint is what the administrator typed and checked, never listed back.
        f"  {n}. {quoted(i.issuer)}, key id {i.key_id}: the fingerprint you typed matched its key"
        for n, i in enumerate(plan.issuers, start=1)
    ]
    said = _out(
        "\n".join(
            [
                f"Applied setup plan {plan.content_sha256} in {folder}.",
                *report,
                "Enrolled:",
                *enrolled,
                _RESTART,
            ]
        )
    )
    if not said:
        # The change is complete and checked, so this is still success. Say so where it can still be read.
        _out(
            f"Applied setup plan {plan.content_sha256} in {folder}. Standard output could not be written, so the "
            f"list of what was written is not shown here. {_RESTART}",
            err=True,
        )
    return EXIT_DONE


def run(args: Any) -> int:
    _reserve_standard_descriptors()
    code = describe(args) if args.command == "admin-describe" else apply(args)
    _leave_the_result_as_it_is()
    return code
