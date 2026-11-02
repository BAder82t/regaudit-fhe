"""Verifier-held revocation state: pins, the monotonic state record, ceremonies and ingest.

EXPERIMENTAL and OFF BY DEFAULT. Importing the package does not load this module, and ``verify`` with revocation
``off`` calls nothing in it. (The CLI's argument parser does import it, to declare the commands.)

Two local stores, kept apart on purpose:

* the **pin** (:class:`Pin`), written only by an operator ceremony. It is the root of trust for revocation, together
  with the recovery anchor it names. The list signer is a delegate of that root. There is no independent approver
  and no quorum;
* the **state record**, one per issuer, advanced only by compare-and-set, so a slow writer can never lower it.

:class:`FileStateStore` is a real single-host store: durable and atomic on one filesystem, and **not independent**.
Whoever can write its directory can replace a record, which is why it can never serve ``required`` under the
``high-assurance`` profile. See section 9 of ``docs/TRUST_REVOCATION_PROTOCOL_PROPOSAL.md``.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from . import _revocation as rv
from ._keys import spki_fingerprint
from ._time import parse_rfc3339
from .canonical import CanonicalError, canonical_bytes, loads_strict
from .trust import TrustStore, issuer_name_problem

MAX_CAS_RETRIES = 8
# Must hold the largest legal list (10 000 entries) in the mark, the archive and the joined actions at once.
MAX_RECORD_BYTES = 32 * 1024 * 1024
MAX_PIN_FILE_BYTES = 4 * 1024 * 1024
RECORD_DOMAIN = b"regaudit-fhe/revocation-state/v1/record\x00"

# A list refused with one of these carries a valid signature by the current authority and conflicts with signed
# history, so nobody without that key can create one. Store conflicts are not here: they depend on the local store,
# which changes, and a public replay must never be able to cause a latch.
SIGNED_CONTRADICTIONS = frozenset({"REVOCATION_FORK", "REVOCATION_NOT_MONOTONE"})
_DIGEST = re.compile(r"[0-9a-f]{64}")


class StateUnavailable(RuntimeError):
    """The state store is unreachable, or its record is unreadable or inconsistent."""


class StateLost(StateUnavailable):
    """The issuer is enrolled but the state store holds no record for it."""


class RecordTooLarge(RuntimeError):
    """Even with the archive pruned, the record does not fit its limit."""


class PinStoreError(RuntimeError):
    """The pinned-authority file is missing, unreadable, malformed or unsafe."""


class StateStore(Protocol):
    """Atomic compare-and-set over opaque per-issuer records."""

    scope: str

    def read(self, issuer: str) -> bytes | None: ...

    def cas(self, issuer: str, expected: bytes | None, new: bytes) -> bool: ...


class FileStateStore:
    """One file per issuer. ``flock`` serialises writers; temp, sync, rename and directory sync commit.

    Real and durable on one host, and not independent. The directory must not be group- or world-writable.
    ``_fault`` is a no-op hook at each commit point, so a test can kill a real process exactly there.
    """

    scope = "LOCAL_FILE"

    def __init__(self, directory: str | Path) -> None:
        self.dir = Path(directory)

    def path(self, issuer: str) -> Path:
        return self.dir / (hashlib.sha256(issuer.encode("utf-8")).hexdigest() + ".state")

    def _fault(self, point: str) -> None:
        """Called at each commit point. Does nothing in the product."""

    def _check_dir(self) -> None:
        try:
            info = os.lstat(self.dir)
        except OSError as exc:
            raise StateUnavailable(f"state directory: {exc}") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise StateUnavailable("state directory is not a directory (symlinks are refused)")
        if _unsafe_owner_or_mode(info):
            raise StateUnavailable("state directory is group- or world-writable, or not ours")

    def read(self, issuer: str) -> bytes | None:
        self._check_dir()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(self.path(issuer), flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StateUnavailable(f"state record: {exc}") from exc
        try:
            with os.fdopen(fd, "rb") as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise StateUnavailable("state record is not a regular file")
                if _unsafe_owner_or_mode(info):
                    raise StateUnavailable("state record is group- or world-writable, or not ours")
                if info.st_size > MAX_RECORD_BYTES:
                    raise StateUnavailable("state record exceeds its size limit")
                return handle.read()
        except OSError as exc:
            raise StateUnavailable(f"state record: {exc}") from exc

    def remove(self, issuer: str, expected: bytes) -> bool:
        """Take the record away if it is still ``expected``. Only undoing a ceremony calls this."""
        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - supported platforms have it
            raise StateUnavailable("this platform has no flock; the file store refuses") from exc
        self._check_dir()
        try:
            lock_fd = os.open(
                self.dir / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
            )
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                if self.read(issuer) != expected:
                    return False
                self.path(issuer).unlink()
            finally:
                os.close(lock_fd)
        except OSError as exc:
            raise StateUnavailable(f"state record: {exc}") from exc
        return True

    def cas(self, issuer: str, expected: bytes | None, new: bytes) -> bool:
        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - supported platforms have it
            raise StateUnavailable("this platform has no flock; the file store refuses") from exc
        self._check_dir()
        target = self.path(issuer)
        try:
            lock_fd = os.open(
                self.dir / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
            )
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                self._sweep_temp_files()
                if self.read(issuer) != expected:
                    return False
                self._commit(target, new, fcntl)
            finally:
                os.close(lock_fd)
        except OSError as exc:
            raise StateUnavailable(f"state record: {exc}") from exc
        return True

    def _sweep_temp_files(self) -> None:
        """Called under the lock: a temp file now can only be a crashed writer's."""
        for leftover in self.dir.glob(".state-*.tmp"):
            with contextlib.suppress(OSError):
                leftover.unlink()

    def _commit(self, target: Path, data: bytes, fcntl: Any) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".state-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                self._fault("mid-write")
                split = len(data) // 2
                handle.write(data[:split])
                handle.flush()
                self._fault("partial-temp")
                handle.write(data[split:])
                handle.flush()
                _sync(handle.fileno(), fcntl)
            self._fault("before-rename")
            os.replace(tmp, target)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        self._fault("after-rename")
        dir_fd = os.open(self.dir, os.O_RDONLY)
        try:
            _sync(dir_fd, fcntl)
        finally:
            os.close(dir_fd)
        self._fault("after-directory-sync")


def _unsafe_owner_or_mode(info: os.stat_result) -> bool:
    if os.name != "posix":
        return False
    return bool(stat.S_IMODE(info.st_mode) & 0o022) or info.st_uid != os.geteuid()


def _sync(fd: int, fcntl: Any) -> None:
    """fsync, and on macOS F_FULLFSYNC, since plain fsync there does not flush the drive cache."""
    full = getattr(fcntl, "F_FULLFSYNC", None)
    if full is not None:
        with contextlib.suppress(
            OSError
        ):  # not every filesystem supports it; fsync below still runs
            fcntl.fcntl(fd, full)
    os.fsync(fd)


# ----------------------------------------------------------------------------- the pin


@dataclass(frozen=True)
class Pin:
    """Created only by an operator's enrollment ceremony, from fingerprints confirmed out of band.

    Never learned from a list or a channel, and needs no signature by a report key.
    """

    issuer: str
    authority_pem: str
    enrollment_id: str
    recovery_pem: str | None = None
    baseline_epoch: int | None = (
        None  # None = first use; 0 = the ceremony asserted no list exists yet
    )
    baseline_digest: str | None = None
    # Stated by a re-baseline ceremony, so that an old statement cannot move the authority backwards.
    authority_generation: int = 1
    recovery_epoch: int = 0
    recovery_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _pin_from(raw: Any) -> Pin:
    members = set(Pin.__dataclass_fields__)
    if not isinstance(raw, dict) or set(raw) != members:
        raise PinStoreError("a pin must have exactly the expected members")
    try:
        pin = Pin(**raw)
        problem = issuer_name_problem(pin.issuer)
        if problem is not None:
            raise PinStoreError(f"a pin's issuer {problem}")
        if not (isinstance(pin.enrollment_id, str) and pin.enrollment_id):
            raise PinStoreError("a pin needs an enrollment_id")
        spki_fingerprint(pin.authority_pem)
        if pin.recovery_pem is not None:
            spki_fingerprint(pin.recovery_pem)
    except PinStoreError:
        raise
    except Exception as exc:
        raise PinStoreError(f"unusable pin: {exc}") from exc
    if type(pin.authority_generation) is not int or pin.authority_generation < 1:
        raise PinStoreError("authority_generation must be a positive integer")
    if type(pin.recovery_epoch) is not int or pin.recovery_epoch < 0:
        raise PinStoreError("recovery_epoch must be a non-negative integer")
    for digest in (pin.baseline_digest, pin.recovery_digest):
        if digest is not None and (not isinstance(digest, str) or not _DIGEST.fullmatch(digest)):
            raise PinStoreError("a digest in a pin must be 64 lowercase hex characters")
    if pin.baseline_epoch is not None and (
        type(pin.baseline_epoch) is not int or pin.baseline_epoch < 0
    ):
        raise PinStoreError("baseline_epoch must be a non-negative integer")
    needs_digest = pin.baseline_epoch is not None and pin.baseline_epoch > 0
    if needs_digest != (pin.baseline_digest is not None):
        raise PinStoreError("a baseline digest goes with a baseline epoch above 0, and only then")
    return pin


def check_pin(pin: Pin) -> None:
    """Raises ``PinStoreError`` if this pin could not be loaded back."""
    _pin_from(pin.to_dict())


def load_pins(path: str | Path) -> dict[str, Pin]:
    """Read the pinned-authority file. Refuses one that another local user could write."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise PinStoreError("the pin file is not a regular file")
            if _unsafe_owner_or_mode(info):
                raise PinStoreError("the pin file is group- or world-writable, or not ours")
            if info.st_size > MAX_PIN_FILE_BYTES:
                raise PinStoreError("the pin file exceeds its size limit")
            doc = loads_strict(handle.read(), max_bytes=MAX_PIN_FILE_BYTES)
    except OSError as exc:
        raise PinStoreError(f"cannot read the pin file: {exc}") from exc
    except (CanonicalError, RecursionError, UnicodeDecodeError) as exc:
        raise PinStoreError(f"the pin file is not valid strict JSON: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) != {"pins"} or not isinstance(doc["pins"], dict):
        raise PinStoreError("the pin file must be an object with one member, pins")
    pins = {issuer: _pin_from(raw) for issuer, raw in doc["pins"].items()}
    if any(pin.issuer != issuer for issuer, pin in pins.items()):
        raise PinStoreError("a pin is filed under another issuer")
    return pins


def check_pin_file_usable(path: str | Path) -> None:
    """Before a ceremony changes anything: the pin file can be read, and a new version can be written beside it."""
    target = Path(path)
    if target.exists():
        load_pins(target)
    if not os.access(target.parent, os.W_OK | os.X_OK):
        raise PinStoreError(f"cannot write the pin file: {str(target.parent)!r} is not writable")


def undo_ceremony(store: FileStateStore, issuer: str, written: bytes, before: bytes | None) -> None:
    """Put the record back after the new pin could not be saved, so that a failed ceremony changes nothing.

    Only if the record is still the one this ceremony wrote: anything newer is left alone.
    """
    undone = store.remove(issuer, written) if before is None else store.cas(issuer, written, before)
    if not undone:
        raise StateUnavailable("the record changed during the ceremony; repeat the ceremony")


def save_pin(path: str | Path, pin: Pin) -> None:
    """Atomic update of one issuer's pin. Only ceremonies call this."""
    check_pin(pin)
    target = Path(path)
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - supported platforms have it
        raise PinStoreError("this platform has no flock") from exc
    try:
        lock_fd = os.open(
            f"{target}.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            pins = load_pins(target) if target.exists() else {}
            pins[pin.issuer] = pin
            data = json.dumps(
                {"pins": {k: v.to_dict() for k, v in sorted(pins.items())}},
                indent=2,
                sort_keys=True,
            ).encode()
            fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".pins-", suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    _sync(handle.fileno(), fcntl)
                os.replace(tmp, target)
            except OSError:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
            dir_fd = os.open(target.parent, os.O_RDONLY)
            try:
                _sync(dir_fd, fcntl)
            finally:
                os.close(dir_fd)
        finally:
            os.close(lock_fd)
    except OSError as exc:
        raise PinStoreError(f"cannot write the pin file: {exc}") from exc


# ----------------------------------------------------------------------------- the record


@dataclass(frozen=True)
class Record:
    seq: int
    enrollment_id: str
    state: rv.RevocationState
    effective: dict[str, dict[str, Any]] = field(
        default_factory=dict
    )  # fingerprint -> joined action
    contradiction: dict[str, str] | None = None
    clock_floor: str | None = None
    adjudicated: tuple[
        str, ...
    ] = ()  # list digests a ceremony has ruled on: replaying one cannot latch
    # Strictest gate settings this record has served: {"mode": ..., "max_evidence_age_us": ...}. Monotonic.
    policy_floor: dict[str, Any] | None = None


def encode(rec: Record) -> bytes:
    payload = {
        "seq": rec.seq,
        "enrollment_id": rec.enrollment_id,
        "marks": {k: m.__dict__ for k, m in rec.state.marks.items()},
        "archive": {k: m.__dict__ for k, m in rec.state.archive.items()},
        "enrollments": {k: e.to_dict() for k, e in rec.state.enrollments.items()},
        "effective": rec.effective,
        "contradiction": rec.contradiction,
        "clock_floor": rec.clock_floor,
        "adjudicated": list(rec.adjudicated),
        "policy_floor": rec.policy_floor,
    }
    digest = hashlib.sha256(RECORD_DOMAIN + canonical_bytes(payload)).hexdigest()
    return json.dumps({"record": payload, "digest": digest}, sort_keys=True).encode()


def fit(rec: Record) -> tuple[Record, bytes]:
    """Prune the archive oldest first to stay under the read limit. The mark and key actions are never pruned;
    a pruned baseline later gives REVOCATION_RECOVERY_BASELINE_UNKNOWN, which fails closed."""
    data = encode(rec)
    limit = MAX_RECORD_BYTES
    while len(data) > limit:
        marks = rec.state.marks
        current = {m.digest for m in marks.values()}
        older = sorted(
            (k for k in rec.state.archive if k not in current),
            key=lambda k: rec.state.archive[k].epoch,
        )
        if not older:
            raise RecordTooLarge(f"{len(data)} bytes")
        archive = dict(rec.state.archive)
        del archive[older[0]]
        rec = replace(rec, state=replace(rec.state, archive=archive))
        data = encode(rec)
    return rec, data


def _check_action_shape(action: Any) -> None:
    if not isinstance(action, dict) or action["status"] not in rv.STATUSES:
        raise ValueError("a joined action is malformed")
    if action["effective_from"] is not None:
        parse_rfc3339(action["effective_from"])
    if not isinstance(action["key_fingerprint"], str):
        raise ValueError("a joined action has no fingerprint")


def _check_record_types(rec: Record) -> None:
    """A digest can be recomputed by whoever damaged the record, so the types are checked too."""
    if type(rec.seq) is not int or rec.seq < 0 or not isinstance(rec.enrollment_id, str):
        raise ValueError("seq or enrollment_id")
    if rec.clock_floor is not None:
        parse_rfc3339(rec.clock_floor)
    if not isinstance(rec.effective, dict):
        raise ValueError("effective")
    for action in rec.effective.values():
        _check_action_shape(action)
    if rec.contradiction is not None and not (
        isinstance(rec.contradiction, dict)
        and {"code", "digest", "mark_digest"} <= set(rec.contradiction)
    ):
        raise ValueError("contradiction")
    if not all(isinstance(x, str) for x in rec.adjudicated):
        raise ValueError("adjudicated")
    if rec.policy_floor is not None:
        floor = rec.policy_floor
        if (
            not isinstance(floor, dict)
            or floor["mode"] not in ("advisory", "required")
            or type(floor["max_evidence_age_us"]) is not int
            or floor["max_evidence_age_us"] <= 0
        ):
            raise ValueError("policy_floor")
    for mark in (*rec.state.marks.values(), *rec.state.archive.values()):
        if type(mark.epoch) is not int or not isinstance(mark.entries, dict):
            raise ValueError("mark")
        parse_rfc3339(mark.issued_at)
        parse_rfc3339(mark.valid_until)
        if mark.accepted_at is not None:
            parse_rfc3339(mark.accepted_at)
        for entry in mark.entries.values():
            _check_action_shape(entry)
    for enrollment in rec.state.enrollments.values():
        spki_fingerprint(enrollment.authority_pem)
        if type(enrollment.generation) is not int or type(enrollment.recovery_epoch) is not int:
            raise ValueError("enrollment")
        if not isinstance(enrollment.compromised, dict):
            raise ValueError("compromised")
        for boundary in enrollment.compromised.values():
            if boundary is not None:
                parse_rfc3339(boundary)


def decode(raw: bytes) -> Record:
    """A torn or corrupted record is unavailable, never empty and never a reason to fall back.

    The digest catches accidental damage. It is not authentication: whoever can write the record can recompute it.
    """
    try:
        doc = loads_strict(raw, max_bytes=MAX_RECORD_BYTES)
        payload = doc["record"]
        expected = hashlib.sha256(RECORD_DOMAIN + canonical_bytes(payload)).hexdigest()
        if doc["digest"] != expected:
            raise ValueError("record digest mismatch")
        state = rv.RevocationState(
            {k: rv.Mark(**m) for k, m in payload["marks"].items()},
            {k: rv.Enrollment.from_dict(e) for k, e in payload["enrollments"].items()},
            {k: rv.Mark(**m) for k, m in payload["archive"].items()},
        )
        if not isinstance(payload["adjudicated"], list):
            raise ValueError("adjudicated")
        rec = Record(
            payload["seq"],
            payload["enrollment_id"],
            state,
            payload["effective"],
            payload["contradiction"],
            payload["clock_floor"],
            tuple(payload["adjudicated"]),
            payload["policy_floor"],
        )
        _check_record_types(rec)
        return rec
    except Exception as exc:
        raise StateUnavailable(f"unreadable state record: {exc}") from exc


def load(store: StateStore, pin: Pin) -> tuple[Record, bytes]:
    raw = store.read(pin.issuer)
    if raw is None:
        raise StateLost(pin.issuer)
    rec = decode(raw)
    if rec.enrollment_id != pin.enrollment_id or pin.issuer not in rec.state.enrollments:
        raise StateUnavailable("state record belongs to another enrollment")
    return rec, raw


def _initial_state(pin: Pin, trust_store: TrustStore | None) -> rv.RevocationState:
    state = rv.enroll(
        rv.RevocationState(),
        pin.issuer,
        pin.authority_pem,
        recovery_pem=pin.recovery_pem,
        store=trust_store,
    )
    enrollment = replace(
        state.enrollments[pin.issuer],
        generation=pin.authority_generation,
        recovery_epoch=pin.recovery_epoch,
        recovery_digest=pin.recovery_digest,
    )
    return state.with_enrollment(enrollment)


def enroll(
    store: StateStore, pin: Pin, trust_store: TrustStore | None = None, *, now: datetime
) -> Record:
    """The ceremony writes the first record, so that a later missing record is detectably lost."""
    check_pin(pin)
    rec = Record(1, pin.enrollment_id, _initial_state(pin, trust_store), clock_floor=rv._z(now))
    if not store.cas(pin.issuer, None, encode(rec)):
        raise ValueError("already enrolled: re-baselining is a separate operator ceremony")
    return rec


def rebaseline(
    store: StateStore,
    pin: Pin,
    *,
    now: datetime,
    trust_store: TrustStore | None = None,
    clear_effective: bool = False,
    accept_loss: bool = False,
    reset_policy_floor: bool = False,
) -> Record:
    """Operator ceremony after lost, restored or contradicted state. A new pin replaces the old one.

    It never loosens as a side effect and never moves the authority backwards: key actions, authority history and
    the policy floor carry over from a readable record, and losing them because the record is gone or unreadable has
    to be said out loud with ``accept_loss``. Clearing key actions or the floor is a local operator act, not an
    issuer statement.
    """
    check_pin(pin)
    state = _initial_state(pin, trust_store)
    fresh = state.enrollments[pin.issuer]
    current = store.read(pin.issuer)
    seq = 0
    effective: dict[str, dict[str, Any]] = {}
    adjudicated: tuple[str, ...] = ()
    floor: dict[str, Any] | None = None
    try:
        old = None if current is None else decode(current)
    except StateUnavailable:
        old = None
    if old is None or pin.issuer not in old.state.enrollments:
        if not accept_loss:
            raise StateUnavailable(
                "no readable record: key actions would be lost; say so with accept_loss"
            )
    else:
        was = old.state.enrollments[pin.issuer]
        if pin.authority_generation < was.generation or pin.recovery_epoch < was.recovery_epoch:
            raise ValueError(
                f"pin is behind the record (generation {was.generation}, recovery {was.recovery_epoch})"
            )
        if fresh.authority_fingerprint in was.compromised:
            raise ValueError("this key was declared compromised: enrol a fresh one")
        if fresh.authority_fingerprint in was.superseded:
            raise ValueError("this key was superseded: its lists would be refused")
        mark = old.state.get(pin.issuer)
        if mark is not None and not accept_loss and (pin.baseline_epoch or 0) < mark.epoch:
            raise ValueError(
                f"the baseline is below the record's mark (epoch {mark.epoch}), which would drop the "
                "epoch floor: state the current baseline, or say so with accept_loss"
            )
        superseded = was.superseded
        replaced_key = was.authority_fingerprint != fresh.authority_fingerprint
        if replaced_key and was.authority_fingerprint not in was.compromised:
            superseded = (*superseded, was.authority_fingerprint)
        fresh = replace(
            fresh,
            compromised=was.compromised,
            superseded=superseded,
            voided=was.voided,
            recovery_digest=pin.recovery_digest or was.recovery_digest,
        )
        state = state.with_enrollment(fresh)
        seq, effective, adjudicated, floor = (
            old.seq,
            old.effective,
            old.adjudicated,
            old.policy_floor,
        )
        if old.contradiction is not None:
            adjudicated = (
                *adjudicated,
                old.contradiction["digest"],
                old.contradiction["mark_digest"],
            )
    if clear_effective:
        effective = {}
    if reset_policy_floor:
        floor = None
    rec, data = fit(
        Record(seq + 1, pin.enrollment_id, state, effective, None, rv._z(now), adjudicated, floor)
    )
    if not store.cas(pin.issuer, current, data):
        raise StateUnavailable("concurrent ceremony")
    return rec


# ----------------------------------------------------------------------------- key action lattice


def join_action(a: dict[str, Any] | None, b: dict[str, Any]) -> dict[str, Any]:
    """active < retired(later) < retired(earlier) < compromised(later) < compromised(earlier) < unknown."""
    if a is None:
        return b
    successor = b.get("successor") or a.get("successor")
    eff_a, eff_b = a["effective_from"], b["effective_from"]
    out: dict[str, Any]
    if "compromised" in (a["status"], b["status"]):
        unknown = any(x["status"] == "compromised" and x["effective_from"] is None for x in (a, b))
        boundary = None if unknown else min(eff_a, eff_b, key=parse_rfc3339)
        out = {**b, "status": "compromised", "effective_from": boundary}
    else:
        out = {**b, "effective_from": min(eff_a, eff_b, key=parse_rfc3339)}
        out["status"] = "replaced" if successor else "retired"
    out.pop("successor", None)
    if successor:
        out["successor"] = successor
    return out


def join_all(
    effective: Mapping[str, dict[str, Any]], listed: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    out = dict(effective)
    for item in listed:
        out[item["key_fingerprint"]] = join_action(out.get(item["key_fingerprint"]), item)
    return out


# ----------------------------------------------------------------------------- ingest (writes state)


@dataclass(frozen=True)
class Ingested:
    accepted: bool
    code: str | None = None
    notes: tuple[str, ...] = ()
    seq: int | None = None


def past_floor(rec: Record, now: datetime) -> bool:
    return rec.clock_floor is not None and now < parse_rfc3339(rec.clock_floor) - rv.SKEW


def _floor(rec: Record, now: datetime) -> str:
    if rec.clock_floor is None or now > parse_rfc3339(rec.clock_floor):
        return rv._z(now)
    return rec.clock_floor


def _mutate(
    store: StateStore,
    pin: Pin,
    now: datetime,
    step: Callable[[Record], tuple[Record | None, Ingested]],
) -> Ingested:
    """Pure verification against a snapshot, then compare-and-set; on a lost race re-verify from scratch."""
    for _ in range(MAX_CAS_RETRIES):
        try:
            rec, raw = load(store, pin)
        except StateLost:
            return Ingested(False, "REVOCATION_STATE_LOST")
        except StateUnavailable:
            return Ingested(False, "REVOCATION_STATE_UNAVAILABLE")
        if past_floor(rec, now):
            return Ingested(False, "REVOCATION_CLOCK_REGRESSION")
        new, outcome = step(rec)
        if new is None:
            return outcome
        try:
            new, data = fit(new)
        except RecordTooLarge:
            return Ingested(False, "REVOCATION_STATE_FULL")
        try:
            if store.cas(pin.issuer, raw, data):
                return replace(outcome, seq=new.seq)
        except StateUnavailable:
            return Ingested(False, "REVOCATION_STATE_UNAVAILABLE")
    return Ingested(False, "REVOCATION_STATE_CONFLICT")


def ingest_list(
    store: StateStore, pin: Pin, raw_list: str | bytes, trust_store: TrustStore, now: datetime
) -> Ingested:
    def step(rec: Record) -> tuple[Record | None, Ingested]:
        if rec.contradiction is not None:
            return None, Ingested(False, "REVOCATION_CONTRADICTORY")
        res = rv.verify_list_enrolled(raw_list, pin.issuer, trust_store, rec.state, now)
        code = res.code
        statement = res.statement
        if (
            res.accepted
            and statement is not None
            and rec.state.get(pin.issuer) is None
            and pin.baseline_epoch is not None
        ):
            epoch = statement["epoch"]
            if epoch < pin.baseline_epoch:
                code = "REVOCATION_ROLLBACK"
            elif (epoch == pin.baseline_epoch and res.digest != pin.baseline_digest) or (
                pin.baseline_digest is not None
                and epoch == pin.baseline_epoch + 1
                and statement["prev_list_digest"] != pin.baseline_digest
            ):
                code = "REVOCATION_FORK"
        if code is not None:
            if code in SIGNED_CONTRADICTIONS:
                digest = rv.list_digest(json.loads(raw_list))
                if digest in rec.adjudicated:
                    return None, Ingested(
                        False, code
                    )  # already ruled on by a ceremony: replay is free
                mark = rec.state.get(pin.issuer)
                latched = replace(
                    rec,
                    seq=rec.seq + 1,
                    contradiction={
                        "code": code,
                        "digest": digest,
                        "mark_digest": mark.digest if mark else "",
                    },
                    clock_floor=_floor(rec, now),
                )
                return latched, Ingested(False, code)
            return None, Ingested(False, code)
        if "REVOCATION_REPEAT" in res.notes:
            return None, Ingested(True, None, res.notes, rec.seq)
        assert statement is not None
        enrollment = rec.state.enrollments[pin.issuer]
        state = rv.commit(rec.state, enrollment.anchor, res, accepted_at=rv._z(now))
        advanced = replace(
            rec,
            seq=rec.seq + 1,
            state=state,
            effective=join_all(rec.effective, statement["entries"]),
            clock_floor=_floor(rec, now),
        )
        return advanced, Ingested(True, None, res.notes)

    return _mutate(store, pin, now, step)


def ingest_transition(
    store: StateStore, pin: Pin, raw: str | bytes, trust_store: TrustStore, now: datetime
) -> Ingested:
    def step(rec: Record) -> tuple[Record | None, Ingested]:
        if rec.contradiction is not None:
            return None, Ingested(False, "REVOCATION_CONTRADICTORY")
        res = rv.verify_transition(raw, rec.state, trust_store, now)
        if not res.accepted:
            return None, Ingested(False, res.code)
        state = rv.apply_authority(rec.state, res)
        return replace(rec, seq=rec.seq + 1, state=state, clock_floor=_floor(rec, now)), Ingested(
            True
        )

    return _mutate(store, pin, now, step)


def ingest_recovery(
    store: StateStore, pin: Pin, raw: str | bytes, trust_store: TrustStore, now: datetime
) -> Ingested:
    def step(rec: Record) -> tuple[Record | None, Ingested]:
        res = rv.verify_recovery(raw, rec.state, trust_store, now)
        if not res.accepted:
            if res.declared is None:
                return None, Ingested(False, res.code)
            told = replace(rec.state.enrollments[pin.issuer], compromised=res.declared)
            noted = replace(
                rec,
                seq=rec.seq + 1,
                state=rec.state.with_enrollment(told),
                clock_floor=_floor(rec, now),
            )
            return noted, Ingested(False, res.code)
        if "REVOCATION_REPEAT" in res.notes:
            return None, Ingested(True, None, res.notes, rec.seq)
        state = rv.apply_authority(rec.state, res)
        recovered = replace(
            rec, seq=rec.seq + 1, state=state, contradiction=None, clock_floor=_floor(rec, now)
        )
        return recovered, Ingested(True, None, res.notes)

    return _mutate(store, pin, now, step)


def ingest_feed(
    store: StateStore,
    pin: Pin,
    *,
    recoveries: list[str],
    transitions: list[str],
    raw_list: str | bytes | None,
    trust_store: TrustStore,
    now: datetime,
) -> Ingested:
    """One poll of a distribution point, which serves everything every time (section 8.4): recoveries by
    ``recovery_epoch``, then transitions by generation with those already passed discarded, then the list."""

    def parsed(items: list[str], key: Callable[[Any], int]) -> list[tuple[int, str]]:
        """Documents this poll can order. An unreadable one is refused by its own ingest."""
        out = []
        for raw in items:
            try:
                out.append((key(loads_strict(raw, max_bytes=rv.MAX_BYTES)), raw))
            except (CanonicalError, RecursionError, UnicodeDecodeError) as exc:
                raise ValueError("REVOCATION_MALFORMED") from exc
        return sorted(out, key=lambda x: x[0] if type(x[0]) is int else 0)

    infrastructure = {
        "REVOCATION_STATE_LOST",
        "REVOCATION_STATE_UNAVAILABLE",
        "REVOCATION_CLOCK_REGRESSION",
        "REVOCATION_STATE_CONFLICT",
        "REVOCATION_STATE_FULL",
    }
    refused: Ingested | None = None
    try:
        ordered_recoveries = parsed(recoveries, lambda d: d["recovery_epoch"])
        ordered_transitions = parsed(transitions, lambda d: d["to_authority"]["generation"])
    except (AttributeError, KeyError, TypeError, ValueError):
        return Ingested(False, "REVOCATION_MALFORMED")
    # A refused statement does not stop the poll. Whatever it may declare has landed, an old one is expected in a
    # feed that serves everything, and anyone who can reach the channel could add junk. The list decides the result.
    for _, raw in ordered_recoveries:
        out = ingest_recovery(store, pin, raw, trust_store, now)
        if out.code in infrastructure:
            return out
        if not out.accepted:
            refused = refused or out
    for generation, raw in ordered_transitions:
        try:
            current = load(store, pin)[0].state.enrollments[pin.issuer].generation
        except StateLost:
            return Ingested(False, "REVOCATION_STATE_LOST")
        except StateUnavailable:
            return Ingested(False, "REVOCATION_STATE_UNAVAILABLE")
        if type(generation) is int and generation <= current:
            continue
        out = ingest_transition(store, pin, raw, trust_store, now)
        if out.code in infrastructure:
            return out
        if not out.accepted:
            refused = refused or out
    if raw_list is None:
        return refused or Ingested(True)
    return ingest_list(store, pin, raw_list, trust_store, now)
