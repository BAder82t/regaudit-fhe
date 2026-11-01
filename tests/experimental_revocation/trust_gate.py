"""EXPERIMENTAL reference model of proposal v2 sections 7 to 10. NOT SHIPPED.

Tests only: the monotonic state store contract, the verification-time gate, the store overlay, the opt-in
wrapper around the unchanged engine, and store migration. ``src/regaudit_fhe`` does not import this and no
verification rule changes. ``FileCasStore`` shows the commit protocol; it is not an independent store, and
``MemoryCasStore`` is a test double for one. See ``docs/TRUST_REVOCATION_PROTOCOL_PROPOSAL.md``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import hashlib
import json
import os
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from regaudit_fhe._keys import spki_fingerprint
from regaudit_fhe.canonical import canonical_bytes, loads_strict
from regaudit_fhe.report_v2 import AuditEnvelopeV2
from regaudit_fhe.trust import TrustStore
from regaudit_fhe.verification import PolicyError, VerificationPolicy, VerificationResult, verify

from . import proto
from .proto import parse_rfc3339

MODE_OFF = "off"
MODE_ADVISORY = "advisory"
MODE_REQUIRED = "required"
MODES = (MODE_OFF, MODE_ADVISORY, MODE_REQUIRED)

DEFAULT_MAX_EVIDENCE_AGE = timedelta(hours=24)
MAX_CAS_RETRIES = 8
MAX_RECORD_BYTES = 32 * 1024 * 1024
RECORD_DOMAIN = b"regaudit-fhe/revocation-state/v1/record\x00"

# Refusals that carry a valid signature by the enrolled authority, so nobody without that key can cause them.
# Store conflicts are not here: they depend on the local store, which changes, and a public replay could trip them.
SIGNED_CONTRADICTIONS = frozenset({"REVOCATION_FORK", "REVOCATION_NOT_MONOTONE"})
# Infrastructure failures (CLI exit 3, HTTP 503). Every other gate code is a policy refusal (exit 1).
INFRASTRUCTURE_CODES = frozenset(
    {
        "REVOCATION_NOT_ENROLLED",
        "REVOCATION_STATE_UNAVAILABLE",
        "REVOCATION_STATE_LOST",
        "REVOCATION_STATE_ROLLBACK",
        "REVOCATION_CLOCK_REGRESSION",
        "REVOCATION_STATE_CONFLICT",
    }
)


class StateUnavailable(RuntimeError):
    """The state store is unreachable, or its record is unreadable or inconsistent."""


class StateLost(StateUnavailable):
    """The issuer is enrolled but the state store holds no record for it."""


class RecordTooLarge(RuntimeError):
    """Even with the archive pruned, the record does not fit its limit."""


class SimulatedCrash(BaseException):
    """Test hook: the process died at this point. BaseException so that no cleanup handler runs."""


class CasStore(Protocol):
    """The state store contract: atomic compare-and-set over opaque per-issuer records."""

    durable: bool
    compare_and_set: bool
    independent: bool
    scope: str

    def read(self, issuer: str) -> bytes | None: ...

    def cas(self, issuer: str, expected: bytes | None, new: bytes) -> bool: ...


class MemoryCasStore:
    """Test double for an independent compare-and-set service."""

    durable = True
    compare_and_set = True
    independent = True
    scope = "INDEPENDENT_CAS"

    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}
        self.down = False

    def read(self, issuer: str) -> bytes | None:
        if self.down:
            raise StateUnavailable("store unreachable")
        return self.data.get(issuer)

    def cas(self, issuer: str, expected: bytes | None, new: bytes) -> bool:
        if self.down:
            raise StateUnavailable("store unreachable")
        if self.data.get(issuer) != expected:
            return False
        self.data[issuer] = new
        return True


class FileCasStore:
    """One file per issuer: flock for compare-and-set, temp + fsync + rename + directory fsync to commit.

    Durable and atomic on one host. Not independent: whoever can write the directory can replace the record.
    """

    durable = True
    compare_and_set = True
    independent = False
    scope = "LOCAL_FILE"

    def __init__(self, directory: str | Path, crash_at: str | None = None) -> None:
        self.dir = Path(directory)
        self.crash_at = crash_at

    def path(self, issuer: str) -> Path:
        return self.dir / (hashlib.sha256(issuer.encode()).hexdigest() + ".state")

    def read(self, issuer: str) -> bytes | None:
        try:
            return self.path(issuer).read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StateUnavailable(str(exc)) from exc

    def _crash(self, point: str) -> None:
        if self.crash_at == point:
            raise SimulatedCrash(point)

    def cas(self, issuer: str, expected: bytes | None, new: bytes) -> bool:
        target = self.path(issuer)
        try:
            with (self.dir / ".lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                current = target.read_bytes() if target.exists() else None
                if current != expected:
                    return False
                fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".state-", suffix=".tmp")
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(new)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.chmod(tmp, 0o600)
                    self._crash("before-rename")
                    os.replace(tmp, target)
                except OSError:
                    with contextlib.suppress(OSError):
                        os.unlink(tmp)
                    raise
                self._crash("after-rename")
                dir_fd = os.open(self.dir, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        except OSError as exc:
            raise StateUnavailable(str(exc)) from exc
        return True


# ----------------------------------------------------------------------------- pinned enrollment and record


@dataclass(frozen=True)
class Pin:
    """Created only by the operator's enrollment ceremony. Never learned from a list or a channel."""

    issuer: str
    authority_pem: str
    enrollment_id: str
    recovery_pem: str | None = None
    baseline_epoch: int | None = None  # None = first use; 0 = the ceremony asserted that no list exists yet
    baseline_digest: str | None = None
    # Stated by a re-baseline ceremony, so that an old statement cannot move the authority backwards.
    authority_generation: int = 1
    recovery_epoch: int = 0
    recovery_digest: str | None = None


@dataclass(frozen=True)
class Record:
    seq: int
    enrollment_id: str
    state: proto.RevocationState
    effective: dict[str, dict[str, Any]] = field(default_factory=dict)  # fingerprint -> joined action
    contradiction: dict[str, str] | None = None
    clock_floor: str | None = None
    adjudicated: tuple[str, ...] = ()  # list digests a ceremony has ruled on: replaying one cannot latch


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
    }
    body = canonical_bytes(payload)
    digest = hashlib.sha256(RECORD_DOMAIN + body).hexdigest()
    return json.dumps({"record": payload, "digest": digest}, sort_keys=True).encode()


def fit(rec: Record) -> tuple[Record, bytes]:
    """Prune the archive oldest first to stay under the read limit. The mark and key actions are never pruned;
    a pruned baseline later gives REVOCATION_RECOVERY_BASELINE_UNKNOWN, which fails closed."""
    data = encode(rec)
    while len(data) > MAX_RECORD_BYTES:
        current = rec.state.get(next(iter(rec.state.enrollments)))
        older = sorted(
            (k for k in rec.state.archive if current is None or k != current.digest),
            key=lambda k: rec.state.archive[k].epoch,
        )
        if not older:
            raise RecordTooLarge(f"{len(data)} bytes")
        archive = dict(rec.state.archive)
        del archive[older[0]]
        rec = replace(rec, state=replace(rec.state, archive=archive))
        data = encode(rec)
    return rec, data


def decode(raw: bytes) -> Record:
    """A torn or corrupted record is unavailable, never empty and never a reason to fall back."""
    try:
        doc = loads_strict(raw, max_bytes=MAX_RECORD_BYTES)
        payload = doc["record"]
        expected = hashlib.sha256(RECORD_DOMAIN + canonical_bytes(payload)).hexdigest()
        if doc["digest"] != expected:
            raise ValueError("record digest mismatch")
        state = proto.RevocationState(
            {k: proto.Mark(**m) for k, m in payload["marks"].items()},
            {k: proto.Enrollment.from_dict(e) for k, e in payload["enrollments"].items()},
            {k: proto.Mark(**m) for k, m in payload["archive"].items()},
        )
        return Record(
            payload["seq"],
            payload["enrollment_id"],
            state,
            payload["effective"],
            payload["contradiction"],
            payload["clock_floor"],
            tuple(payload["adjudicated"]),
        )
    except StateUnavailable:
        raise
    except Exception as exc:
        raise StateUnavailable(f"unreadable state record: {exc}") from exc


def load(store: CasStore, pin: Pin) -> tuple[Record, bytes]:
    raw = store.read(pin.issuer)
    if raw is None:
        raise StateLost(pin.issuer)
    rec = decode(raw)
    if rec.enrollment_id != pin.enrollment_id:
        raise StateUnavailable("state record belongs to another enrollment")
    return rec, raw


def _initial_state(pin: Pin, trust_store: TrustStore | None) -> proto.RevocationState:
    state = proto.enroll(
        proto.RevocationState(),
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
    store: CasStore, pin: Pin, trust_store: TrustStore | None = None, *, now: datetime
) -> Record:
    """The ceremony writes the first record, so that a later missing record is detectably lost."""
    rec = Record(1, pin.enrollment_id, _initial_state(pin, trust_store), clock_floor=proto._z(now))
    if not store.cas(pin.issuer, None, encode(rec)):
        raise ValueError("already enrolled: re-baselining is a separate operator ceremony")
    return rec


def rebaseline(
    store: CasStore,
    pin: Pin,
    *,
    now: datetime,
    trust_store: TrustStore | None = None,
    clear_effective: bool = False,
    accept_loss: bool = False,
) -> Record:
    """Operator ceremony after lost, restored or contradicted state. A new pin replaces the old one.

    It never loosens as a side effect and never moves the authority backwards: key actions and authority
    history carry over from a readable record, and losing them because the record is gone or unreadable has
    to be said out loud with ``accept_loss``. Clearing key actions is a local act, not an issuer statement.
    """
    state = _initial_state(pin, trust_store)
    fresh = state.enrollments[pin.issuer]
    current = store.read(pin.issuer)
    seq = 0
    effective: dict[str, dict[str, Any]] = {}
    adjudicated: tuple[str, ...] = ()
    try:
        old = None if current is None else decode(current)
    except StateUnavailable:
        old = None
    if old is None:
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
        seq, effective, adjudicated = old.seq, old.effective, old.adjudicated
        if old.contradiction is not None:
            adjudicated = (
                *adjudicated,
                old.contradiction["digest"],
                old.contradiction["mark_digest"],
            )
    if clear_effective:
        effective = {}
    rec, data = fit(Record(seq + 1, pin.enrollment_id, state, effective, None, proto._z(now), adjudicated))
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


def overlay(store: TrustStore, issuer: str, effective: Mapping[str, dict[str, Any]]) -> TrustStore:
    """A view for one verification. The trust-store file is never written, so that a key enrolled later
    still gets its listed state, and so that no commit ever spans two files."""
    mine = [
        action
        for kid, entry in store.entries.items()
        if entry.issuer == issuer
        and (action := effective.get(spki_fingerprint(entry.public_key_pem))) is not None
    ]
    return proto.apply_entries(store, mine) if mine else store


# ----------------------------------------------------------------------------- ingest (writes state)


@dataclass(frozen=True)
class Ingested:
    accepted: bool
    code: str | None = None
    notes: tuple[str, ...] = ()
    seq: int | None = None


def _past_floor(rec: Record, now: datetime) -> bool:
    return rec.clock_floor is not None and now < parse_rfc3339(rec.clock_floor) - proto.SKEW


def _floor(rec: Record, now: datetime) -> str:
    if rec.clock_floor is None or now > parse_rfc3339(rec.clock_floor):
        return proto._z(now)
    return rec.clock_floor


def _mutate(
    store: CasStore,
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
        if _past_floor(rec, now):
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
    store: CasStore, pin: Pin, raw_list: str | bytes, trust_store: TrustStore, now: datetime
) -> Ingested:
    def step(rec: Record) -> tuple[Record | None, Ingested]:
        if rec.contradiction is not None:
            return None, Ingested(False, "REVOCATION_CONTRADICTORY")
        res = proto.verify_list_enrolled(raw_list, pin.issuer, trust_store, rec.state, now)
        code = res.code
        if res.accepted and rec.state.get(pin.issuer) is None and pin.baseline_epoch is not None:
            epoch = res.statement["epoch"]  # type: ignore[index]
            if epoch < pin.baseline_epoch:
                code = "REVOCATION_ROLLBACK"
            elif (epoch == pin.baseline_epoch and res.digest != pin.baseline_digest) or (
                pin.baseline_digest is not None
                and epoch == pin.baseline_epoch + 1
                and res.statement["prev_list_digest"] != pin.baseline_digest  # type: ignore[index]
            ):
                code = "REVOCATION_FORK"
        if code is not None:
            if code in SIGNED_CONTRADICTIONS:
                digest = proto.list_digest(json.loads(raw_list))
                if digest in rec.adjudicated:
                    return None, Ingested(False, code)  # already ruled on by a ceremony: replay is free
                mark = rec.state.get(pin.issuer)
                new = replace(
                    rec,
                    seq=rec.seq + 1,
                    contradiction={
                        "code": code,
                        "digest": digest,
                        "mark_digest": mark.digest if mark else "",
                    },
                    clock_floor=_floor(rec, now),
                )
                return new, Ingested(False, code)
            return None, Ingested(False, code)
        if "REVOCATION_REPEAT" in res.notes:
            return None, Ingested(True, None, res.notes, rec.seq)
        enrollment = rec.state.enrollments[pin.issuer]
        state = proto.commit(rec.state, enrollment.anchor, res, accepted_at=proto._z(now))
        new = replace(
            rec,
            seq=rec.seq + 1,
            state=state,
            effective=join_all(rec.effective, res.statement["entries"]),  # type: ignore[index]
            clock_floor=_floor(rec, now),
        )
        return new, Ingested(True, None, res.notes)

    return _mutate(store, pin, now, step)


def ingest_transition(
    store: CasStore, pin: Pin, raw: str | bytes, trust_store: TrustStore, now: datetime
) -> Ingested:
    def step(rec: Record) -> tuple[Record | None, Ingested]:
        if rec.contradiction is not None:
            return None, Ingested(False, "REVOCATION_CONTRADICTORY")
        res = proto.verify_transition(raw, rec.state, trust_store, now)
        if not res.accepted:
            return None, Ingested(False, res.code)
        state = proto.apply_authority(rec.state, res)
        return replace(rec, seq=rec.seq + 1, state=state, clock_floor=_floor(rec, now)), Ingested(True)

    return _mutate(store, pin, now, step)


def ingest_recovery(
    store: CasStore, pin: Pin, raw: str | bytes, trust_store: TrustStore, now: datetime
) -> Ingested:
    def step(rec: Record) -> tuple[Record | None, Ingested]:
        res = proto.verify_recovery(raw, rec.state, trust_store, now)
        if not res.accepted:
            if res.declared is None:
                return None, Ingested(False, res.code)
            told = replace(rec.state.enrollments[pin.issuer], compromised=res.declared)
            new = replace(
                rec,
                seq=rec.seq + 1,
                state=rec.state.with_enrollment(told),
                clock_floor=_floor(rec, now),
            )
            return new, Ingested(False, res.code)
        if "REVOCATION_REPEAT" in res.notes:
            return None, Ingested(True, None, res.notes, rec.seq)
        state = proto.apply_authority(rec.state, res)
        new = replace(
            rec, seq=rec.seq + 1, state=state, contradiction=None, clock_floor=_floor(rec, now)
        )
        return new, Ingested(True, None, res.notes)

    return _mutate(store, pin, now, step)


def ingest_feed(
    store: CasStore,
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

    def parsed(items: list[str]) -> list[tuple[dict[str, Any], str]]:
        return [(json.loads(raw), raw) for raw in items]

    for _, raw in sorted(parsed(recoveries), key=lambda x: x[0]["recovery_epoch"]):
        out = ingest_recovery(store, pin, raw, trust_store, now)
        if not out.accepted:
            return out
    for doc, raw in sorted(parsed(transitions), key=lambda x: x[0]["to_authority"]["generation"]):
        try:
            current = load(store, pin)[0].state.enrollments[pin.issuer].generation
        except StateUnavailable:
            return Ingested(False, "REVOCATION_STATE_UNAVAILABLE")
        if doc["to_authority"]["generation"] <= current:
            continue
        out = ingest_transition(store, pin, raw, trust_store, now)
        if not out.accepted:
            return out
    if raw_list is None:
        return Ingested(True)
    return ingest_list(store, pin, raw_list, trust_store, now)


# ----------------------------------------------------------------------------- gate (reads state only)


@dataclass
class RevocationContext:
    mode: str
    store: CasStore
    pins: dict[str, Pin]
    max_evidence_age: timedelta = DEFAULT_MAX_EVIDENCE_AGE
    require_independent_store: bool = False  # owner decision OD-3; recommended True for high-assurance
    # This process's memory of where the record was, per enrollment: (seq, epoch, generation, recovery_epoch).
    known_position: dict[tuple[str, str], tuple[int, int, int, int]] = field(default_factory=dict)


@dataclass(frozen=True)
class GateResult:
    ok: bool
    code: str | None
    effective: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)


def gate(ctx: RevocationContext, issuer: str, now: datetime) -> GateResult:
    pin = ctx.pins.get(issuer)
    if pin is None:
        return GateResult(False, "REVOCATION_NOT_ENROLLED")
    try:
        rec, _ = load(ctx.store, pin)
    except StateLost:
        return GateResult(False, "REVOCATION_STATE_LOST")
    except StateUnavailable:
        return GateResult(False, "REVOCATION_STATE_UNAVAILABLE")

    def stop(code: str) -> GateResult:
        return GateResult(False, code, rec.effective)

    enrollment = rec.state.enrollments[issuer]
    held = rec.state.get(issuer)
    position = (
        rec.seq,
        held.epoch if held else 0,
        enrollment.generation,
        enrollment.recovery_epoch,
    )
    known = ctx.known_position.get((issuer, pin.enrollment_id))
    if known is not None:
        # seq counts writes, and authentic old lists can walk it back up, so the position is compared too.
        # Only a newer recovery statement may lower the epoch or the generation.
        same_recovery = position[3] == known[3]
        if (
            position[0] < known[0]
            or position[3] < known[3]
            or (same_recovery and (position[1] < known[1] or position[2] < known[2]))
        ):
            return stop("REVOCATION_STATE_ROLLBACK")
    ctx.known_position[(issuer, pin.enrollment_id)] = position
    if rec.contradiction is not None:
        return stop("REVOCATION_CONTRADICTORY")
    if _past_floor(rec, now):
        return stop("REVOCATION_CLOCK_REGRESSION")
    mark = rec.state.get(issuer)
    if mark is None:
        return stop("REVOCATION_DATA_ABSENT")
    if proto.condemned(mark, enrollment.compromised):
        return stop("REVOCATION_AUTHORITY_COMPROMISED")
    issued, until = parse_rfc3339(mark.issued_at), parse_rfc3339(mark.valid_until)
    if now >= until or now - issued > ctx.max_evidence_age:
        return stop("REVOCATION_DATA_STALE")
    evidence = {
        "revocation_evidence": "verified-as-of-" + mark.issued_at,
        "epoch": mark.epoch,
        "digest": mark.digest,
        "valid_until": mark.valid_until,
        "state_seq": rec.seq,
    }
    return GateResult(True, None, rec.effective, evidence)


# ----------------------------------------------------------------------------- the opt-in wrapper


@dataclass(frozen=True)
class Decision:
    result: VerificationResult
    revocation: dict[str, Any] | None


def check_config(policy: VerificationPolicy, ctx: RevocationContext) -> None:
    if ctx.mode not in MODES:
        raise PolicyError(f"unknown revocation mode {ctx.mode!r}")
    store = policy.trust_store
    if store is None or not store.entries:
        raise PolicyError("REVOCATION_STORE_UNSUPPORTED: migrate the trust store to the entries form")
    if policy.historical_acceptance == "signer-asserted":
        raise PolicyError("signer-asserted time cannot be combined with a revocation mode")
    if policy.profile == "high-assurance" and ctx.mode == MODE_ADVISORY:
        raise PolicyError("the high-assurance profile has no advisory revocation mode")
    if ctx.mode == MODE_REQUIRED:
        if not (ctx.store.durable and ctx.store.compare_and_set):
            raise PolicyError("required revocation needs a durable compare-and-set state store")
        if ctx.require_independent_store and not ctx.store.independent:
            raise PolicyError("this deployment requires an independent state store")
        if any(pin.baseline_epoch is None for pin in ctx.pins.values()):
            raise PolicyError("required revocation needs an enrollment baseline, not first use")


def _with_code(result: VerificationResult, code: str, *, blocking: bool) -> VerificationResult:
    reasons = result.reasons if code in result.reasons else (*result.reasons, code)
    if not blocking:
        return replace(result, reasons=reasons)
    held = result.blocking_reasons
    return replace(
        result,
        reasons=reasons,
        blocking_reasons=held if code in held else (*held, code),
        accepted=False,
        trust_status="INVALID",
    )


def _compare_presented(
    ctx: RevocationContext, pin: Pin, raw: str | bytes, store: TrustStore, now: datetime
) -> str | None:
    """Evidence delivered with the artifact can refuse this call and nothing else. It is compared against the
    record and never written: TRUST_SPEC 4.6 rule 1 keeps trust history out of that channel."""
    try:
        rec, _ = load(ctx.store, pin)
    except StateUnavailable:
        return None  # the gate reports it
    return proto.verify_list_enrolled(raw, pin.issuer, store, rec.state, now).code


def verify_with_revocation(
    env: Any,
    policy: VerificationPolicy,
    ctx: RevocationContext,
    *,
    presented: str | bytes | None = None,
) -> Decision:
    """``off`` is the unchanged engine, exactly. Otherwise the gate runs first, so that a gate refusal never
    burns a replay identifier, and the engine then runs on the overlay. The issuer whose state is consulted
    comes from the verifier's trust store, never from the report."""
    if ctx.mode == MODE_OFF:
        return Decision(verify(env, policy), None)
    check_config(policy, ctx)
    store = policy.trust_store
    assert store is not None
    now = policy.now()
    receipt = env.receipt if isinstance(env.receipt, dict) else {}
    key_id = env.key_id if isinstance(env, AuditEnvelopeV2) else receipt.get("key_id", "")
    entry = store.entry(key_id) if isinstance(key_id, str) else None
    policy_id = f"regaudit-fhe/{policy.profile}+revocation-{ctx.mode}/v1"
    always = {
        "state_store_scope": ctx.store.scope,
        "max_evidence_age_s": ctx.max_evidence_age.total_seconds(),
        "limit": proto.ROLLBACK_LIMIT,
    }
    if entry is None or entry.issuer is None:  # the engine refuses an unknown key on its own
        return Decision(
            replace(verify(env, policy), policy_id=policy_id),
            {"gate": "not-applicable", "revocation_evidence": "unproven", **always},
        )
    issuer = entry.issuer
    pin = ctx.pins.get(issuer)
    presented_code = None
    if presented is not None and pin is not None:
        presented_code = _compare_presented(ctx, pin, presented, store, now)
    verdict = gate(ctx, issuer, now)
    view = overlay(store, issuer, verdict.effective)
    code = verdict.code or presented_code
    held_back = ctx.mode == MODE_REQUIRED and code is not None
    mode = "check" if held_back and policy.replay_mode == "record" else policy.replay_mode
    result = verify(env, dataclasses.replace(policy, trust_store=view, replay_mode=mode))
    if code is not None:
        result = _with_code(result, code, blocking=ctx.mode == MODE_REQUIRED)
    disclosure = {"gate": "ok" if code is None else code, **always, **verdict.evidence}
    if code is not None:
        disclosure["revocation_evidence"] = "unproven"
    return Decision(replace(result, policy_id=policy_id), disclosure)


# ----------------------------------------------------------------------------- trust-store migration


class MigrationRefused(ValueError):
    """Nothing was produced."""


def store_form(payload: Mapping[str, Any]) -> str:
    if "entries" in payload:
        return "entries"
    return "legacy-keys" if isinstance(payload.get("keys"), Mapping) else "bare-mapping"


def migrate_store(
    payload: Mapping[str, Any], issuers: Mapping[str, str], *, as_of: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Legacy or bare store to the entries form. The issuer of each key is an operator statement.

    A flat ``revoked`` key becomes compromised with an unknown boundary, never retired: the legacy form
    does not say why it was revoked, and only the strictest reading is safe.
    """
    form = store_form(payload)
    if form == "entries":
        raise MigrationRefused("already an entries store")
    source = TrustStore.from_dict(payload)
    missing = sorted(set(source.keys) - set(issuers))
    if missing:
        raise MigrationRefused(f"no issuer stated for {missing}; issuers are never inferred")
    extra = sorted(set(issuers) - set(source.keys))
    if extra:
        raise MigrationRefused(f"issuer stated for unknown key_id(s) {extra}")
    entries: dict[str, dict[str, Any]] = {}
    report: list[dict[str, Any]] = []
    for kid in sorted(source.keys):
        was = "revoked" if kid in source.revoked else "active"
        item: dict[str, Any] = {
            "issuer": issuers[kid],
            "public_key_pem": source.keys[kid],
            "status": "compromised" if was == "revoked" else "active",
        }
        pin = source.parameter_set_pins.get(kid)
        if pin is not None:
            item["parameter_set_pin"] = pin
        entries[kid] = item
        report.append(
            {
                "key_id": kid,
                "fingerprint": spki_fingerprint(source.keys[kid]),
                "from": was,
                "to": item["status"],
                "issuer": issuers[kid],
                "reason_code_change": (
                    "KEY_REVOKED -> KEY_COMPROMISED_NO_CHRONOLOGY" if was == "revoked" else None
                ),
                "new_refusal_possible": "ISSUER_MISMATCH",
            }
        )
    out = {"entries": entries, "as_of": as_of}
    migrated = TrustStore.from_dict(out)
    if {k: spki_fingerprint(v) for k, v in migrated.keys.items()} != {
        k: spki_fingerprint(v) for k, v in source.keys.items()
    }:
        raise MigrationRefused("a key changed during migration")
    return out, report
