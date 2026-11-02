"""The verifier gate for signed revocation data. EXPERIMENTAL and OFF BY DEFAULT.

Report signatures establish origin; separately signed revocation data establishes current authorization policy;
the verifier retains its own authority state. A valid report signature does not mean the issuer remains trusted.

``off`` is the unchanged engine and reads nothing. The revocation-aware ``high-assurance`` profile is **unavailable**:
it needs an independently protected, durable, monotonic state store, none has been qualified, and an object declaring
itself independent would be self-attestation, so no argument can enable it. It never falls back to a local file.
``required`` and ``advisory`` are available under the lower profiles, on the single-host file store only.

Wording rule: "verified as of" is the strongest thing a result may say. Nothing may say a key "is not revoked". The
enrolled pin and recovery anchor are the root and the list signer a delegate, with no independent approver and no
quorum: a governance limitation, disclosed in every policy-evidence section.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from . import _revocation as rv
from . import _revocation_state as st
from . import _verification_response as vr
from ._keys import spki_fingerprint
from ._time import parse_rfc3339
from .report_v2 import AuditEnvelopeV2
from .trust import TrustStore
from .verification import PolicyError, VerificationPolicy, VerificationResult, verify

MODE_OFF = "off"
MODE_ADVISORY = "advisory"
MODE_REQUIRED = "required"
MODES = (MODE_OFF, MODE_ADVISORY, MODE_REQUIRED)

# Owner ruling: the evidence age in required mode is capped at 24 hours. Shorter is allowed.
MAX_EVIDENCE_AGE_CAP = timedelta(hours=24)
DEFAULT_MAX_EVIDENCE_AGE = MAX_EVIDENCE_AGE_CAP

HIGH_ASSURANCE_UNAVAILABLE = (
    "REVOCATION_HIGH_ASSURANCE_UNAVAILABLE: the revocation-aware high-assurance profile needs an independently "
    "protected, durable, monotonic state store and none is qualified. It does not fall back to a local file. "
    "Existing high-assurance verification with revocation off does not evaluate revocation."
)
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
# Blocks in every mode: being in advisory mode must not be a way around a record that has served required.
ALWAYS_BLOCKING = frozenset({"REVOCATION_POLICY_DOWNGRADE"})


def _checked_evidence_age(value: Any) -> timedelta:
    if not isinstance(value, timedelta):
        raise PolicyError("max_evidence_age must be a timedelta")
    if value <= timedelta(0):
        raise PolicyError("max_evidence_age must be positive")
    if value > MAX_EVIDENCE_AGE_CAP:
        raise PolicyError("max_evidence_age is capped at 24 hours")
    return value


@dataclass
class RevocationContext:
    """The gate's inputs. ``pins`` come from the pinned-authority store, never from a list or a channel."""

    mode: str
    store: st.StateStore
    pins: dict[str, st.Pin]
    max_evidence_age: timedelta = DEFAULT_MAX_EVIDENCE_AGE
    # This process's memory of where the record was, per enrollment: (seq, epoch, generation, recovery_epoch).
    known_position: dict[tuple[str, str], tuple[int, int, int, int]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise PolicyError(f"unknown revocation mode {self.mode!r}; expected one of {MODES}")
        _checked_evidence_age(self.max_evidence_age)


@dataclass(frozen=True)
class GateResult:
    ok: bool
    code: str | None
    effective: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    notes: tuple[str, ...] = ()


def _us(age: timedelta) -> int:
    return age // timedelta(microseconds=1)


def _bind_floor(
    ctx: RevocationContext, pin: st.Pin, rec: st.Record, raw: bytes, requested: int
) -> tuple[st.Record, int, bool] | str:
    """The strictest settings this record has served only ever get stricter. A weaker setting cannot make stale
    evidence acceptable again. Writes only when the floor tightens, so a normal verification writes nothing."""
    floor = rec.policy_floor
    floor_age = floor["max_evidence_age_us"] if floor else None
    floor_mode = floor["mode"] if floor else None
    if floor_mode == MODE_REQUIRED and ctx.mode != MODE_REQUIRED:
        return "REVOCATION_POLICY_DOWNGRADE"
    age = requested if floor_age is None else min(requested, floor_age)
    if floor is not None and age == floor_age and floor_mode == ctx.mode:
        return rec, age, requested > age
    new = replace(rec, seq=rec.seq + 1, policy_floor={"mode": ctx.mode, "max_evidence_age_us": age})
    try:
        new, data = st.fit(new)
        if not ctx.store.cas(pin.issuer, raw, data):
            return "REVOCATION_STATE_CONFLICT"
    except (st.RecordTooLarge, st.StateUnavailable):
        return "REVOCATION_STATE_UNAVAILABLE"
    return new, age, requested > age


def gate(ctx: RevocationContext, issuer: str, now: datetime) -> GateResult:
    pin = ctx.pins.get(issuer)
    if pin is None:
        return GateResult(False, "REVOCATION_NOT_ENROLLED")
    try:
        rec, raw = st.load(ctx.store, pin)
    except st.StateLost:
        return GateResult(False, "REVOCATION_STATE_LOST")
    except st.StateUnavailable:
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
    for _ in range(st.MAX_CAS_RETRIES):
        bound = _bind_floor(ctx, pin, rec, raw, _us(ctx.max_evidence_age))
        if bound != "REVOCATION_STATE_CONFLICT":
            break
        try:  # another process bound the floor first: read what it wrote and go again
            rec, raw = st.load(ctx.store, pin)
        except st.StateUnavailable:
            return stop("REVOCATION_STATE_UNAVAILABLE")
    if isinstance(bound, str):
        return stop(bound)
    rec, age_us, floor_applied = bound
    notes = ("REVOCATION_POLICY_FLOOR_APPLIED",) if floor_applied else ()
    ctx.known_position[(issuer, pin.enrollment_id)] = (rec.seq, *position[1:])
    if rec.contradiction is not None:
        return stop("REVOCATION_CONTRADICTORY")
    if st.past_floor(rec, now):
        return stop("REVOCATION_CLOCK_REGRESSION")
    mark = rec.state.get(issuer)
    if mark is None:
        return stop("REVOCATION_DATA_ABSENT")
    if rv.condemned(mark, enrollment.compromised):
        return stop("REVOCATION_AUTHORITY_COMPROMISED")
    issued, until = parse_rfc3339(mark.issued_at), parse_rfc3339(mark.valid_until)
    if now >= until or now - issued > timedelta(microseconds=age_us):
        effective_age = {"effective_max_evidence_age_s": age_us / 1_000_000}
        return GateResult(False, "REVOCATION_DATA_STALE", rec.effective, effective_age, notes)
    evidence = {
        "revocation_evidence": "verified-as-of-" + mark.issued_at,
        "epoch": mark.epoch,
        "digest": mark.digest,
        "valid_until": mark.valid_until,
        "state_seq": rec.seq,
        "effective_max_evidence_age_s": age_us / 1_000_000,
    }
    return GateResult(True, None, rec.effective, evidence, notes)


def overlay(store: TrustStore, issuer: str, effective: Mapping[str, dict[str, Any]]) -> TrustStore:
    """A view for one verification. The trust-store file is never written, so that a key enrolled later
    still gets its listed state, and so that no commit ever spans two files."""
    mine = [
        action
        for entry in store.entries.values()
        if entry.issuer == issuer
        and (action := effective.get(spki_fingerprint(entry.public_key_pem))) is not None
    ]
    return rv.apply_entries(store, mine) if mine else store


@dataclass(frozen=True)
class Decision:
    """``result`` has the same shape as the engine's. ``revocation`` is the disclosure; ``None`` under ``off``."""

    result: VerificationResult
    revocation: dict[str, Any] | None


def policy_evidence(decision: Decision | None = None) -> dict[str, Any]:
    """The versioned, optional policy-evidence section. Never part of the default output."""
    return vr.policy_evidence(None if decision is None else decision.revocation)


def response_v2(decision: Decision) -> dict[str, Any]:
    """The opt-in response for a decision. See :mod:`regaudit_fhe._verification_response`."""
    return vr.response_v2(decision.result.to_dict(), decision.revocation)


def _check_config(policy: VerificationPolicy, ctx: RevocationContext) -> None:
    # Checked here as well as at construction, since the context is a mutable object.
    if ctx.mode not in (MODE_ADVISORY, MODE_REQUIRED):
        raise PolicyError(f"unknown revocation mode {ctx.mode!r}")
    _checked_evidence_age(ctx.max_evidence_age)
    store = policy.trust_store
    if store is None or not store.entries:
        raise PolicyError(
            "REVOCATION_STORE_UNSUPPORTED: migrate the trust store to the entries form"
        )
    if any(entry.issuer is None for entry in store.entries.values()):
        raise PolicyError("every trust-store entry needs an issuer under a revocation mode")
    if policy.historical_acceptance == "signer-asserted":
        raise PolicyError("signer-asserted time cannot be combined with a revocation mode")
    if policy.profile == "high-assurance" and ctx.mode == MODE_ADVISORY:
        raise PolicyError("the high-assurance profile has no advisory revocation mode")
    if ctx.mode == MODE_REQUIRED and any(pin.baseline_epoch is None for pin in ctx.pins.values()):
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
    ctx: RevocationContext, pin: st.Pin, raw: str | bytes, store: TrustStore, now: datetime
) -> str | None:
    """Evidence delivered with the artifact can refuse this call and nothing else. It is compared against the
    record and never written: TRUST_SPEC 4.6 rule 1 keeps trust history out of that channel."""
    try:
        rec, _ = st.load(ctx.store, pin)
    except st.StateUnavailable:
        return None  # the gate reports it
    return rv.verify_list_enrolled(raw, pin.issuer, store, rec.state, now).code


def _run_gate(
    env: Any,
    policy: VerificationPolicy,
    ctx: RevocationContext,
    *,
    presented: str | bytes | None = None,
    _unqualified_test_path: bool = False,
) -> Decision:
    """The algorithm, with no qualification of the store. PRIVATE: production callers go through
    :func:`verify_with_revocation`. Only the tests pass ``_unqualified_test_path``, to exercise the algorithm under
    ``high-assurance`` on a test double. That is simulated evidence, not an available mode.

    The gate runs first, so that a gate refusal never burns a replay identifier, and the engine then runs on the
    overlay. The issuer whose state is consulted comes from the verifier's trust store, never from the report.
    """
    if type(policy.profile) is not str or (
        policy.profile == "high-assurance" and not _unqualified_test_path
    ):
        raise PolicyError(HIGH_ASSURANCE_UNAVAILABLE)
    _check_config(policy, ctx)
    store = policy.trust_store
    assert store is not None
    now = policy.now()
    receipt = env.receipt if isinstance(env.receipt, dict) else {}
    key_id = env.key_id if isinstance(env, AuditEnvelopeV2) else receipt.get("key_id", "")
    entry = store.entry(key_id) if isinstance(key_id, str) else None
    policy_id = f"regaudit-fhe/{policy.profile}+revocation-{ctx.mode}/v1"
    always = {
        "mode": ctx.mode,
        "state_store_scope": ctx.store.scope,
        "max_evidence_age_s": ctx.max_evidence_age.total_seconds(),
        "limit": rv.ROLLBACK_LIMIT,
    }
    if entry is None:  # the engine refuses an unknown key on its own
        return Decision(
            replace(verify(env, policy), policy_id=policy_id),
            {"gate": "not-applicable", "revocation_evidence": "unproven", **always},
        )
    issuer = entry.issuer
    assert issuer is not None  # _check_config
    pin = ctx.pins.get(issuer)
    presented_code = None
    if presented is not None and pin is not None:
        presented_code = _compare_presented(ctx, pin, presented, store, now)
    verdict = gate(ctx, issuer, now)
    view = overlay(store, issuer, verdict.effective)
    code = verdict.code or presented_code
    blocks = code is not None and (ctx.mode == MODE_REQUIRED or code in ALWAYS_BLOCKING)
    replay_mode = "check" if blocks and policy.replay_mode == "record" else policy.replay_mode
    result = verify(env, dataclasses.replace(policy, trust_store=view, replay_mode=replay_mode))
    for note in verdict.notes:
        result = _with_code(result, note, blocking=False)
    if code is not None:
        result = _with_code(result, code, blocking=blocks)
    disclosure = {"gate": "ok" if code is None else code, **always, **verdict.evidence}
    if code is not None:
        disclosure["revocation_evidence"] = "unproven"
    return Decision(replace(result, policy_id=policy_id), disclosure)


def verify_with_revocation(
    env: Any,
    policy: VerificationPolicy,
    ctx: RevocationContext,
    *,
    presented: str | bytes | None = None,
) -> Decision:
    """The one public path. ``off`` is exactly the engine. ``high-assurance`` with any other mode always refuses,
    whatever store is passed: an object cannot attest its own independence. Other profiles run only on the shipped
    :class:`~regaudit_fhe._revocation_state.FileStateStore`, and disclose that it is a local file."""
    if ctx.mode == MODE_OFF:
        return Decision(verify(env, policy), None)
    if type(policy.profile) is not str or policy.profile == "high-assurance":
        raise PolicyError(HIGH_ASSURANCE_UNAVAILABLE)
    if type(ctx.store) is not st.FileStateStore:
        raise PolicyError("only the shipped single-host file store is available to this gate")
    return _run_gate(env, policy, ctx, presented=presented)
