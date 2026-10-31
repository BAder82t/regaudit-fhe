"""Verification engine shared by the library, the CLI and the HTTP server.

One :class:`VerificationPolicy` and one :func:`verify` apply the trust rules in
``docs/TRUST_SPEC.md`` to both ``report.v1`` and ``report.v2`` envelopes, so no
entry point can obtain a weaker policy by being a different entry point.

Phase 3A scope
--------------
Implemented: signed v2 identity checks, key lifecycle (active / retired /
compromised) against a **locally provisioned** trust store, chronology from a
caller-pinned timestamp verifier, freshness, audience, and local replay
detection.

Not implemented (held by the project owner, see the spec): trust-anchor
distribution, anchor-signed bundles, any production timestamp authority,
shared replay infrastructure, and high-assurance historical acceptance. In
particular there is no mechanism in this release that produces an
*authenticated* :class:`TrustHistory`, so historical acceptance of retired or
compromised keys can only be exercised by a caller that supplies one; the
default is to refuse.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from ._keys import spki_fingerprint
from ._provenance import CONTRADICTION, UNVERIFIABLE
from ._provenance import check_provenance as _check_provenance
from ._time import parse_rfc3339
from .canonical import CanonicalError, decode_canonical_b64
from .replay import SCOPE_LOCAL_PERSISTENT, ReplayCache
from .report_v2 import AuditEnvelopeV2
from .reports import AuditEnvelope, canonical_json, sha256_hex, verify_signature
from .trust import KeyEntry, TrustStore

PROFILES = ("development", "confidential", "high-assurance")

TRUSTED = "TRUSTED"
SELF_SIGNED_ONLY = "SELF_SIGNED_ONLY"
INVALID = "INVALID"

CHRONOLOGY_NONE = "NONE"
CHRONOLOGY_SIGNER_ASSERTED = "SIGNER_ASSERTED"
CHRONOLOGY_AUTHENTICATED = "AUTHENTICATED"

TS_ABSENT = "ABSENT"
TS_UNVERIFIED = "UNVERIFIED"
TS_VERIFIED = "VERIFIED"
TS_FAILED = "FAILED"

CONSUMPTION_NOT_CHECKED = "NOT_CHECKED"
CONSUMPTION_CHECKED = "CHECKED_NOT_CONSUMED"
# Recorded in a *local* store at verification time. It is not coupled to any
# downstream operation and is not an exactly-once guarantee.
CONSUMPTION_RECORDED_LOCAL = "RECORDED_LOCAL"

HISTORY_UNPROVEN = "UNPROVEN"
HISTORY_FRESH = "FRESH"
HISTORY_STALE = "STALE"

DEFAULT_RETENTION = timedelta(days=30)


class PolicyError(RuntimeError):
    """The verification policy is unsafe or inconsistent; refuse to use it."""


class VerificationUnavailable(RuntimeError):
    """Required verification infrastructure is missing, so no verdict can be given.

    Raised instead of falling back to a weaker check (for example verifying a
    report against its own embedded key).
    """


@dataclass(frozen=True)
class TimestampEvidence:
    """What a pinned timestamp verifier established about one token."""

    gen_time: datetime
    accuracy: timedelta = timedelta(0)


class TimestampVerifier(Protocol):
    """Caller-pinned verifier for a timestamp or witness token.

    It receives the envelope's sealed digest and the raw token bytes and
    returns :class:`TimestampEvidence` only if the token authentically binds
    exactly that digest, else ``None``. regaudit-fhe ships no implementation
    and no default authority.
    """

    def __call__(self, sealed_digest: bytes, token: bytes) -> TimestampEvidence | None:
        """Return the evidence if ``token`` authentically binds ``sealed_digest``, else ``None``."""


@dataclass(frozen=True)
class TrustHistory:
    """The verifier's knowledge of how current its key-status history is.

    ``authenticated`` MUST be true only if the history was obtained through an
    anchor-authenticated mechanism. No such mechanism exists in Phase 3A (O8),
    so nothing in this library sets it; it is an explicit seam.
    """

    as_of: datetime
    authenticated: bool


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class VerificationPolicy:
    profile: str = "development"
    trust_store: TrustStore | None = None
    allow_self_signed: bool = False
    allow_legacy_v1: bool | None = None
    verifier_id: str | None = None
    max_age: timedelta | None = None
    clock_skew: timedelta = timedelta(minutes=5)
    now: Callable[[], datetime] = field(default=_utcnow, compare=False)
    historical_acceptance: str = "authenticated"
    timestamp_verifier: TimestampVerifier | None = field(default=None, compare=False)
    require_verified_timestamp: bool = False
    trust_history: TrustHistory | None = None
    trust_history_max_age: timedelta = timedelta(hours=24)
    replay_cache: ReplayCache | None = field(default=None, compare=False)
    replay_mode: str = "off"
    # Trust-bearing paths (verify_trusted, CLI verify, /v1/verify) turn this on: an envelope whose signed backend or
    # parameter_set_hash contradicts its own parameter_set is refused. Off keeps the legacy library behaviour.
    check_provenance: bool = False

    def __post_init__(self) -> None:
        if self.profile not in PROFILES:
            raise PolicyError(f"unknown profile {self.profile!r}; expected one of {PROFILES}")
        if self.allow_self_signed and self.profile != "development":
            raise PolicyError(
                f"--allow-self-signed / allow_self_signed is a development-only option and is "
                f"refused under the {self.profile!r} profile"
            )
        if self.historical_acceptance not in ("authenticated", "signer-asserted"):
            raise PolicyError("historical_acceptance must be 'authenticated' or 'signer-asserted'")
        if self.historical_acceptance == "signer-asserted" and self.profile != "development":
            raise PolicyError(
                "historical_acceptance='signer-asserted' is allowed in the development profile only"
            )
        if self.replay_mode not in ("off", "check", "record"):
            raise PolicyError("replay_mode must be 'off', 'check' or 'record'")
        if self.replay_mode != "off" and self.replay_cache is None:
            raise PolicyError("replay_mode requires a replay_cache")
        if self.max_age is not None and self.max_age <= timedelta(0):
            raise PolicyError("max_age must be positive")
        if self.clock_skew < timedelta(0):
            raise PolicyError("clock_skew must not be negative")
        if self.trust_history_max_age <= timedelta(0):
            raise PolicyError("trust_history_max_age must be positive")
        if self.verifier_id is not None and (
            not isinstance(self.verifier_id, str) or not self.verifier_id
        ):
            raise PolicyError("verifier_id must be a non-empty string")
        if self.require_verified_timestamp and self.timestamp_verifier is None:
            raise PolicyError(
                "require_verified_timestamp needs a pinned timestamp_verifier; none is bundled"
            )
        if self.profile != "development":
            if self.trust_store is None:
                raise PolicyError(f"the {self.profile!r} profile requires a trust store")
            if self.max_age is None:
                raise PolicyError(f"the {self.profile!r} profile requires max_age")
            if self.replay_mode == "off" or self.replay_cache is None:
                raise PolicyError(f"the {self.profile!r} profile requires replay checking")
            if self.replay_cache.scope != SCOPE_LOCAL_PERSISTENT:
                raise PolicyError(
                    f"the {self.profile!r} profile requires a persistent replay cache "
                    "(an in-memory cache is lost on restart)"
                )
        if self.profile == "high-assurance" and self.verifier_id is None:
            raise PolicyError("the 'high-assurance' profile requires a verifier_id (audience)")

    @property
    def legacy_v1_allowed(self) -> bool:
        if self.allow_legacy_v1 is not None:
            return self.allow_legacy_v1
        return self.profile != "high-assurance"

    @property
    def policy_id(self) -> str:
        return f"regaudit-fhe/{self.profile}/v1"


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of :func:`verify`.

    Branch on ``trust_status`` / ``accepted``. ``accepted`` is the single
    authoritative policy decision and is true only for ``TRUSTED``.
    ``valid`` is deprecated and kept only for compatibility.
    """

    trust_status: str
    accepted: bool
    integrity_valid: bool
    issuer_trusted: bool
    key_status: str
    chronology: str
    signed_not_after: str | None
    timestamp_status: str
    reasons: tuple[str, ...]
    blocking_reasons: tuple[str, ...]
    policy_id: str
    format: str
    replay_scope: str
    replay_durable: bool | None
    consumption: str
    trust_history: str
    trust_store_as_of: str | None
    issuer: str
    key_id: str
    primitive: str
    issued_at: str
    regulations: tuple[str, ...]
    parameter_set_hash: str
    deployment_id: str | None = None
    audit_run_id: str | None = None

    @property
    def valid(self) -> bool:
        """Deprecated alias of :attr:`accepted`."""
        warnings.warn(
            "VerificationResult.valid is deprecated; use `accepted` (the authoritative "
            "policy decision) or `trust_status`",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.accepted

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_status": self.trust_status,
            "accepted": self.accepted,
            "valid": self.accepted,  # deprecated alias, kept for compatibility
            "integrity_valid": self.integrity_valid,
            "issuer_trusted": self.issuer_trusted,
            "key_status": self.key_status,
            "chronology": self.chronology,
            "signed_not_after": self.signed_not_after,
            "timestamp_status": self.timestamp_status,
            "reasons": list(self.reasons),
            "blocking_reasons": list(self.blocking_reasons),
            "policy_id": self.policy_id,
            "format": self.format,
            "replay_scope": self.replay_scope,
            "replay_durable": self.replay_durable,
            "consumption": self.consumption,
            "trust_history": self.trust_history,
            "trust_store_as_of": self.trust_store_as_of,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "primitive": self.primitive,
            "issued_at": self.issued_at,
            "regulations": list(self.regulations),
            "parameter_set_hash": self.parameter_set_hash,
            "deployment_id": self.deployment_id,
            "audit_run_id": self.audit_run_id,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _norm_pem(pem: str) -> str:
    return pem.strip().replace("\r\n", "\n")


def _effective_max_age(policy: VerificationPolicy) -> timedelta | None:
    """The explicit ``max_age`` or, when replay checking is on without one, the
    replay retention: a report must never remain acceptable after the cache has
    forgotten its identifier."""
    if policy.max_age is not None:
        return policy.max_age
    return DEFAULT_RETENTION if policy.replay_mode != "off" else None


def _aware_now(policy: VerificationPolicy) -> datetime:
    moment = policy.now()
    if not isinstance(moment, datetime) or moment.tzinfo is None or moment.utcoffset() is None:
        raise PolicyError("the verification clock must return a timezone-aware datetime")
    return moment


def _history_state(policy: VerificationPolicy, now: datetime) -> str:
    history = policy.trust_history
    if history is None or not history.authenticated:
        return HISTORY_UNPROVEN
    if history.as_of.tzinfo is None or history.as_of > now + policy.clock_skew:
        return HISTORY_UNPROVEN
    if now - history.as_of > policy.trust_history_max_age:
        return HISTORY_STALE
    return HISTORY_FRESH


def _evaluate_timestamps(
    env: AuditEnvelope | AuditEnvelopeV2, policy: VerificationPolicy, now: datetime
) -> tuple[str, TimestampEvidence | None]:
    """Timestamp status and the earliest verified evidence.

    ``report.v1`` tokens bind the signed body only (not the signature or the
    key), so they can never be VERIFIED and never yield chronology.
    """
    if isinstance(env, AuditEnvelope):
        return (TS_ABSENT if env.timestamp is None else TS_UNVERIFIED), None
    if not env.timestamps:
        return TS_ABSENT, None
    verifier = policy.timestamp_verifier
    if verifier is None:
        return TS_UNVERIFIED, None
    try:
        digest = env.sealed_digest()
    except CanonicalError:
        return TS_FAILED, None
    verified: list[TimestampEvidence] = []
    for item in env.timestamps:
        evidence: Any
        try:
            evidence = verifier(digest, decode_canonical_b64(item["token_b64"]))
        except Exception:  # a hostile or broken verifier must never accept
            evidence = None
        if (
            isinstance(evidence, TimestampEvidence)
            and isinstance(evidence.gen_time, datetime)
            and evidence.gen_time.tzinfo is not None
            and evidence.gen_time.utcoffset() is not None
            and isinstance(evidence.accuracy, timedelta)
            and evidence.accuracy >= timedelta(0)
            and evidence.gen_time <= now + policy.clock_skew
        ):
            verified.append(evidence)
    if not verified:
        return TS_FAILED, None
    return TS_VERIFIED, min(verified, key=lambda e: e.gen_time)


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------


def verify(env: AuditEnvelope | AuditEnvelopeV2, policy: VerificationPolicy) -> VerificationResult:
    """Verify an envelope under ``policy``; fail closed on every doubt.

    Raises :class:`VerificationUnavailable` when there is no trust material and
    the development self-signed check was not enabled. Never returns
    ``accepted`` for a report that could not be tied to a registered issuer.

    **Not a strict acceptance path on its own.** ``verify_report(parse_envelope(...))`` keeps the
    lenient legacy parse (a v1 report is read with its original tolerant field handling) and, unless
    ``policy.check_provenance`` is set, does not compare ``backend`` and ``parameter_set_hash`` with
    ``parameter_set``. It is unchanged in 0.2.0 for compatibility, but it is not suitable for an
    independently trusted acceptance decision: use :func:`regaudit_fhe.verify_trusted`, or parse with
    :func:`regaudit_fhe.report_v2.parse_envelope_strict` and set ``check_provenance=True``.
    """
    now = _aware_now(policy)
    v2 = isinstance(env, AuditEnvelopeV2)
    if not v2 and not isinstance(env, AuditEnvelope):
        raise TypeError("verify() expects an AuditEnvelope or AuditEnvelopeV2")
    fmt = "v2" if v2 else "v1"
    store = policy.trust_store
    if store is None and not policy.allow_self_signed:
        raise VerificationUnavailable(
            "no trust material configured: refusing to verify a report against its own embedded key"
        )

    reasons: list[str] = []
    blocking: list[str] = []

    def note(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    def block(code: str) -> None:
        note(code)
        if code not in blocking:
            blocking.append(code)

    # ----- identity and integrity ------------------------------------------
    receipt = env.receipt if isinstance(env.receipt, dict) else {}
    if isinstance(env, AuditEnvelopeV2):
        key_id: Any = env.key_id
    else:
        key_id = receipt.get("key_id", "")
    if not isinstance(key_id, str):
        key_id = ""
        block("MALFORMED_ENVELOPE")
    embedded_pem = receipt.get("public_key_pem")
    embedded_pem = embedded_pem if isinstance(embedded_pem, str) else ""
    sig_b64 = receipt.get("signature_b64")
    sig_b64 = sig_b64 if isinstance(sig_b64, str) else ""

    signing_input: bytes | None
    try:
        if isinstance(env, AuditEnvelopeV2):
            signing_input = env.signing_input()
        else:
            signing_input = canonical_json(env.signed_body())
    except (CanonicalError, TypeError, ValueError):
        signing_input = None
        block("MALFORMED_ENVELOPE")

    sha_ok = signing_input is not None and sha256_hex(signing_input) == receipt.get("sha256")
    if not sha_ok:
        block("HASH_MISMATCH")

    entry: KeyEntry | None = store.entry(key_id) if store is not None else None
    registered_pem = entry.public_key_pem if entry is not None else None
    verify_pem = registered_pem if store is not None else embedded_pem

    sig_ok = False
    if signing_input is not None and sig_b64 and verify_pem:
        try:
            sig_ok = bool(verify_signature(verify_pem, signing_input, sig_b64))
        except Exception:
            sig_ok = False
    if (store is None or entry is not None) and not sig_ok:
        block("SIGNATURE_INVALID")
    integrity_valid = sha_ok and sig_ok

    # ----- chronology --------------------------------------------------------
    try:
        issued: datetime | None = parse_rfc3339(env.issued_at)
    except ValueError:
        issued = None
        block("MALFORMED_ENVELOPE")  # an unreadable issue time cannot be reasoned about
    ts_status, evidence = _evaluate_timestamps(env, policy, now)
    if evidence is not None:
        chronology = CHRONOLOGY_AUTHENTICATED
    elif issued is not None:
        chronology = CHRONOLOGY_SIGNER_ASSERTED
    else:
        chronology = CHRONOLOGY_NONE
    signed_not_after = evidence.gen_time.isoformat() if evidence is not None else None
    if not v2:
        note("LEGACY_V1_FORMAT")
    if policy.check_provenance:
        prov_status, _ = _check_provenance(env)
        if prov_status == CONTRADICTION:
            block("PROVENANCE_CONTRADICTION")
        elif prov_status == UNVERIFIABLE:
            note("PROVENANCE_UNVERIFIABLE")

    base: dict[str, Any] = {
        "policy_id": policy.policy_id,
        "format": fmt,
        "chronology": chronology,
        "signed_not_after": signed_not_after,
        "timestamp_status": ts_status,
        "trust_store_as_of": store.as_of.isoformat() if store and store.as_of else None,
        "issuer": env.issuer,
        "key_id": key_id,
        "primitive": env.primitive,
        "issued_at": env.issued_at,
        "regulations": tuple(env.regulations),
        "parameter_set_hash": env.parameter_set_hash,
        "deployment_id": env.deployment_id if isinstance(env, AuditEnvelopeV2) else None,
        "audit_run_id": env.audit_run_id if isinstance(env, AuditEnvelopeV2) else None,
    }

    # ----- no trust material: development self-signed check ------------------
    if store is None:
        note("SELF_SIGNED_NO_TRUST_MATERIAL")
        status = SELF_SIGNED_ONLY if integrity_valid and not blocking else INVALID
        return VerificationResult(
            trust_status=status,
            accepted=False,
            integrity_valid=integrity_valid,
            issuer_trusted=False,
            key_status="none",
            reasons=tuple(reasons),
            blocking_reasons=tuple(blocking),
            replay_scope="NONE",
            replay_durable=None,
            consumption=CONSUMPTION_NOT_CHECKED,
            trust_history=_history_state(policy, now),
            **base,
        )

    # ----- issuer identity (spec 3.1) ---------------------------------------
    identity_ok = True
    if entry is None:
        block("ISSUER_UNKNOWN")
        identity_ok = False
        key_status = "unknown"
    else:
        key_status = entry.status
        if _norm_pem(entry.public_key_pem) != _norm_pem(embedded_pem):
            block("KEY_EMBEDDED_MISMATCH")
            identity_ok = False
        if isinstance(env, AuditEnvelopeV2):
            try:
                fingerprint_ok = env.public_key_fingerprint == spki_fingerprint(
                    entry.public_key_pem
                )
            except ValueError:
                fingerprint_ok = False
            if not fingerprint_ok:
                block("FINGERPRINT_MISMATCH")
                identity_ok = False
        if entry.issuer is not None and env.issuer != entry.issuer:
            block("ISSUER_MISMATCH")
            identity_ok = False
        if entry.deployments is not None and (
            not isinstance(env, AuditEnvelopeV2) or env.deployment_id not in entry.deployments
        ):
            block("DEPLOYMENT_NOT_ALLOWED")
            identity_ok = False
        if entry.primitives is not None and (
            not isinstance(env.primitive, str) or env.primitive not in entry.primitives
        ):
            # A report.v1 is not type-checked on parse: an unhashable primitive must be refused,
            # not raise TypeError out of the engine.
            block("PRIMITIVE_NOT_ALLOWED")
            identity_ok = False
        if (
            entry.parameter_set_pin is not None
            and entry.parameter_set_pin != env.parameter_set_hash
        ):
            block("PIN_MISMATCH")
            identity_ok = False
    issuer_trusted = entry is not None and identity_ok and sig_ok

    # ----- key lifecycle and chronology rules (spec 4) ----------------------
    if entry is not None:
        _apply_key_lifecycle(entry, v2, issued, evidence, policy, now, note=note, block=block)

    # ----- timestamp policy ---------------------------------------------------
    if ts_status == TS_FAILED:
        block("TIMESTAMP_FAILED")
    if policy.require_verified_timestamp and ts_status != TS_VERIFIED:
        block("TIMESTAMP_REQUIRED")

    # ----- format, audience, freshness ---------------------------------------
    if not v2 and not policy.legacy_v1_allowed:
        block("LEGACY_V1_FORMAT")
    audience = env.audience if isinstance(env, AuditEnvelopeV2) else None
    if audience is not None:
        if policy.verifier_id is not None:
            if policy.verifier_id not in audience:
                block("AUDIENCE_MISMATCH")
        elif policy.profile != "development":
            block("AUDIENCE_MISMATCH")
    elif policy.profile == "high-assurance":
        block("AUDIENCE_MISMATCH")
    max_age = _effective_max_age(policy)
    if max_age is not None and issued is not None:
        if issued > now + policy.clock_skew:
            block("REPORT_FROM_FUTURE")
        elif now - issued > max_age:
            block("REPORT_TOO_OLD")

    # ----- local replay (last: only a report that would be accepted counts) ---
    consumption = CONSUMPTION_NOT_CHECKED
    replay_scope = "NONE"
    replay_durable: bool | None = None
    if policy.replay_mode != "off" and not blocking:
        consumption, replay_scope, replay_durable = _apply_replay(
            env, policy, now, fmt=fmt, key_id=key_id, note=note, block=block
        )

    accepted = not blocking and integrity_valid and issuer_trusted
    if not issuer_trusted:
        # Nothing about time is established for an artifact whose issuer is not
        # authenticated, so do not present chronology for it.
        base["chronology"] = CHRONOLOGY_NONE
        base["signed_not_after"] = None
    return VerificationResult(
        trust_status=TRUSTED if accepted else INVALID,
        accepted=accepted,
        integrity_valid=integrity_valid,
        issuer_trusted=issuer_trusted,
        key_status=key_status,
        reasons=tuple(reasons),
        blocking_reasons=tuple(blocking),
        replay_scope=replay_scope,
        replay_durable=replay_durable,
        consumption=consumption,
        trust_history=_history_state(policy, now),
        **base,
    )


def _apply_key_lifecycle(
    entry: KeyEntry,
    v2: bool,
    issued: datetime | None,
    evidence: TimestampEvidence | None,
    policy: VerificationPolicy,
    now: datetime,
    *,
    note: Callable[[str], None],
    block: Callable[[str], None],
) -> None:
    if entry.not_before is not None and (
        (issued is not None and issued < entry.not_before)
        or (evidence is not None and evidence.gen_time < entry.not_before)
    ):
        block("KEY_NOT_YET_VALID")

    status = entry.status
    if status == "active":
        return
    if status == "revoked":
        block("KEY_REVOKED")
        return
    if status == "compromised" and entry.compromised_from is None:
        # Unknown compromise boundary: nothing this key signed is trusted
        # evidence, whatever time the signer or a token claims.
        block("KEY_COMPROMISED_NO_CHRONOLOGY")
        return

    def history_ok() -> bool:
        return policy.profile != "high-assurance" and _history_state(policy, now) == HISTORY_FRESH

    if status == "compromised":
        boundary = entry.compromised_from
        assert boundary is not None
        # Only authenticated chronology over the sealed artifact counts; v1
        # tokens bind the body only, so a v1 report can never qualify.
        if not v2 or evidence is None:
            block("KEY_COMPROMISED_NO_CHRONOLOGY")
        elif not (evidence.gen_time + evidence.accuracy < boundary):
            block("SIGNED_AFTER_COMPROMISE")
        if not history_ok():
            block("TRUST_STORE_FRESHNESS_UNPROVEN")
        return

    # retired
    retired_at = entry.retired_at
    assert retired_at is not None
    if policy.profile == "development" and policy.historical_acceptance == "signer-asserted":
        if issued is None:
            block("KEY_RETIRED_NO_CHRONOLOGY")
        elif issued >= retired_at:  # strict: equality is refused (no reliable order)
            block("SIGNED_AFTER_RETIREMENT")
        else:
            note("CHRONOLOGY_UNAUTHENTICATED")
        return
    if not v2 or evidence is None:
        block("KEY_RETIRED_NO_CHRONOLOGY")
    elif evidence.gen_time + evidence.accuracy >= retired_at:
        # Strict, like the compromise boundary: a timestamp equal to the retirement
        # time does not by itself show the signature preceded it. A reliable event
        # order (e.g. authenticated sequence numbers) would be needed to allow it.
        block("SIGNED_AFTER_RETIREMENT")
    if not history_ok():
        block("TRUST_STORE_FRESHNESS_UNPROVEN")


def _apply_replay(
    env: AuditEnvelope | AuditEnvelopeV2,
    policy: VerificationPolicy,
    now: datetime,
    *,
    fmt: str,
    key_id: str,
    note: Callable[[str], None],
    block: Callable[[str], None],
) -> tuple[str, str, bool | None]:
    if not isinstance(env, AuditEnvelopeV2):
        # v1 has no audit_run_id, so it cannot be replay-checked.
        (note if policy.profile == "development" else block)("REPLAY_ID_MISSING")
        return CONSUMPTION_NOT_CHECKED, "NONE", None
    cache = policy.replay_cache
    assert cache is not None
    durable = bool(getattr(cache, "durable", False))
    # A report is fresh until issued_at + max_age, and issued_at may be up to
    # clock_skew in the future, so remember the id for max_age + 2*skew.
    retain = (_effective_max_age(policy) or DEFAULT_RETENTION) + 2 * policy.clock_skew
    try:
        if policy.replay_mode == "check":
            if cache.seen(key_id, env.audit_run_id, now=now):
                block("REPLAY_DETECTED")
            return CONSUMPTION_CHECKED, cache.scope, durable
        if cache.record(key_id, env.audit_run_id, now=now, retain=retain):
            return CONSUMPTION_RECORDED_LOCAL, cache.scope, durable
        block("REPLAY_DETECTED")
        return CONSUMPTION_CHECKED, cache.scope, durable
    except Exception:  # any store failure, of any type
        (note if policy.profile == "development" else block)("REPLAY_STATE_UNAVAILABLE")
        return CONSUMPTION_NOT_CHECKED, "NONE", None
