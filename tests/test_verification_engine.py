"""Phase 3A verification engine: policy, key lifecycle, chronology, replay.

Every refusal is paired with a positive control that differs only in the
property under test.
"""

from __future__ import annotations

import threading
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.replay import InMemoryReplayCache, ReplayStateError, SqliteReplayCache
from regaudit_fhe.report_v2 import AuditEnvelopeV2, envelope_v2, public_key_fingerprint
from regaudit_fhe.trust import TrustStore
from regaudit_fhe.verification import (
    PolicyError,
    TimestampEvidence,
    TrustHistory,
    VerificationPolicy,
    VerificationResult,
    VerificationUnavailable,
    verify,
)

UTC = timezone.utc
NOW = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
ISSUED = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
RETIRED_AT = datetime(2026, 9, 1, 0, 0, tzinfo=UTC)
COMPROMISED_FROM = datetime(2026, 9, 15, 0, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)


def _clock() -> datetime:
    return NOW


def _report():
    return rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )


def _signer(key_id="acme-1"):
    return rf.Signer.generate(issuer="acme", key_id=key_id)


def _entry(signer, **over):
    base = {"issuer": signer.issuer, "public_key_pem": signer.public_key_pem(), "status": "active"}
    base.update(over)
    return base


def _store(signer, **over) -> TrustStore:
    return TrustStore.from_dict({"entries": {signer.key_id: _entry(signer, **over)}})


def _v2(signer, **kw) -> AuditEnvelopeV2:
    args = dict(deployment_id="prod-eu-1", issued_at=ISSUED, audit_run_id=None)
    args.update(kw)
    return envelope_v2("fairness", _report(), signer=signer, **args)


def _policy(store, **kw) -> VerificationPolicy:
    kw.setdefault("now", _clock)
    return VerificationPolicy(profile=kw.pop("profile", "development"), trust_store=store, **kw)


def _tsa(gen_time: datetime, accuracy: timedelta = timedelta(0)):
    """A fake pinned timestamp verifier and a matching minter."""

    def verifier(digest: bytes, token: bytes) -> TimestampEvidence | None:
        if token == b"ok:" + digest:
            return TimestampEvidence(gen_time=gen_time, accuracy=accuracy)
        return None

    def attach(env: AuditEnvelopeV2) -> AuditEnvelopeV2:
        return env.with_timestamp(
            issuer="tsa.test", token=b"ok:" + env.sealed_digest(), issued_at=gen_time
        )

    return verifier, attach


FRESH = TrustHistory(as_of=NOW - HOUR, authenticated=True)


def _reasons(r: VerificationResult) -> set[str]:
    return set(r.reasons)


# ---------------------------------------------------------------------------
# Acceptance and the three trust states
# ---------------------------------------------------------------------------


def test_active_key_v2_is_trusted_and_accepted():
    s = _signer()
    r = verify(_v2(s), _policy(_store(s)))
    assert r.trust_status == "TRUSTED" and r.accepted is True
    assert r.integrity_valid and r.issuer_trusted
    assert r.key_status == "active"
    assert r.chronology == "SIGNER_ASSERTED" and r.signed_not_after is None
    assert r.format == "v2" and r.policy_id == "regaudit-fhe/development/v1"
    assert r.consumption == "NOT_CHECKED" and r.replay_scope == "NONE"


def test_tampered_v2_envelope_is_invalid():
    s = _signer()
    env = _v2(s)
    assert verify(env, _policy(_store(s))).accepted  # control
    env.result["tampered"] = True
    r = verify(env, _policy(_store(s)))
    assert r.trust_status == "INVALID" and not r.accepted and not r.integrity_valid
    assert "HASH_MISMATCH" in _reasons(r)


def test_signature_by_another_key_is_invalid():
    s = _signer()
    other = _signer()  # same key_id would be needed to pass lookup; build one
    forged = _v2(
        rf.Signer(
            issuer="acme",
            key_id=s.key_id,
            private_key=other.private_key,
            public_key=other.public_key,
        )
    )
    r = verify(forged, _policy(_store(s)))
    assert r.trust_status == "INVALID" and not r.accepted
    assert {"SIGNATURE_INVALID", "KEY_EMBEDDED_MISMATCH"} <= _reasons(r)


def test_self_signed_without_trust_material_is_never_accepted():
    s = _signer()
    policy = VerificationPolicy(profile="development", allow_self_signed=True, now=_clock)
    r = verify(_v2(s), policy)
    assert r.trust_status == "SELF_SIGNED_ONLY" and r.accepted is False
    assert r.integrity_valid is True and r.issuer_trusted is False and r.key_status == "none"
    assert "SELF_SIGNED_NO_TRUST_MATERIAL" in _reasons(r)
    v1 = rf.envelope("fairness", _report(), signer=s)
    r1 = verify(v1, policy)
    assert r1.trust_status == "SELF_SIGNED_ONLY" and r1.accepted is False


def test_tampered_self_signed_is_invalid_not_self_signed():
    s = _signer()
    env = _v2(s)
    env.result["tampered"] = True
    r = verify(env, VerificationPolicy(allow_self_signed=True, now=_clock))
    assert r.trust_status == "INVALID" and not r.accepted


def test_no_trust_material_and_no_dev_flag_is_unavailable_not_a_verdict():
    with pytest.raises(VerificationUnavailable):
        verify(_v2(_signer()), VerificationPolicy(now=_clock))


def test_dev_flag_does_not_override_a_configured_trust_store():
    s = _signer()
    other = _signer("mallory-1")
    policy = _policy(_store(s), allow_self_signed=True)
    assert verify(_v2(s), policy).trust_status == "TRUSTED"
    r = verify(_v2(other), policy)
    assert r.trust_status == "INVALID" and "ISSUER_UNKNOWN" in _reasons(r)


# ---------------------------------------------------------------------------
# Issuer identity (spec 3.1)
# ---------------------------------------------------------------------------


def test_unknown_issuer_key_id():
    s = _signer()
    r = verify(_v2(_signer("acme-2")), _policy(_store(s)))
    assert r.trust_status == "INVALID" and "ISSUER_UNKNOWN" in _reasons(r)
    assert r.key_status == "unknown" and not r.issuer_trusted


def test_signed_issuer_must_match_the_registered_issuer():
    s = _signer()
    assert verify(_v2(s), _policy(_store(s))).accepted  # control
    r = verify(_v2(s), _policy(_store(s, issuer="someone-else")))
    assert r.trust_status == "INVALID" and "ISSUER_MISMATCH" in _reasons(r)
    assert r.issuer_trusted is False


def test_embedded_pem_and_signed_fingerprint_must_match_the_registered_key():
    s = _signer()
    env = _v2(s)
    other = _signer("x")
    env.receipt["public_key_pem"] = other.public_key_pem()
    r = verify(env, _policy(_store(s)))
    assert r.trust_status == "INVALID" and "KEY_EMBEDDED_MISMATCH" in _reasons(r)
    assert r.integrity_valid  # the signature itself still verifies under the registered key


def test_signed_fingerprint_must_match_the_registered_key():
    s = _signer()
    other = _signer("o")

    class LyingProvider:
        """Signs with ``s`` but advertises another key's PEM (so the signed
        fingerprint and embedded PEM name the wrong key)."""

        issuer = s.issuer
        key_id = s.key_id

        def public_key_pem(self) -> str:
            return other.public_key_pem()

        def sign(self, body: bytes) -> bytes:
            return s.sign(body)

    env = envelope_v2(
        "fairness", _report(), signer=LyingProvider(), deployment_id="d", issued_at=ISSUED
    )
    assert env.public_key_fingerprint == public_key_fingerprint(other.public_key_pem())
    r = verify(env, _policy(_store(s)))
    assert r.trust_status == "INVALID" and "FINGERPRINT_MISMATCH" in _reasons(r)
    assert r.integrity_valid  # signature verifies under the registered key


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"deployments": ["prod-us-1"]}, "DEPLOYMENT_NOT_ALLOWED"),
        ({"primitives": ["drift"]}, "PRIMITIVE_NOT_ALLOWED"),
        ({"parameter_set_pin": "0" * 64}, "PIN_MISMATCH"),
    ],
)
def test_registered_scope_is_enforced(over, reason):
    s = _signer()
    ok = {
        "deployments": ["prod-eu-1"],
        "primitives": ["fairness"],
        "parameter_set_pin": _v2(s).parameter_set_hash,
    }
    assert verify(_v2(s), _policy(_store(s, **ok))).accepted  # control
    r = verify(_v2(s), _policy(_store(s, **{**ok, **over})))
    assert r.trust_status == "INVALID" and reason in _reasons(r)
    assert r.issuer_trusted is False


def test_audit_run_ids_default_to_distinct_uuids():
    s = _signer()
    assert _v2(s, audit_run_id=None).audit_run_id != _v2(s, audit_run_id=None).audit_run_id


# ---------------------------------------------------------------------------
# Legacy v1
# ---------------------------------------------------------------------------


def test_v1_active_key_is_accepted_with_a_legacy_label_in_development():
    s = _signer()
    v1 = rf.envelope("fairness", _report(), signer=s)
    r = verify(v1, _policy(_store(s)))
    assert r.trust_status == "TRUSTED" and r.accepted and r.format == "v1"
    assert "LEGACY_V1_FORMAT" in _reasons(r)
    assert r.chronology == "SIGNER_ASSERTED"


def test_v1_can_be_refused_by_policy():
    s = _signer()
    v1 = rf.envelope("fairness", _report(), signer=s)
    r = verify(v1, _policy(_store(s), allow_legacy_v1=False))
    assert r.trust_status == "INVALID" and "LEGACY_V1_FORMAT" in _reasons(r)
    assert r.issuer_trusted is True  # the issuer is genuine; the policy refused the format


def test_v1_timestamp_never_counts_as_verified_or_authenticated():
    s = _signer()
    tsa = rf.TimestampAuthority(issuer="t", sign_callable=lambda b: b"tok")
    v1 = rf.envelope("fairness", _report(), signer=s, timestamp_authority=tsa)
    verifier, _ = _tsa(NOW - HOUR)
    r = verify(v1, _policy(_store(s), timestamp_verifier=verifier))
    assert r.timestamp_status == "UNVERIFIED" and r.chronology == "SIGNER_ASSERTED"
    assert r.signed_not_after is None
    refused = verify(
        v1, _policy(_store(s), timestamp_verifier=verifier, require_verified_timestamp=True)
    )
    assert refused.trust_status == "INVALID" and "TIMESTAMP_REQUIRED" in _reasons(refused)


@pytest.mark.parametrize(
    "over",
    [
        {"status": "compromised"},
        {"status": "compromised", "compromised_from": "2026-09-15T00:00:00Z"},
    ],
)
def test_v1_from_a_compromised_key_is_always_refused(over):
    s = _signer()
    v1 = rf.envelope("fairness", _report(), signer=s)
    assert verify(v1, _policy(_store(s))).accepted  # control
    r = verify(v1, _policy(_store(s, **over), historical_acceptance="signer-asserted"))
    assert r.trust_status == "INVALID" and not r.accepted


def test_v1_from_a_legacy_revoked_key_is_refused():
    s = _signer()
    v1 = rf.envelope("fairness", _report(), signer=s)
    store = TrustStore.from_dict({"keys": {s.key_id: s.public_key_pem()}, "revoked": [s.key_id]})
    r = verify(v1, _policy(store))
    assert r.trust_status == "INVALID" and r.key_status == "revoked"
    assert "KEY_REVOKED" in _reasons(r)


# ---------------------------------------------------------------------------
# Key lifecycle: retirement
# ---------------------------------------------------------------------------

RETIRED = {"status": "retired", "retired_at": RETIRED_AT.isoformat()}


def test_retired_key_without_chronology_is_refused_by_default():
    s = _signer()
    early = _v2(s, issued_at=RETIRED_AT - timedelta(days=5))
    r = verify(early, _policy(_store(s, **RETIRED)))
    assert r.trust_status == "INVALID" and r.key_status == "retired"
    assert {"KEY_RETIRED_NO_CHRONOLOGY", "TRUST_STORE_FRESHNESS_UNPROVEN"} <= _reasons(r)


def test_retired_key_signer_asserted_is_a_development_only_opt_in():
    s = _signer()
    early = _v2(s, issued_at=RETIRED_AT - timedelta(days=5))
    late = _v2(s, issued_at=RETIRED_AT + timedelta(days=5))
    p = _policy(_store(s, **RETIRED), historical_acceptance="signer-asserted")
    ok = verify(early, p)
    assert ok.trust_status == "TRUSTED" and ok.accepted
    assert ok.chronology == "SIGNER_ASSERTED" and "CHRONOLOGY_UNAUTHENTICATED" in _reasons(ok)
    bad = verify(late, p)
    assert bad.trust_status == "INVALID" and "SIGNED_AFTER_RETIREMENT" in _reasons(bad)


def test_signer_asserted_historical_acceptance_is_refused_outside_development(tmp_path: Path):
    s = _signer()
    with pytest.raises(PolicyError, match="development"):
        VerificationPolicy(
            profile="confidential",
            trust_store=_store(s),
            historical_acceptance="signer-asserted",
            max_age=timedelta(days=30),
            replay_mode="check",
            replay_cache=SqliteReplayCache(tmp_path / "r.db"),
            now=_clock,
        )


def test_retired_key_with_authenticated_chronology_and_fresh_history_is_trusted():
    s = _signer()
    verifier, attach = _tsa(RETIRED_AT - timedelta(days=1))
    env = attach(_v2(s, issued_at=RETIRED_AT - timedelta(days=2)))
    p = _policy(_store(s, **RETIRED), timestamp_verifier=verifier, trust_history=FRESH)
    r = verify(env, p)
    assert r.trust_status == "TRUSTED" and r.accepted
    assert r.chronology == "AUTHENTICATED" and r.timestamp_status == "VERIFIED"
    assert r.signed_not_after == (RETIRED_AT - timedelta(days=1)).isoformat()
    assert r.trust_history == "FRESH"


def test_retired_key_signed_after_retirement_is_refused_even_with_a_valid_token():
    s = _signer()
    verifier, attach = _tsa(RETIRED_AT + timedelta(days=1))
    env = attach(_v2(s, issued_at=RETIRED_AT - timedelta(days=2)))
    r = verify(env, _policy(_store(s, **RETIRED), timestamp_verifier=verifier, trust_history=FRESH))
    assert r.trust_status == "INVALID" and "SIGNED_AFTER_RETIREMENT" in _reasons(r)


@pytest.mark.parametrize(
    "history",
    [
        None,
        TrustHistory(as_of=NOW - HOUR, authenticated=False),
        TrustHistory(as_of=NOW - timedelta(days=30), authenticated=True),
        TrustHistory(as_of=NOW + timedelta(days=1), authenticated=True),
    ],
    ids=["none", "unauthenticated", "stale", "from-the-future"],
)
def test_historical_acceptance_requires_fresh_authenticated_trust_history(history):
    s = _signer()
    verifier, attach = _tsa(RETIRED_AT - timedelta(days=1))
    env = attach(_v2(s, issued_at=RETIRED_AT - timedelta(days=2)))
    good = _policy(_store(s, **RETIRED), timestamp_verifier=verifier, trust_history=FRESH)
    assert verify(env, good).accepted  # control
    r = verify(
        env, _policy(_store(s, **RETIRED), timestamp_verifier=verifier, trust_history=history)
    )
    assert r.trust_status == "INVALID" and "TRUST_STORE_FRESHNESS_UNPROVEN" in _reasons(r)
    assert r.chronology == "AUTHENTICATED"  # the chronology was fine; the history was not


def test_high_assurance_never_accepts_historical_keys_in_phase_3a(tmp_path: Path):
    s = _signer()
    verifier, attach = _tsa(RETIRED_AT - timedelta(days=1))
    env = attach(_v2(s, issued_at=RETIRED_AT - timedelta(days=2), audience=["reg"]))
    r = verify(
        env,
        _policy(
            _store(s, **RETIRED),
            profile="high-assurance",
            timestamp_verifier=verifier,
            trust_history=FRESH,
            max_age=timedelta(days=365),
            verifier_id="reg",
            replay_mode="check",
            replay_cache=SqliteReplayCache(tmp_path / "r.db"),
        ),
    )
    assert r.trust_status == "INVALID" and "TRUST_STORE_FRESHNESS_UNPROVEN" in _reasons(r)


# ---------------------------------------------------------------------------
# Key lifecycle: compromise
# ---------------------------------------------------------------------------

COMPROMISED_KNOWN = {"status": "compromised", "compromised_from": COMPROMISED_FROM.isoformat()}


def test_compromised_known_boundary_with_earlier_authenticated_chronology_is_trusted():
    s = _signer()
    verifier, attach = _tsa(COMPROMISED_FROM - timedelta(days=2), accuracy=timedelta(seconds=1))
    env = attach(_v2(s, issued_at=COMPROMISED_FROM - timedelta(days=3)))
    r = verify(
        env,
        _policy(_store(s, **COMPROMISED_KNOWN), timestamp_verifier=verifier, trust_history=FRESH),
    )
    assert r.trust_status == "TRUSTED" and r.key_status == "compromised"
    assert r.chronology == "AUTHENTICATED"


@pytest.mark.parametrize(
    ("gen_offset", "accuracy", "reason"),
    [
        (timedelta(seconds=0), timedelta(0), "SIGNED_AFTER_COMPROMISE"),  # exactly at the boundary
        (timedelta(days=2), timedelta(0), "SIGNED_AFTER_COMPROMISE"),
        (
            timedelta(seconds=-1),
            timedelta(seconds=5),
            "SIGNED_AFTER_COMPROMISE",
        ),  # accuracy overlaps
    ],
    ids=["at-boundary", "after", "accuracy-overlaps"],
)
def test_compromised_known_boundary_refuses_chronology_not_strictly_earlier(
    gen_offset, accuracy, reason
):
    s = _signer()
    verifier, attach = _tsa(COMPROMISED_FROM + gen_offset, accuracy)
    env = attach(_v2(s, issued_at=COMPROMISED_FROM - timedelta(days=3)))
    r = verify(
        env,
        _policy(_store(s, **COMPROMISED_KNOWN), timestamp_verifier=verifier, trust_history=FRESH),
    )
    assert r.trust_status == "INVALID" and reason in _reasons(r)


def test_compromised_key_ignores_signer_asserted_time_even_in_development():
    s = _signer()
    env = _v2(s, issued_at=COMPROMISED_FROM - timedelta(days=30))  # claims a safe date
    r = verify(
        env,
        _policy(_store(s, **COMPROMISED_KNOWN), historical_acceptance="signer-asserted"),
    )
    assert r.trust_status == "INVALID" and "KEY_COMPROMISED_NO_CHRONOLOGY" in _reasons(r)


def test_compromised_unknown_boundary_rejects_all_even_with_chronology():
    s = _signer()
    verifier, attach = _tsa(datetime(2020, 1, 1, tzinfo=UTC))  # absurdly early, but valid
    env = attach(_v2(s, issued_at=datetime(2020, 1, 1, tzinfo=UTC)))
    r = verify(
        env,
        _policy(_store(s, status="compromised"), timestamp_verifier=verifier, trust_history=FRESH),
    )
    assert r.trust_status == "INVALID" and "KEY_COMPROMISED_NO_CHRONOLOGY" in _reasons(r)


def test_active_key_before_not_before_is_refused():
    s = _signer()
    nb = (ISSUED + timedelta(days=1)).isoformat()
    assert verify(_v2(s), _policy(_store(s))).accepted  # control
    r = verify(_v2(s), _policy(_store(s, not_before=nb)))
    assert r.trust_status == "INVALID" and "KEY_NOT_YET_VALID" in _reasons(r)


# ---------------------------------------------------------------------------
# Timestamp binding
# ---------------------------------------------------------------------------


def test_timestamp_statuses():
    s = _signer()
    verifier, attach = _tsa(NOW - HOUR)
    plain = _v2(s)
    assert verify(plain, _policy(_store(s))).timestamp_status == "ABSENT"
    stamped = attach(plain)
    assert verify(stamped, _policy(_store(s))).timestamp_status == "UNVERIFIED"
    assert (
        verify(stamped, _policy(_store(s), timestamp_verifier=verifier)).timestamp_status
        == "VERIFIED"
    )
    junk = plain.with_timestamp(issuer="t", token=b"junk", issued_at=NOW)
    r = verify(junk, _policy(_store(s), timestamp_verifier=verifier))
    assert r.timestamp_status == "FAILED" and r.trust_status == "INVALID"
    assert "TIMESTAMP_FAILED" in _reasons(r)


def test_one_good_token_outweighs_a_junk_token_anyone_could_attach():
    s = _signer()
    verifier, attach = _tsa(NOW - HOUR)
    env = attach(_v2(s)).with_timestamp(issuer="t", token=b"junk", issued_at=NOW)
    r = verify(env, _policy(_store(s), timestamp_verifier=verifier))
    assert r.timestamp_status == "VERIFIED" and r.trust_status == "TRUSTED"


def test_raising_or_future_dated_verifiers_are_failed_not_verified():
    s = _signer()
    env = _v2(s).with_timestamp(issuer="t", token=b"x", issued_at=NOW)

    def boom(digest, token):
        raise RuntimeError("tsa down")

    assert verify(env, _policy(_store(s), timestamp_verifier=boom)).timestamp_status == "FAILED"
    future, _ = _tsa(NOW + timedelta(days=2))
    env2 = _tsa(NOW + timedelta(days=2))[1](_v2(s))
    r = verify(env2, _policy(_store(s), timestamp_verifier=future))
    assert r.timestamp_status == "FAILED"


def test_require_verified_timestamp_needs_verified_evidence():
    s = _signer()
    verifier, attach = _tsa(NOW - HOUR)
    plain = _v2(s)
    p = _policy(_store(s), timestamp_verifier=verifier, require_verified_timestamp=True)
    assert verify(attach(plain), p).accepted  # control
    for env in (plain, plain.with_timestamp(issuer="t", token=b"junk", issued_at=NOW)):
        r = verify(env, p)
        assert r.trust_status == "INVALID"
        assert _reasons(r) & {"TIMESTAMP_REQUIRED", "TIMESTAMP_FAILED"}
    no_verifier = _policy(_store(s))
    assert verify(attach(plain), no_verifier).accepted  # unverified is fine when not required
    with pytest.raises(PolicyError):
        _policy(_store(s), require_verified_timestamp=True)  # cannot be satisfied: no verifier


def test_a_token_over_a_different_signed_artifact_does_not_verify():
    """The F2 attack: reuse a genuine earlier token with a re-keyed envelope."""
    good, attacker = _signer("acme-1"), _signer("acme-1")  # same key_id, different key
    verifier, attach = _tsa(COMPROMISED_FROM - timedelta(days=2))
    genuine = attach(
        _v2(
            good,
            issued_at=COMPROMISED_FROM - timedelta(days=3),
            audit_run_id="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f7",
        )
    )
    forged = _v2(
        attacker,
        issued_at=COMPROMISED_FROM - timedelta(days=3),
        audit_run_id="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f7",
    )
    forged.timestamps = list(genuine.timestamps)  # steal the old token
    store = TrustStore.from_dict({"entries": {"acme-1": _entry(attacker, **COMPROMISED_KNOWN)}})
    r = verify(forged, _policy(store, timestamp_verifier=verifier, trust_history=FRESH))
    assert r.trust_status == "INVALID" and r.timestamp_status == "FAILED"
    # control: the genuine envelope with the same token would have passed chronology
    genuine_store = TrustStore.from_dict({"entries": {"acme-1": _entry(good, **COMPROMISED_KNOWN)}})
    assert verify(
        genuine, _policy(genuine_store, timestamp_verifier=verifier, trust_history=FRESH)
    ).accepted


# ---------------------------------------------------------------------------
# Audience and freshness
# ---------------------------------------------------------------------------


def test_audience_is_enforced_when_both_sides_name_one():
    s = _signer()
    env = _v2(s, audience=["regulator-a", "regulator-b"])
    assert verify(env, _policy(_store(s), verifier_id="regulator-a")).accepted  # control
    r = verify(env, _policy(_store(s), verifier_id="regulator-z"))
    assert r.trust_status == "INVALID" and "AUDIENCE_MISMATCH" in _reasons(r)
    assert verify(env, _policy(_store(s))).accepted  # development: no verifier id, not enforced


def test_max_age_and_future_dated_reports():
    s = _signer()
    p = _policy(_store(s), max_age=timedelta(days=30))
    assert verify(_v2(s, issued_at=NOW - timedelta(days=29)), p).accepted  # control
    exactly = verify(_v2(s, issued_at=NOW - timedelta(days=30)), p)
    assert exactly.accepted  # boundary is inclusive
    old = verify(_v2(s, issued_at=NOW - timedelta(days=31)), p)
    assert old.trust_status == "INVALID" and "REPORT_TOO_OLD" in _reasons(old)
    future = verify(_v2(s, issued_at=NOW + timedelta(hours=1)), p)
    assert future.trust_status == "INVALID" and "REPORT_FROM_FUTURE" in _reasons(future)


# ---------------------------------------------------------------------------
# Local replay
# ---------------------------------------------------------------------------


def test_replay_modes_and_consumption_labels():
    s = _signer()
    cache = InMemoryReplayCache()
    env = _v2(s)
    off = verify(env, _policy(_store(s)))
    assert off.consumption == "NOT_CHECKED" and off.replay_scope == "NONE"
    check = _policy(_store(s), replay_mode="check", replay_cache=cache)
    for _ in range(2):  # check never records, so it never refuses a first sighting
        r = verify(env, check)
        assert r.accepted and r.consumption == "CHECKED_NOT_CONSUMED"
        assert r.replay_scope == "LOCAL_PROCESS"
    record = _policy(_store(s), replay_mode="record", replay_cache=cache)
    first = verify(env, record)
    assert first.accepted and first.consumption == "RECORDED_LOCAL"
    second = verify(env, record)
    assert second.trust_status == "INVALID" and "REPLAY_DETECTED" in _reasons(second)
    # a later "check" now sees the recorded id too
    assert "REPLAY_DETECTED" in _reasons(verify(env, check))


def test_a_forgery_cannot_burn_a_genuine_audit_run_id():
    s = _signer()
    cache = InMemoryReplayCache()
    record = _policy(_store(s), replay_mode="record", replay_cache=cache)
    run_id = "3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f7"
    forged = _v2(_signer("acme-1"), audit_run_id=run_id)  # same key_id, wrong key
    assert verify(forged, record).trust_status == "INVALID"
    genuine = _v2(s, audit_run_id=run_id)
    assert verify(genuine, record).accepted  # control: the id was not burned


def test_replay_ids_are_scoped_by_key_id():
    a, b = _signer("acme-1"), _signer("acme-2")
    store = TrustStore.from_dict({"entries": {"acme-1": _entry(a), "acme-2": _entry(b)}})
    cache = InMemoryReplayCache()
    record = _policy(store, replay_mode="record", replay_cache=cache)
    run_id = "3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f7"
    assert verify(_v2(a, audit_run_id=run_id), record).accepted
    assert verify(_v2(b, audit_run_id=run_id), record).accepted


def test_replay_failure_fails_open_only_in_development():
    s = _signer()

    class Broken:
        scope = "LOCAL_PROCESS"

        def seen(self, *a, **k):
            raise ReplayStateError("down")

        def record(self, *a, **k):
            raise ReplayStateError("down")

    dev = verify(_v2(s), _policy(_store(s), replay_mode="record", replay_cache=Broken()))
    assert dev.accepted and dev.consumption == "NOT_CHECKED"
    assert "REPLAY_STATE_UNAVAILABLE" in _reasons(dev)


def test_replay_cache_exceptions_of_any_type_do_not_escape(tmp_path: Path):
    s = _signer()

    class Weird:
        scope = "LOCAL_PERSISTENT"

        def seen(self, *a, **k):
            raise ValueError("boom")

        def record(self, *a, **k):
            raise ValueError("boom")

    policy = _confidential(_store(s), tmp_path, replay_cache=Weird(), verifier_id="reg")
    r = verify(_v2(s, audience=["reg"]), policy)
    assert r.trust_status == "INVALID" and "REPLAY_STATE_UNAVAILABLE" in _reasons(r)


def test_concurrent_verification_of_one_report_is_accepted_exactly_once():
    s = _signer()
    cache = InMemoryReplayCache()
    policy = _policy(_store(s), replay_mode="record", replay_cache=cache)
    env = _v2(s)
    outcomes: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        accepted = verify(env, policy).accepted
        with lock:
            outcomes.append(accepted)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1


# ---------------------------------------------------------------------------
# Profiles and policy validation
# ---------------------------------------------------------------------------


def _confidential(store, tmp_path: Path, **over) -> VerificationPolicy:
    args = dict(
        profile="confidential",
        trust_store=store,
        max_age=timedelta(days=60),
        replay_mode="record",
        replay_cache=SqliteReplayCache(tmp_path / "replay.db"),
        now=_clock,
    )
    args.update(over)
    return VerificationPolicy(**args)


def test_confidential_profile_accepts_an_active_key_report(tmp_path: Path):
    s = _signer()
    p = _confidential(_store(s), tmp_path, verifier_id="reg")
    r = verify(_v2(s, audience=["reg"]), p)
    assert r.trust_status == "TRUSTED" and r.accepted
    assert r.replay_scope == "LOCAL_PERSISTENT" and r.consumption == "RECORDED_LOCAL"
    assert r.policy_id == "regaudit-fhe/confidential/v1"


def test_confidential_requires_an_audience_match_when_the_report_names_one(tmp_path: Path):
    s = _signer()
    p = _confidential(_store(s), tmp_path)  # no verifier id configured
    r = verify(_v2(s, audience=["reg"]), p)
    assert r.trust_status == "INVALID" and "AUDIENCE_MISMATCH" in _reasons(r)
    assert verify(_v2(s), _confidential(_store(s), tmp_path)).accepted  # control: no audience named


def test_confidential_replay_failure_is_fail_closed(tmp_path: Path):
    s = _signer()

    class Down:
        scope = "LOCAL_PERSISTENT"

        def seen(self, *a, **k):
            raise ReplayStateError("down")

        def record(self, *a, **k):
            raise ReplayStateError("down")

    r = verify(_v2(s), _confidential(_store(s), tmp_path, replay_cache=Down()))
    assert r.trust_status == "INVALID" and "REPLAY_STATE_UNAVAILABLE" in _reasons(r)


def test_confidential_cannot_replay_check_a_v1_report(tmp_path: Path):
    s = _signer()
    v1 = rf.envelope("fairness", _report(), signer=s)  # stamped with the real clock
    real_clock = {"now": lambda: datetime.now(UTC)}
    ok = verify(v1, _confidential(_store(s), tmp_path, **real_clock, replay_mode="check"))
    assert "REPLAY_ID_MISSING" in _reasons(ok)
    r = verify(v1, _confidential(_store(s), tmp_path, **real_clock))
    assert r.trust_status == "INVALID" and "REPLAY_ID_MISSING" in _reasons(r)


def test_high_assurance_refuses_v1_by_default_and_requires_an_audience(tmp_path: Path):
    s = _signer()

    def ha(**over):
        args = dict(
            profile="high-assurance",
            trust_store=_store(s),
            max_age=timedelta(days=60),
            verifier_id="reg",
            replay_mode="record",
            replay_cache=SqliteReplayCache(tmp_path / f"ha-{len(over)}-{id(over)}.db"),
            now=_clock,
        )
        args.update(over)
        return VerificationPolicy(**args)

    ok = verify(_v2(s, audience=["reg"]), ha())
    assert ok.trust_status == "TRUSTED"  # control
    no_aud = verify(_v2(s), ha())
    assert no_aud.trust_status == "INVALID" and "AUDIENCE_MISMATCH" in _reasons(no_aud)
    v1 = rf.envelope("fairness", _report(), signer=s)
    assert "LEGACY_V1_FORMAT" in _reasons(verify(v1, ha()))
    assert verify(v1, ha()).trust_status == "INVALID"


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"profile": "prod"}, "profile"),
        ({"profile": "confidential", "trust_store": None}, "trust store"),
        ({"allow_self_signed": True, "profile": "confidential"}, "development"),
        ({"allow_self_signed": True, "profile": "high-assurance"}, "development"),
        ({"max_age": timedelta(0)}, "max_age"),
        ({"clock_skew": timedelta(seconds=-1)}, "clock_skew"),
        ({"replay_mode": "record"}, "replay_cache"),
        ({"replay_mode": "sometimes"}, "replay_mode"),
        ({"historical_acceptance": "whenever"}, "historical_acceptance"),
        ({"trust_history_max_age": timedelta(0)}, "trust_history_max_age"),
    ],
)
def test_policy_validation_refuses_unsafe_configurations(kwargs, match):
    s = _signer()
    base = {"trust_store": _store(s), "now": _clock}
    assert VerificationPolicy(**base)  # control
    with pytest.raises(PolicyError, match=match):
        VerificationPolicy(**{**base, **kwargs})


def test_confidential_policy_needs_max_age_and_a_persistent_replay_cache(tmp_path: Path):
    s = _signer()
    good = dict(
        profile="confidential",
        trust_store=_store(s),
        max_age=timedelta(days=30),
        replay_mode="record",
        replay_cache=SqliteReplayCache(tmp_path / "r.db"),
        now=_clock,
    )
    assert VerificationPolicy(**good)  # control
    for key, value, match in (
        ("max_age", None, "max_age"),
        ("replay_mode", "off", "replay"),
        ("replay_cache", InMemoryReplayCache(), "persistent"),
        ("replay_cache", None, "replay"),
    ):
        with pytest.raises(PolicyError, match=match):
            VerificationPolicy(**{**good, key: value})
    with pytest.raises(PolicyError, match="verifier_id"):
        VerificationPolicy(**{**good, "profile": "high-assurance"})


def test_policy_error_is_a_runtime_error():
    assert issubclass(PolicyError, RuntimeError)


# ---------------------------------------------------------------------------
# Result contract and `valid` deprecation
# ---------------------------------------------------------------------------


def test_result_to_dict_has_the_authoritative_fields_and_no_warning():
    s = _signer()
    r = verify(_v2(s), _policy(_store(s)))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        d = r.to_dict()
    for key in (
        "trust_status",
        "accepted",
        "integrity_valid",
        "issuer_trusted",
        "key_status",
        "chronology",
        "signed_not_after",
        "timestamp_status",
        "reasons",
        "policy_id",
        "replay_scope",
        "consumption",
        "trust_history",
        "format",
        "valid",
    ):
        assert key in d, key
    assert d["valid"] == d["accepted"]
    assert isinstance(d["reasons"], list)


def test_valid_is_deprecated_but_preserved():
    s = _signer()
    r = verify(_v2(s), _policy(_store(s)))
    with pytest.warns(DeprecationWarning, match="accepted"):
        assert r.valid is True
    refused = verify(_v2(_signer("zz")), _policy(_store(s)))
    with pytest.warns(DeprecationWarning):
        assert refused.valid is False


def test_accepted_is_true_only_for_trusted():
    s = _signer()
    cases = [
        verify(_v2(s), _policy(_store(s))),
        verify(_v2(s), VerificationPolicy(allow_self_signed=True, now=_clock)),
        verify(_v2(_signer("q")), _policy(_store(s))),
    ]
    for r in cases:
        assert r.accepted == (r.trust_status == "TRUSTED")
    assert [r.trust_status for r in cases] == ["TRUSTED", "SELF_SIGNED_ONLY", "INVALID"]


# ---------------------------------------------------------------------------
# Security review findings (round 2)
# ---------------------------------------------------------------------------


def test_unparseable_issued_at_is_refused_even_without_max_age():
    s = _signer()
    v1 = rf.envelope("fairness", _report(), signer=s)
    store = _store(s, not_before=(ISSUED - timedelta(days=400)).isoformat())
    assert verify(v1, _policy(store, now=lambda: datetime.now(UTC))).accepted  # control
    v1.issued_at = "garbage"
    r = verify(v1, _policy(store, now=lambda: datetime.now(UTC)))
    assert r.trust_status == "INVALID" and "MALFORMED_ENVELOPE" in _reasons(r)


def test_replay_enabled_implies_a_maximum_age_so_ids_cannot_outlive_their_retention():
    s = _signer()
    cache = InMemoryReplayCache()
    p = _policy(_store(s), replay_mode="record", replay_cache=cache)  # no explicit max_age
    assert verify(_v2(s, issued_at=NOW - timedelta(days=29)), p).accepted  # control
    r = verify(_v2(s, issued_at=NOW - timedelta(days=40)), p)
    assert r.trust_status == "INVALID" and "REPORT_TOO_OLD" in _reasons(r)


def test_replay_retention_covers_a_future_dated_report_to_the_last_instant():
    s = _signer()
    cache = InMemoryReplayCache()
    skew = timedelta(minutes=5)
    max_age = timedelta(days=1)
    p = _policy(
        _store(s), replay_mode="record", replay_cache=cache, max_age=max_age, clock_skew=skew
    )
    env = _v2(s, issued_at=NOW + skew)  # as far in the future as is tolerated
    assert verify(env, p).accepted
    # the instant the report stops being fresh, the id must still be remembered
    last_fresh = NOW + skew + max_age
    assert cache.seen("acme-1", env.audit_run_id, now=last_fresh)


def test_chronology_is_not_reported_for_an_unauthenticated_issuer():
    s = _signer()
    other = _signer("unknown-key")
    verifier, attach = _tsa(NOW - HOUR)
    env = attach(_v2(other))
    r = verify(env, _policy(_store(s), timestamp_verifier=verifier))
    assert r.trust_status == "INVALID" and "ISSUER_UNKNOWN" in _reasons(r)
    assert r.chronology == "NONE" and r.signed_not_after is None
    ok = verify(attach(_v2(s)), _policy(_store(s), timestamp_verifier=verifier))
    assert ok.chronology == "AUTHENTICATED" and ok.signed_not_after is not None  # control
