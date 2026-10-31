"""Qualification of the local trust-lifecycle commands (0.3.0 candidate).

Synthetic keys only. Three things are pinned here:

* the state-transition matrix of ``retire`` / ``revoke`` (state x command -> result/refusal);
* the verification-outcome matrix (key state x issue time vs boundary x profile x evidence),
  derived from ``docs/TRUST_SPEC.md`` section 4 independently of the engine, run against
  stores that the lifecycle commands themselves produced;
* file-level behaviour: permissions, symlinks, malformed/oversized input, migration forms.

The store is an unauthenticated local file. Nothing here claims authoritative revocation.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import regaudit_fhe as rf
from regaudit_fhe import _trust_lifecycle as lc
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.trust import MAX_TRUST_STORE_BYTES, TrustStore, TrustStoreError
from regaudit_fhe.verification import (
    TimestampEvidence,
    TrustHistory,
    VerificationPolicy,
    verify,
)

UTC = timezone.utc
NOW = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
ISSUED = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
DAY = timedelta(days=1)
FRESH = TrustHistory(as_of=NOW - timedelta(hours=1), authenticated=True)
STALE = TrustHistory(as_of=NOW - timedelta(days=3), authenticated=True)
UNAUTH = TrustHistory(as_of=NOW - timedelta(hours=1), authenticated=False)


def _pem() -> str:
    return (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def _two_key_store(tmp_path: Path, name: str = "store.json") -> Path:
    path = tmp_path / name
    entries = {
        k: {"issuer": "acme", "public_key_pem": _pem(), "status": "active"} for k in ("a-1", "b-1")
    }
    path.write_text(json.dumps({"entries": entries}, indent=2) + "\n")
    return path


def _entry(path: Path, key_id: str) -> dict:
    return json.loads(path.read_text())["entries"][key_id]


# ============================================================================
# 1. State-transition matrix (state x command -> result / refusal)
# ============================================================================

R = "2026-10-01T00:00:00Z"
C_EARLY = "2026-09-15T00:00:00Z"
C_LATE = "2026-10-05T00:00:00Z"


def _put_in_state(path: Path, state: str) -> None:
    if state == "retired":
        lc.retire(str(path), "a-1", at=R, now=NOW)
    elif state == "compromised-unknown":
        lc.revoke(str(path), "a-1", compromised_from=None, now=NOW)
    elif state == "compromised-bounded":
        lc.revoke(str(path), "a-1", compromised_from=C_EARLY, now=NOW)
    else:
        assert state == "active"


# (state, command kwargs, expected final (status, retired_at, compromised_from) or None=refused)
TRANSITIONS = [
    ("active", ("retire", {"at": R}), ("retired", R, None)),
    ("active", ("retire", {"at": None}), ("retired", "2026-10-10T12:00:00Z", None)),
    ("active", ("revoke", {"compromised_from": C_EARLY}), ("compromised", None, C_EARLY)),
    ("active", ("revoke", {"compromised_from": None}), ("compromised", None, None)),
    ("retired", ("retire", {"at": R}), None),  # no re-retire
    ("retired", ("retire", {"at": "2026-09-01T00:00:00Z"}), None),  # no re-dating, earlier either
    ("retired", ("revoke", {"compromised_from": C_EARLY}), ("compromised", None, C_EARLY)),
    ("retired", ("revoke", {"compromised_from": R}), ("compromised", None, R)),  # == retired_at ok
    ("retired", ("revoke", {"compromised_from": C_LATE}), None),  # would loosen
    ("retired", ("revoke", {"compromised_from": None}), ("compromised", None, None)),
    ("compromised-unknown", ("retire", {"at": None}), None),
    ("compromised-unknown", ("revoke", {"compromised_from": C_EARLY}), None),  # no edit boundary
    ("compromised-unknown", ("revoke", {"compromised_from": None}), None),
    ("compromised-bounded", ("retire", {"at": None}), None),
    ("compromised-bounded", ("revoke", {"compromised_from": "2026-09-01T00:00:00Z"}), None),
    ("compromised-bounded", ("revoke", {"compromised_from": None}), None),  # no widening either
]


@pytest.mark.parametrize(("state", "command", "expected"), TRANSITIONS)
def test_state_transition_matrix(tmp_path, state, command, expected):
    path = _two_key_store(tmp_path)
    _put_in_state(path, state)
    other_before = _entry(path, "b-1")
    snapshot = path.read_bytes()
    prev_before = (
        Path(str(path) + ".prev").read_bytes() if Path(str(path) + ".prev").exists() else None
    )
    name, kwargs = command
    fn = lc.retire if name == "retire" else lc.revoke
    if expected is None:
        with pytest.raises(lc.LifecycleRefused):
            fn(str(path), "a-1", now=NOW, **kwargs)
        assert path.read_bytes() == snapshot  # refusal writes nothing
        prev_after = (
            Path(str(path) + ".prev").read_bytes() if Path(str(path) + ".prev").exists() else None
        )
        assert prev_after == prev_before
        return
    fn(str(path), "a-1", now=NOW, **kwargs)
    e = _entry(path, "a-1")
    assert (e["status"], e.get("retired_at"), e.get("compromised_from")) == expected
    assert _entry(path, "b-1") == other_before  # a bystander key is byte-for-byte unchanged
    TrustStore.from_json(str(path))  # still a valid store


@pytest.mark.parametrize("cmd", ["retire", "revoke"])
def test_unknown_key_refused_for_both_commands(tmp_path, cmd):
    path = _two_key_store(tmp_path)
    before = path.read_bytes()
    fn = lc.retire if cmd == "retire" else lc.revoke
    kwargs = {"at": None} if cmd == "retire" else {"compromised_from": None}
    with pytest.raises(lc.LifecycleRefused, match="not in the trust store"):
        fn(str(path), "ghost", now=NOW, **kwargs)
    assert path.read_bytes() == before and not Path(str(path) + ".prev").exists()


def test_key_id_is_matched_exactly_not_by_prefix_or_case(tmp_path):
    path = _two_key_store(tmp_path)
    for bad in ("A-1", "a-", "a-1 ", "a-1\n", ""):
        with pytest.raises(lc.LifecycleRefused):
            lc.retire(str(path), bad, at=None, now=NOW)
    assert _entry(path, "a-1")["status"] == "active"


def test_naive_clock_refused(tmp_path):
    path = _two_key_store(tmp_path)
    with pytest.raises(lc.LifecycleRefused, match="timezone"):
        lc.retire(str(path), "a-1", at=None, now=datetime(2026, 10, 10, 12, 0))


def test_boundary_exactly_at_future_skew_is_accepted_beyond_is_refused(tmp_path):
    path = _two_key_store(tmp_path)
    ok = (NOW + lc.FUTURE_SKEW).isoformat().replace("+00:00", "Z")
    lc.retire(str(path), "a-1", at=ok, now=NOW)
    over = (NOW + lc.FUTURE_SKEW + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    with pytest.raises(lc.LifecycleRefused, match="future"):
        lc.revoke(str(path), "b-1", compromised_from=over, now=NOW)


def test_boundary_with_offset_is_normalised_to_utc(tmp_path):
    path = _two_key_store(tmp_path)
    lc.retire(str(path), "a-1", at="2026-10-01T02:00:00+02:00", now=NOW)
    assert _entry(path, "a-1")["retired_at"] == "2026-10-01T00:00:00Z"


def test_retire_equal_to_not_before_is_allowed_earlier_is_not(tmp_path):
    path = _two_key_store(tmp_path)
    data = json.loads(path.read_text())
    data["entries"]["a-1"]["not_before"] = "2026-06-01T00:00:00Z"
    path.write_text(json.dumps(data))
    with pytest.raises(lc.LifecycleRefused, match="not_before"):
        lc.retire(str(path), "a-1", at="2026-05-31T23:59:59Z", now=NOW)
    lc.retire(str(path), "a-1", at="2026-06-01T00:00:00Z", now=NOW)


def test_as_of_equal_to_future_skew_allowed_beyond_refused(tmp_path):
    path = _two_key_store(tmp_path)
    lc.retire(str(path), "a-1", at=None, now=NOW + lc.FUTURE_SKEW)
    lc.revoke(str(path), "b-1", compromised_from=None, now=NOW)  # exactly at the skew
    path2 = _two_key_store(tmp_path, "s2.json")
    lc.retire(str(path2), "a-1", at=None, now=NOW + lc.FUTURE_SKEW + timedelta(seconds=1))
    with pytest.raises(lc.LifecycleRefused, match="as_of"):
        lc.revoke(str(path2), "b-1", compromised_from=None, now=NOW)


def test_result_reports_before_after_and_digest(tmp_path):
    import hashlib

    path = _two_key_store(tmp_path)
    res = lc.retire(str(path), "a-1", at=R, now=NOW)
    assert res["before"] == {"status": "active", "retired_at": None, "compromised_from": None}
    assert res["after"] == {"status": "retired", "retired_at": R, "compromised_from": None}
    assert res["store_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert res["backup"] == str(path) + ".prev" and res["key_id"] == "a-1"


def test_status_rows_fields(tmp_path):
    path = _two_key_store(tmp_path)
    lc.retire(str(path), "a-1", at=R, now=NOW)
    lc.revoke(str(path), "b-1", compromised_from=C_EARLY, now=NOW)
    out = lc.status_rows(str(path))
    rows = {r["key_id"]: r for r in out["keys"]}
    assert rows["a-1"]["status"] == "retired" and rows["a-1"]["retired_at"] == R
    assert rows["a-1"]["compromised_from"] is None
    assert rows["b-1"]["status"] == "compromised" and rows["b-1"]["compromised_from"] == C_EARLY
    assert rows["b-1"]["retired_at"] is None
    assert len(rows["a-1"]["fingerprint_sha256"]) == 64
    assert out["as_of"] == "2026-10-10T12:00:00Z" and out["authenticated"] is False
    only = lc.status_rows(str(path), "b-1")
    assert [r["key_id"] for r in only["keys"]] == ["b-1"]
    assert out["store_mode"] == "0644" and out["warnings"] == []


# ============================================================================
# 2. Verification-outcome matrix on stores produced by the lifecycle commands
# ============================================================================

PROFILES = ["development", "confidential", "high-assurance"]
VERIFIER = "reg-1"
BOUNDARY = datetime(2026, 9, 15, tzinfo=UTC)


def _build_store(tmp_path: Path, signer: rf.Signer, state: str) -> TrustStore:
    path = tmp_path / "matrix-store.json"
    entry = {"issuer": signer.issuer, "public_key_pem": signer.public_key_pem(), "status": "active"}
    path.write_text(json.dumps({"entries": {signer.key_id: entry}}))
    stamp = BOUNDARY.isoformat().replace("+00:00", "Z")
    if state == "retired":
        lc.retire(str(path), signer.key_id, at=stamp, now=NOW)
    elif state == "compromised-bounded":
        lc.revoke(str(path), signer.key_id, compromised_from=stamp, now=NOW)
    elif state == "compromised-unknown":
        lc.revoke(str(path), signer.key_id, compromised_from=None, now=NOW)
    elif state == "unknown":
        path.write_text(
            json.dumps(
                {"entries": {"someone-else": {**entry, "public_key_pem": _pem(), "issuer": "x"}}}
            )
        )
    return TrustStore.from_json(str(path))


def _report():
    import numpy as np

    return rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))


def _tsa(gen: datetime):
    def verifier(digest: bytes, token: bytes):
        return TimestampEvidence(gen, timedelta(0)) if token == b"ok:" + digest else None

    return verifier


def _policy(store, profile, tmp_path, **kw):
    args: dict = {"trust_store": store, "now": lambda: NOW, "profile": profile}
    if profile != "development":
        args.update(
            max_age=timedelta(days=90),
            replay_mode="record",
            replay_cache=SqliteReplayCache(tmp_path / "replay.db"),
            verifier_id=VERIFIER,
        )
    args.update(kw)
    return VerificationPolicy(**args)


def _expected(state, when, profile, evidence, mode):
    """Spec section 4, written independently of verification.py.

    ``when``: 'before' | 'after' (timestamp genTime relative to the boundary);
    ``evidence``: 'none' | 'ts' | 'ts+fresh' | 'ts+stale' | 'ts+unauth';
    ``mode``: 'auth' (default) | 'asserted' (development signer-asserted historical acceptance).
    Returns (accepted, one required blocking code or None).
    """
    if state == "unknown":
        return False, "ISSUER_UNKNOWN"
    if state == "active":
        return True, None
    if state == "compromised-unknown":
        return False, "KEY_COMPROMISED_NO_CHRONOLOGY"
    has_ts = evidence != "none"
    fresh_history = evidence == "ts+fresh" and profile != "high-assurance"
    after_code = "SIGNED_AFTER_RETIREMENT" if state == "retired" else "SIGNED_AFTER_COMPROMISE"
    none_code = (
        "KEY_RETIRED_NO_CHRONOLOGY" if state == "retired" else "KEY_COMPROMISED_NO_CHRONOLOGY"
    )
    if state == "retired" and mode == "asserted":
        # signer-asserted: issued_at is what counts (the matrix signs with issued_at = `when`)
        return (when == "before"), (None if when == "before" else after_code)
    if not has_ts:
        return False, none_code
    if when == "after":
        return False, after_code
    if not fresh_history:
        return False, "TRUST_STORE_FRESHNESS_UNPROVEN"
    return True, None


MATRIX = []
for _state in ("active", "retired", "compromised-bounded", "compromised-unknown", "unknown"):
    for _when in ("before", "after"):
        for _prof in PROFILES:
            for _ev in ("none", "ts", "ts+fresh", "ts+stale", "ts+unauth"):
                MATRIX.append((_state, _when, _prof, _ev))


@pytest.mark.parametrize(("state", "when", "profile", "evidence"), MATRIX)
def test_verification_outcome_matrix(tmp_path, state, when, profile, evidence):
    signer = rf.Signer.generate(issuer="acme", key_id="acme-1")
    store = _build_store(tmp_path, signer, state)
    gen = BOUNDARY - 5 * DAY if when == "before" else BOUNDARY + 5 * DAY
    env = envelope_v2(
        "drift",
        _report(),
        signer=signer,
        deployment_id="prod-1",
        audience=[VERIFIER],
        issued_at=min(gen, ISSUED),
    )
    kw: dict = {}
    if evidence != "none":
        env = env.with_timestamp(issuer="t", token=b"ok:" + env.sealed_digest(), issued_at=gen)
        kw["timestamp_verifier"] = _tsa(gen)
        kw["trust_history"] = {"ts+fresh": FRESH, "ts+stale": STALE, "ts+unauth": UNAUTH}.get(
            evidence
        )
    result = verify(env, _policy(store, profile, tmp_path, **kw))
    accepted, code = _expected(state, when, profile, evidence, "auth")
    assert result.accepted is accepted, (result.blocking_reasons, result.reasons)
    if code is not None:
        assert code in result.blocking_reasons, result.blocking_reasons
    assert result.key_status == {"unknown": "unknown", "compromised-bounded": "compromised",
                                 "compromised-unknown": "compromised"}.get(state, state)  # fmt: skip


@pytest.mark.parametrize("state", ["retired", "compromised-bounded", "compromised-unknown"])
@pytest.mark.parametrize("when", ["before", "after"])
def test_development_signer_asserted_acceptance(tmp_path, state, when):
    """Only a retired key can use signer-asserted time; a compromised key never can."""
    signer = rf.Signer.generate(issuer="acme", key_id="acme-1")
    store = _build_store(tmp_path, signer, state)
    issued = BOUNDARY - 5 * DAY if when == "before" else BOUNDARY + 5 * DAY
    env = envelope_v2("drift", _report(), signer=signer, deployment_id="p", issued_at=issued)
    pol = VerificationPolicy(
        trust_store=store, now=lambda: NOW, historical_acceptance="signer-asserted"
    )
    result = verify(env, pol)
    if state == "retired":
        assert result.accepted is (when == "before")
        if when == "before":
            assert "CHRONOLOGY_UNAUTHENTICATED" in result.reasons
            assert result.chronology == "SIGNER_ASSERTED"
    else:
        assert result.accepted is False
        assert "KEY_COMPROMISED_NO_CHRONOLOGY" in result.blocking_reasons


@pytest.mark.parametrize("profile", ["confidential", "high-assurance"])
def test_signer_asserted_acceptance_is_refused_outside_development(tmp_path, profile):
    signer = rf.Signer.generate(issuer="acme", key_id="acme-1")
    store = _build_store(tmp_path, signer, "retired")
    with pytest.raises(Exception, match="development"):
        _policy(store, profile, tmp_path, historical_acceptance="signer-asserted")


def test_no_retroactive_invalidation_by_local_edit_alone(tmp_path):
    """Lifecycle sequence: sign, timestamp, retire later, revoke later with a later boundary.

    Authentic history stays acceptable (under the chronology + fresh-history rules) after
    retirement and after a revoke whose boundary is after the timestamp, and is refused
    once the boundary is moved before the timestamp. The command never rewrites a report.
    """
    signer = rf.Signer.generate(issuer="acme", key_id="acme-1")
    path = tmp_path / "s.json"
    path.write_text(
        json.dumps(
            {
                "entries": {
                    "acme-1": {
                        "issuer": "acme",
                        "public_key_pem": signer.public_key_pem(),
                        "status": "active",
                    }
                }
            }
        )
    )
    signed = datetime(2026, 9, 1, tzinfo=UTC)
    env = envelope_v2("drift", _report(), signer=signer, deployment_id="p", issued_at=signed)
    env = env.with_timestamp(issuer="t", token=b"ok:" + env.sealed_digest(), issued_at=signed)
    kw = {"timestamp_verifier": _tsa(signed), "trust_history": FRESH}

    def accepted() -> tuple[bool, tuple[str, ...]]:
        r = verify(env, VerificationPolicy(trust_store=TrustStore.from_json(str(path)),
                                           now=lambda: NOW, **kw))  # fmt: skip
        return r.accepted, tuple(r.blocking_reasons)

    assert accepted() == (True, ())
    lc.retire(str(path), "acme-1", at="2026-09-10T00:00:00Z", now=NOW)
    assert accepted() == (True, ())  # signed before retirement: still acceptable history
    lc.revoke(str(path), "acme-1", compromised_from="2026-09-05T00:00:00Z", now=NOW)
    assert accepted() == (True, ())  # boundary after the timestamp: still acceptable history

    path2 = tmp_path / "s2.json"
    path2.write_bytes(Path(str(path) + ".prev").read_bytes())  # the retired-only copy
    lc.revoke(str(path2), "acme-1", compromised_from="2026-08-01T00:00:00Z", now=NOW)
    ok, why = verify_with(path2, env, kw)
    assert not ok and "SIGNED_AFTER_COMPROMISE" in why
    path3 = tmp_path / "s3.json"
    path3.write_bytes(path2.read_bytes())
    # the same sign/verify pair, revoked with unknown boundary, is refused outright
    p4 = tmp_path / "s4.json"
    p4.write_bytes(Path(str(path2) + ".prev").read_bytes())
    lc.revoke(str(p4), "acme-1", compromised_from=None, now=NOW)
    ok, why = verify_with(p4, env, kw)
    assert not ok and "KEY_COMPROMISED_NO_CHRONOLOGY" in why


def verify_with(path: Path, env, kw) -> tuple[bool, tuple[str, ...]]:
    r = verify(
        env,
        VerificationPolicy(trust_store=TrustStore.from_json(str(path)), now=lambda: NOW, **kw),
    )
    return r.accepted, tuple(r.blocking_reasons)


def test_rotation_new_key_id_and_old_retired(tmp_path):
    """Rotation: both keys live in the store under distinct key_ids; each report names its own."""
    old = rf.Signer.generate(issuer="acme", key_id="acme-2026a")
    new = rf.Signer.generate(issuer="acme", key_id="acme-2026b")
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"entries": {
        s.key_id: {"issuer": "acme", "public_key_pem": s.public_key_pem(), "status": "active"}
        for s in (old, new)}}))  # fmt: skip
    lc.retire(str(path), "acme-2026a", at="2026-10-01T00:00:00Z", now=NOW)
    store = TrustStore.from_json(str(path))
    pol = VerificationPolicy(trust_store=store, now=lambda: NOW)
    e_new = envelope_v2("drift", _report(), signer=new, deployment_id="p", issued_at=ISSUED)
    assert verify(e_new, pol).accepted
    e_old = envelope_v2("drift", _report(), signer=old, deployment_id="p", issued_at=ISSUED)
    assert not verify(e_old, pol).accepted  # retired old key: no chronology evidence -> refused
    # a DIFFERENT key presented under the retired key_id is not treated as the old key
    impostor = rf.Signer.generate(issuer="acme", key_id="acme-2026a")
    e_imp = envelope_v2("drift", _report(), signer=impostor, deployment_id="p", issued_at=ISSUED)
    r = verify(e_imp, pol)
    assert not r.accepted and "KEY_EMBEDDED_MISMATCH" in r.blocking_reasons
    # nor is the new key accepted under a key_id that was never enrolled for it
    other = rf.Signer.generate(issuer="acme", key_id="acme-2026c")
    e_other = envelope_v2("drift", _report(), signer=other, deployment_id="p", issued_at=ISSUED)
    assert "ISSUER_UNKNOWN" in verify(e_other, pol).blocking_reasons


def test_key_material_and_other_entries_untouched_by_every_transition(tmp_path):
    path = _two_key_store(tmp_path)
    before = json.loads(path.read_text())["entries"]
    lc.retire(str(path), "a-1", at=R, now=NOW)
    lc.revoke(str(path), "a-1", compromised_from=C_EARLY, now=NOW)
    after = json.loads(path.read_text())["entries"]
    assert after["a-1"]["public_key_pem"] == before["a-1"]["public_key_pem"]
    assert after["a-1"]["issuer"] == before["a-1"]["issuer"]
    assert set(after) == set(before)  # nothing is ever deleted


# ============================================================================
# 3. Files: permissions, symlinks, malformed, oversized, migration forms
# ============================================================================


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644, 0o664, 0o400, 0o444])
def test_store_and_backup_keep_exactly_the_original_mode(tmp_path, mode):
    path = _two_key_store(tmp_path)
    os.chmod(path, mode)
    old_umask = os.umask(0o077)  # a hostile umask must not narrow the result
    try:
        lc.retire(str(path), "a-1", at=None, now=NOW)
        lc.revoke(str(path), "b-1", compromised_from=None, now=NOW)
    finally:
        os.umask(old_umask)
    prev = Path(str(path) + ".prev")
    assert stat.S_IMODE(path.stat().st_mode) == mode
    assert stat.S_IMODE(prev.stat().st_mode) == mode


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_permissive_umask_does_not_widen(tmp_path):
    path = _two_key_store(tmp_path)
    os.chmod(path, 0o600)
    old = os.umask(0)
    try:
        lc.retire(str(path), "a-1", at=None, now=NOW)
    finally:
        os.umask(old)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(Path(str(path) + ".prev").stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_world_writable_store_warns_but_is_still_edited_with_same_mode(tmp_path):
    path = _two_key_store(tmp_path)
    os.chmod(path, 0o666)  # noqa: S103 - the test needs a world-writable store
    res = lc.retire(str(path), "a-1", at=None, now=NOW)
    assert res["warnings"] and "0666" in res["warnings"][0]
    assert stat.S_IMODE(path.stat().st_mode) == 0o666  # reported, not silently "fixed"
    assert lc.status_rows(str(path))["warnings"]


def test_trust_add_then_lifecycle_keeps_trust_add_mode(tmp_path):
    path = _two_key_store(tmp_path)
    os.chmod(path, 0o644)  # what 'trust add' writes
    lc.retire(str(path), "a-1", at=None, now=NOW)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_no_temp_files_remain_after_success_or_refusal(tmp_path):
    path = _two_key_store(tmp_path)
    lc.retire(str(path), "a-1", at=None, now=NOW)
    with pytest.raises(lc.LifecycleRefused):
        lc.retire(str(path), "a-1", at=None, now=NOW)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["store.json", "store.json.prev"]


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
def test_symlinked_store_is_edited_through_the_link(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real = _two_key_store(real_dir, "trust.json")
    link = tmp_path / "link.json"
    link.symlink_to(real)
    lc.retire(str(link), "a-1", at=None, now=NOW)
    assert link.is_symlink() and os.path.realpath(link) == str(real.resolve())
    assert _entry(real, "a-1")["status"] == "retired"
    assert (real_dir / "trust.json.prev").exists() and not (tmp_path / "link.json.prev").exists()
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".trust-")]
    assert not [p for p in real_dir.iterdir() if p.name.startswith(".trust-")]
    assert lc.status_rows(str(link))["keys"][0]["status"] == "retired"


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
def test_chain_of_symlinks_and_relative_link(tmp_path):
    real = _two_key_store(tmp_path, "trust.json")
    (tmp_path / "l1").symlink_to("trust.json")
    (tmp_path / "l2").symlink_to("l1")
    lc.revoke(str(tmp_path / "l2"), "b-1", compromised_from=None, now=NOW)
    assert (tmp_path / "l2").is_symlink() and (tmp_path / "l1").is_symlink()
    assert _entry(real, "b-1")["status"] == "compromised"


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
def test_dangling_and_looping_symlinks_refused(tmp_path):
    (tmp_path / "dangling").symlink_to(tmp_path / "nowhere")
    (tmp_path / "loop1").symlink_to("loop2")
    (tmp_path / "loop2").symlink_to("loop1")
    for name in ("dangling", "loop1"):
        with pytest.raises(TrustStoreError):
            lc.retire(str(tmp_path / name), "a-1", at=None, now=NOW)
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".trust-")]


def test_directory_and_missing_path_refused(tmp_path):
    with pytest.raises(TrustStoreError, match="regular file"):
        lc.retire(str(tmp_path), "a-1", at=None, now=NOW)
    with pytest.raises(TrustStoreError, match="does not exist"):
        lc.retire(str(tmp_path / "nope.json"), "a-1", at=None, now=NOW)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_fifo_is_refused_without_blocking(tmp_path):
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    with pytest.raises(TrustStoreError, match="regular file"):
        lc.retire(str(fifo), "a-1", at=None, now=NOW)


MALFORMED = {
    "empty-file": b"",
    "whitespace": b"  \n",
    "not-json": b"{not json",
    "truncated": b'{"entries": {"a-1": {',
    "array": b"[]",
    "string": b'"entries"',
    "null": b"null",
    "empty-entries": b'{"entries": {}}',
    "entries-not-object": b'{"entries": []}',
    "duplicate-key": b'{"entries": {"a-1": {}}, "entries": {}}',
    "nan": b'{"entries": {}, "x": NaN}',
    "non-utf8": b'{"entries": {"\xff": {}}}',
    "bom": b'\xef\xbb\xbf{"entries": {}}',
    "unknown-top-member": None,  # filled below
    "unknown-entry-field": None,
    "bad-status": None,
    "retired-without-retired_at": None,
    "deep-nesting": b"[" * 5000 + b"]" * 5000,
}


def _mutated_payload(kind: str) -> bytes:
    p = {"entries": {"a-1": {"issuer": "acme", "public_key_pem": _pem(), "status": "active"}}}
    if kind == "unknown-top-member":
        p["revoked"] = []  # type: ignore[assignment]
    elif kind == "unknown-entry-field":
        p["entries"]["a-1"]["rogue"] = 1
    elif kind == "bad-status":
        p["entries"]["a-1"]["status"] = "revoked"
    elif kind == "retired-without-retired_at":
        p["entries"]["a-1"]["status"] = "retired"
    return json.dumps(p).encode()


@pytest.mark.parametrize("kind", sorted(MALFORMED))
@pytest.mark.parametrize("cmd", ["retire", "revoke", "status"])
def test_malformed_store_is_refused_and_left_untouched(tmp_path, kind, cmd):
    path = tmp_path / "bad.json"
    body = MALFORMED[kind] if MALFORMED[kind] is not None else _mutated_payload(kind)
    path.write_bytes(body)
    with pytest.raises((TrustStoreError, lc.LifecycleRefused)):
        if cmd == "retire":
            lc.retire(str(path), "a-1", at=None, now=NOW)
        elif cmd == "revoke":
            lc.revoke(str(path), "a-1", compromised_from=None, now=NOW)
        else:
            lc.status_rows(str(path))
    assert path.read_bytes() == body
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bad.json"]


def test_oversized_store_refused_before_reading(tmp_path, monkeypatch):
    path = tmp_path / "big.json"
    with path.open("wb") as fh:
        fh.truncate(MAX_TRUST_STORE_BYTES + 1)  # sparse file: never materialised
    read = []
    monkeypatch.setattr(Path, "read_bytes", lambda self: read.append(self) or b"")
    with pytest.raises(TrustStoreError, match="exceeds"):
        lc.retire(str(path), "a-1", at=None, now=NOW)
    assert read == []  # refused on stat, not after slurping it into memory


def test_store_at_the_size_limit_is_not_refused_for_size(tmp_path):
    path = _two_key_store(tmp_path)
    data = json.loads(path.read_text())
    data["entries"]["a-1"]["issuer"] = "x" * 1000
    path.write_text(json.dumps(data))
    lc.retire(str(path), "a-1", at=None, now=NOW)  # control: a large-ish valid store works


def test_many_entries_store_edit_is_correct(tmp_path):
    path = tmp_path / "many.json"
    entries = {
        f"k-{i:04d}": {"issuer": "acme", "public_key_pem": _pem(), "status": "active"}
        for i in range(300)
    }
    path.write_text(json.dumps({"entries": entries}, indent=2))
    lc.retire(str(path), "k-0150", at=None, now=NOW)
    after = TrustStore.from_json(str(path))
    assert sum(1 for e in after.entries.values() if e.status == "retired") == 1
    assert after.entry("k-0150").status == "retired"  # type: ignore[union-attr]


# ----- migration / store forms -------------------------------------------------


def test_bare_mapping_and_legacy_keys_forms_are_refused_by_edit_not_converted(tmp_path):
    forms = {
        "bare.json": {"k": _pem()},
        "legacy.json": {"keys": {"k": _pem()}, "revoked": []},
        "legacy-revoked.json": {"keys": {"k": _pem(), "j": _pem()}, "revoked": ["j"]},
    }
    for name, payload in forms.items():
        p = tmp_path / name
        p.write_text(json.dumps(payload))
        before = p.read_bytes()
        for fn in (
            lambda q: lc.retire(q, "k", at=None, now=NOW),
            lambda q: lc.revoke(q, "k", compromised_from=None, now=NOW),
        ):
            with pytest.raises(TrustStoreError, match="entries"):
                fn(str(p))
        assert p.read_bytes() == before
    assert sorted(x.name for x in tmp_path.iterdir()) == sorted(forms)


def test_status_distinguishes_all_three_forms_and_is_read_only(tmp_path):
    forms = {
        "bare.json": ({"k": _pem()}, "bare-mapping"),
        "legacy.json": ({"keys": {"k": _pem(), "j": _pem()}, "revoked": ["j"]}, "legacy-keys"),
        "entries.json": (
            {"entries": {"k": {"issuer": "a", "public_key_pem": _pem(), "status": "active"}}},
            "entries",
        ),
    }
    for name, (payload, form) in forms.items():
        p = tmp_path / name
        p.write_text(json.dumps(payload))
        before = p.read_bytes()
        out = lc.status_rows(str(p))
        assert out["store_form"] == form
        assert p.read_bytes() == before
    legacy = lc.status_rows(str(tmp_path / "legacy.json"))
    assert {r["key_id"]: r["status"] for r in legacy["keys"]} == {"j": "revoked", "k": "active"}


def test_manual_migration_of_legacy_store_is_a_re_enrolment_and_loads(tmp_path):
    """The documented migration path: re-enrol into an entries store, then edit."""
    pem = _pem()
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps({"keys": {"k": pem}, "revoked": []}))
    new = tmp_path / "entries.json"
    new.write_text(
        json.dumps(
            {"entries": {"k": {"issuer": "acme", "public_key_pem": pem, "status": "active"}}}
        )
    )
    assert TrustStore.from_json(str(legacy)).keys == TrustStore.from_json(str(new)).keys
    lc.revoke(str(new), "k", compromised_from=None, now=NOW)
    assert TrustStore.from_json(str(new)).is_revoked("k")
    assert not TrustStore.from_json(str(legacy)).is_revoked("k")  # the old file is not touched


def test_entries_store_with_unusual_but_valid_fields_roundtrips(tmp_path):
    path = tmp_path / "s.json"
    e = {
        "issuer": "acme",
        "public_key_pem": _pem(),
        "status": "active",
        "not_before": "2026-01-01T00:00:00Z",
        "deployments": ["prod-1"],
        "primitives": ["drift", "fairness"],
        "parameter_set_pin": "a" * 64,
    }
    path.write_text(json.dumps({"entries": {"k": e, "j": {**e, "public_key_pem": _pem()}}}))
    before = TrustStore.from_json(str(path)).entry("j")
    lc.retire(str(path), "k", at=None, now=NOW)
    new = json.loads(path.read_text())["entries"]
    assert {k: v for k, v in new["k"].items() if k not in ("status", "retired_at")} == {
        k: v for k, v in e.items() if k != "status"
    }
    assert TrustStore.from_json(str(path)).entry("j") == before


def test_unicode_issuer_is_preserved_through_an_edit(tmp_path):
    path = tmp_path / "s.json"
    path.write_text(
        json.dumps(
            {
                "entries": {
                    "k": {"issuer": "Bänk Ünïcode ✓", "public_key_pem": _pem(), "status": "active"}
                }
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    lc.retire(str(path), "k", at=None, now=NOW)
    assert TrustStore.from_json(str(path)).entry("k").issuer == "Bänk Ünïcode ✓"  # type: ignore[union-attr]


def test_backup_chain_is_one_generation(tmp_path):
    path = _two_key_store(tmp_path)
    first = path.read_bytes()
    lc.retire(str(path), "a-1", at=None, now=NOW)
    second = path.read_bytes()
    lc.revoke(str(path), "b-1", compromised_from=None, now=NOW)
    prev = Path(str(path) + ".prev").read_bytes()
    assert prev == second and prev != first  # only the last generation is kept (documented)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.parametrize(
    ("mode", "warns"),
    [(0o644, False), (0o600, False), (0o640, False), (0o664, True), (0o620, True), (0o666, True)],
)
def test_writable_by_group_or_other_is_flagged(tmp_path, mode, warns):
    path = _two_key_store(tmp_path)
    os.chmod(path, mode)
    assert bool(lc.status_rows(str(path))["warnings"]) is warns


def test_edit_that_would_produce_an_invalid_store_is_refused_before_any_write(tmp_path):
    """Defence in depth: the post-change payload is re-validated with the engine's own loader."""
    path = _two_key_store(tmp_path)
    before = path.read_bytes()

    def corrupt(entry, _now):
        entry["status"] = "retired"  # retired without retired_at is not a valid store

    with pytest.raises(lc.LifecycleRefused, match="nothing written"):
        lc._mutate(str(path), "a-1", NOW, corrupt)
    assert path.read_bytes() == before and not Path(str(path) + ".prev").exists()


def test_status_never_writes_even_on_a_read_only_directory(tmp_path):
    path = _two_key_store(tmp_path)
    before = path.read_bytes()
    lc.status_rows(str(path))
    assert path.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["store.json"]


def test_key_id_filter_in_status_excludes_the_others(tmp_path):
    path = _two_key_store(tmp_path)
    assert [r["key_id"] for r in lc.status_rows(str(path), "b-1")["keys"]] == ["b-1"]


def test_output_timestamps_are_rfc3339_utc_z_and_loadable(tmp_path):
    path = _two_key_store(tmp_path)
    res = lc.retire(str(path), "a-1", at="2026-10-01T00:00:00.5+00:00", now=NOW)
    assert res["after"]["retired_at"].endswith("Z") and "+" not in res["after"]["retired_at"]
    assert res["as_of"].endswith("Z")
    assert res["after"]["retired_at"] == "2026-10-01T00:00:00.500000Z"
    TrustStore.from_json(str(path))


# ============================================================================
# 4. CLI surface (real processes)
# ============================================================================


def _cli(work: Path, *args: str):
    from tests.test_trust_lifecycle import _cli as run

    return run(*args, cwd=work)


def _enrolled(tmp_path: Path) -> str:
    kg = _cli(tmp_path, "keygen", "--key-id", "k-1", "--issuer", "acme", "--private-key", "k.pem",
              "--public-key", "k.pub")  # fmt: skip
    assert kg.returncode == 0, kg.stderr
    fp = json.loads(kg.stdout)["fingerprint_sha256"]
    add = _cli(tmp_path, "trust", "add", "--store", "s.json", "--key-id", "k-1", "--issuer", "acme",
               "--public-key", "k.pub", "--fingerprint", fp)  # fmt: skip
    assert add.returncode == 0, add.stderr
    return fp


def test_cli_retire_honours_at_and_revoke_honours_boundary(tmp_path):
    _enrolled(tmp_path)
    r = _cli(tmp_path, "trust", "retire", "--store", "s.json", "--key-id", "k-1",
             "--at", "2026-01-02T03:04:05Z")  # fmt: skip
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["after"]["retired_at"] == "2026-01-02T03:04:05Z"
    v = _cli(tmp_path, "trust", "revoke", "--store", "s.json", "--key-id", "k-1",
             "--compromised-from", "2026-01-01T00:00:00Z")  # fmt: skip
    assert v.returncode == 0, v.stderr
    assert json.loads(v.stdout)["after"]["compromised_from"] == "2026-01-01T00:00:00Z"
    st = _cli(tmp_path, "trust", "status", "--store", "s.json", "--key-id", "k-1")
    assert st.returncode == 0 and json.loads(st.stdout)["keys"][0]["status"] == "compromised"


def test_cli_refusals_exit_2_unusable_exit_3_and_write_nothing(tmp_path):
    _enrolled(tmp_path)
    before = (tmp_path / "s.json").read_bytes()
    for args in (
        ("retire", "--key-id", "ghost"),
        ("revoke", "--key-id", "ghost"),
        ("retire", "--key-id", "k-1", "--at", "2999-01-01T00:00:00Z"),
        ("revoke", "--key-id", "k-1", "--compromised-from", "nonsense"),
    ):
        r = _cli(tmp_path, "trust", *args[:1], "--store", "s.json", *args[1:])
        assert r.returncode == 2 and "refused" in r.stderr, (args, r.stderr)
    assert (tmp_path / "s.json").read_bytes() == before
    (tmp_path / "legacy.json").write_text(json.dumps({"keys": {"k": _pem()}}))
    r = _cli(tmp_path, "trust", "retire", "--store", "legacy.json", "--key-id", "k")
    assert r.returncode == 3 and "entries" in r.stderr
    s = _cli(tmp_path, "trust", "status", "--store", "s.json", "--key-id", "ghost")
    assert s.returncode == 2


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits and symlinks")
def test_cli_mode_after_trust_add_is_preserved_and_symlink_survives(tmp_path):
    _enrolled(tmp_path)
    assert stat.S_IMODE((tmp_path / "s.json").stat().st_mode) == 0o644  # what trust add writes
    os.chmod(tmp_path / "s.json", 0o640)
    (tmp_path / "link.json").symlink_to("s.json")
    r = _cli(tmp_path, "trust", "retire", "--store", "link.json", "--key-id", "k-1")
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "link.json").is_symlink()
    assert stat.S_IMODE((tmp_path / "s.json").stat().st_mode) == 0o640
    assert stat.S_IMODE((tmp_path / "s.json.prev").stat().st_mode) == 0o640


def test_cli_status_output_marks_store_unauthenticated(tmp_path):
    _enrolled(tmp_path)
    out = json.loads(_cli(tmp_path, "trust", "status", "--store", "s.json").stdout)
    assert (
        out["authenticated"] is False and "not an independent revocation authority" in out["note"]
    )
