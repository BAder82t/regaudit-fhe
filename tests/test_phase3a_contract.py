"""Phase 3A contract decisions and acceptance gates.

Covers the six owner decisions and the consistency gates across the library,
the CLI (real processes) and the HTTP server.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

import regaudit_fhe as rf
from regaudit_fhe.replay import InMemoryReplayCache, SqliteReplayCache
from regaudit_fhe.report_v2 import AuditEnvelopeV2, envelope_v2
from regaudit_fhe.server import ServerConfig, build_app, check_dev_exposure, load_config_from_env
from regaudit_fhe.trust import TrustStore, TrustStoreError
from regaudit_fhe.verification import (
    TimestampEvidence,
    TrustHistory,
    VerificationPolicy,
    verify,
)
from tests._asgi import client_for

UTC = timezone.utc
NOW = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
ISSUED = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
BOUNDARY = datetime(2026, 9, 15, 0, 0, tzinfo=UTC)
FRESH = TrustHistory(as_of=NOW - timedelta(hours=1), authenticated=True)
SEC = timedelta(seconds=1)


def _report():
    return rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )


def _signer(key_id="acme-1"):
    return rf.Signer.generate(issuer="acme", key_id=key_id)


def _store(signer, **over) -> TrustStore:
    entry = {"issuer": signer.issuer, "public_key_pem": signer.public_key_pem(), "status": "active"}
    entry.update(over)
    return TrustStore.from_dict({"entries": {signer.key_id: entry}})


def _v2(signer, **kw) -> AuditEnvelopeV2:
    args = dict(deployment_id="prod-eu-1", issued_at=ISSUED)
    args.update(kw)
    return envelope_v2("fairness", _report(), signer=signer, **args)


def _tsa(gen_time: datetime, accuracy: timedelta = timedelta(0)):
    def verifier(digest: bytes, token: bytes):
        return TimestampEvidence(gen_time, accuracy) if token == b"ok:" + digest else None

    def attach(env):
        return env.with_timestamp(
            issuer="t", token=b"ok:" + env.sealed_digest(), issued_at=gen_time
        )

    return verifier, attach


def _policy(store, **kw):
    return VerificationPolicy(trust_store=store, now=lambda: NOW, **kw)


# ===========================================================================
# Decision 6: strict chronology boundaries (retirement AND compromise)
# ===========================================================================

BOUNDARY_CASES = [
    # (genTime - boundary, accuracy, accepted)
    (-timedelta(days=1), timedelta(0), True),
    (-SEC, timedelta(0), True),
    (timedelta(0), timedelta(0), False),  # equality is refused, for both boundaries
    (-SEC, SEC, False),  # genTime + accuracy == boundary: the latest possible time equals it
    (-2 * SEC, SEC, True),
    (SEC, timedelta(0), False),
]


@pytest.mark.parametrize(("offset", "accuracy", "accepted"), BOUNDARY_CASES)
def test_retirement_boundary_is_strict(offset, accuracy, accepted):
    s = _signer()
    retired = BOUNDARY
    verifier, attach = _tsa(retired + offset, accuracy)
    store = _store(s, status="retired", retired_at=retired.isoformat())
    r = verify(attach(_v2(s)), _policy(store, timestamp_verifier=verifier, trust_history=FRESH))
    assert r.accepted is accepted, (offset, accuracy, r.reasons)
    if not accepted:
        assert "SIGNED_AFTER_RETIREMENT" in r.blocking_reasons


@pytest.mark.parametrize(("offset", "accuracy", "accepted"), BOUNDARY_CASES)
def test_compromise_boundary_is_strict(offset, accuracy, accepted):
    s = _signer()
    verifier, attach = _tsa(BOUNDARY + offset, accuracy)
    store = _store(s, status="compromised", compromised_from=BOUNDARY.isoformat())
    r = verify(attach(_v2(s)), _policy(store, timestamp_verifier=verifier, trust_history=FRESH))
    assert r.accepted is accepted, (offset, accuracy, r.reasons)
    if not accepted:
        assert "SIGNED_AFTER_COMPROMISE" in r.blocking_reasons


def test_retirement_equality_is_refused_for_signer_asserted_time_too():
    s = _signer()
    store = _store(s, status="retired", retired_at=BOUNDARY.isoformat())
    p = _policy(store, historical_acceptance="signer-asserted")
    ok = verify(_v2(s, issued_at=BOUNDARY - SEC), p)
    assert ok.accepted and "CHRONOLOGY_UNAUTHENTICATED" in ok.reasons
    at = verify(_v2(s, issued_at=BOUNDARY), p)
    assert at.trust_status == "INVALID" and "SIGNED_AFTER_RETIREMENT" in at.blocking_reasons


def test_a_valid_timestamp_does_not_establish_trust_history_completeness():
    """O8 stays in force: chronology alone never accepts a historical key."""
    s = _signer()
    verifier, attach = _tsa(BOUNDARY - timedelta(days=2))
    store = _store(s, status="retired", retired_at=BOUNDARY.isoformat())
    env = attach(_v2(s))
    good = verify(env, _policy(store, timestamp_verifier=verifier, trust_history=FRESH))
    assert good.accepted  # control: chronology and an (injected) authenticated history
    for history in (None, TrustHistory(as_of=NOW, authenticated=False)):
        r = verify(env, _policy(store, timestamp_verifier=verifier, trust_history=history))
        assert r.chronology == "AUTHENTICATED" and not r.accepted
        assert "TRUST_STORE_FRESHNESS_UNPROVEN" in r.blocking_reasons


# ===========================================================================
# Decision 4: required timestamps need genuinely verified evidence
# ===========================================================================


def test_required_timestamp_refuses_every_kind_of_non_evidence():
    s = _signer()
    other = _signer("other")
    verifier, attach = _tsa(NOW - timedelta(hours=1))
    store = _store(s)
    p = _policy(store, timestamp_verifier=verifier, require_verified_timestamp=True)
    assert verify(attach(_v2(s)), p).accepted  # control

    plain = _v2(s)
    stolen = _v2(s)
    stolen.timestamps = list(attach(_v2(other)).timestamps)  # bound to another artifact
    cases = {
        "absent": plain,
        "junk token": plain.with_timestamp(issuer="t", token=b"junk", issued_at=NOW),
        "token for another artifact": stolen,
    }
    for name, env in cases.items():
        r = verify(env, p)
        assert r.trust_status == "INVALID", name
        assert {"TIMESTAMP_REQUIRED", "TIMESTAMP_FAILED"} & set(r.blocking_reasons), name
    # diagnostics keep absence distinct from failed verification
    assert verify(plain, p).timestamp_status == "ABSENT"
    assert verify(cases["junk token"], p).timestamp_status == "FAILED"

    def boom(digest, token):
        raise RuntimeError("tsa down")

    raising = _policy(store, timestamp_verifier=boom, require_verified_timestamp=True)
    assert verify(attach(_v2(s)), raising).trust_status == "INVALID"

    def malformed(digest, token):
        return "not evidence"

    bad_type = _policy(store, timestamp_verifier=malformed, require_verified_timestamp=True)
    r = verify(attach(_v2(s)), bad_type)
    assert r.trust_status == "INVALID" and r.timestamp_status == "FAILED"


# ===========================================================================
# Decision 1: replay states and durability disclosure
# ===========================================================================


def test_replay_state_labels_and_durability_are_disclosed(tmp_path: Path):
    s = _signer()
    store = _store(s)
    off = verify(_v2(s, issued_at=NOW - timedelta(days=1)), _policy(store))
    assert (off.consumption, off.replay_scope, off.replay_durable) == ("NOT_CHECKED", "NONE", None)
    mem = verify(
        _v2(s, issued_at=NOW - timedelta(days=1)),
        _policy(store, replay_mode="record", replay_cache=InMemoryReplayCache()),
    )
    assert mem.consumption == "RECORDED_LOCAL"
    assert mem.replay_scope == "LOCAL_PROCESS" and mem.replay_durable is False
    disk = verify(
        _v2(s, issued_at=NOW - timedelta(days=1)),
        _policy(store, replay_mode="record", replay_cache=SqliteReplayCache(tmp_path / "r.db")),
    )
    assert disk.consumption == "RECORDED_LOCAL"
    assert disk.replay_scope == "LOCAL_PERSISTENT" and disk.replay_durable is True
    check = verify(
        _v2(s, issued_at=NOW - timedelta(days=1)),
        _policy(store, replay_mode="check", replay_cache=InMemoryReplayCache()),
    )
    assert check.consumption == "CHECKED_NOT_CONSUMED" and check.replay_durable is False
    assert mem.to_dict()["replay_durable"] is False and disk.to_dict()["replay_durable"] is True


def test_reserved_and_consumed_are_never_produced_in_phase_3a(tmp_path: Path):
    s = _signer()
    produced = set()
    for mode in ("off", "check", "record"):
        cache = InMemoryReplayCache() if mode != "off" else None
        policy = _policy(_store(s), replay_mode=mode, replay_cache=cache)
        for _ in range(2):
            produced.add(verify(_v2(s, issued_at=NOW - timedelta(days=1)), policy).consumption)
        produced.add(verify(rf.envelope("fairness", _report(), signer=s), policy).consumption)
    assert produced <= {"NOT_CHECKED", "CHECKED_NOT_CONSUMED", "RECORDED_LOCAL"}


# ===========================================================================
# Decision 5: Unix sockets are refused for the development option only
# ===========================================================================


def test_unix_sockets_are_refused_for_the_development_option():
    scope = {"server": ("/run/regaudit.sock", None), "client": None}
    reason = check_dev_exposure(scope, {}, ())
    assert reason is not None and "loopback" in reason
    assert check_dev_exposure({"server": None, "client": None}, {}, ()) is not None
    # a loopback host with no port is not an authenticated TCP address
    odd = {"server": ("127.0.0.1", None), "client": ("127.0.0.1", 1)}
    assert check_dev_exposure(odd, {}, ()) is not None
    # control: a loopback TCP socket is still allowed
    assert (
        check_dev_exposure({"server": ("127.0.0.1", 80), "client": ("127.0.0.1", 1)}, {}, ())
        is None
    )


@pytest.mark.parametrize(
    "server", [None, ("/run/regaudit.sock", None)], ids=["uvicorn-uds", "asgi-uds"]
)
def test_normal_trusted_verification_still_works_over_a_unix_socket(server):
    s = _signer()
    config = ServerConfig(
        api_keys={}, dev_mode=True, max_body_bytes=1 << 20, rate_limit_per_min=600,
        request_timeout_s=10.0, cors_origins=(), trust_store=_store(s),
    )  # fmt: skip
    client = client_for(build_app(config=config), peer=None, server=server)
    r = client.post("/v1/verify", json={"envelope": _v2(s, issued_at=datetime.now(UTC)).to_dict()})
    assert r.status_code == 200 and r.json()["trust_status"] == "TRUSTED"


@pytest.mark.parametrize(
    "server", [None, ("/run/regaudit.sock", None)], ids=["uvicorn-uds", "asgi-uds"]
)
def test_development_option_over_a_unix_socket_is_refused(server):
    s = _signer()
    config = ServerConfig(
        api_keys={}, dev_mode=True, max_body_bytes=1 << 20, rate_limit_per_min=600,
        request_timeout_s=10.0, cors_origins=(), allow_self_signed=True,
    )  # fmt: skip
    client = client_for(build_app(config=config), peer=None, server=server)
    r = client.post("/v1/verify", json={"envelope": _v2(s).to_dict()})
    assert r.status_code == 403 and "trust_status" not in r.json()


# ===========================================================================
# Decision 3 + gate: CLI exit codes, four outcomes, real processes
# ===========================================================================


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", "verify", *args],
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip


def _files(tmp_path: Path, signer, **entry_over):
    entry = {"issuer": signer.issuer, "public_key_pem": signer.public_key_pem(), "status": "active"}
    entry.update(entry_over)
    store = tmp_path / "trust.json"
    store.write_text(json.dumps({"entries": {signer.key_id: entry}}))
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_v2(signer, issued_at=datetime.now(UTC)).to_dict()))
    return str(report), str(store)


def test_cli_exit_codes_for_the_four_outcomes(tmp_path: Path):
    s = _signer()
    report, store = _files(tmp_path, s)
    accepted = run("-i", report, "--trusted-keys", store)
    assert accepted.returncode == 0 and json.loads(accepted.stdout)["accepted"] is True
    compromised_dir = tmp_path / "compromised"
    compromised_dir.mkdir()
    _, compromised = _files(compromised_dir, s, status="compromised")
    refused = run("-i", report, "--trusted-keys", compromised)
    assert refused.returncode == 1 and json.loads(refused.stdout)["accepted"] is False
    omitted = run("-i", report)
    assert omitted.returncode == 2 and omitted.stdout == ""
    unavailable = run("-i", report, "--trusted-keys", str(tmp_path / "missing.json"))
    assert unavailable.returncode == 3 and unavailable.stdout == ""


@pytest.mark.parametrize("path", ["", "   "], ids=["empty-string", "blank"])
def test_cli_a_supplied_but_empty_trusted_keys_path_is_infrastructure_failure(tmp_path, path):
    """The option WAS given: an unusable value is exit 3, not 'omitted' (exit 2)."""
    s = _signer()
    report, _ = _files(tmp_path, s)
    p = run("-i", report, "--trusted-keys", path)
    assert p.returncode == 3 and p.stdout == ""


def test_cli_refuses_v1_in_confidential_profile_with_replay_required(tmp_path: Path):
    s = _signer()
    store = tmp_path / "trust.json"
    store.write_text(
        json.dumps(
            {
                "entries": {
                    s.key_id: {
                        "issuer": s.issuer,
                        "public_key_pem": s.public_key_pem(),
                        "status": "active",
                    }
                }
            }
        )
    )
    v1 = tmp_path / "v1.json"
    v1.write_text(json.dumps(rf.envelope("fairness", _report(), signer=s).to_dict()))
    args = ("-i", str(v1), "--trusted-keys", str(store), "--profile", "confidential",
            "--max-age-seconds", "3600", "--replay-db", str(tmp_path / "r.db"),
            "--replay-mode", "record")  # fmt: skip
    p = run(*args)
    assert p.returncode == 1 and "REPLAY_ID_MISSING" in json.loads(p.stdout)["blocking_reasons"]
    dev = run("-i", str(v1), "--trusted-keys", str(store))
    assert dev.returncode == 0  # control: v1 is still verifiable in the development profile


# ===========================================================================
# Gates: key aliases, key scope, canonical base64, development exception
# ===========================================================================


def test_gate_key_alias_is_refused_by_every_loader(tmp_path: Path, monkeypatch):
    s = _signer("k1")
    entry = {"issuer": s.issuer, "public_key_pem": s.public_key_pem()}
    payload = {
        "entries": {"k1": {**entry, "status": "compromised"}, "k2": {**entry, "status": "active"}}
    }
    path = tmp_path / "alias.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(TrustStoreError):
        TrustStore.from_dict(payload)
    with pytest.raises(TrustStoreError):
        TrustStore.from_json(path)
    monkeypatch.setenv("REGAUDIT_FHE_TRUST_STORE", str(path))
    with pytest.raises(TrustStoreError):
        load_config_from_env()
    report = tmp_path / "r.json"
    report.write_text(json.dumps(_v2(_signer("k2")).to_dict()))
    p = run("-i", str(report), "--trusted-keys", str(path))
    assert p.returncode == 3 and p.stdout == ""


SCOPE_CASES = [
    ({"issuer": "someone-else"}, "ISSUER_MISMATCH"),
    ({"deployments": ["prod-us-1"]}, "DEPLOYMENT_NOT_ALLOWED"),
    ({"primitives": ["drift"]}, "PRIMITIVE_NOT_ALLOWED"),
    ({"not_before": "2099-01-01T00:00:00Z"}, "KEY_NOT_YET_VALID"),
]


@pytest.mark.parametrize(("over", "reason"), SCOPE_CASES, ids=[c[1] for c in SCOPE_CASES])
def test_gate_key_scope_is_honoured_by_library_cli_and_http(tmp_path: Path, over, reason):
    s = _signer()
    env = _v2(s, issued_at=datetime.now(UTC))
    # library (shared engine)
    ok = verify(env, VerificationPolicy(trust_store=_store(s)))
    assert ok.accepted
    lib = verify(env, VerificationPolicy(trust_store=_store(s, **over)))
    assert lib.trust_status == "INVALID" and reason in lib.blocking_reasons
    # CLI (real process)
    report, store_ok = _files(tmp_path, s)
    assert run("-i", report, "--trusted-keys", store_ok).returncode == 0
    scoped_dir = tmp_path / "scoped"
    scoped_dir.mkdir()
    _, store_bad = _files(scoped_dir, s, **over)
    cli = run("-i", report, "--trusted-keys", store_bad)
    assert cli.returncode == 1 and reason in json.loads(cli.stdout)["blocking_reasons"]

    # HTTP server
    def serve(store):
        config = ServerConfig(
            api_keys={}, dev_mode=True, max_body_bytes=1 << 20, rate_limit_per_min=600,
            request_timeout_s=10.0, cors_origins=(), trust_store=store,
        )  # fmt: skip
        return client_for(build_app(config=config))

    good = serve(_store(s)).post("/v1/verify", json={"envelope": env.to_dict()})
    assert good.json()["accepted"] is True
    bad = serve(_store(s, **over)).post("/v1/verify", json={"envelope": env.to_dict()})
    body = bad.json()
    assert (
        body["accepted"] is False and body["valid"] is False and reason in body["blocking_reasons"]
    )


def _noncanonical_b64(text: str) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    body, pad = text.rstrip("="), text[len(text.rstrip("=")) :]
    mask = 0b1111 if pad == "==" else 0b11
    variant = body[:-1] + alphabet[alphabet.index(body[-1]) ^ mask] + pad
    assert base64.b64decode(variant, validate=True) == base64.b64decode(text)
    return variant


def test_gate_alternate_base64_cannot_change_artifact_identity(tmp_path: Path):
    s = _signer()
    env = _v2(s, issued_at=datetime.now(UTC)).with_timestamp(issuer="t", token=b"ab", issued_at=NOW)
    data = env.to_dict()
    data["receipt"]["signature_b64"] = _noncanonical_b64(data["receipt"]["signature_b64"])
    with pytest.raises(rf.EnvelopeFormatError):
        rf.parse_envelope(data)
    # CLI: malformed input
    _, store = _files(tmp_path, s)
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(data))
    assert run("-i", str(bad), "--trusted-keys", store).returncode == 2
    # HTTP: 422
    config = ServerConfig(
        api_keys={}, dev_mode=True, max_body_bytes=1 << 20, rate_limit_per_min=600,
        request_timeout_s=10.0, cors_origins=(), trust_store=_store(s),
    )  # fmt: skip
    assert (
        client_for(build_app(config=config)).post("/v1/verify", json={"envelope": data}).status_code
        == 422
    )
    # the sealed digest is independent of the (refused) alternate text
    assert env.sealed_digest() == rf.parse_envelope(env.to_dict()).sealed_digest()


def test_gate_no_path_from_self_signed_to_trusted_on_any_entry_point(tmp_path: Path):
    s = _signer()
    v2_now = _v2(s, issued_at=datetime.now(UTC))
    v1 = rf.envelope("fairness", _report(), signer=s)
    tampered = _v2(s, issued_at=datetime.now(UTC))
    tampered.result["x"] = 1
    for env in (v2_now, v1, tampered):
        # library
        r = verify(env, VerificationPolicy(allow_self_signed=True))
        assert r.accepted is False and r.trust_status in ("SELF_SIGNED_ONLY", "INVALID")
        assert r.key_status == "none" and r.issuer_trusted is False
        # HTTP (loopback, development)
        config = ServerConfig(
            api_keys={}, dev_mode=True, max_body_bytes=1 << 20, rate_limit_per_min=600,
            request_timeout_s=10.0, cors_origins=(), allow_self_signed=True,
        )  # fmt: skip
        body = (
            client_for(build_app(config=config))
            .post("/v1/verify", json={"envelope": env.to_dict()})
            .json()
        )
        assert body["accepted"] is False and body["valid"] is False
        assert body["trust_status"] in ("SELF_SIGNED_ONLY", "INVALID")
        # CLI
        path = tmp_path / f"{id(env)}.json"
        path.write_text(json.dumps(env.to_dict()))
        p = run("-i", str(path), "--allow-self-signed")
        assert p.returncode == 1
        assert json.loads(p.stdout)["trust_status"] in ("SELF_SIGNED_ONLY", "INVALID")


# ===========================================================================
# Gate: specification, changelog and README reflect the decisions
# ===========================================================================

ROOT = Path(__file__).resolve().parent.parent


def _doc(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_every_reason_code_the_engine_can_emit_is_documented_in_the_spec():
    source = (ROOT / "src/regaudit_fhe/verification.py").read_text(encoding="utf-8")
    emitted = set(re.findall(r'(?:block|note)\("([A-Z_]+)"\)', source))
    emitted |= set(re.findall(r'\)\("([A-Z_]+)"\)', source))  # (note if ... else block)("CODE")
    assert len(emitted) > 25
    spec = _doc("docs/TRUST_SPEC.md")
    missing = sorted(code for code in emitted if code not in spec)
    assert not missing, f"reason codes missing from docs/TRUST_SPEC.md: {missing}"


def test_consumption_states_and_durability_are_in_the_spec():
    spec = _doc("docs/TRUST_SPEC.md")
    for state in ("NOT_CHECKED", "CHECKED_NOT_CONSUMED", "RECORDED_LOCAL", "RESERVED", "CONSUMED"):
        assert state in spec
    assert "replay_durable" in spec and "crash-durable" in spec


def test_spec_states_the_exact_strict_boundary_semantics():
    spec = _doc("docs/TRUST_SPEC.md")
    assert "strictly" in spec and "equality is refused" in spec.lower()
    assert "inclusive" not in spec.split("### 4.3")[1].split("### 4.5")[0].lower().replace(
        "not inclusive", ""
    )


def test_changelog_and_readme_record_the_contract_decisions():
    changelog = _doc("CHANGELOG.md")
    for phrase in ("RECORDED_LOCAL", "retirement", "Unix", "replay_durable", "--trusted-keys"):
        assert phrase in changelog, phrase
    readme = _doc("README.md")
    assert "exits **0 only when the report is accepted**" in readme


# ===========================================================================
# Consistency review round: gaps found by the focused review
# ===========================================================================


def test_gate_direct_trust_store_construction_refuses_key_aliases():
    s = _signer("a")
    pem = s.public_key_pem()
    crlf = pem.replace("\n", "\r\n") + "\r\n\r\n"
    with pytest.raises(TrustStoreError, match="same public key"):
        TrustStore(keys={"a": pem, "b": pem}, revoked=frozenset({"a"}))
    with pytest.raises(TrustStoreError, match="same public key"):
        TrustStore(keys={"a": pem, "b": crlf}, revoked=frozenset({"a"}))
    with pytest.raises(TrustStoreError):
        TrustStore(keys={"a": "not a pem"})
    entry_a = _store(s).entry("a")
    assert entry_a is not None
    entries = {
        "a": entry_a,
        "b": type(entry_a)(key_id="b", public_key_pem=pem, status="active", issuer="acme"),
    }
    with pytest.raises(TrustStoreError, match="same public key"):
        TrustStore(keys={k: e.public_key_pem for k, e in entries.items()}, entries=entries)
    assert TrustStore(keys={"a": pem})  # control: one key under one id is fine


def _flip_trailing_bits(text: str) -> str:
    return _noncanonical_b64(text)


V1_B64_VARIANTS = {
    "trailing-bits": _flip_trailing_bits,
    "embedded-newline": lambda t: t[:10] + "\n" + t[10:],
    "appended-garbage": lambda t: t + "!!",
    "whitespace-prefix": lambda t: " " + t,
}


@pytest.mark.parametrize("variant", sorted(V1_B64_VARIANTS))
def test_gate_alternate_base64_is_refused_on_the_v1_path_too(variant):
    from regaudit_fhe.trust import TrustStore as TS

    s = _signer()
    v1 = rf.envelope("fairness", _report(), signer=s)
    store = TS.from_dict({"keys": {s.key_id: s.public_key_pem()}})
    assert verify(v1, VerificationPolicy(trust_store=store)).accepted  # control
    assert rf.verify_envelope(v1, trust_store=store).trust_status == "TRUSTED"
    v1.receipt["signature_b64"] = V1_B64_VARIANTS[variant](v1.receipt["signature_b64"])
    engine = verify(v1, VerificationPolicy(trust_store=store))
    assert engine.trust_status == "INVALID" and "SIGNATURE_INVALID" in engine.blocking_reasons
    legacy = rf.verify_envelope(v1, trust_store=store)
    assert legacy.trust_status == "INVALID" and legacy.signature_valid is False
    assert rf.verify_receipt(v1, trust_store=store, strict=True) is False


def test_gate_alternate_base64_v1_timestamp_token_cannot_reach_a_verifier():
    s = _signer()
    tsa = rf.TimestampAuthority(issuer="t", sign_callable=lambda b: b"ab")  # token "YWI="
    v1 = rf.envelope("fairness", _report(), signer=s, timestamp_authority=tsa)
    store = TrustStore.from_dict({"keys": {s.key_id: s.public_key_pem()}})
    seen: list[bytes] = []

    def accept_anything(body: bytes, token: bytes) -> bool:
        seen.append(token)
        return True

    ok = rf.verify_envelope(v1, trust_store=store, tsa_verifier=accept_anything)
    assert ok.timestamp_status == "VERIFIED" and seen == [b"ab"]  # control
    assert v1.timestamp is not None
    v1.timestamp["token_b64"] = "YWJ="  # same bytes, non-canonical text
    seen.clear()
    bad = rf.verify_envelope(v1, trust_store=store, tsa_verifier=accept_anything)
    assert bad.timestamp_status == "FAILED" and seen == []


def test_gate_flag_plus_store_never_turns_an_unregistered_issuer_into_trusted(tmp_path: Path):
    s, other = _signer(), _signer("mallory-1")
    report, store = _files(tmp_path, s)
    both = run("-i", report, "--trusted-keys", store, "--allow-self-signed")
    assert (
        both.returncode == 0 and json.loads(both.stdout)["issuer_trusted"] is True
    )  # via the store
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other_report, _ = _files(other_dir, other)
    p = run("-i", other_report, "--trusted-keys", store, "--allow-self-signed")
    assert p.returncode == 1
    verdict = json.loads(p.stdout)
    assert verdict["accepted"] is False and "ISSUER_UNKNOWN" in verdict["blocking_reasons"]


def test_cli_input_errors_are_reported_before_infrastructure_errors(tmp_path: Path):
    """Documented precedence: a malformed report (2) is reported before an unusable
    trust store (3) when both apply."""
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    p = run("-i", str(bad), "--trusted-keys", str(tmp_path / "missing.json"))
    assert p.returncode == 2 and p.stdout == ""


class _FailingReplay:
    scope = "LOCAL_PERSISTENT"
    durable = True

    def seen(self, *a, **k):
        from regaudit_fhe.replay import ReplayStateError

        raise ReplayStateError("store went away")

    record = seen


def test_replay_store_failure_during_verification_is_infrastructure_not_policy_cli(
    tmp_path: Path, monkeypatch, capsys
):
    """Outside development an unavailable replay store is exit 3, never a policy refusal."""
    import regaudit_fhe.cli as cli
    from regaudit_fhe.replay import ReplayStateError

    s = _signer()
    report, store = _files(tmp_path, s)

    def broken(self, *a, **k):
        raise ReplayStateError("store went away")

    monkeypatch.setattr(SqliteReplayCache, "record", broken)
    monkeypatch.setattr(SqliteReplayCache, "seen", broken)
    args = ["verify", "-i", report, "--trusted-keys", store, "--profile", "confidential",
            "--max-age-seconds", "3600", "--replay-db", str(tmp_path / "r.db"),
            "--replay-mode", "record"]  # fmt: skip
    code = cli.main(args)
    out = capsys.readouterr()
    assert code == 3 and out.out == "" and "replay" in out.err.lower()
    # control: development fails open with a disclosed note and still obeys the trust verdict
    dev = cli.main(["verify", "-i", report, "--trusted-keys", store, "--replay-db",
                    str(tmp_path / "r2.db"), "--replay-mode", "record"])  # fmt: skip
    dev_out = capsys.readouterr()
    assert dev == 0 and "REPLAY_STATE_UNAVAILABLE" in json.loads(dev_out.out)["reasons"]


def test_replay_store_failure_during_verification_is_503_over_http_outside_development():
    s = _signer()
    config = ServerConfig(
        api_keys={}, dev_mode=True, max_body_bytes=1 << 20, rate_limit_per_min=600,
        request_timeout_s=10.0, cors_origins=(), trust_store=_store(s), profile="confidential",
        max_age_s=3600.0, replay_cache=_FailingReplay(), replay_mode="record",
    )  # fmt: skip
    client = client_for(build_app(config=config))
    env = _v2(s, issued_at=datetime.now(UTC))
    r = client.post("/v1/verify", json={"envelope": env.to_dict()})
    assert r.status_code == 503 and "accepted" not in r.json()


def test_docs_have_no_stale_inclusive_retirement_wording_and_list_all_consumption_states():
    spec = _doc("docs/TRUST_SPEC.md")
    assert "signed_not_after ≤" not in spec and "≤ `retired_at`" not in spec
    row = next(line for line in spec.splitlines() if line.startswith("| `consumption` | enum"))
    for state in ("NOT_CHECKED", "CHECKED_NOT_CONSUMED", "RECORDED_LOCAL", "RESERVED", "CONSUMED"):
        assert state in row, state
    sec7 = spec.split("## 7. Legacy v1")[1].split("## 8.")[0]
    assert "refused" in sec7.lower() and "confidential" in sec7


def test_readme_and_threat_model_record_the_contract_decisions():
    readme, threat = _doc("README.md"), _doc("docs/THREAT_MODEL.md")
    for phrase in ("RECORDED_LOCAL", "replay_durable", "strictly earlier", "report.v1"):
        assert phrase in readme, phrase
    for phrase in ("RECORDED_LOCAL", "strict", "Unix", "--trusted-keys"):
        assert phrase in threat, phrase


# ===========================================================================
# Re-check round: documentation precision and one hardening nit
# ===========================================================================


def test_trust_store_entry_key_id_must_match_its_map_key():
    s = _signer()
    entry = _store(s).entry(s.key_id)
    assert entry is not None
    other = type(entry)(
        key_id="different", public_key_pem=entry.public_key_pem, status="active", issuer="acme"
    )
    with pytest.raises(TrustStoreError, match="key_id"):
        TrustStore(keys={s.key_id: entry.public_key_pem}, entries={s.key_id: other})
    assert TrustStore(keys={s.key_id: entry.public_key_pem}, entries={s.key_id: entry})  # control


def test_spec_reason_code_table_lists_every_emitted_code():
    source = (ROOT / "src/regaudit_fhe/verification.py").read_text(encoding="utf-8")
    emitted = set(re.findall(r'(?:block|note)\("([A-Z_]+)"\)', source))
    emitted |= set(re.findall(r'\)\("([A-Z_]+)"\)', source))
    table = _doc("docs/TRUST_SPEC.md").split("### 8.3 Reason codes")[1].split("### 8.4")[0]
    missing = sorted(code for code in emitted if code not in table)
    assert not missing, f"codes missing from the TRUST_SPEC §8.3 table: {missing}"


def test_spec_boundary_wording_is_precise_and_unknown_boundary_is_unconditional():
    spec = _doc("docs/TRUST_SPEC.md")
    lifecycle = spec.split("### 4.3")[1].split("### 4.5")[0]
    assert "at or before `signed_not_after`" not in spec
    assert "signed_not_after + accuracy" not in spec
    assert "latest_signing_time" in lifecycle
    # an unknown compromise boundary is refused whatever any token claims
    assert "unless independent chronology predates" not in spec


def test_spec_6_2_does_not_overstate_not_checked_and_defines_checked_precisely():
    sec = _doc("docs/TRUST_SPEC.md").split("### 6.2")[1].split("Required by profile")[0]
    sec = " ".join(sec.split()).lower()  # ignore line wrapping and case
    assert "when replay checking is not configured" in sec
    assert "this call recorded nothing" in sec


def test_deployment_and_threat_model_qualify_their_one_liners():
    deployment = _doc("docs/DEPLOYMENT.md")
    row = next(
        line
        for line in deployment.splitlines()
        if "/v1/verify" in line
        and "|" in line
        and "audit:verify" in line
        and "Verify" in line
        and "503" in line
    )
    assert "development" in row.lower()
    threat = _doc("docs/THREAT_MODEL.md")
    assert "Replay protection is not provided." not in threat.replace("for `report.v1`", "")


def test_docs_put_incompatible_configuration_under_exit_2_not_3():
    readme = _doc("README.md")
    row3 = next(line for line in readme.splitlines() if line.startswith("| `3` |"))
    row2 = next(line for line in readme.splitlines() if line.startswith("| `2` |"))
    assert "unsafe profile" not in row3.lower() and "profile settings" not in row3.lower()
    assert "incompatible" in row2.lower()
    spec = _doc("docs/TRUST_SPEC.md")
    row = next(
        line
        for line in spec.splitlines()
        if "Required verification infrastructure unavailable" in line
    )
    assert "unsafe" not in row.lower()
    assert "incompatible configuration" in spec.lower()
