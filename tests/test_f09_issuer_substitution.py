"""F-09, cross-tenant issuer substitution, on every store form, policy, report format and verification path.

Tenant B holds a key the verifier enrolled for B. B signs a report whose signed issuer name is tenant A's. What must hold
is issuer attribution: a TRUSTED result with ``issuer_trusted`` true says the name in the report is the name the trust store
states for the key that verified it. A store that states no issuer cannot show that, however few keys it holds.

A store without issuers is refused under ``confidential`` and ``high-assurance``, loudly and before any report is read. In
``development`` and on the lenient library paths the verdict is unchanged.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import regaudit_fhe as rf
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2, parse_envelope, parse_envelope_strict
from regaudit_fhe.reports import verify_envelope, verify_envelope_or_raise, verify_receipt
from regaudit_fhe.trust import KeyEntry, UntrustedIssuer
from regaudit_fhe.verification import PolicyError, VerificationPolicy, verify

T = datetime.now(timezone.utc).replace(microsecond=0)
RUN = "3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e60a"
PROFILES = ("development", "confidential", "high-assurance")


def _key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())


def signer(seed: bytes, issuer: str, key_id: str) -> rf.Signer:
    key = _key(seed)
    return rf.Signer(issuer=issuer, key_id=key_id, private_key=key, public_key=key.public_key())


ALICE = signer(b"tenant-a", "alice-bank", "alice-1")
BOB = signer(b"tenant-b", "bob-lab", "bob-1")
FORGED = signer(b"tenant-b", "alice-bank", "bob-1")  # B's real key, A's name


def _entries(**over) -> dict:
    return {
        "entries": {
            "alice-1": {"issuer": "alice-bank", "public_key_pem": ALICE.public_key_pem(), "status": "active"},
            "bob-1": {"issuer": "bob-lab", "public_key_pem": BOB.public_key_pem(), "status": "active"},
            **over,
        }
    }


STORES = {
    "bare": {"alice-1": ALICE.public_key_pem(), "bob-1": BOB.public_key_pem()},
    "legacy": {"keys": {"alice-1": ALICE.public_key_pem(), "bob-1": BOB.public_key_pem()}},
    # One key, one operator: the count of keys is not the property.
    "legacy-one-key": {"keys": {"bob-1": BOB.public_key_pem()}},
    "entries": _entries(),
}
UNBOUND = ("bare", "legacy", "legacy-one-key")


def report(who: rf.Signer, fmt: str = "v2"):
    result = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    if fmt == "v1":
        return rf.envelope("drift", result, signer=who)
    return envelope_v2(
        "drift", result, signer=who, deployment_id="p", audience=("reg",), issued_at=T, audit_run_id=RUN
    )


def policy(profile: str, store: dict, tmp_path: Path, **kw) -> VerificationPolicy:
    args = {"profile": profile, "trust_store": rf.TrustStore.from_dict(store), "check_provenance": True, **kw}
    if profile != "development":
        args.update(
            max_age=timedelta(hours=1),
            verifier_id="reg",
            replay_mode="record",
            replay_cache=SqliteReplayCache(tmp_path / f"{profile}.db"),
        )
    return VerificationPolicy(**args)


def outcome(env, profile: str, form: str, tmp_path: Path) -> str:
    """What the engine does: the verdict, or that the policy itself was refused."""
    try:
        pol = policy(profile, STORES[form], tmp_path)
    except PolicyError:
        return "POLICY_REFUSED"
    return verify(parse_envelope_strict(json.dumps(env.to_dict())), pol).trust_status


# form, profile -> the v2 substitution's outcome.
EXPECTED = {
    ("bare", "development"): "TRUSTED",
    ("bare", "confidential"): "POLICY_REFUSED",
    ("bare", "high-assurance"): "POLICY_REFUSED",
    ("legacy", "development"): "TRUSTED",
    ("legacy", "confidential"): "POLICY_REFUSED",
    ("legacy", "high-assurance"): "POLICY_REFUSED",
    ("legacy-one-key", "development"): "TRUSTED",
    ("legacy-one-key", "confidential"): "POLICY_REFUSED",
    ("legacy-one-key", "high-assurance"): "POLICY_REFUSED",
    ("entries", "development"): "INVALID",
    ("entries", "confidential"): "INVALID",
    ("entries", "high-assurance"): "INVALID",
}


@pytest.mark.parametrize(("form", "profile"), sorted(EXPECTED))
def test_substituted_issuer_in_a_v2_report(form, profile, tmp_path):
    assert outcome(report(FORGED), profile, form, tmp_path) == EXPECTED[form, profile]


@pytest.mark.parametrize("profile", PROFILES)
def test_the_entries_guard_itself_refuses_the_substitution(profile, tmp_path):
    res = verify(report(FORGED), policy(profile, STORES["entries"], tmp_path))
    assert res.blocking_reasons == ("ISSUER_MISMATCH",)  # no other check got there first
    assert not res.accepted and not res.issuer_trusted
    assert res.consumption == "NOT_CHECKED"  # a refused report does not burn the replay id


@pytest.mark.parametrize("profile", PROFILES)
def test_a_v1_substitution_never_passes_an_entries_store(profile, tmp_path):
    res = verify(report(FORGED, "v1"), policy(profile, STORES["entries"], tmp_path))
    assert not res.accepted and "ISSUER_MISMATCH" in res.blocking_reasons


@pytest.mark.parametrize(
    "name", ["Alice-Bank", "alice-bank ", " alice-bank", "alice‐bank", "аlice-bank", "alice-bank\u0000"]
)
def test_a_lookalike_of_the_enrolled_name_is_a_different_name(name, tmp_path):
    env = report(signer(b"tenant-a", name, "alice-1"))
    res = verify(env, policy("development", STORES["entries"], tmp_path))
    assert res.blocking_reasons == ("ISSUER_MISMATCH",)


@pytest.mark.parametrize("form", sorted(STORES))
@pytest.mark.parametrize("profile", PROFILES)
def test_control_another_tenants_key_id_never_verifies(form, profile, tmp_path):
    """Claiming A's key_id with B's key is caught by the key comparison on every form: it needs no issuer."""
    if form in UNBOUND and profile != "development":
        with pytest.raises(PolicyError, match="states the issuer of each key"):
            policy(profile, STORES[form], tmp_path)
        return
    pol = policy(profile, STORES[form], tmp_path)
    res = verify(report(signer(b"tenant-b", "alice-bank", "alice-1")), pol)
    assert not res.accepted and not res.issuer_trusted
    assert {"KEY_EMBEDDED_MISMATCH", "ISSUER_UNKNOWN"} & set(res.blocking_reasons)


@pytest.mark.parametrize("profile", PROFILES)
def test_control_the_honest_tenant_is_trusted_on_an_entries_store(profile, tmp_path):
    for who in (ALICE, BOB):
        res = verify(report(who), policy(profile, STORES["entries"], tmp_path))
        assert res.accepted and res.issuer_trusted and res.issuer == who.issuer


def test_control_every_entries_verdict_is_the_same_for_an_honest_report_as_a_legacy_one_today(tmp_path):
    a = verify(report(BOB), policy("development", STORES["entries"], tmp_path))
    b = verify(report(BOB), policy("development", STORES["legacy"], tmp_path))
    assert (a.trust_status, a.issuer_trusted) == (b.trust_status, b.issuer_trusted) == ("TRUSTED", True)


# ------------------------------------------------------------------ the other acceptance paths


@pytest.mark.parametrize(("form", "expected"), [("legacy", "TRUSTED"), ("bare", "TRUSTED"), ("entries", "INVALID")])
def test_verify_trusted_with_its_default_policy(form, expected):
    res = rf.verify_trusted(json.dumps(report(FORGED).to_dict()), rf.TrustStore.from_dict(STORES[form]))
    assert res.verdict.value == expected
    assert (res.reasons == ("ISSUER_MISMATCH",)) == (form == "entries")


@pytest.mark.parametrize(("form", "expected"), [("legacy", "TRUSTED"), ("entries", "INVALID")])
def test_the_lenient_engine_path(form, expected):
    env = parse_envelope(report(FORGED).to_dict())
    res = verify(env, VerificationPolicy(trust_store=rf.TrustStore.from_dict(STORES[form])))
    assert res.trust_status == expected


@pytest.mark.parametrize(("form", "expected"), [("legacy", "TRUSTED"), ("bare", "TRUSTED"), ("entries", "INVALID")])
def test_the_legacy_verifier_with_a_store(form, expected):
    res = verify_envelope(report(FORGED, "v1"), trust_store=rf.TrustStore.from_dict(STORES[form]))
    assert res.trust_status == expected
    assert res.issuer_trusted is (expected == "TRUSTED")


def test_the_legacy_verifier_with_a_plain_mapping():
    res = verify_envelope(report(FORGED, "v1"), trusted_keys=STORES["bare"])
    assert res.trust_status == "TRUSTED" and res.issuer_trusted and res.issuer == "alice-bank"


@pytest.mark.parametrize(("form", "expected"), [("legacy", True), ("bare", True), ("entries", False)])
def test_verify_receipt_and_verify_envelope_or_raise(form, expected):
    """The two other published entry points on the legacy verifier: same verdict as it, on every form."""
    env = report(FORGED, "v1")
    store = rf.TrustStore.from_dict(STORES[form])
    assert verify_receipt(env, trust_store=store) is expected
    if expected:
        assert verify_envelope_or_raise(env, trust_store=store).trust_status == "TRUSTED"
    else:
        with pytest.raises(UntrustedIssuer, match="issuer name"):
            verify_envelope_or_raise(env, trust_store=store)


def _cli(tmp_path: Path, form: str, profile: str) -> subprocess.CompletedProcess[str]:
    (tmp_path / "r.json").write_text(json.dumps(report(FORGED).to_dict()))
    (tmp_path / "t.json").write_text(json.dumps(STORES[form]))
    args = ["-i", "r.json", "--trusted-keys", "t.json", "--profile", profile]
    if profile != "development":
        args += ["--verifier-id", "reg", "--max-age-seconds", "3600", "--replay-mode", "record", "--replay-db", "x.db"]
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", "verify", *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=tmp_path,
        check=False,
    )


CLI_EXIT = {
    ("legacy", "development"): 0,
    ("legacy", "confidential"): 2,
    ("legacy", "high-assurance"): 2,
    ("entries", "development"): 1,
    ("entries", "confidential"): 1,
    ("entries", "high-assurance"): 1,
}


@pytest.mark.parametrize(("form", "profile"), sorted(CLI_EXIT))
def test_the_real_cli(form, profile, tmp_path):
    out = _cli(tmp_path, form, profile)
    assert out.returncode == CLI_EXIT[form, profile], out.stderr
    if form == "entries":
        assert json.loads(out.stdout)["reason"] == "ISSUER_MISMATCH"
    elif profile != "development":
        assert not out.stdout and "states the issuer of each key" in out.stderr and "trust add" in out.stderr


def _server(form: str, profile: str, tmp_path: Path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from regaudit_fhe.server import ServerConfig, build_app
    from tests._asgi import client_for

    kw = {}
    if profile != "development":
        kw = {
            "max_age_s": 3600,
            "verifier_id": "reg",
            "replay_mode": "record",
            "replay_cache": SqliteReplayCache(tmp_path / "http.db"),
        }
    cfg = ServerConfig(
        api_keys={},
        dev_mode=True,
        max_body_bytes=1 << 20,
        rate_limit_per_min=600,
        request_timeout_s=10.0,
        cors_origins=(),
        profile=profile,
        trust_store=rf.TrustStore.from_dict(STORES[form]),
        **kw,
    )
    return client_for(build_app(config=cfg), base_url="http://127.0.0.1:8000")


@pytest.mark.parametrize("profile", ["confidential", "high-assurance"])
@pytest.mark.parametrize("form", UNBOUND)
def test_the_http_server_will_not_start_on_a_store_without_issuers(form, profile, tmp_path):
    with pytest.raises(PolicyError, match="states the issuer of each key"):
        _server(form, profile, tmp_path)


@pytest.mark.parametrize(
    ("form", "profile", "expected"),
    [
        ("legacy", "development", "TRUSTED"),
        ("entries", "development", "INVALID"),
        ("entries", "confidential", "INVALID"),
        ("entries", "high-assurance", "INVALID"),
    ],
)
def test_the_http_server(form, profile, expected, tmp_path):
    client = _server(form, profile, tmp_path)
    res = client.post("/v1/verify", json={"envelope": report(FORGED).to_dict()})
    assert res.status_code == 200, res.text
    assert res.json()["trust_status"] == expected


def test_a_revocation_mode_already_refuses_a_store_without_issuers(tmp_path):
    from regaudit_fhe import _revocation_gate as gate
    from regaudit_fhe import _revocation_state as st

    ctx = gate.RevocationContext("advisory", st.FileStateStore(tmp_path / "state"), {})
    pol = VerificationPolicy(trust_store=rf.TrustStore.from_dict(STORES["legacy"]))
    with pytest.raises(PolicyError, match="REVOCATION_STORE_UNSUPPORTED"):
        gate.verify_with_revocation(report(FORGED), pol, ctx)


# ------------------------------------------------------------------ the refusal itself


@pytest.mark.parametrize("profile", ["confidential", "high-assurance"])
def test_verify_trusted_refuses_the_policy_not_the_report(profile, tmp_path):
    strict = policy(profile, STORES["entries"], tmp_path)
    with pytest.raises(PolicyError, match="states the issuer of each key"):
        rf.verify_trusted(json.dumps(report(ALICE).to_dict()), rf.TrustStore.from_dict(STORES["legacy"]), policy=strict)


@pytest.mark.parametrize("profile", ["confidential", "high-assurance"])
def test_a_strict_policy_cannot_be_moved_onto_a_store_without_issuers(profile, tmp_path):
    strict = policy(profile, STORES["entries"], tmp_path)
    with pytest.raises(PolicyError):
        dataclasses.replace(strict, trust_store=rf.TrustStore.from_dict(STORES["legacy"]))


def test_an_entry_built_without_an_issuer_does_not_count_as_bound(tmp_path):
    entry = KeyEntry(key_id="bob-1", public_key_pem=BOB.public_key_pem(), status="active", issuer=None)
    store = rf.TrustStore(keys={"bob-1": BOB.public_key_pem()}, entries={"bob-1": entry})
    assert not store.binds_issuers
    with pytest.raises(PolicyError):
        VerificationPolicy(
            profile="confidential",
            trust_store=store,
            max_age=timedelta(hours=1),
            replay_mode="record",
            replay_cache=SqliteReplayCache(tmp_path / "e.db"),
        )
