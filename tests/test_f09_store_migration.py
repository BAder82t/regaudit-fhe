"""The way off a store without issuers, run on reports really signed by the published 0.1.0, 0.1.1, 0.2.0 and 0.2.1 wheels."""

from __future__ import annotations

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
from regaudit_fhe._keys import spki_fingerprint
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2, parse_envelope
from regaudit_fhe.verification import PolicyError, VerificationPolicy, verify

HERE = Path(__file__).parent
VERSIONS = ("0.1.0", "0.1.1", "0.2.0", "0.2.1")
VECTORS = {
    v: json.loads((HERE / "experimental_revocation/published_vectors" / f"by_{v}.json").read_text()) for v in VERSIONS
}
CASES = [(v, kind) for v in VERSIONS for kind in sorted(VECTORS[v]["reports"])]
NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
PEM = VECTORS["0.2.1"]["public_key_pem"]
ISSUER = VECTORS["0.2.1"]["issuer"]
KEY_ID = VECTORS["0.2.1"]["key_id"]


def cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=cwd,
        check=False,
    )


def migrate(tmp_path: Path, source: dict, *issuers: str, target: str = "new.json") -> subprocess.CompletedProcess[str]:
    (tmp_path / "old.json").write_text(json.dumps(source))
    flags = [x for i in issuers for x in ("--issuer", i)]
    return cli("trust", "migrate", "--source", "old.json", "--target", target, *flags, cwd=tmp_path)


def store_from(tmp_path: Path, name: str = "new.json") -> rf.TrustStore:
    return rf.TrustStore.from_json(str(tmp_path / name))


def strict(profile: str, store: rf.TrustStore, tmp_path: Path) -> VerificationPolicy:
    return VerificationPolicy(
        profile=profile,
        trust_store=store,
        now=lambda: NOW,
        max_age=timedelta(days=90),
        verifier_id="reg",
        replay_mode="record",
        replay_cache=SqliteReplayCache(tmp_path / f"{profile}.db"),
    )


@pytest.mark.parametrize(("version", "kind"), CASES)
@pytest.mark.parametrize("form", ["bare", "legacy"])
def test_an_honest_published_report_gets_the_same_verdict_after_migrating(version, kind, form, tmp_path):
    source = {KEY_ID: PEM} if form == "bare" else {"keys": {KEY_ID: PEM}}
    out = migrate(tmp_path, source, f"{KEY_ID}={ISSUER}")
    assert out.returncode == 0, out.stderr
    env = parse_envelope(json.dumps(VECTORS[version]["reports"][kind]))
    before = verify(env, VerificationPolicy(trust_store=rf.TrustStore.from_dict(source), now=lambda: NOW))
    after = verify(env, VerificationPolicy(trust_store=store_from(tmp_path), now=lambda: NOW))
    assert before.trust_status == after.trust_status == "TRUSTED"
    assert after.issuer_trusted
    assert [r for r in before.reasons if r != "ISSUER_UNBOUND"] == [
        r for r in after.reasons if r != "ISSUER_OPERATOR_DECLARED"
    ]
    assert "ISSUER_OPERATOR_DECLARED" in after.reasons  # owner's ruling: a migration's issuer is labelled as a statement


@pytest.mark.parametrize("profile", ["confidential", "high-assurance", "secure-v1"])
def test_a_strict_policy_refuses_the_old_store_and_the_migrated_one(profile, tmp_path):
    """Owner's ruling: a migrated issuer is a local operator's statement, not an authenticated enrollment."""
    source = {"keys": {KEY_ID: PEM}}
    with pytest.raises(PolicyError, match="states the issuer of each key"):
        strict(profile, rf.TrustStore.from_dict(source), tmp_path)
    assert migrate(tmp_path, source, f"{KEY_ID}={ISSUER}").returncode == 0
    with pytest.raises(PolicyError, match="ISSUER_ENROLLMENT_UNAUTHENTICATED"):
        strict(profile, store_from(tmp_path), tmp_path)


@pytest.mark.parametrize(("version", "kind"), CASES)
@pytest.mark.parametrize("profile", ["confidential", "high-assurance", "secure-v1"])
def test_the_upgrade_path_left_is_trust_add_in_a_new_store(version, kind, profile, tmp_path):
    (tmp_path / "k.pub").write_text(PEM)
    out = cli(
        "trust", "add", "--store", "t.json", "--key-id", KEY_ID, "--issuer", ISSUER, "--public-key", "k.pub",
        "--fingerprint", spki_fingerprint(PEM), cwd=tmp_path,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    res = verify(
        parse_envelope(json.dumps(VECTORS[version]["reports"][kind])),
        strict(profile, store_from(tmp_path, "t.json"), tmp_path),
    )
    # As the published 0.2.1 wheel decides with an entries store: report.v1 is refused in these policies whatever the
    # store, and high-assurance needs an audience.
    expected = kind == "v2-audience" or (kind == "v2-no-audience" and profile != "high-assurance")
    assert res.accepted is expected, res.blocking_reasons
    assert "ISSUER_MISMATCH" not in res.blocking_reasons


@pytest.mark.parametrize(("version", "kind"), CASES)
def test_stating_another_issuer_refuses_that_tenants_reports(version, kind, tmp_path):
    assert migrate(tmp_path, {"keys": {KEY_ID: PEM}}, f"{KEY_ID}=someone-else").returncode == 0
    res = verify(
        parse_envelope(json.dumps(VECTORS[version]["reports"][kind])),
        VerificationPolicy(trust_store=store_from(tmp_path), now=lambda: NOW),
    )
    assert not res.accepted and "ISSUER_MISMATCH" in res.blocking_reasons


def test_the_published_0_1_0_store_and_reports(tmp_path):
    base = HERE / "vectors/published_0_1_0"
    source = json.loads((base / "trust_store_legacy.json").read_text())
    entries = json.loads((base / "trust_store_entries.json").read_text())["entries"]
    stated = [f"{k}={v['issuer']}" for k, v in entries.items()]
    out = migrate(tmp_path, source, *stated)
    assert out.returncode == 0, out.stderr
    old = rf.TrustStore.from_dict(source)
    new = store_from(tmp_path)
    assert set(new.keys) == set(old.keys)
    assert new.binds_issuers and not old.binds_issuers
    seen = 0
    for path in sorted(base.glob("v[12]_*.json")):
        env = parse_envelope(path.read_text())
        a = verify(env, VerificationPolicy(trust_store=old, now=lambda: NOW))
        b = verify(env, VerificationPolicy(trust_store=new, now=lambda: NOW))
        assert (a.trust_status, a.accepted) == (b.trust_status, b.accepted), path.name
        seen += 1
    assert seen >= 10  # the loop did run over the published reports


def test_the_source_is_left_as_it_was_and_an_existing_target_is_refused(tmp_path):
    source = {"keys": {KEY_ID: PEM}}
    assert migrate(tmp_path, source, f"{KEY_ID}={ISSUER}").returncode == 0
    raw = (tmp_path / "old.json").read_bytes()
    assert json.loads(raw) == source
    written = (tmp_path / "new.json").read_bytes()
    again = migrate(tmp_path, source, f"{KEY_ID}={ISSUER}")
    assert again.returncode != 0 and (tmp_path / "new.json").read_bytes() == written


def test_an_issuer_is_never_inferred(tmp_path):
    out = migrate(tmp_path, {"keys": {KEY_ID: PEM}})
    assert out.returncode == 2 and "never inferred" in out.stderr
    assert not (tmp_path / "new.json").exists()


def test_a_dry_run_writes_nothing(tmp_path):
    (tmp_path / "old.json").write_text(json.dumps({"keys": {KEY_ID: PEM}}))
    out = cli(
        "trust", "migrate", "--source", "old.json", "--target", "new.json", "--issuer", f"{KEY_ID}={ISSUER}", "--dry-run",
        cwd=tmp_path,
    )  # fmt: skip
    assert out.returncode == 0 and not (tmp_path / "new.json").exists()


def test_a_revoked_key_stays_refused_and_a_pin_stays(tmp_path):
    pin = VECTORS["0.2.1"]["reports"]["v2-audience"]["parameter_set_hash"]
    source = {"keys": {KEY_ID: PEM}, "revoked": [KEY_ID], "parameter_set_pins": {KEY_ID: pin}}
    assert migrate(tmp_path, source, f"{KEY_ID}={ISSUER}").returncode == 0
    new = store_from(tmp_path)
    assert new.entry(KEY_ID).parameter_set_pin == pin
    env = parse_envelope(json.dumps(VECTORS["0.2.1"]["reports"]["v2-audience"]))
    res = verify(env, VerificationPolicy(trust_store=new, now=lambda: NOW))
    assert not res.accepted and res.blocking_reasons == ("KEY_COMPROMISED_NO_CHRONOLOGY",)


def test_a_known_limit_one_key_that_signed_under_two_names_keeps_only_the_stated_one(tmp_path):
    """An entries store has one issuer per key. Reports under a former name are refused after migrating, and that is the
    property working: it cannot tell a rename from a substitution. The operator enrolls under one name, or a new key."""
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"renamed").digest())
    result = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    signed = {}
    for name in ("old-name", "new-name"):
        who = rf.Signer(issuer=name, key_id="k", private_key=key, public_key=key.public_key())
        signed[name] = envelope_v2(
            "drift", result, signer=who, deployment_id="p", issued_at=NOW, audit_run_id="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6aa"
        )
    assert migrate(tmp_path, {"keys": {"k": who.public_key_pem()}}, "k=new-name").returncode == 0
    pol = VerificationPolicy(trust_store=store_from(tmp_path), now=lambda: NOW)
    assert verify(signed["new-name"], pol).accepted
    assert verify(signed["old-name"], pol).blocking_reasons == ("ISSUER_MISMATCH",)
