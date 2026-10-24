"""Phase 1: ``/v1/verify`` fails closed without an authenticated issuer."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

import regaudit_fhe as rf
from regaudit_fhe.server import (
    ServerConfig,
    assert_safe_bind,
    build_app,
    load_config_from_env,
)
from regaudit_fhe.trust import TrustStore, TrustStoreError


def _config(**overrides) -> ServerConfig:
    base = dict(
        api_keys={},
        dev_mode=True,
        max_body_bytes=1 << 20,
        rate_limit_per_min=600,
        request_timeout_s=10.0,
        cors_origins=(),
    )
    base.update(overrides)
    return ServerConfig(**base)


def _signed_env(signer: rf.Signer) -> dict:
    report = rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )
    return rf.envelope("fairness", report, signer=signer).to_dict()


def _store(signer: rf.Signer, **extra) -> TrustStore:
    return TrustStore.from_dict({"keys": {signer.key_id: signer.public_key_pem()}, **extra})


def _verify(client: TestClient, env: dict):
    return client.post("/v1/verify", json={"envelope": env})


@pytest.fixture
def signer() -> rf.Signer:
    return rf.Signer.generate(issuer="acme", key_id="acme-1")


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------


def test_verify_without_trust_store_fails_closed(signer):
    client = TestClient(build_app(config=_config()))
    r = _verify(client, _signed_env(signer))
    assert r.status_code == 503
    assert "valid" not in r.json() or r.json()["valid"] is not True
    assert "trust store" in r.text.lower()


def test_verify_with_trust_store_trusted_issuer(signer):
    client = TestClient(build_app(config=_config(trust_store=_store(signer))))
    r = _verify(client, _signed_env(signer))
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert body["trust_status"] == "TRUSTED"
    # Existing response contract is preserved.
    assert {"primitive", "issued_at", "regulations"} <= set(body)


def test_verify_unknown_issuer_is_invalid(signer):
    other = rf.Signer.generate(issuer="mallory", key_id="mal-1")
    client = TestClient(build_app(config=_config(trust_store=_store(signer))))
    body = _verify(client, _signed_env(other)).json()
    assert body["valid"] is False
    assert body["trust_status"] == "INVALID"


def test_verify_revoked_issuer_is_invalid(signer):
    client = TestClient(
        build_app(config=_config(trust_store=_store(signer, revoked=[signer.key_id])))
    )
    body = _verify(client, _signed_env(signer)).json()
    assert body["valid"] is False
    assert body["trust_status"] == "INVALID"


def test_verify_tampered_envelope_is_invalid(signer):
    client = TestClient(build_app(config=_config(trust_store=_store(signer))))
    env = _signed_env(signer)
    env["result"]["tampered"] = True
    body = _verify(client, env).json()
    assert body["valid"] is False
    assert body["trust_status"] == "INVALID"


def test_verify_requires_verified_timestamp_when_configured(signer):
    tsa = rf.TimestampAuthority(issuer="t", sign_callable=lambda b: b"tok")
    report = rf.audit_fairness(
        np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([0.0, 1.0])
    )
    env = rf.envelope("fairness", report, signer=signer, timestamp_authority=tsa).to_dict()
    store = _store(signer)
    lenient = TestClient(build_app(config=_config(trust_store=store)))
    assert _verify(lenient, env).json()["valid"] is True
    strict = TestClient(
        build_app(config=_config(trust_store=store, require_verified_timestamp=True))
    )
    body = _verify(strict, env).json()
    assert body["valid"] is False
    assert body["timestamp_status"] == "UNVERIFIED"
    verified = TestClient(
        build_app(
            config=_config(
                trust_store=store,
                require_verified_timestamp=True,
                tsa_verifier=lambda body, token: token == b"tok",
            )
        )
    )
    assert _verify(verified, env).json()["valid"] is True


# ---------------------------------------------------------------------------
# Development-only escape hatch
# ---------------------------------------------------------------------------


def test_allow_self_signed_never_reports_trusted(signer):
    client = TestClient(build_app(config=_config(allow_self_signed=True)))
    r = _verify(client, _signed_env(signer))
    assert r.status_code == 200
    body = r.json()
    assert body["trust_status"] == "SELF_SIGNED_ONLY"
    assert body["valid"] is False  # never satisfies a trusted-issuer policy
    assert body["integrity_valid"] is True


def test_allow_self_signed_does_not_bypass_a_configured_trust_store(signer):
    other = rf.Signer.generate(issuer="mallory", key_id="mal-1")
    client = TestClient(
        build_app(config=_config(allow_self_signed=True, trust_store=_store(signer)))
    )
    body = _verify(client, _signed_env(other)).json()
    assert body["trust_status"] == "INVALID"
    assert body["valid"] is False
    good = _verify(client, _signed_env(signer)).json()
    assert good["trust_status"] == "TRUSTED"


@pytest.mark.parametrize("profile", ["confidential", "high-assurance"])
def test_allow_self_signed_refused_in_production_profiles(profile):
    with pytest.raises(RuntimeError, match="allow-self-signed"):
        build_app(config=_config(allow_self_signed=True, profile=profile))


def test_allow_self_signed_allowed_in_development_profile():
    build_app(config=_config(allow_self_signed=True, profile="development"))


def test_unknown_profile_refused():
    with pytest.raises(RuntimeError, match="profile"):
        build_app(config=_config(profile="prod"))


@pytest.mark.parametrize("host", ["0.0.0.0", "10.0.0.5", "example.com"])
def test_allow_self_signed_refuses_non_loopback_bind(host):
    with pytest.raises(RuntimeError, match="allow-self-signed"):
        assert_safe_bind(host, dev_mode=False, allow_self_signed=True)


def test_allow_self_signed_permits_loopback_bind():
    assert_safe_bind("127.0.0.1", dev_mode=False, allow_self_signed=True)


# ---------------------------------------------------------------------------
# Config loading fails closed
# ---------------------------------------------------------------------------


def test_env_trust_store_missing_file_raises(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("REGAUDIT_FHE_TRUST_STORE", str(tmp_path / "missing.json"))
    with pytest.raises(TrustStoreError):
        load_config_from_env()


def test_env_trust_store_malformed_raises(monkeypatch, tmp_path: Path):
    p = tmp_path / "ts.json"
    p.write_text("{nope")
    monkeypatch.setenv("REGAUDIT_FHE_TRUST_STORE", str(p))
    with pytest.raises(TrustStoreError):
        load_config_from_env()


def test_env_trust_store_valid_loads(monkeypatch, tmp_path: Path, signer):
    p = tmp_path / "ts.json"
    p.write_text(json.dumps({"keys": {signer.key_id: signer.public_key_pem()}}))
    monkeypatch.setenv("REGAUDIT_FHE_TRUST_STORE", str(p))
    cfg = load_config_from_env()
    assert cfg.trust_store is not None and cfg.trust_store.is_known(signer.key_id)


def test_env_allow_self_signed_in_high_assurance_raises(monkeypatch):
    monkeypatch.setenv("REGAUDIT_FHE_ALLOW_SELF_SIGNED", "1")
    monkeypatch.setenv("REGAUDIT_FHE_PROFILE", "high-assurance")
    with pytest.raises(RuntimeError, match="allow-self-signed"):
        load_config_from_env()


def test_env_defaults_do_not_allow_self_signed(monkeypatch):
    monkeypatch.delenv("REGAUDIT_FHE_ALLOW_SELF_SIGNED", raising=False)
    monkeypatch.delenv("REGAUDIT_FHE_PROFILE", raising=False)
    monkeypatch.delenv("REGAUDIT_FHE_TRUST_STORE", raising=False)
    cfg = load_config_from_env()
    assert cfg.allow_self_signed is False
    assert cfg.trust_store is None
    assert cfg.profile == "development"


@pytest.mark.parametrize("body", [{}, {"schema": "regaudit-fhe.report.v1"}])
def test_malformed_envelope_is_rejected_not_500(signer, body):
    client = TestClient(build_app(config=_config(trust_store=_store(signer))))
    r = client.post("/v1/verify", json={"envelope": body})
    assert r.status_code == 422
    # control: a well-formed envelope from the registered issuer is accepted
    assert _verify(client, _signed_env(signer)).status_code == 200


def test_cli_trust_store_flag_overrides_broken_env_var(monkeypatch, tmp_path: Path, signer):
    import regaudit_fhe.cli as cli

    pytest.importorskip("uvicorn")
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"keys": {signer.key_id: signer.public_key_pem()}}))
    started: dict = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: started.update(app=app))
    monkeypatch.setenv("REGAUDIT_FHE_TRUST_STORE", str(tmp_path / "missing.json"))
    assert cli.main(["serve", "--trust-store", str(good)]) == 0
    assert "app" in started
    # control: the broken env var alone still aborts startup
    started.clear()
    assert cli.main(["serve"]) == 2
    assert not started
