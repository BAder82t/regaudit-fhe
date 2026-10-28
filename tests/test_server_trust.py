"""Phase 1: ``/v1/verify`` fails closed without an authenticated issuer."""

from __future__ import annotations

import importlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

import regaudit_fhe as rf
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.server import (
    ServerConfig,
    assert_safe_bind,
    build_app,
    check_dev_exposure,
    load_config_from_env,
)
from regaudit_fhe.trust import TrustStore, TrustStoreError
from regaudit_fhe.verification import TimestampEvidence
from tests._asgi import client_for


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


LOOPBACK = "http://127.0.0.1:8000"


def _client(config: ServerConfig, *, base_url: str = LOOPBACK) -> TestClient:
    """A client whose server socket is loopback (Starlette defaults to 'testserver')."""
    return client_for(build_app(config=config), base_url=base_url)


def _signed_env(signer: rf.Signer) -> dict:
    report = rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )
    return rf.envelope("fairness", report, signer=signer).to_dict()


def _store(signer: rf.Signer, **over) -> TrustStore:
    entry = {"issuer": signer.issuer, "public_key_pem": signer.public_key_pem(), "status": "active"}
    entry.update(over)
    return TrustStore.from_dict({"entries": {signer.key_id: entry}})


def _verify(client: TestClient, env: dict):
    return client.post("/v1/verify", json={"envelope": env})


@pytest.fixture
def signer() -> rf.Signer:
    return rf.Signer.generate(issuer="acme", key_id="acme-1")


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------


def test_verify_without_trust_store_fails_closed(signer):
    client = _client(_config())
    r = _verify(client, _signed_env(signer))
    assert r.status_code == 503
    assert "valid" not in r.json() or r.json()["valid"] is not True
    assert "trust store" in r.text.lower()


def test_verify_with_trust_store_trusted_issuer(signer):
    client = _client(_config(trust_store=_store(signer)))
    r = _verify(client, _signed_env(signer))
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert body["trust_status"] == "TRUSTED"
    # Existing response contract is preserved.
    assert {"primitive", "issued_at", "regulations"} <= set(body)


def test_verify_unknown_issuer_is_invalid(signer):
    other = rf.Signer.generate(issuer="mallory", key_id="mal-1")
    client = _client(_config(trust_store=_store(signer)))
    body = _verify(client, _signed_env(other)).json()
    assert body["valid"] is False
    assert body["trust_status"] == "INVALID"


def test_verify_revoked_issuer_is_invalid(signer):
    client = _client(_config(trust_store=_store(signer, status="compromised")))
    body = _verify(client, _signed_env(signer)).json()
    assert body["valid"] is False
    assert body["trust_status"] == "INVALID"


def test_verify_tampered_envelope_is_invalid(signer):
    client = _client(_config(trust_store=_store(signer)))
    env = _signed_env(signer)
    env["result"]["tampered"] = True
    body = _verify(client, env).json()
    assert body["valid"] is False
    assert body["trust_status"] == "INVALID"


def _v2_env(signer: rf.Signer, **kw) -> rf.report_v2.AuditEnvelopeV2:
    report = rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )
    return envelope_v2("fairness", report, signer=signer, deployment_id="prod-eu-1", **kw)


def test_verify_accepts_a_v2_envelope_from_a_registered_issuer(signer):
    client = _client(_config(trust_store=_store(signer)))
    body = _verify(client, _v2_env(signer).to_dict()).json()
    assert body["valid"] is True and body["accepted"] is True
    assert body["trust_status"] == "TRUSTED" and body["format"] == "v2"
    assert body["key_status"] == "active" and body["issuer_trusted"] is True
    assert body["policy_id"] == "regaudit-fhe/development/v1"


def test_verify_requires_verified_timestamp_when_configured(signer):
    now = datetime.now(timezone.utc)
    stamp_time = now - timedelta(hours=1)

    def tsa_verifier(digest: bytes, token: bytes):
        return TimestampEvidence(gen_time=stamp_time) if token == b"ok:" + digest else None

    env = _v2_env(signer)
    stamped = env.with_timestamp(
        issuer="t", token=b"ok:" + env.sealed_digest(), issued_at=stamp_time
    )
    store = _store(signer)
    lenient = _client(_config(trust_store=store))
    assert _verify(lenient, stamped.to_dict()).json()["valid"] is True
    # required, but no verifier is pinned: the configuration itself is refused
    with pytest.raises(RuntimeError, match="timestamp"):
        build_app(config=_config(trust_store=store, require_verified_timestamp=True))
    required = _client(
        _config(trust_store=store, require_verified_timestamp=True, timestamp_verifier=tsa_verifier)
    )
    ok = _verify(required, stamped.to_dict()).json()
    assert ok["valid"] is True and ok["timestamp_status"] == "VERIFIED"
    for unverified in (env, env.with_timestamp(issuer="t", token=b"junk", issued_at=stamp_time)):
        body = _verify(required, unverified.to_dict()).json()
        assert body["valid"] is False and body["trust_status"] == "INVALID"


def test_v1_timestamp_never_satisfies_a_required_timestamp_policy(signer):
    tsa = rf.TimestampAuthority(issuer="t", sign_callable=lambda b: b"tok")
    report = rf.audit_fairness(
        np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([0.0, 1.0])
    )
    v1 = rf.envelope("fairness", report, signer=signer, timestamp_authority=tsa).to_dict()
    client = _client(
        _config(
            trust_store=_store(signer),
            require_verified_timestamp=True,
            timestamp_verifier=lambda d, t: TimestampEvidence(gen_time=datetime.now(timezone.utc)),
        )
    )
    body = _verify(client, v1).json()
    assert body["valid"] is False and "TIMESTAMP_REQUIRED" in body["reasons"]


# ---------------------------------------------------------------------------
# Request parsing: strict, bounded, no 500s
# ---------------------------------------------------------------------------


def test_duplicate_json_keys_in_the_request_are_refused(signer):
    client = _client(_config(trust_store=_store(signer)))
    env = json.dumps(_v2_env(signer).to_dict())
    good = '{"envelope": ' + env + "}"
    assert client.post("/v1/verify", content=good).status_code == 200  # control
    dup = '{"envelope": ' + env + ', "envelope": ' + env + "}"
    assert client.post("/v1/verify", content=dup).status_code == 422
    inner_dup = '{"envelope": ' + env[:-1] + ', "issuer": "mallory"}}'
    assert client.post("/v1/verify", content=inner_dup).status_code == 422


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"[]",
        b'{"envelope": []}',
        b'{"envelope": {}, "extra": 1}',
        b'{"envelope": {"schema": "regaudit-fhe.report.v9"}}',
        b'{"envelope": NaN}',
        b"\xff\xfe",
    ],
)
def test_malformed_requests_are_422_not_500(signer, raw):
    client = _client(_config(trust_store=_store(signer)))
    assert client.post("/v1/verify", content=raw).status_code == 422


def test_chunked_bodies_cannot_bypass_the_size_limit(signer):
    client = _client(_config(trust_store=_store(signer), max_body_bytes=1024))

    def chunks():
        for _ in range(64):
            yield b"x" * 1024  # no Content-Length header is sent for a generator

    assert client.post("/v1/verify", content=chunks()).status_code == 413
    small = '{"envelope": ' + json.dumps(_v2_env(signer).to_dict()) + "}"
    assert len(small) > 1024
    assert client.post("/v1/verify", content=small).status_code == 413  # also by Content-Length


# ---------------------------------------------------------------------------
# Development-only escape hatch
# ---------------------------------------------------------------------------


def test_allow_self_signed_never_reports_trusted(signer):
    client = _client(_config(allow_self_signed=True))
    r = _verify(client, _signed_env(signer))
    assert r.status_code == 200
    body = r.json()
    assert body["trust_status"] == "SELF_SIGNED_ONLY"
    assert body["valid"] is False  # never satisfies a trusted-issuer policy
    assert body["integrity_valid"] is True


def test_allow_self_signed_does_not_bypass_a_configured_trust_store(signer):
    other = rf.Signer.generate(issuer="mallory", key_id="mal-1")
    client = _client(_config(allow_self_signed=True, trust_store=_store(signer)))
    body = _verify(client, _signed_env(other)).json()
    assert body["trust_status"] == "INVALID"
    assert body["valid"] is False
    good = _verify(client, _signed_env(signer)).json()
    assert good["trust_status"] == "TRUSTED"


def test_allow_self_signed_is_refused_on_a_non_loopback_socket(signer):
    """Request-time enforcement: it holds for an embedded build_app() too."""
    config = _config(allow_self_signed=True)
    assert _verify(_client(config), _signed_env(signer)).status_code == 200  # control
    for base in ("http://192.168.1.5:8000", "http://0.0.0.0:8000", "http://testserver"):
        remote = client_for(build_app(config=config), base_url=base)
        r = _verify(remote, _signed_env(signer))
        assert r.status_code == 403, base
        assert "valid" not in r.json() and "trust_status" not in r.json()


@pytest.mark.parametrize(
    "header",
    ["X-Forwarded-For", "Forwarded", "X-Real-IP", "X-Forwarded-Host", "X-Forwarded-Proto"],
)
def test_forwarding_headers_are_never_proof_of_loopback(signer, header):
    client = _client(_config(allow_self_signed=True))
    assert _verify(client, _signed_env(signer)).status_code == 200  # control
    value = "127.0.0.1"
    r = client.post("/v1/verify", json={"envelope": _signed_env(signer)}, headers={header: value})
    assert r.status_code == 403


def test_profile_is_rechecked_at_request_time(signer):
    config = _config(allow_self_signed=True)
    client = _client(config)
    assert _verify(client, _signed_env(signer)).status_code == 200  # control
    object.__setattr__(config, "profile", "confidential")  # simulate a tampered config object
    assert _verify(client, _signed_env(signer)).status_code == 403


def test_the_dev_option_is_inert_when_a_trust_store_is_configured(signer):
    """With a store the hatch is not in play, so it must not add a restriction
    or a bypass: a remote socket is still served, and still only TRUSTED/INVALID."""
    config = _config(allow_self_signed=True, trust_store=_store(signer))
    remote = client_for(build_app(config=config), base_url="http://192.168.1.5:8000")
    r = _verify(remote, _signed_env(signer))
    assert r.status_code == 200 and r.json()["trust_status"] == "TRUSTED"


def _scope(server=("127.0.0.1", 8000), client=("127.0.0.1", 5555)):
    return {"server": server, "client": client}


@pytest.mark.parametrize(
    "server",
    [("127.0.0.1", 80), ("::1", 80), ("127.5.5.5", 80)],
)
def test_exposure_allows_loopback_tcp_sockets(server):
    assert check_dev_exposure(_scope(server=server), {}, ()) is None


@pytest.mark.parametrize(
    "server",
    [
        ("0.0.0.0", 80),
        ("10.0.0.5", 80),
        ("example.com", 80),
        ("testserver", 80),
        ("", 80),
        None,
        ("/run/regaudit.sock", None),  # Unix sockets are refused for the development option
    ],
)
def test_exposure_refuses_everything_else(server):
    assert check_dev_exposure(_scope(server=server), {}, ()) is not None


def test_exposure_trusted_proxy_policy():
    proxies = ("10.0.0.0/24",)
    peer = ("10.0.0.7", 4000)
    ok = {"x-forwarded-for": "127.0.0.1"}
    # no policy: any forwarding header refuses, and says why
    reason = check_dev_exposure(_scope(client=peer), ok, ())
    assert reason is not None and "trusted-proxy policy" in reason
    # trusted peer, loopback origin: allowed (control)
    assert check_dev_exposure(_scope(client=peer), ok, proxies) is None
    # untrusted peer cannot vouch for anything
    assert check_dev_exposure(_scope(client=("203.0.113.5", 1)), ok, proxies) is not None
    # no X-Forwarded-For to establish the origin
    assert check_dev_exposure(_scope(client=peer), {"x-real-ip": "127.0.0.1"}, proxies) is not None
    # external origin
    assert (
        check_dev_exposure(_scope(client=peer), {"x-forwarded-for": "203.0.113.9"}, proxies)
        is not None
    )
    # a client-supplied leftmost loopback entry is ignored: the proxy appended the real origin
    spoof = {"x-forwarded-for": "127.0.0.1, 203.0.113.9"}
    assert check_dev_exposure(_scope(client=peer), spoof, proxies) is not None
    # chain through a second trusted proxy still resolves to the loopback origin
    chain = {"x-forwarded-for": "127.0.0.1, 10.0.0.9"}
    assert check_dev_exposure(_scope(client=peer), chain, proxies) is None
    # garbage in the header refuses
    assert check_dev_exposure(_scope(client=peer), {"x-forwarded-for": "not-an-ip"}, proxies)


def test_exposure_refuses_malformed_trusted_proxy_entries():
    assert check_dev_exposure(
        _scope(client=("10.0.0.7", 1)), {"x-forwarded-for": "127.0.0.1"}, ("garbage",)
    )


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
    client = _client(_config(trust_store=_store(signer)))
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


# ---------------------------------------------------------------------------
# Security review findings (round 2)
# ---------------------------------------------------------------------------


def test_exposure_also_requires_a_loopback_client_when_one_is_reported():
    assert check_dev_exposure(_scope(client=("127.0.0.1", 1)), {}, ()) is None  # control
    assert check_dev_exposure(_scope(client=("203.0.113.9", 5555)), {}, ()) is not None
    # no peer information: the origin cannot be established, so the option is refused
    assert check_dev_exposure(_scope(client=None), {}, ()) is not None


@pytest.mark.parametrize(
    "header", ["x-client-ip", "true-client-ip", "cf-connecting-ip", "via", "x-forwarded-server"]
)
def test_more_forwarding_headers_are_treated_as_proxy_evidence(header):
    assert check_dev_exposure(_scope(), {}, ()) is None  # control
    assert check_dev_exposure(_scope(), {header: "127.0.0.1"}, ()) is not None


def test_ipv4_mapped_loopback_is_recognised():
    assert check_dev_exposure(_scope(server=("::ffff:127.0.0.1", 80)), {}, ()) is None
    assert check_dev_exposure(_scope(server=("::ffff:10.0.0.5", 80)), {}, ()) is not None


class _MultiHeaders:
    """Starlette-style headers: one name may carry several lines."""

    def __init__(self, lines):
        self._lines = list(lines)

    def __contains__(self, name):
        return any(k.lower() == name.lower() for k, _ in self._lines)

    def get(self, name, default=None):
        # a naive .get() sees only the FIRST line (the client-controlled one)
        for k, v in self._lines:
            if k.lower() == name.lower():
                return v
        return default

    def getlist(self, name):
        return [v for k, v in self._lines if k.lower() == name.lower()]


def test_every_x_forwarded_for_line_is_considered():
    proxies = ("10.0.0.0/24",)
    peer = ("10.0.0.7", 4000)
    lines = [("x-forwarded-for", "127.0.0.1"), ("x-forwarded-for", "203.0.113.9")]
    # a client-supplied first line claims loopback; the proxy appended the real origin
    assert check_dev_exposure(_scope(client=peer), _MultiHeaders(lines), proxies) is not None
    honest = [("x-forwarded-for", "127.0.0.1")]
    assert check_dev_exposure(_scope(client=peer), _MultiHeaders(honest), proxies) is None


def test_slow_verification_does_not_block_the_event_loop(signer, monkeypatch):
    """Deterministic: the slow verifier waits for a release that only the event
    loop can grant (after serving /healthz). If verification ran on the loop,
    the release could never happen and the wait would time out."""
    import asyncio
    import threading

    import httpx

    server_mod = importlib.import_module("regaudit_fhe.server")

    real = server_mod.verify
    released = threading.Event()
    outcome: dict[str, bool] = {}

    def slow(env, policy):
        outcome["released_in_time"] = released.wait(timeout=5.0)
        return real(env, policy)

    monkeypatch.setattr(server_mod, "verify", slow)
    app = build_app(config=_config(trust_store=_store(signer)))
    body = {"envelope": _v2_env(signer).to_dict()}

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 1))
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as c:
            slow_call = asyncio.create_task(c.post("/v1/verify", json=body))
            await asyncio.sleep(0.05)
            health = await c.get("/healthz")  # needs a free event loop
            assert health.status_code == 200
            released.set()
            assert (await slow_call).status_code == 200

    asyncio.run(scenario())
    assert outcome["released_in_time"] is True


def test_max_age_zero_or_non_finite_is_a_configuration_error_not_no_limit(signer):
    store = _store(signer)
    assert build_app(config=_config(trust_store=store, max_age_s=3600.0))  # control
    for bad in (0.0, -5.0, float("nan"), float("inf"), 1e300):
        with pytest.raises(RuntimeError, match="max_age"):
            build_app(config=_config(trust_store=store, max_age_s=bad))


def test_server_module_exports_are_stable_and_the_old_model_is_gone():
    server = importlib.import_module("regaudit_fhe.server")

    assert hasattr(server, "build_app") and not hasattr(server, "VerifyRequest")


# ---------------------------------------------------------------------------
# Strict parsing on the verification path (0.2.0)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update(approved_by="regulator"),
        lambda e: e.update(regulations="AB"),
        lambda e: e.pop("backend"),
        lambda e: e["receipt"].update(note="unsigned"),
        lambda e: e.update(primitive=["fairness"]),
    ],
    ids=["unknown-member", "coerced-list", "defaulted-member", "receipt-extra", "primitive-type"],
)
def test_ambiguous_v1_json_is_not_verified_at_all(signer, mutate):
    env = _signed_env(signer)
    config = _config(trust_store=_store(signer))
    with _client(config) as client:
        assert _verify(client, env).status_code == 200  # the unmodified report is TRUSTED
        mutate(env)
        resp = _verify(client, env)
    assert resp.status_code == 422, resp.text
