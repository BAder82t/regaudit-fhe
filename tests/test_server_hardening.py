"""Production-hardening tests for the HTTP audit server.

Covers authentication, scope-based authorization, body size limit,
rate limiting, request-id propagation, CORS, structured logging, the
privacy-boundary warning, and the no-payload-in-logs guarantee.
"""

from __future__ import annotations

import io
import logging

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from regaudit_fhe.server import (
    PRIVACY_WARNING,
    ServerConfig,
    TokenBucketRateLimiter,
    assert_safe_bind,
    build_app,
)

VALID_FAIRNESS = {
    "y_true": [1, 0, 1, 0],
    "y_pred": [1, 0, 0, 0],
    "group_a": [1, 1, 0, 0],
    "group_b": [0, 0, 1, 1],
    "threshold": 0.1,
}


def _config(**overrides) -> ServerConfig:
    base = dict(
        api_keys={},
        dev_mode=False,
        max_body_bytes=1 << 20,
        rate_limit_per_min=600,
        request_timeout_s=10.0,
        cors_origins=(),
    )
    base.update(overrides)
    return ServerConfig(**base)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_missing_bearer_token_returns_401():
    app = build_app(config=_config(api_keys={"k1": frozenset({"audit:run"})}))
    r = TestClient(app).post("/v1/audit/fairness", json=VALID_FAIRNESS)
    assert r.status_code == 401
    assert "Bearer" in r.headers.get("WWW-Authenticate", "")


def test_unknown_bearer_token_returns_401():
    app = build_app(config=_config(api_keys={"k1": frozenset({"audit:run"})}))
    r = TestClient(app).post(
        "/v1/audit/fairness", json=VALID_FAIRNESS, headers={"Authorization": "Bearer wrong"}
    )
    assert r.status_code == 401


def test_valid_bearer_token_passes_auth():
    app = build_app(config=_config(api_keys={"k1": frozenset({"audit:run"})}))
    r = TestClient(app).post(
        "/v1/audit/fairness", json=VALID_FAIRNESS, headers={"Authorization": "Bearer k1"}
    )
    assert r.status_code == 200, r.text


def test_dev_mode_disables_auth():
    app = build_app(config=_config(dev_mode=True))
    r = TestClient(app).post("/v1/audit/fairness", json=VALID_FAIRNESS)
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Authorization (scopes)
# ---------------------------------------------------------------------------


def test_missing_scope_returns_403():
    app = build_app(config=_config(api_keys={"k1": frozenset({"audit:read"})}))
    r = TestClient(app).post(
        "/v1/audit/fairness", json=VALID_FAIRNESS, headers={"Authorization": "Bearer k1"}
    )
    assert r.status_code == 403
    assert "audit:run" in r.json()["detail"]


def test_admin_scope_grants_every_action():
    app = build_app(config=_config(api_keys={"root": frozenset({"admin"})}))
    headers = {"Authorization": "Bearer root"}
    c = TestClient(app)
    assert c.post("/v1/audit/fairness", json=VALID_FAIRNESS, headers=headers).status_code == 200
    assert c.get("/v1/schemas", headers=headers).status_code == 200


# ---------------------------------------------------------------------------
# Body size limit
# ---------------------------------------------------------------------------


def test_request_body_above_limit_returns_413():
    app = build_app(config=_config(api_keys={"k1": frozenset({"audit:run"})}, max_body_bytes=128))
    big = {
        "y_true": [1, 0] * 1000,
        "y_pred": [1, 0] * 1000,
        "group_a": [1] * 2000,
        "group_b": [0] * 2000,
    }
    r = TestClient(app).post("/v1/audit/fairness", json=big, headers={"Authorization": "Bearer k1"})
    assert r.status_code == 413


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


def test_rate_limit_returns_429_when_exhausted():
    app = build_app(config=_config(api_keys={"k1": frozenset({"audit:run"})}, rate_limit_per_min=2))
    headers = {"Authorization": "Bearer k1"}
    c = TestClient(app)
    assert c.post("/v1/audit/fairness", json=VALID_FAIRNESS, headers=headers).status_code == 200
    assert c.post("/v1/audit/fairness", json=VALID_FAIRNESS, headers=headers).status_code == 200
    r = c.post("/v1/audit/fairness", json=VALID_FAIRNESS, headers=headers)
    assert r.status_code == 429
    assert r.headers.get("Retry-After") == "60"


def test_token_bucket_refills_over_time():
    bucket = TokenBucketRateLimiter(60)
    for _ in range(60):
        assert bucket.acquire("k") is True
    assert bucket.acquire("k") is False
    bucket._buckets["k"][1] -= 2.5  # simulate ~2.5 s elapsed
    assert bucket.acquire("k") is True


# ---------------------------------------------------------------------------
# Request-id and structured logs (no PHI/PII echo)
# ---------------------------------------------------------------------------


def _capture_logger() -> tuple[logging.Logger, io.StringIO]:
    buffer = io.StringIO()
    logger = logging.getLogger("regaudit-fhe.server.test")
    logger.handlers = []
    handler = logging.StreamHandler(buffer)
    from regaudit_fhe.server import _JSONFormatter

    handler.setFormatter(_JSONFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger, buffer


def test_access_log_does_not_contain_request_payload():
    logger, buffer = _capture_logger()
    app = build_app(config=_config(dev_mode=True), logger=logger)
    r = TestClient(app).post("/v1/audit/fairness", json=VALID_FAIRNESS)
    assert r.status_code == 200
    body = buffer.getvalue()
    assert "y_true" not in body
    assert "y_pred" not in body
    assert "group_a" not in body
    assert "1, 0, 1, 0" not in body
    assert "audit_evaluated" in body


def test_request_id_is_propagated():
    app = build_app(config=_config(dev_mode=True))
    r = TestClient(app).post(
        "/v1/audit/fairness", json=VALID_FAIRNESS, headers={"x-request-id": "test-rid-42"}
    )
    assert r.status_code == 200
    assert r.headers.get("x-request-id") == "test-rid-42"


def test_request_id_is_generated_when_missing():
    app = build_app(config=_config(dev_mode=True))
    r = TestClient(app).post("/v1/audit/fairness", json=VALID_FAIRNESS)
    assert r.status_code == 200
    rid = r.headers.get("x-request-id")
    assert rid and len(rid) >= 16


# ---------------------------------------------------------------------------
# CORS policy
# ---------------------------------------------------------------------------


def test_cors_default_does_not_allow_arbitrary_origins():
    app = build_app(config=_config(dev_mode=True))
    r = TestClient(app).options(
        "/v1/audit/fairness",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


def test_cors_allowlist_grants_named_origin():
    app = build_app(config=_config(dev_mode=True, cors_origins=("https://app.example",)))
    r = TestClient(app).options(
        "/v1/audit/fairness",
        headers={
            "Origin": "https://app.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert r.headers.get("access-control-allow-origin") == "https://app.example"


# ---------------------------------------------------------------------------
# Privacy-boundary surface
# ---------------------------------------------------------------------------


def test_readyz_returns_privacy_boundary_warning():
    app = build_app(config=_config(dev_mode=True))
    r = TestClient(app).get("/readyz")
    assert r.status_code == 200
    assert r.json()["privacy_boundary_warning"] == PRIVACY_WARNING


def test_privacy_warning_text_is_loud():
    assert "NOT A PRIVACY BOUNDARY" in PRIVACY_WARNING
    assert "plaintext" in PRIVACY_WARNING


# ---------------------------------------------------------------------------
# Schema endpoint enforces auth + scope
# ---------------------------------------------------------------------------


def test_schema_endpoint_requires_read_scope():
    app = build_app(config=_config(api_keys={"k1": frozenset({"audit:run"})}))
    r = TestClient(app).get("/v1/schemas", headers={"Authorization": "Bearer k1"})
    assert r.status_code == 403
    r = TestClient(build_app(config=_config(api_keys={"k1": frozenset({"audit:read"})}))).get(
        "/v1/schemas", headers={"Authorization": "Bearer k1"}
    )
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Schema validation enforced by the audit endpoint
# ---------------------------------------------------------------------------


def test_audit_endpoint_returns_422_on_schema_violation():
    app = build_app(config=_config(dev_mode=True))
    r = TestClient(app).post("/v1/audit/fairness", json={"y_true": [1, 2, 3]})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Constant-time bearer compare + key_id non-leak
# ---------------------------------------------------------------------------


def test_caller_key_id_is_hashed_not_raw_token():
    logger, buffer = _capture_logger()
    cfg = _config(api_keys={"super-secret-token": frozenset({"audit:run"})})
    app = build_app(config=cfg, logger=logger)
    r = TestClient(app).post(
        "/v1/audit/fairness",
        json=VALID_FAIRNESS,
        headers={"Authorization": "Bearer super-secret-token"},
    )
    assert r.status_code == 200
    body = buffer.getvalue()
    assert "super-secret-token" not in body
    # The logged key_id field exists but holds an opaque hash prefix.
    assert "key_id" in body


def test_unknown_token_still_returns_401_under_constant_time_path():
    cfg = _config(api_keys={"k1": frozenset({"audit:run"})})
    app = build_app(config=cfg)
    r = TestClient(app).post(
        "/v1/audit/fairness", json=VALID_FAIRNESS, headers={"Authorization": "Bearer k2"}
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# DEV_MODE bind guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_assert_safe_bind_allows_loopback_in_dev_mode(host):
    assert_safe_bind(host, dev_mode=True)  # must not raise


@pytest.mark.parametrize(
    "host", ["0.0.0.0", "10.0.0.1", "192.168.1.1", "::", "2001:db8::1", "example.com"]
)
def test_assert_safe_bind_refuses_non_loopback_in_dev_mode(host):
    with pytest.raises(RuntimeError, match="non-loopback"):
        assert_safe_bind(host, dev_mode=True)


@pytest.mark.parametrize("host", ["0.0.0.0", "example.com", "10.0.0.1"])
def test_assert_safe_bind_allows_any_host_when_auth_enabled(host):
    assert_safe_bind(host, dev_mode=False)  # must not raise
