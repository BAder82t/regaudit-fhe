"""HTTP server tests (requires the [server] extra)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from regaudit_fhe.server import ServerConfig, build_app


def _dev_config(**overrides) -> ServerConfig:
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


@pytest.fixture
def client() -> TestClient:
    return TestClient(build_app(config=_dev_config()))


def test_healthz(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_readyz_includes_privacy_boundary_warning(client: TestClient) -> None:
    r = client.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body["ready"] is True
    assert "privacy_boundary_warning" in body
    assert "NOT A PRIVACY BOUNDARY" in body["privacy_boundary_warning"]


def test_version_endpoint_reports_library_version(client: TestClient) -> None:
    r = client.get("/version")
    assert r.status_code == 200
    body = r.json()
    assert body["library_version"]
    assert body["python"]
    assert "tenseal" in body


def test_schema_unknown_primitive(client: TestClient) -> None:
    r = client.get("/v1/schemas/nonsense")
    assert r.status_code == 404


def test_audit_and_verify_roundtrip(client: TestClient) -> None:
    payload = {
        "y_true": [1, 0, 1, 1, 0, 1, 0, 0],
        "y_pred": [1, 0, 1, 0, 0, 1, 1, 0],
        "group_a": [1, 1, 1, 1, 0, 0, 0, 0],
        "group_b": [0, 0, 0, 0, 1, 1, 1, 1],
        "threshold": 0.1,
    }
    r = client.post("/v1/audit/fairness", json=payload)
    assert r.status_code == 200, r.text
    env = r.json()
    assert env["primitive"] == "fairness"
    assert env["depth_budget"]["consumed"] >= 1

    v = client.post("/v1/verify", json={"envelope": env})
    assert v.status_code == 200
    assert v.json()["valid"] is True


def test_drift_endpoint(client: TestClient) -> None:
    r = client.post("/v1/audit/drift", json={
        "p": [1, 2, 3, 4],
        "q": [2, 2, 3, 3],
        "drift_threshold": 0.005,
    })
    assert r.status_code == 200
    env = r.json()
    assert "distance" in env["result"]
