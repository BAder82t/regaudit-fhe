"""Shared by the test modules: a client for a configuration, and what the verifier says with no portal in between."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from fastapi.testclient import TestClient
from regaudit_portal.app import build_app
from regaudit_portal.config import ConfigProblem, load_portal

import regaudit_fhe as rf
from regaudit_fhe.report_v2 import envelope_v2, parse_envelope_strict
from regaudit_fhe.reports import ParameterSet
from regaudit_fhe.verification import verify

PORT = 8765
JSON_HEADERS = {"content-type": "application/json"}


def client_for(config: Path | None, port: int = PORT) -> TestClient:
    return TestClient(build_app(config, port=port), base_url=f"http://127.0.0.1:{port}")


def post(client: TestClient, demo: Path, name: str):
    return client.post(
        "/api/verify", content=(demo / "sample-reports" / name).read_bytes(), headers=JSON_HEADERS
    )


def backend_verdict(demo: Path, name: str) -> dict:
    """What the verifier returns for this report under this configuration, with no portal in between."""
    portal = load_portal(demo / "portal-config.json")
    env = parse_envelope_strict(json.loads((demo / "sample-reports" / name).read_text()))
    return verify(env, portal.policy).to_dict()


def not_ready(config: Path, demo: Path, client_port: int = PORT) -> None:
    client = client_for(config, client_port)
    status = client.get("/api/status").json()
    assert status["ready"] is False and "administrator" in status["message"]
    response = client.post(
        "/api/verify",
        content=(demo / "sample-reports" / "1-trusted.json").read_bytes(),
        headers=JSON_HEADERS,
    )
    assert response.status_code == 503 and "verification" not in response.json()
    with pytest.raises(ConfigProblem):
        load_portal(config)


def rewrite(demo: Path, **change) -> Path:
    path = demo / "portal-config.json"
    config = json.loads(path.read_text())
    config.update(change)
    path.write_text(json.dumps(config))
    return path


def make_portal(
    root: Path,
    *,
    issuer: str = "Example Synthetic Issuer",
    profile: str = "confidential",
    verifier_id: str = "demo-verifier",
    entry: dict[str, Any] | None = None,
    key_id: str = "k1",
) -> tuple[Path, rf.Signer]:
    """A portal configuration that trusts one synthetic key, with ``entry`` changing that key's trust-store entry."""
    signer = rf.Signer.generate(issuer=issuer, key_id=key_id)
    record = {"issuer": issuer, "public_key_pem": signer.public_key_pem(), "status": "active"}
    record.update(entry or {})
    root.mkdir(mode=0o700, parents=True)
    (root / "trust-store.json").write_text(json.dumps({"entries": {key_id: record}}))
    config = {
        "trust_store": "trust-store.json",
        "profile": profile,
        "verifier_id": verifier_id,
        "max_age_days": 30,
        "replay_mode": "check",
        "replay_db": "replay.db",
    }
    (root / "portal-config.json").write_text(json.dumps(config))
    for name in ("trust-store.json", "portal-config.json"):
        os.chmod(root / name, 0o600)
    return root / "portal-config.json", signer


def signed_report(
    signer: rf.Signer,
    *,
    audience: tuple[str, ...] | None = ("demo-verifier",),
    parameter_set: ParameterSet | None = None,
) -> bytes:
    """A synthetic ``report.v2`` signed by ``signer``. ``audience=None`` leaves the audience out."""
    report = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    env = envelope_v2(
        "drift",
        report,
        signer=signer,
        deployment_id="synthetic-test",
        audience=list(audience) if audience is not None else None,
        parameter_set=parameter_set,
        issued_at=datetime.now(timezone.utc),
        audit_run_id=str(uuid.uuid4()),
    )
    return json.dumps(env.to_dict()).encode()


def post_bytes(client: TestClient, content: bytes):
    return client.post("/api/verify", content=content, headers=JSON_HEADERS)


def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty home folder for this test, so nothing real is read, and what is created there can be seen."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


def snapshot(root: Path) -> dict[str, tuple]:
    """Everything under ``root``, with enough about each entry to notice any change: kind, size, mode and times."""
    found: dict[str, tuple] = {}
    for path in sorted([root, *root.rglob("*")]):
        info = path.lstat()
        kind = "link" if path.is_symlink() else "dir" if path.is_dir() else "file"
        found[str(path.relative_to(root))] = (kind, info.st_size, info.st_mode, info.st_mtime_ns)
    return found


def install_configuration(demo: Path, folder: Path, *, mode: int = 0o700) -> Path:
    """Put a demonstration's configuration and trust list into ``folder``, the way an administrator would."""
    import shutil

    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, mode)
    for name in ("portal-config.json", "trust-store.json"):
        shutil.copy(demo / name, folder / name)
        os.chmod(folder / name, 0o600)
    return folder / "portal-config.json"
