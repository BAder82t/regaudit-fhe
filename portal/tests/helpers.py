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
    issuer: str = "Northwind Test Issuer",
    profile: str = "confidential",
    verifier_id: str = "demo-verifier",
    entry: dict[str, Any] | None = None,
    key_id: str = "k1",
    trust_mode: str | None = "customer",
) -> tuple[Path, rf.Signer]:
    """A portal configuration that trusts one synthetic key, with ``entry`` changing that key's trust-store entry.

    It says ``"trust_mode": "customer"``, as every new configuration must. ``trust_mode=None`` leaves the setting out,
    as a legacy configuration made before it existed does."""
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
    if trust_mode is not None:
        config["trust_mode"] = trust_mode
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


# ----------------------------------------------------------------------------- setup plans

PLAN_VERIFIER = "northwind-verifier"


def issuer_signer(issuer: str = "Northwind Ltd", key_id: str = "northwind-2026") -> rf.Signer:
    return rf.Signer.generate(issuer=issuer, key_id=key_id)


def fingerprint_of(signer: rf.Signer) -> str:
    from regaudit_fhe._keys import spki_fingerprint

    return spki_fingerprint(signer.public_key_pem())


def plan_request(
    signers: list[rf.Signer],
    *,
    mode: str = "first-setup",
    profile: str = "confidential",
    verifier_id: str = PLAN_VERIFIER,
    max_age_days: Any = 30,
    replay_mode: str = "check",
    fingerprints: list[str] | None = None,
) -> dict[str, Any]:
    """What the prepare page sends for these issuers, each with the fingerprint of its own key unless told otherwise."""
    typed = fingerprints if fingerprints is not None else [fingerprint_of(s) for s in signers]
    request: dict[str, Any] = {
        "mode": mode,
        "issuers": [
            {
                "issuer": s.issuer,
                "key_id": s.key_id,
                "public_key": s.public_key_pem(),
                "fingerprint": f,
            }
            for s, f in zip(signers, typed, strict=True)
        ],
    }
    if mode == "first-setup":
        request["configuration"] = {
            "profile": profile,
            "verifier_id": verifier_id,
            "max_age_days": max_age_days,
            "replay_mode": replay_mode,
        }
    return request


def prepare_plan(signers: list[rf.Signer], **options: Any) -> str:
    """A plan file's text, made by the same code the prepare route uses."""
    from regaudit_portal.plan import prepared

    status, body = prepared(json.dumps(plan_request(signers, **options)).encode())
    assert status == 200, body
    return body["plan_text"]


def crafted_plan(content: dict[str, Any]) -> bytes:
    """Any plan content with a checksum that matches it: what someone hostile can make without the portal."""
    import hashlib

    from regaudit_fhe.canonical import canonical_bytes

    body = {k: v for k, v in content.items() if k != "content_sha256"}
    return json.dumps(
        {**body, "content_sha256": hashlib.sha256(canonical_bytes(body)).hexdigest()}
    ).encode()


# ----------------------------------------------------------------------------- an administrator's own configuration

SYNTHETIC_ISSUER = "Northwind Test Issuer"


VERIFIER = "demo-verifier"
MAX_REPORT_BYTES = 1 << 20


def synthetic_report(
    signer: rf.Signer, parameter_set: ParameterSet | None = None, issued_at: datetime | None = None
) -> str:
    """A report signed now (or at ``issued_at``) by a key the test holds, for the verifier ``demo-verifier``."""
    report = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    env = envelope_v2(
        "drift",
        report,
        signer=signer,
        deployment_id="synthetic-demo",
        audience=[VERIFIER],
        parameter_set=parameter_set,
        issued_at=issued_at or datetime.now(timezone.utc),
        audit_run_id=str(uuid.uuid4()),
    )
    return json.dumps(env.to_dict(), indent=2)


def make_synthetic_portal(directory: Path, *, trust_mode: str | None = "customer") -> Path:
    """Sample files like demo-setup's, signed with fresh keys for an ordinary issuer, under ``"trust_mode": "customer"``.

    To the portal this looks like an administrator's own configuration, which is what most tests need. demo-setup's
    own output holds the bundled demonstration key and says it is a demonstration, so it is never taken for that.
    ``trust_mode="demonstration"`` makes a folder like the ones the earlier demo-setup made, with fresh keys and the
    marker. ``trust_mode=None`` leaves the setting out, as a legacy configuration does.
    """
    root = Path(directory).absolute()
    reports = root / "sample-reports"
    root.mkdir(mode=0o700, parents=True)
    reports.mkdir(mode=0o700)
    issuer = rf.Signer.generate(issuer=SYNTHETIC_ISSUER, key_id="northwind-test-key")
    outsider = rf.Signer.generate(issuer=SYNTHETIC_ISSUER, key_id="northwind-outsider-key")
    store = {
        "entries": {
            issuer.key_id: {
                "issuer": SYNTHETIC_ISSUER,
                "public_key_pem": issuer.public_key_pem(),
                "status": "active",
            }
        }
    }
    (root / "trust-store.json").write_text(json.dumps(store, indent=2) + "\n")
    config = {
        "trust_store": "trust-store.json",
        "profile": "confidential",
        "verifier_id": VERIFIER,
        "max_age_days": 30,
        "replay_mode": "check",
        "replay_db": "replay.db",
    }
    if trust_mode is not None:
        config["trust_mode"] = trust_mode
    (root / "portal-config.json").write_text(json.dumps(config, indent=2) + "\n")
    good = synthetic_report(issuer)
    (reports / "1-trusted.json").write_text(good)
    (reports / "2-untrusted-signer.json").write_text(synthetic_report(outsider))
    other_name = rf.Signer("Another Issuer", issuer.key_id, issuer.private_key, issuer.public_key)
    (reports / "3-valid-signature-wrong-issuer.json").write_text(synthetic_report(other_name))
    changed = json.loads(good)
    changed["deployment_id"] = "changed-after-signing"
    (reports / "4-changed-after-signing.json").write_text(json.dumps(changed, indent=2))
    (reports / "5-not-a-report.json").write_text('{"hello": "this is not a signed report"}\n')
    (reports / "6-too-large.json").write_text(" " * (MAX_REPORT_BYTES + 1))
    declares = ParameterSet(backend="tenseal-ckks", poly_modulus_degree=8192, security_bits=192)
    (reports / "7-declares-encrypted-backend.json").write_text(synthetic_report(issuer, declares))
    for path in (root / "trust-store.json", root / "portal-config.json"):
        os.chmod(path, 0o600)
    return root
