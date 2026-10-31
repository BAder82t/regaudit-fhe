"""Backend / parameter-set self-consistency in the strict trust-bearing paths.

Each contradiction is a validly signed envelope that disagrees with itself; absent evidence is
reported as unverifiable and never refused. The legacy library path (``verify_report`` without
``check_provenance``) is unchanged. None of this proves that an FHE computation ran.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe._provenance import CONSISTENT, CONTRADICTION, UNVERIFIABLE, check_provenance
from regaudit_fhe.report_v2 import parse_envelope
from regaudit_fhe.reports import ParameterSet, canonical_json, sha256_hex
from regaudit_fhe.verification import VerificationPolicy


@dataclasses.dataclass(frozen=True)
class _Doctored(ParameterSet):
    """A parameter set whose pieces disagree, or have another shape, as a hostile or odd signer could produce."""

    inner_backend: Any = None
    wrong_hash: bool = False
    extra: bool = False
    drop_backend: bool = False

    def to_dict(self) -> dict[str, Any]:
        body = super().to_dict()
        if self.inner_backend is not None:
            body["backend"] = self.inner_backend
        if self.drop_backend:
            del body["backend"]
        if self.extra:
            body["note"] = "other producer"
        return body

    def hash(self) -> str:
        if self.wrong_hash:
            return "0" * 64
        return sha256_hex(canonical_json(self.to_dict()))


@pytest.fixture(scope="module")
def signer():
    return rf.Signer.generate(issuer="acme", key_id="acme-1")


@pytest.fixture(scope="module")
def store(signer):
    return rf.TrustStore.from_dict({"keys": {"acme-1": signer.public_key_pem()}})


@pytest.fixture(scope="module")
def report():
    return rf.audit_drift(np.array([0.2, 0.3, 0.5]), np.array([0.25, 0.25, 0.5]))


def _signed(fmt, report, signer, params):
    if fmt == "v1":
        return rf.envelope("drift", report, signer=signer, parameter_set=params)
    return rf.envelope_v2("drift", report, signer=signer, parameter_set=params, deployment_id="d")


CASES = {
    "backend_contradiction": (_Doctored(inner_backend="tenseal-ckks"), CONTRADICTION),
    "hash_contradiction": (_Doctored(wrong_hash=True), CONTRADICTION),
    "consistent": (ParameterSet(backend="tenseal-ckks", poly_modulus_degree=8192), CONSISTENT),
    "default_plaintext": (ParameterSet(), CONSISTENT),
    "non_string_backend_in_parameter_set": (_Doctored(inner_backend=5), CONTRADICTION),
    "no_backend_in_parameter_set": (_Doctored(drop_backend=True), UNVERIFIABLE),
    "unknown_shape_unknown_hash": (_Doctored(extra=True, wrong_hash=True), UNVERIFIABLE),
}


@pytest.mark.parametrize("fmt", ["v1", "v2"])
@pytest.mark.parametrize("case", sorted(CASES))
def test_check_provenance_separates_contradiction_from_absent_evidence(case, fmt, report, signer):
    params, expected = CASES[case]
    status, _ = check_provenance(_signed(fmt, report, signer, params))
    assert status == expected


@pytest.mark.parametrize("fmt", ["v1", "v2"])
@pytest.mark.parametrize("case", sorted(CASES))
def test_verify_trusted_refuses_only_demonstrated_contradictions(case, fmt, report, signer, store):
    params, expected = CASES[case]
    env = _signed(fmt, report, signer, params)
    out = rf.verify_trusted(env.to_json(), store)
    if expected == CONTRADICTION:
        assert out.verdict is rf.TrustVerdict.INVALID
        assert "PROVENANCE_CONTRADICTION" in out.reasons
        assert (
            out.result is not None and out.result.integrity_valid
        )  # signed, intact, still refused
    else:
        assert out.verdict is rf.TrustVerdict.TRUSTED
        assert ("PROVENANCE_UNVERIFIABLE" in out.reasons) == (expected == UNVERIFIABLE)


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_legacy_library_path_is_unchanged(fmt, report, signer, store):
    env = parse_envelope(_signed(fmt, report, signer, _Doctored(wrong_hash=True)).to_json())
    legacy = rf.verify_report(env, VerificationPolicy(trust_store=store))
    assert legacy.accepted and legacy.trust_status == "TRUSTED"
    assert "PROVENANCE_UNVERIFIABLE" not in legacy.reasons
    strict = rf.verify_report(env, VerificationPolicy(trust_store=store, check_provenance=True))
    assert not strict.accepted and "PROVENANCE_CONTRADICTION" in strict.blocking_reasons


def test_a_contradiction_also_blocks_the_self_signed_development_check(report, signer):
    env = _signed("v2", report, signer, _Doctored(inner_backend="openfhe-ckks"))
    policy = VerificationPolicy(allow_self_signed=True, check_provenance=True)
    result = rf.verify_report(env, policy)
    assert result.trust_status == "INVALID"


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", "verify", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _store_file(tmp_path: Path, signer) -> str:
    entry = {"issuer": signer.issuer, "public_key_pem": signer.public_key_pem(), "status": "active"}
    path = tmp_path / "trust.json"
    path.write_text(json.dumps({"entries": {signer.key_id: entry}}))
    return str(path)


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_cli_verify_refuses_a_contradiction_and_accepts_unverifiable(fmt, tmp_path, report, signer):
    trust = _store_file(tmp_path, signer)
    bad = tmp_path / "bad.json"
    bad.write_text(_signed(fmt, report, signer, _Doctored(inner_backend="tenseal-ckks")).to_json())
    proc = _cli("--input", str(bad), "--trusted-keys", trust)
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["reason"] == "PROVENANCE_CONTRADICTION"
    odd = tmp_path / "odd.json"
    odd.write_text(_signed(fmt, report, signer, _Doctored(drop_backend=True)).to_json())
    proc = _cli("--input", str(odd), "--trusted-keys", trust)
    assert proc.returncode == 0, proc.stderr
    assert "PROVENANCE_UNVERIFIABLE" in json.loads(proc.stdout)["reasons"]


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_server_verify_refuses_a_contradiction(fmt, report, signer, store):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from regaudit_fhe.server import ServerConfig, build_app
    from tests._asgi import client_for

    config = ServerConfig(
        api_keys={},
        dev_mode=True,
        max_body_bytes=1 << 20,
        rate_limit_per_min=600,
        request_timeout_s=10.0,
        cors_origins=(),
        trust_store=store,
    )
    client = client_for(build_app(config=config), base_url="http://127.0.0.1:8000")
    bad = _signed(fmt, report, signer, _Doctored(wrong_hash=True)).to_dict()
    body = client.post("/v1/verify", json={"envelope": bad}).json()
    assert body["valid"] is False and body["trust_status"] == "INVALID"
    good = _signed(fmt, report, signer, ParameterSet()).to_dict()
    assert client.post("/v1/verify", json={"envelope": good}).json()["trust_status"] == "TRUSTED"
