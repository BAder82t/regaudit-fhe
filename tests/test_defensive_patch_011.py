"""0.1.1 defensive patch: controlled client errors instead of signing garbage or crashing.

Each test asserts the exact HTTP status and the exact response body, not just "an error".

* M2: a non-finite audit result is never signed (HTTP 422, CLI exit 2, library ValueError).
* M3: ``/v1/verify`` answers 422 (not 500) when the report's ``primitive`` is not a string, and the
  library verifier refuses it instead of raising ``TypeError``.
* L1: ``/v1/audit/{primitive}`` parses its body with the strict JSON policy of ``/v1/verify``.
"""

from __future__ import annotations

import copy
import json
import logging

import numpy as np
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

import regaudit_fhe as rf
from regaudit_fhe.cli import main
from regaudit_fhe.report_v2 import parse_envelope
from regaudit_fhe.reports import AuditEnvelope, Signer, envelope, verify_envelope
from regaudit_fhe.server import ServerConfig, build_app
from regaudit_fhe.trust import TrustStore
from regaudit_fhe.verification import VerificationPolicy, verify

AUTH = {"Authorization": "Bearer t"}
JSON_HEADERS = {**AUTH, "Content-Type": "application/json"}
INCONSISTENT = {"detail": "the audit input is inconsistent (see the input schema)"}
OVERFLOW = {"model_polynomials": [[1e308] * 4] * 3, "test_input": [1e308]}


def _config(**kw) -> ServerConfig:
    base = dict(
        api_keys={"t": frozenset({"admin"}), "r": frozenset({"audit:read"})},
        dev_mode=False,
        max_body_bytes=1 << 20,
        rate_limit_per_min=10000,
        request_timeout_s=30.0,
        cors_origins=(),
    )
    base.update(kw)
    return ServerConfig(**base)


def _client(**kw) -> TestClient:
    return TestClient(build_app(config=_config(**kw), logger=logging.getLogger("t011")))


# --------------------------------------------------------------------------- M2


def test_m2_server_refuses_to_sign_a_non_finite_result() -> None:
    r = _client().post("/v1/audit/disagreement", json=OVERFLOW, headers=AUTH)
    assert r.status_code == 422
    assert r.json() == INCONSISTENT


@pytest.mark.parametrize(
    "result",
    [{"x": float("nan")}, {"x": [1.0, {"y": float("inf")}]}, {"x": (float("-inf"),)}],
)
def test_m2_envelope_refuses_a_non_finite_result(result) -> None:
    signer = Signer.generate(issuer="acme", key_id="ka")
    with pytest.raises(ValueError, match="non-finite"):
        envelope("drift", result, signer=signer)


def test_m2_envelope_refuses_a_non_finite_dp_block() -> None:
    signer = Signer.generate(issuer="acme", key_id="ka")
    with pytest.raises(ValueError, match="non-finite"):
        envelope("drift", {"x": 1.0}, signer=signer, dp={"epsilon": float("inf")})


def test_m2_finite_results_still_sign_and_verify() -> None:
    signer = Signer.generate(issuer="acme", key_id="ka")
    report = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.5, 0.5]))
    env = envelope("drift", report, signer=signer)
    assert env.receipt["signature_alg"]
    out = verify_envelope(env)
    assert out.sha256_valid
    assert out.signature_valid


def test_m2_cli_reports_a_non_finite_result_as_rejected_input(tmp_path, capsys) -> None:
    src = tmp_path / "in.json"
    src.write_text(json.dumps(OVERFLOW))
    assert main(["audit", "disagreement", "-i", str(src)]) == 2
    assert "non-finite" in capsys.readouterr().err


# --------------------------------------------------------------------------- M3


def _store(signer: Signer, **entry) -> TrustStore:
    return TrustStore.from_dict(
        {
            "entries": {
                signer.key_id: {
                    "issuer": signer.issuer,
                    "public_key_pem": signer.public_key_pem(),
                    "status": "active",
                    **entry,
                }
            }
        }
    )


def _signed_drift(signer: Signer) -> dict:
    report = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.5, 0.5]))
    return envelope("drift", report, signer=signer).to_dict()


HOSTILE = [[], ["drift"], {}, {"a": 1}, None, 5, True]


@pytest.mark.parametrize("hostile", HOSTILE)
def test_m3_verify_endpoint_answers_422_for_a_non_string_primitive(hostile) -> None:
    signer = Signer.generate(issuer="acme", key_id="ka")
    data = _signed_drift(signer)
    data["primitive"] = hostile
    client = _client(
        api_keys={"v": frozenset({"audit:verify"})},
        trust_store=_store(signer, primitives=["drift"]),
    )
    r = client.post(
        "/v1/verify",
        content=json.dumps({"envelope": data}),
        headers={"Authorization": "Bearer v", "Content-Type": "application/json"},
    )
    assert r.status_code == 422
    assert r.json() == {"detail": "malformed envelope"}


def test_m3_verify_endpoint_still_gives_a_verdict_for_a_string_primitive() -> None:
    signer = Signer.generate(issuer="acme", key_id="ka")
    data = _signed_drift(signer)
    client = _client(
        api_keys={"v": frozenset({"audit:verify"})},
        trust_store=_store(signer, primitives=["drift"]),
    )
    r = client.post(
        "/v1/verify",
        content=json.dumps({"envelope": data}),
        headers={"Authorization": "Bearer v", "Content-Type": "application/json"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] is True
    assert body["trust_status"] == "TRUSTED"


@pytest.mark.parametrize("hostile", HOSTILE)
def test_m3_library_verifier_refuses_instead_of_raising(hostile) -> None:
    signer = Signer.generate(issuer="acme", key_id="ka")
    data = copy.deepcopy(_signed_drift(signer))
    data["primitive"] = hostile
    store = _store(signer, primitives=["drift"])

    result = verify(parse_envelope(json.dumps(data)), VerificationPolicy(trust_store=store))
    assert not result.accepted
    assert "PRIMITIVE_NOT_ALLOWED" in result.blocking_reasons

    outcome = verify_envelope(AuditEnvelope.from_dict(data), trust_store=store)
    assert not outcome.issuer_trusted
    assert outcome.trust_status != "TRUSTED"


# --------------------------------------------------------------------------- L1

DRIFT = b'{"p":[0.5,0.5],"q":[0.5,0.5]}'
NOT_STRICT = {"detail": "request body is not strict JSON"}
NOT_OBJECT = {"detail": "request body must be an object"}


def test_l1_valid_body_still_works() -> None:
    r = _client().post("/v1/audit/drift", content=DRIFT, headers=JSON_HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["primitive"] == "drift"
    assert set(body["receipt"]) >= {"sha256", "signature_b64", "key_id"}


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b'{"p":[0.5,0.5],"p":[0.1,0.9],"q":[0.5,0.5]}', NOT_STRICT),  # duplicate key
        (b'{"p":[0.5,NaN],"q":[0.5,0.5]}', NOT_STRICT),  # NaN literal
        (b'{"p":[0.5,Infinity],"q":[0.5,0.5]}', NOT_STRICT),  # Infinity literal
        (DRIFT + b" trailing", NOT_STRICT),  # trailing data
        (b"\xef\xbb\xbf" + DRIFT, NOT_STRICT),  # BOM
        (b"", NOT_STRICT),  # empty
        (b"[1,2]", NOT_OBJECT),  # not an object
        (b"3", NOT_OBJECT),
    ],
)
def test_l1_ambiguous_body_is_refused_with_422_and_a_fixed_body(body, expected) -> None:
    r = _client().post("/v1/audit/drift", content=body, headers=JSON_HEADERS)
    assert r.status_code == 422
    assert r.json() == expected


def test_l1_scope_and_unknown_primitive_are_unchanged() -> None:
    c = _client()
    r = c.post("/v1/audit/drift", content=DRIFT, headers={"Authorization": "Bearer r"})
    assert r.status_code == 403
    r = c.post("/v1/audit/drift", content=DRIFT)
    assert r.status_code == 401
    r = c.post("/v1/audit/nope", content=b"{}", headers=JSON_HEADERS)
    assert r.status_code == 404


def test_l1_schema_errors_still_422() -> None:
    r = _client().post("/v1/audit/drift", content=b'{"p":[0.5,0.5]}', headers=JSON_HEADERS)
    assert r.status_code == 422
    assert isinstance(r.json()["detail"], str)


def test_l1_oversize_body_is_413_before_authentication() -> None:
    c = _client(max_body_bytes=64)
    r = c.post("/v1/audit/drift", content=b" " * 200, headers={"Content-Type": "application/json"})
    assert r.status_code == 413
