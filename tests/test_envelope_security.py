"""Cryptographic-envelope tests.

Covers Ed25519 signing, canonical-JSON tamper detection, parameter-set
binding, input commitments, and the optional timestamp-authority hook.
"""

from __future__ import annotations

import base64
import json

import numpy as np

import regaudit_fhe as rf


def _sample_report() -> rf.FairnessReport:
    y = np.array([1.0, 0.0, 1.0, 0.0])
    return rf.audit_fairness(y, y, y, 1.0 - y)


def test_envelope_carries_full_security_block() -> None:
    signer = rf.Signer.generate(issuer="acme.example", key_id="acme-2026-01")
    params = rf.ParameterSet(backend="tenseal-ckks",
                             poly_modulus_degree=32768,
                             multiplicative_depth=6,
                             coeff_mod_bit_sizes=(60, 40, 40, 40, 40, 40, 40, 60),
                             scaling_factor_bits=40,
                             backend_version="0.3.16")
    env = rf.envelope("fairness", _sample_report(),
                      parameter_set=params, signer=signer,
                      input_commitments=rf.commitments_for(
                          {"y_true": np.array([1, 0, 1, 0])}))
    body = env.to_dict()
    assert body["schema"] == "regaudit-fhe.report.v1"
    assert body["schema_version"] == "regaudit-fhe.report.v1"
    assert body["algorithm_version"] == "0.0.4"
    assert body["backend"] == "tenseal-ckks"
    assert body["parameter_set"]["poly_modulus_degree"] == 32768
    assert body["parameter_set"]["security_bits"] == 128
    assert body["parameter_set"]["multiplicative_depth"] == 6
    assert body["parameter_set_hash"], "parameter_set_hash must be set"
    assert body["receipt"]["signature_alg"] == "Ed25519"
    assert body["receipt"]["key_id"] == "acme-2026-01"
    assert "BEGIN PUBLIC KEY" in body["receipt"]["public_key_pem"]
    assert body["receipt"]["sha256"]
    assert body["receipt"]["signature_b64"]


def test_canonical_json_is_byte_stable() -> None:
    obj = {"b": 2, "a": [1, 2, 3], "c": {"y": 9, "x": 8}}
    a = rf.canonical_json(obj)
    b = rf.canonical_json(json.loads(a.decode("utf-8")))
    assert a == b
    assert b'"a":[1,2,3]' in a
    assert a.startswith(b'{"a"')


def test_signed_envelope_verifies() -> None:
    signer = rf.Signer.generate(issuer="acme.example")
    env = rf.envelope("fairness", _sample_report(), signer=signer)
    out = rf.verify_envelope(env)
    assert out.valid is True
    assert out.signature_valid is True
    assert out.sha256_valid is True


def test_tamper_in_result_fails_verification() -> None:
    signer = rf.Signer.generate(issuer="acme.example")
    env = rf.envelope("fairness", _sample_report(), signer=signer)
    env.result["demographic_parity_diff"] = 999.0
    out = rf.verify_envelope(env)
    assert out.valid is False
    assert out.sha256_valid is False
    assert out.signature_valid is False


def test_tamper_in_parameter_set_fails_verification() -> None:
    signer = rf.Signer.generate(issuer="acme.example")
    params = rf.ParameterSet(backend="tenseal-ckks",
                             poly_modulus_degree=32768,
                             multiplicative_depth=6,
                             coeff_mod_bit_sizes=(60, 40, 40, 40, 40, 40, 40, 60),
                             scaling_factor_bits=40)
    env = rf.envelope("fairness", _sample_report(),
                      parameter_set=params, signer=signer)
    env.parameter_set["poly_modulus_degree"] = 16384
    out = rf.verify_envelope(env)
    assert out.valid is False


def test_signature_swap_fails_verification() -> None:
    signer_a = rf.Signer.generate(issuer="A", key_id="kA")
    signer_b = rf.Signer.generate(issuer="B", key_id="kB")
    env_a = rf.envelope("fairness", _sample_report(), signer=signer_a)
    env_b = rf.envelope("fairness", _sample_report(), signer=signer_b)
    env_a.receipt["signature_b64"] = env_b.receipt["signature_b64"]
    out = rf.verify_envelope(env_a)
    assert out.signature_valid is False


def test_trusted_key_pinning_rejects_unknown_issuer() -> None:
    signer = rf.Signer.generate(issuer="A", key_id="acme-2026-01")
    env = rf.envelope("fairness", _sample_report(), signer=signer)
    out = rf.verify_envelope(env, trusted_keys={"other-key": "pem"})
    assert out.issuer_trusted is False
    assert out.valid is False


def test_trusted_key_pinning_accepts_known_issuer() -> None:
    signer = rf.Signer.generate(issuer="A", key_id="acme-2026-01")
    env = rf.envelope("fairness", _sample_report(), signer=signer)
    out = rf.verify_envelope(
        env, trusted_keys={"acme-2026-01": signer.public_key_pem()})
    assert out.issuer_trusted is True
    assert out.valid is True


def test_input_commitments_record_all_inputs() -> None:
    inputs = {"y_true": np.array([1, 0, 1, 0]),
              "y_pred": np.array([1, 0, 0, 0])}
    commits = rf.commitments_for(inputs)
    names = sorted(c["name"] for c in commits)
    assert names == ["y_pred", "y_true"]
    digest = rf.commit_input("y_true", inputs["y_true"])
    matches = next(c for c in commits if c["name"] == "y_true")
    assert digest["sha256"] == matches["sha256"]


def test_optional_timestamp_block_is_signed() -> None:
    def fake_tsa(body: bytes) -> bytes:
        return b"FAKE-TSA-RESPONSE-" + body[:8]
    tsa = rf.TimestampAuthority(issuer="https://tsa.example",
                                sign_callable=fake_tsa)
    signer = rf.Signer.generate(issuer="A")
    env = rf.envelope("fairness", _sample_report(),
                      signer=signer, timestamp_authority=tsa)
    assert env.timestamp is not None
    assert env.timestamp["issuer"] == "https://tsa.example"
    decoded = base64.b64decode(env.timestamp["token_b64"])
    assert decoded.startswith(b"FAKE-TSA-RESPONSE-")
    out = rf.verify_envelope(env)
    assert out.valid is True
    assert out.timestamp_valid is True


def test_envelope_round_trips_through_json() -> None:
    signer = rf.Signer.generate(issuer="A")
    env = rf.envelope("fairness", _sample_report(), signer=signer)
    payload = env.to_json()
    parsed = rf.AuditEnvelope.from_dict(json.loads(payload))
    assert rf.verify_envelope(parsed).valid is True
