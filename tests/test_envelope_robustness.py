"""Envelope tampering, malformed JSON, and schema-mismatch tests."""

from __future__ import annotations

import base64
import copy
import json

import numpy as np
import pytest

import regaudit_fhe as rf


def _sample_envelope() -> rf.AuditEnvelope:
    y = np.array([1.0, 0.0, 1.0, 0.0])
    report = rf.audit_fairness(y, y, y, 1.0 - y)
    signer = rf.Signer.generate(issuer="acme", key_id="k1")
    return rf.envelope("fairness", report, signer=signer)


# --------------------------------------------------------------------------
# Malformed JSON
# --------------------------------------------------------------------------


def test_from_dict_rejects_missing_schema_field():
    body = _sample_envelope().to_dict()
    body.pop("schema")
    with pytest.raises(KeyError):
        rf.AuditEnvelope.from_dict(body)


def test_from_dict_rejects_missing_receipt():
    body = _sample_envelope().to_dict()
    body.pop("receipt")
    with pytest.raises(KeyError):
        rf.AuditEnvelope.from_dict(body)


def test_malformed_json_string_round_trip_raises():
    payload = "not-valid-json-at-all"
    with pytest.raises(json.JSONDecodeError):
        json.loads(payload)


def test_envelope_round_trips_through_canonical_json():
    env = _sample_envelope()
    body = json.loads(env.to_json())
    parsed = rf.AuditEnvelope.from_dict(body)
    assert rf.verify_envelope(parsed).valid is True


# --------------------------------------------------------------------------
# Schema validation
# --------------------------------------------------------------------------


def test_schema_field_must_be_recognised_v1():
    env = _sample_envelope()
    assert env.schema == "regaudit-fhe.report.v1"
    assert env.schema_version == "regaudit-fhe.report.v1"
    assert env.algorithm_version == "0.0.4"


def test_unknown_schema_version_does_not_match_signature():
    env = _sample_envelope()
    env.schema_version = "regaudit-fhe.report.vUNKNOWN"
    out = rf.verify_envelope(env)
    assert out.valid is False
    assert out.sha256_valid is False


# --------------------------------------------------------------------------
# Receipt tampering
# --------------------------------------------------------------------------


def test_receipt_sha256_tamper_fails_verification():
    env = _sample_envelope()
    env.receipt["sha256"] = "0" * 64
    out = rf.verify_envelope(env)
    assert out.sha256_valid is False
    assert out.valid is False


def test_result_field_tamper_breaks_sha256():
    env = _sample_envelope()
    env.result["demographic_parity_diff"] = 999.0
    out = rf.verify_envelope(env)
    assert out.sha256_valid is False
    assert out.signature_valid is False


def test_issuer_field_tamper_breaks_sha256():
    env = _sample_envelope()
    env.issuer = "evil-tenant"
    out = rf.verify_envelope(env)
    assert out.sha256_valid is False


def test_input_commitments_tamper_breaks_sha256():
    env = _sample_envelope()
    env.input_commitments.append({"name": "extra", "sha256": "deadbeef"})
    out = rf.verify_envelope(env)
    assert out.sha256_valid is False


# --------------------------------------------------------------------------
# Signature tampering
# --------------------------------------------------------------------------


def test_random_signature_bytes_fail_verification():
    env = _sample_envelope()
    env.receipt["signature_b64"] = base64.b64encode(b"not-a-real-signature"
                                                     ).decode("ascii")
    out = rf.verify_envelope(env)
    assert out.signature_valid is False
    assert out.valid is False


def test_signature_block_swap_with_other_envelope_fails():
    env_a = _sample_envelope()
    env_b = _sample_envelope()
    env_a.receipt["signature_b64"] = env_b.receipt["signature_b64"]
    out = rf.verify_envelope(env_a)
    assert out.signature_valid is False


def test_public_key_swap_invalidates_signature():
    env_a = _sample_envelope()
    env_b = _sample_envelope()
    env_a.receipt["public_key_pem"] = env_b.receipt["public_key_pem"]
    out = rf.verify_envelope(env_a)
    assert out.signature_valid is False


def test_signature_b64_invalid_base64_fails_gracefully():
    env = _sample_envelope()
    env.receipt["signature_b64"] = "not-base64@#$%"
    out = rf.verify_envelope(env)
    assert out.signature_valid is False


# --------------------------------------------------------------------------
# Backend / parameter-set mismatch
# --------------------------------------------------------------------------


def test_backend_mismatch_fails_sha256_check():
    env = _sample_envelope()
    env.backend = "openfhe-ckks"
    out = rf.verify_envelope(env)
    assert out.sha256_valid is False


def test_parameter_set_field_change_breaks_sha256():
    signer = rf.Signer.generate(issuer="acme", key_id="k1")
    params = rf.ParameterSet(backend="tenseal-ckks",
                             poly_modulus_degree=32768,
                             multiplicative_depth=6,
                             coeff_mod_bit_sizes=(60, 40, 40, 40, 40, 40, 40, 60),
                             scaling_factor_bits=40)
    y = np.array([1.0, 0.0, 1.0, 0.0])
    report = rf.audit_fairness(y, y, y, 1.0 - y)
    env = rf.envelope("fairness", report, signer=signer, parameter_set=params)
    env.parameter_set["poly_modulus_degree"] = 16384
    out = rf.verify_envelope(env)
    assert out.sha256_valid is False
    assert out.valid is False


def test_parameter_set_hash_mismatch_against_pinned_value():
    signer = rf.Signer.generate(issuer="acme", key_id="k1")
    params = rf.ParameterSet(backend="tenseal-ckks",
                             poly_modulus_degree=32768,
                             multiplicative_depth=6,
                             coeff_mod_bit_sizes=(60, 40, 40, 40, 40, 40, 40, 60),
                             scaling_factor_bits=40)
    y = np.array([1.0, 0.0, 1.0, 0.0])
    env = rf.envelope("fairness", rf.audit_fairness(y, y, y, 1.0 - y),
                      signer=signer, parameter_set=params)
    expected_hash = params.hash()
    different_params = rf.ParameterSet(backend="tenseal-ckks",
                                       poly_modulus_degree=16384,
                                       multiplicative_depth=6,
                                       coeff_mod_bit_sizes=(60, 40, 40, 40, 40, 40, 40, 60),
                                       scaling_factor_bits=40)
    assert env.parameter_set_hash == expected_hash
    assert env.parameter_set_hash != different_params.hash()


# --------------------------------------------------------------------------
# Trusted-key store enforcement
# --------------------------------------------------------------------------


def test_unknown_issuer_rejected_when_trusted_keys_supplied():
    env = _sample_envelope()
    out = rf.verify_envelope(env, trusted_keys={"some-other-key": "pem"})
    assert out.issuer_trusted is False
    assert out.valid is False


def test_known_issuer_accepted_when_trusted_keys_supplied():
    signer = rf.Signer.generate(issuer="acme", key_id="acme-2026-01")
    y = np.array([1.0, 0.0, 1.0, 0.0])
    env = rf.envelope("fairness", rf.audit_fairness(y, y, y, 1.0 - y),
                      signer=signer)
    out = rf.verify_envelope(
        env, trusted_keys={"acme-2026-01": signer.public_key_pem()})
    assert out.issuer_trusted is True
    assert out.valid is True


# --------------------------------------------------------------------------
# Deep-copy independence (regression guard)
# --------------------------------------------------------------------------


def test_deepcopy_does_not_invalidate_envelope():
    env = _sample_envelope()
    cloned = copy.deepcopy(env)
    assert rf.verify_envelope(cloned).valid is True


def test_envelope_to_dict_does_not_mutate():
    env = _sample_envelope()
    before = env.to_json()
    env.to_dict()
    after = env.to_json()
    assert before == after
