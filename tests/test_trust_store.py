"""Tests for TrustStore loader and verify_envelope_or_raise typed exceptions."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.trust import (
    EnvelopeVerificationError,
    HashMismatch,
    InvalidSignature,
    RevokedIssuer,
    TrustStore,
    TrustStoreError,
    UntrustedIssuer,
    WrongParameterSet,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_envelope(*, key_id: str = "k1") -> tuple[rf.AuditEnvelope, str]:
    """Produce a real signed envelope and return it + issuer PEM."""
    signer = rf.Signer.generate(issuer="acme", key_id=key_id)
    report = rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )
    env = rf.envelope("fairness", report, signer=signer)
    return env, signer.public_key_pem()


def _trust_store_for(env: rf.AuditEnvelope, pem: str, **kwargs) -> TrustStore:
    payload = {
        "keys": {env.receipt["key_id"]: pem},
        **kwargs,
    }
    return TrustStore.from_dict(payload)


# ---------------------------------------------------------------------------
# TrustStore parsing
# ---------------------------------------------------------------------------


def test_trust_store_accepts_legacy_flat_mapping():
    env, pem = _make_envelope()
    store = TrustStore.from_dict({env.receipt["key_id"]: pem})
    assert store.is_known(env.receipt["key_id"])
    assert not store.is_revoked(env.receipt["key_id"])
    assert store.expected_parameter_set_hash(env.receipt["key_id"]) is None


def test_trust_store_accepts_full_payload(tmp_path: Path):
    env, pem = _make_envelope()
    payload = {
        "keys": {"k1": pem, "k2": pem},
        "revoked": ["k2"],
        "parameter_set_pins": {"k1": env.parameter_set_hash},
    }
    p = tmp_path / "trust.json"
    p.write_text(json.dumps(payload))
    store = TrustStore.from_json(p)
    assert store.is_known("k1")
    assert store.is_revoked("k2")
    assert store.expected_parameter_set_hash("k1") == env.parameter_set_hash


def test_trust_store_rejects_non_pem_value():
    with pytest.raises(TrustStoreError, match="not a PEM"):
        TrustStore.from_dict({"k1": "not-a-pem"})


def test_trust_store_rejects_revocation_for_unknown_key():
    _, pem = _make_envelope()
    with pytest.raises(TrustStoreError, match="revoked"):
        TrustStore.from_dict(
            {
                "keys": {"k1": pem},
                "revoked": ["ghost"],
            }
        )


def test_trust_store_rejects_pin_for_unknown_key():
    _, pem = _make_envelope()
    with pytest.raises(TrustStoreError, match="parameter_set_pins"):
        TrustStore.from_dict(
            {
                "keys": {"k1": pem},
                "parameter_set_pins": {"ghost": "deadbeef"},
            }
        )


def test_trust_store_rejects_empty_payload():
    with pytest.raises(TrustStoreError, match="at least one"):
        TrustStore.from_dict({})


def test_trust_store_from_json_rejects_invalid_json(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(TrustStoreError, match="not valid JSON"):
        TrustStore.from_json(p)


# ---------------------------------------------------------------------------
# verify_envelope_or_raise — happy path
# ---------------------------------------------------------------------------


def test_verify_envelope_or_raise_returns_outcome_on_success():
    env, pem = _make_envelope()
    store = _trust_store_for(env, pem)
    outcome = rf.verify_envelope_or_raise(env, trust_store=store)
    assert outcome.valid
    assert outcome.signature_valid
    assert outcome.issuer_trusted


def test_verify_envelope_or_raise_requires_trust_store():
    env, _ = _make_envelope()
    with pytest.raises(TypeError, match="requires a TrustStore"):
        rf.verify_envelope_or_raise(env)


# ---------------------------------------------------------------------------
# verify_envelope_or_raise — typed failures
# ---------------------------------------------------------------------------


def test_unknown_key_id_raises_untrusted_issuer():
    env, pem = _make_envelope(key_id="real-issuer")
    store = TrustStore.from_dict({"someone-else": pem})
    with pytest.raises(UntrustedIssuer, match="real-issuer"):
        rf.verify_envelope_or_raise(env, trust_store=store)


def test_revoked_key_id_raises_revoked_issuer():
    env, pem = _make_envelope()
    store = _trust_store_for(env, pem, revoked=[env.receipt["key_id"]])
    with pytest.raises(RevokedIssuer, match="revocation"):
        rf.verify_envelope_or_raise(env, trust_store=store)


def test_pinned_param_hash_mismatch_raises_wrong_parameter_set():
    env, pem = _make_envelope()
    store = _trust_store_for(
        env,
        pem,
        parameter_set_pins={env.receipt["key_id"]: "0" * 64},
    )
    with pytest.raises(WrongParameterSet, match="parameter_set_hash"):
        rf.verify_envelope_or_raise(env, trust_store=store)


def test_tampered_body_raises_hash_mismatch():
    env, pem = _make_envelope()
    store = _trust_store_for(env, pem)
    env.regulations = [*env.regulations, "TAMPER"]
    with pytest.raises((HashMismatch, InvalidSignature)):
        rf.verify_envelope_or_raise(env, trust_store=store)


def test_substituted_pem_raises_untrusted_issuer():
    env, _ = _make_envelope()
    other_signer = rf.Signer.generate(issuer="acme", key_id=env.receipt["key_id"])
    store = TrustStore.from_dict(
        {
            env.receipt["key_id"]: other_signer.public_key_pem(),
        }
    )
    with pytest.raises((UntrustedIssuer, InvalidSignature)):
        rf.verify_envelope_or_raise(env, trust_store=store)


# ---------------------------------------------------------------------------
# Sanity: every typed error is an EnvelopeVerificationError subclass
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc_type",
    [HashMismatch, InvalidSignature, UntrustedIssuer, RevokedIssuer, WrongParameterSet],
)
def test_all_failures_subclass_envelope_verification_error(exc_type):
    assert issubclass(exc_type, EnvelopeVerificationError)
