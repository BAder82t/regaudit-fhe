"""Public surface of the Phase 3A trust core, and the ``valid`` deprecation."""

from __future__ import annotations

import warnings

import numpy as np
import pytest

import regaudit_fhe as rf

NEW_NAMES = [
    "AuditEnvelopeV2",
    "envelope_v2",
    "parse_envelope",
    "EnvelopeFormatError",
    "CanonicalError",
    "VerificationPolicy",
    "VerificationResult",
    "verify_report",
    "PolicyError",
    "VerificationUnavailable",
    "TimestampEvidence",
    "TrustHistory",
    "KeyEntry",
    "InMemoryReplayCache",
    "SqliteReplayCache",
    "ReplayStateError",
]


@pytest.mark.parametrize("name", NEW_NAMES)
def test_new_names_are_exported(name):
    assert hasattr(rf, name) and name in rf.__all__


def test_build_app_is_a_documented_supported_entry_point():
    pytest.importorskip("fastapi")
    import regaudit_fhe.server as server

    assert "build_app" in server.__all__
    assert server.build_app.__doc__ and "supported" in server.build_app.__doc__.lower()
    for name in server.__all__:
        assert hasattr(server, name), name


def _signed():
    signer = rf.Signer.generate(issuer="acme", key_id="k1")
    report = rf.audit_fairness(
        np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([0.0, 1.0])
    )
    return rf.envelope("fairness", report, signer=signer), signer


def test_legacy_outcome_valid_is_deprecated_but_preserved():
    env, signer = _signed()
    outcome = rf.verify_envelope(env, trusted_keys={"k1": signer.public_key_pem()})
    with pytest.warns(DeprecationWarning, match="valid"):
        assert outcome.valid is True
    refused = rf.verify_envelope(env, trusted_keys={"nope": signer.public_key_pem()})
    with pytest.warns(DeprecationWarning):
        assert refused.valid is False


def test_legacy_outcome_other_access_paths_do_not_warn():
    env, signer = _signed()
    outcome = rf.verify_envelope(env, trusted_keys={"k1": signer.public_key_pem()})
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert outcome.trust_status == "TRUSTED"
        assert outcome.to_dict()["valid"] is True  # the key is kept for compatibility
        repr(outcome)
        assert outcome == outcome


def test_verify_receipt_still_returns_a_plain_bool_without_warning():
    env, signer = _signed()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert rf.verify_receipt(env, trusted_keys={"k1": signer.public_key_pem()}, strict=True)
