"""The legacy boolean answers warn, name the self-signed case, and return what they always did."""

from __future__ import annotations

import warnings

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe import reports


@pytest.fixture(scope="module")
def signer():
    return rf.Signer.generate(issuer="acme", key_id="acme-1")


@pytest.fixture(scope="module")
def env(signer):
    report = rf.audit_drift(np.array([0.2, 0.8]), np.array([0.3, 0.7]))
    return rf.envelope("drift", report, signer=signer)


@pytest.fixture(autouse=True)
def _fresh_once_flags():
    reports._WEAK_WARNING.reset()
    reports._RECEIPT_DEPRECATION.reset()


def _collect(fn):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        value = fn()
    return value, [w for w in caught if issubclass(w.category, DeprecationWarning)]


def test_verify_receipt_without_trust_material_warns_and_still_returns_true(env):
    reports._WEAK_WARNING.reset()
    value, deprecations = _collect(lambda: rf.verify_receipt(env))
    assert value is True
    assert len(deprecations) == 1
    text = str(deprecations[0].message)
    assert "SELF-SIGNED" in text and "verify_trusted" in text and "trust_status" in text
    assert deprecations[0].filename == __file__  # points at the caller, not at the library


def test_verify_receipt_deprecation_is_once_per_process_not_every_call(env):
    reports._RECEIPT_DEPRECATION.reset()
    first_value, first = _collect(lambda: rf.verify_receipt(env))
    second_value, second = _collect(lambda: rf.verify_receipt(env))
    assert len(first) == 1 and second == []
    assert first_value is True and second_value is True  # the return value never changes


def test_verify_receipt_with_trust_material_does_not_warn(env, signer):
    store = rf.TrustStore.from_dict({"keys": {"acme-1": signer.public_key_pem()}})
    for kwargs in (
        {"trust_store": store},
        {"trusted_keys": store},
        {"trusted_keys": {"acme-1": signer.public_key_pem()}, "strict": True},
    ):
        value, deprecations = _collect(lambda kwargs=kwargs: rf.verify_receipt(env, **kwargs))
        assert value is True and deprecations == []


def test_verify_receipt_strict_without_material_still_returns_false_without_noise(env):
    value, deprecations = _collect(lambda: rf.verify_receipt(env, strict=True))
    assert value is False and deprecations == []


def test_verify_receipt_return_values_are_unchanged_for_a_tampered_report(env):
    bad = rf.AuditEnvelope.from_dict(env.to_dict())
    bad.result = dict(bad.result, distance=99.0)
    value, _ = _collect(lambda: rf.verify_receipt(bad))
    assert value is False


def test_outcome_valid_warns_naming_the_self_signed_case_and_keeps_its_value(env, signer):
    self_signed = rf.verify_envelope(env)
    assert self_signed.trust_status == "SELF_SIGNED_ONLY"
    value, deprecations = _collect(lambda: self_signed.valid)
    assert value is True  # unchanged: True although nobody authenticated the issuer
    text = str(deprecations[0].message)
    assert len(deprecations) == 1
    assert text.startswith(
        "VerificationOutcome.valid is deprecated"
    )  # pyproject filter relies on it
    assert "SELF-SIGNED" in text and "verify_trusted" in text and "TRUSTED" in text

    trusted = rf.verify_envelope(env, trusted_keys={"acme-1": signer.public_key_pem()})
    value, deprecations = _collect(lambda: trusted.valid)
    assert value is True and len(deprecations) == 1


def test_outcome_valid_is_still_false_for_an_unknown_issuer(env):
    outcome = rf.verify_envelope(
        env, trusted_keys={"someone-else": rf.Signer.generate(issuer="x").public_key_pem()}
    )
    value, deprecations = _collect(lambda: outcome.valid)
    assert value is False and len(deprecations) == 1


def test_the_new_api_emits_no_deprecation_warning(env, signer):
    store = rf.TrustStore.from_dict({"keys": {"acme-1": signer.public_key_pem()}})
    value, deprecations = _collect(lambda: rf.verify_trusted(env.to_json(), store).trusted)
    assert value is True and deprecations == []
