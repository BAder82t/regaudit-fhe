"""Pins the README table "A valid signature is not a trusted signer".

An attacker can sign with their own key and embed it, so every check that uses only the embedded
key says "intact" for a forgery. Only a registered key says "trusted". These tests fix which API
surface answers which question, so the documentation cannot drift from the behaviour.
"""

from __future__ import annotations

import warnings

import numpy as np
import pytest

import regaudit_fhe as rf


@pytest.fixture(scope="module")
def report():
    return rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )


@pytest.fixture(scope="module")
def approved():
    return rf.Signer.generate(issuer="acme", key_id="acme-1")


@pytest.fixture(scope="module")
def forger():
    return rf.Signer.generate(issuer="acme", key_id="acme-1")  # same names, different key


@pytest.fixture(scope="module")
def store(approved):
    return rf.TrustStore.from_dict({"keys": {"acme-1": approved.public_key_pem()}})


def _v2(report, signer):
    return rf.envelope_v2("fairness", report, signer=signer, deployment_id="dep-1")


def test_a_forged_report_is_intact_on_its_own_but_not_trusted(report, forger, store):
    forged = _v2(report, forger)
    own = rf.verify_report(forged, rf.VerificationPolicy(allow_self_signed=True))
    assert own.integrity_valid and own.trust_status == "SELF_SIGNED_ONLY" and not own.accepted
    against_store = rf.verify_report(forged, rf.VerificationPolicy(trust_store=store))
    assert against_store.trust_status == "INVALID" and not against_store.accepted
    assert "KEY_EMBEDDED_MISMATCH" in against_store.blocking_reasons


def test_the_approved_key_is_trusted(report, approved, store):
    res = rf.verify_report(_v2(report, approved), rf.VerificationPolicy(trust_store=store))
    assert res.trust_status == "TRUSTED" and res.accepted


def test_no_trust_material_and_no_opt_in_is_refused_not_trusted(report, forger):
    with pytest.raises(rf.VerificationUnavailable):
        rf.verify_report(_v2(report, forger), rf.VerificationPolicy())


def test_verify_receipt_returns_true_for_a_forgery(report, forger):
    """Documented trap: a truthy return value is integrity only. Do not use it to accept."""
    env = rf.envelope("fairness", report, signer=forger)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        assert rf.verify_receipt(env) is True


def test_legacy_valid_flag_is_true_for_a_self_signed_report_but_trust_status_is_not(report, forger):
    env = rf.envelope("fairness", report, signer=forger)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        outcome = rf.verify_envelope(env)
        assert outcome.valid is True  # the trap the README warns about
    assert outcome.trust_status == "SELF_SIGNED_ONLY"
