"""Differential-privacy output-perturbation tests."""

from __future__ import annotations

import math

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe import dp


def test_laplace_scale_and_gaussian_sigma_formulas():
    assert dp.laplace_scale(sensitivity=2.0, epsilon=4.0) == pytest.approx(0.5)
    sigma = dp.gaussian_sigma(sensitivity=1.0, epsilon=1.0, delta=1e-5)
    assert sigma == pytest.approx(math.sqrt(2 * math.log(1.25 / 1e-5)))


@pytest.mark.parametrize("mechanism", [dp.LAPLACE, dp.GAUSSIAN])
def test_noise_is_unbiased_and_correctly_scaled(mechanism):
    spec = dp.DPSpec(
        sensitivity=1.0,
        epsilon=0.5,
        mechanism=mechanism,
        delta=1e-6 if mechanism == dp.GAUSSIAN else 0.0,
    )
    rng = dp.make_rng(123)
    draws = np.array([dp.privatize_value(3.0, spec, rng) - 3.0 for _ in range(20000)])
    assert abs(draws.mean()) < 0.1  # unbiased
    if mechanism == dp.LAPLACE:
        # Var(Laplace(b)) = 2 b^2.
        assert draws.std() == pytest.approx(math.sqrt(2) * spec.noise_scale(), rel=0.1)
    else:
        assert draws.std() == pytest.approx(spec.noise_scale(), rel=0.1)


def test_seed_determinism():
    spec = dp.DPSpec(sensitivity=1.0, epsilon=1.0)
    a = dp.privatize_value(0.0, spec, dp.make_rng(7))
    b = dp.privatize_value(0.0, spec, dp.make_rng(7))
    assert a == b


def test_invalid_parameters_rejected():
    with pytest.raises(dp.DPError):
        dp.DPSpec(sensitivity=0.0, epsilon=1.0)
    with pytest.raises(dp.DPError):
        dp.DPSpec(sensitivity=1.0, epsilon=-1.0)
    with pytest.raises(dp.DPError):
        dp.DPSpec(sensitivity=1.0, epsilon=1.0, mechanism="exponential")
    with pytest.raises(dp.DPError):
        dp.DPSpec(sensitivity=1.0, epsilon=1.0, mechanism=dp.GAUSSIAN, delta=0.0)
    with pytest.raises(dp.DPError):
        dp.DPSpec(sensitivity=1.0, epsilon=1.0, mechanism=dp.LAPLACE, delta=0.1)


def test_privatize_report_noises_named_fields_only():
    report = rf.fairness_oracle(
        np.array([1, 0, 1, 1.0]),
        np.array([1, 0, 0, 1.0]),
        np.array([1, 1, 0, 0.0]),
        np.array([0, 0, 1, 1.0]),
    )
    spec = dp.DPSpec(sensitivity=0.5, epsilon=1.0)
    priv, block = dp.privatize_report(report, {"demographic_parity_diff": spec}, rng=dp.make_rng(1))
    # named field changed, unnamed field untouched
    assert priv.demographic_parity_diff != report.demographic_parity_diff
    assert priv.equal_opportunity_diff == report.equal_opportunity_diff
    assert block["applied"] is True
    assert block["fields"]["demographic_parity_diff"]["mechanism"] == dp.LAPLACE


def test_privatize_report_rejects_boolean_and_unknown_fields():
    report = rf.fairness_oracle(
        np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([0.0, 1.0])
    )
    spec = dp.DPSpec(sensitivity=1.0, epsilon=1.0)
    with pytest.raises(dp.DPError):
        dp.privatize_report(report, {"threshold_breached": spec})
    with pytest.raises(dp.DPError):
        dp.privatize_report(report, {"no_such_field": spec})


def test_accountant_basic_composition_and_budget():
    acc = dp.PrivacyAccountant(epsilon_budget=1.0)
    spec = dp.DPSpec(sensitivity=1.0, epsilon=0.4)
    acc.charge(spec)
    acc.charge(spec)
    assert acc.spent_epsilon == pytest.approx(0.8)
    assert acc.remaining_epsilon() == pytest.approx(0.2)
    with pytest.raises(dp.DPError):
        acc.charge(spec)  # would reach 1.2 > budget


def test_dp_block_is_signed_into_envelope_and_tamper_evident():
    report = rf.fairness_oracle(
        np.array([1, 0, 1, 1.0]),
        np.array([1, 0, 0, 1.0]),
        np.array([1, 1, 0, 0.0]),
        np.array([0, 0, 1, 1.0]),
    )
    spec = dp.DPSpec(sensitivity=0.5, epsilon=1.0)
    priv, block = dp.privatize_report(report, {"demographic_parity_diff": spec}, rng=dp.make_rng(2))
    signer = rf.Signer.generate(issuer="acme", key_id="k1")
    env = rf.envelope("fairness", priv, signer=signer, dp=block)
    keys = {"k1": signer.public_key_pem()}

    assert env.dp is not None and env.dp["applied"] is True
    assert "dp" in env.signed_body()
    assert rf.verify_receipt(env, trusted_keys=keys, strict=True)

    # Tampering with the disclosed epsilon breaks the signature.
    env.dp["fields"]["demographic_parity_diff"]["epsilon"] = 99.0
    assert not rf.verify_receipt(env, trusted_keys=keys, strict=True)


def test_dp_block_survives_envelope_roundtrip():
    report = rf.fairness_oracle(
        np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([0.0, 1.0])
    )
    spec = dp.DPSpec(sensitivity=1.0, epsilon=2.0, mechanism=dp.GAUSSIAN, delta=1e-5)
    priv, block = dp.privatize_report(report, {"demographic_parity_diff": spec}, rng=dp.make_rng(3))
    env = rf.envelope("fairness", priv, dp=block)
    restored = rf.AuditEnvelope.from_dict(env.to_dict())
    assert restored.dp == env.dp
