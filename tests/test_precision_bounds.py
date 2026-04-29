"""Precision-bound tests.

Verifies that:

  - CKKSParams' ``precision_loss_bound`` is enforced at construction
    time (rejects scaling-factor configurations whose worst-case
    plaintext-side loss exceeds the bound),
  - the encrypted backend produces output within a per-primitive
    error envelope on inputs typical of regulatory audits,
  - the README's ``max abs error`` claims (~1e-5 .. ~1e-7 range at
    N=2^14) hold up when re-run on the same fixed seed.
"""

from __future__ import annotations

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.fhe import CKKSParams, ParameterValidationError

# ---------------------------------------------------------------------------
# CKKSParams precision-bound enforcement
# ---------------------------------------------------------------------------


def test_default_precision_bound_is_strict_for_depth_six():
    p = CKKSParams()
    worst_case = p.multiplicative_depth * (2.0 ** -p.scaling_mod_size)
    assert worst_case <= p.precision_loss_bound


def test_too_small_scaling_mod_size_rejected():
    with pytest.raises(ParameterValidationError, match="precision loss"):
        CKKSParams(scaling_mod_size=20, precision_loss_bound=1e-9)


def test_precision_bound_scales_with_depth():
    p_low = CKKSParams(multiplicative_depth=1)
    p_high = CKKSParams(multiplicative_depth=6)
    worst_low = p_low.multiplicative_depth * (2.0 ** -p_low.scaling_mod_size)
    worst_high = p_high.multiplicative_depth * (2.0 ** -p_high.scaling_mod_size)
    assert worst_high > worst_low
    assert worst_high <= p_high.precision_loss_bound


def test_precision_bound_outside_unit_interval_rejected():
    with pytest.raises(ParameterValidationError, match="precision_loss_bound"):
        CKKSParams(precision_loss_bound=0.0)
    with pytest.raises(ParameterValidationError, match="precision_loss_bound"):
        CKKSParams(precision_loss_bound=2.0)


# ---------------------------------------------------------------------------
# End-to-end precision: encrypted output stays within envelope
# ---------------------------------------------------------------------------


tenseal = pytest.importorskip("tenseal")
from regaudit_fhe.fhe import build_d6_context  # noqa: E402
from regaudit_fhe.fhe import primitives as fhe_p  # noqa: E402


@pytest.fixture(scope="module")
def ctx():
    return build_d6_context()


# Per-primitive precision envelopes: error ceilings the README and the
# benchmark SUMMARY.md are entitled to claim. If a primitive starts
# violating its bound, this test fails loudly.
PRECISION_ENVELOPES = {
    "fairness":     5e-5,
    "provenance":   5e-4,
    "drift":        5e-4,
    "calibration":  1e-9,
    "concordance":  1e-9,
    "disagreement": 5e-5,
}


def test_fairness_decrypt_error_within_envelope(ctx):
    rng = np.random.default_rng(20260427)
    n = 64
    y_t = (rng.uniform(size=n) < 0.4).astype(float)
    y_p = (rng.uniform(size=n) < 0.4).astype(float)
    g_a = (rng.uniform(size=n) < 0.5).astype(float)
    g_b = 1.0 - g_a
    plain = rf.audit_fairness(y_t, y_p, g_a, g_b)
    enc = fhe_p.fairness_encrypted(ctx, y_t, y_p, g_a, g_b)
    err = max(abs(plain.demographic_parity_diff
                  - enc.demographic_parity_diff),
              abs(plain.equal_opportunity_diff
                  - enc.equal_opportunity_diff),
              abs(plain.predictive_parity_diff
                  - enc.predictive_parity_diff))
    assert err < PRECISION_ENVELOPES["fairness"]


def test_drift_decrypt_error_within_envelope(ctx):
    rng = np.random.default_rng(20260427)
    n = 16
    p = rng.uniform(size=n)
    q = p + rng.normal(scale=0.05, size=n)
    plain = rf.audit_drift(p, q)
    enc = fhe_p.w1_encrypted(ctx, p, q)
    err = abs(plain.distance - enc.distance)
    assert err < PRECISION_ENVELOPES["drift"], (
        f"drift error {err:.3e} exceeds envelope "
        f"{PRECISION_ENVELOPES['drift']:.3e}"
    )


def test_provenance_decrypt_error_within_envelope(ctx):
    rng = np.random.default_rng(20260427)
    n = 64
    attr = np.abs(rng.standard_normal(n))
    rows = np.arange(n)
    plain = rf.audit_provenance(attr, rows, n_buckets=8, k=3)
    enc = fhe_p.topk_provenance_encrypted(ctx, attr, rows, n_buckets=8, k=3)
    err = float(np.max(np.abs(plain.bucket_aggregates
                              - enc.bucket_aggregates)))
    assert err < PRECISION_ENVELOPES["provenance"]


def test_disagreement_decrypt_error_within_envelope(ctx):
    coeffs = [(0.0, 1.0 + 0.05 * i, 0.02 * i, 0.0) for i in range(5)]
    x = np.linspace(-0.4, 0.4, 16)
    plain = rf.audit_disagreement(coeffs, x)
    enc = fhe_p.disagreement_encrypted(ctx, coeffs, x)
    err = abs(plain.pairwise_variance - enc.pairwise_variance)
    assert err < PRECISION_ENVELOPES["disagreement"]


# ---------------------------------------------------------------------------
# Threshold stability under encryption noise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", list(range(10)))
def test_threshold_decision_does_not_flip_under_typical_noise(ctx, seed):
    """Repeat the threshold-stability check across 10 random seeds; if
    CKKS noise ever flips a breach decision, this test fails."""
    rng = np.random.default_rng(seed)
    n = 32
    y_t = (rng.uniform(size=n) < 0.4).astype(float)
    y_p = ((rng.uniform(size=n) < 0.4) | y_t.astype(bool)).astype(float)
    g_a = (rng.uniform(size=n) < 0.5).astype(float)
    if g_a.sum() == 0 or g_a.sum() == n:
        pytest.skip("group degeneracy")
    g_b = 1.0 - g_a
    plain = rf.audit_fairness(y_t, y_p, g_a, g_b, threshold=0.1)
    enc = fhe_p.fairness_encrypted(ctx, y_t, y_p, g_a, g_b, threshold=0.1)
    assert plain.threshold_breached == enc.threshold_breached, (
        f"seed {seed}: encryption noise flipped the breach decision"
    )
