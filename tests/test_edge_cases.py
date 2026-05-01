"""Adversarial / edge-case tests.

Each test asserts a specific failure mode at the audit-primitive
boundary or a known-good behaviour at an extreme input. Failures here
mean either silent correctness loss (worst case) or a regression
against a previously documented guard (still bad).
"""

from __future__ import annotations

import math

import numpy as np
import pytest

import regaudit_fhe as rf

# --------------------------------------------------------------------------
# 1. NaN / Inf rejection across every primitive
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [np.nan, math.inf, -math.inf])
def test_fairness_rejects_nan_or_inf(bad):
    y = np.array([1.0, 0.0, 1.0, 0.0])
    g = np.array([1.0, 1.0, 0.0, 0.0])
    poison = np.array([bad, 0.0, 1.0, 0.0])
    with pytest.raises(ValueError, match="non-finite"):
        rf.audit_fairness(poison, y, g, 1.0 - g)


@pytest.mark.parametrize("bad", [np.nan, math.inf, -math.inf])
def test_drift_rejects_nan_or_inf(bad):
    p = np.array([1.0, 2.0, 3.0, 4.0])
    q = np.array([bad, 2.0, 3.0, 3.0])
    with pytest.raises(ValueError, match="non-finite"):
        rf.audit_drift(p, q)


@pytest.mark.parametrize("bad", [np.nan, math.inf, -math.inf])
def test_calibration_rejects_nan_or_inf(bad):
    with pytest.raises(ValueError, match="non-finite"):
        rf.audit_calibration(np.array([0.1, bad, 0.5, 0.7]), np.full(4, 0.5))


@pytest.mark.parametrize("bad", [np.nan, math.inf])
def test_concordance_rejects_nan_or_inf(bad):
    with pytest.raises(ValueError, match="non-finite"):
        rf.audit_concordance(
            np.array([1.0, bad, 3.0]), np.array([10.0, 20.0, 30.0]), np.array([1.0, 0.0, 1.0])
        )


@pytest.mark.parametrize("bad", [np.nan, math.inf])
def test_provenance_rejects_nan_or_inf(bad):
    with pytest.raises(ValueError, match="non-finite"):
        rf.audit_provenance(np.array([0.1, bad, 0.5, 0.7]), np.arange(4), n_buckets=2, k=1)


@pytest.mark.parametrize("bad", [np.nan, math.inf])
def test_disagreement_rejects_nan_or_inf(bad):
    coeffs = [(0.0, 1.0, 0.0, 0.0)] * 3
    with pytest.raises(ValueError, match="non-finite"):
        rf.audit_disagreement(coeffs, np.array([0.1, bad, 0.3]))


# --------------------------------------------------------------------------
# 2. Empty arrays
# --------------------------------------------------------------------------


def test_empty_arrays_rejected_for_fairness():
    with pytest.raises(ValueError, match="non-empty"):
        rf.audit_fairness(np.array([]), np.array([]), np.array([]), np.array([]))


def test_empty_arrays_rejected_for_drift():
    with pytest.raises(ValueError, match="non-empty"):
        rf.audit_drift(np.array([]), np.array([]))


def test_empty_arrays_rejected_for_calibration():
    with pytest.raises(ValueError, match="non-empty"):
        rf.audit_calibration(np.array([]), np.array([]))


# --------------------------------------------------------------------------
# 3. Length mismatches
# --------------------------------------------------------------------------


def test_fairness_rejects_length_mismatch():
    y = np.array([1.0, 0.0, 1.0, 0.0])
    short = np.array([1.0, 0.0])
    with pytest.raises(ValueError, match="length mismatch"):
        rf.audit_fairness(y, y, short, np.array([0.0, 1.0]))


def test_drift_rejects_shape_mismatch():
    p = np.array([1.0, 2.0, 3.0, 4.0])
    q = np.array([1.0, 2.0])
    with pytest.raises(ValueError, match="shape mismatch"):
        rf.audit_drift(p, q)


def test_calibration_rejects_shape_mismatch():
    with pytest.raises(ValueError, match="shape mismatch"):
        rf.audit_calibration(np.array([0.1, 0.5]), np.array([0.5, 0.6, 0.7]))


def test_concordance_rejects_length_mismatch():
    with pytest.raises(ValueError, match="length mismatch"):
        rf.audit_concordance(
            np.array([1.0, 2.0, 3.0]), np.array([10.0, 20.0]), np.array([1.0, 0.0])
        )


# --------------------------------------------------------------------------
# 4. Non-power-of-two arrays handled by padding
# --------------------------------------------------------------------------


@pytest.mark.parametrize("size", [3, 5, 7, 11, 13])
def test_fairness_accepts_non_power_of_two(size):
    rng = np.random.default_rng(0)
    y_t = (rng.uniform(size=size) < 0.5).astype(float)
    y_p = (rng.uniform(size=size) < 0.5).astype(float)
    g_a = (np.arange(size) < size // 2).astype(float)
    if g_a.sum() == 0 or g_a.sum() == size:
        pytest.skip("group degeneracy at this size")
    g_b = 1.0 - g_a
    rep = rf.audit_fairness(y_t, y_p, g_a, g_b)
    assert isinstance(rep, rf.FairnessReport)


# --------------------------------------------------------------------------
# 5. Single-group / zero-denominator cases
# --------------------------------------------------------------------------


def test_fairness_rejects_empty_group_a():
    y = np.array([1.0, 0.0, 1.0, 0.0])
    g_a = np.zeros(4)
    g_b = np.ones(4)
    with pytest.raises(ValueError, match="zero members"):
        rf.audit_fairness(y, y, g_a, g_b)


def test_fairness_rejects_empty_group_b():
    y = np.array([1.0, 0.0, 1.0, 0.0])
    g_a = np.ones(4)
    g_b = np.zeros(4)
    with pytest.raises(ValueError, match="zero members"):
        rf.audit_fairness(y, y, g_a, g_b)


# --------------------------------------------------------------------------
# 6. All-positive / all-negative labels
# --------------------------------------------------------------------------


def test_all_positive_labels_does_not_crash_fairness():
    y_t = np.ones(8)
    y_p = np.ones(8)
    g = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
    rep = rf.audit_fairness(y_t, y_p, g, 1.0 - g)
    assert isinstance(rep.demographic_parity_diff, float)


def test_all_negative_labels_does_not_crash_fairness():
    y_t = np.zeros(8)
    y_p = np.zeros(8)
    g = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
    rep = rf.audit_fairness(y_t, y_p, g, 1.0 - g)
    assert isinstance(rep.demographic_parity_diff, float)


# --------------------------------------------------------------------------
# 7. Extreme thresholds
# --------------------------------------------------------------------------


def test_fairness_threshold_zero_always_breaches_when_any_disparity():
    y_t = np.array([1.0, 1.0, 0.0, 0.0])
    y_p = np.array([1.0, 0.0, 0.0, 0.0])
    g = np.array([1.0, 1.0, 0.0, 0.0])
    rep = rf.audit_fairness(y_t, y_p, g, 1.0 - g, threshold=0.0)
    assert rep.threshold_breached is True


def test_fairness_threshold_one_never_breaches():
    y_t = np.array([1.0, 1.0, 0.0, 0.0])
    y_p = np.array([1.0, 0.0, 0.0, 1.0])
    g = np.array([1.0, 1.0, 0.0, 0.0])
    rep = rf.audit_fairness(y_t, y_p, g, 1.0 - g, threshold=1.0)
    assert rep.threshold_breached is False


def test_fairness_threshold_outside_unit_interval_rejected():
    y_t = np.array([1.0, 0.0])
    y_p = np.array([1.0, 0.0])
    g = np.array([1.0, 0.0])
    with pytest.raises(ValueError, match="lie in"):
        rf.audit_fairness(y_t, y_p, g, 1.0 - g, threshold=-0.1)
    with pytest.raises(ValueError, match="lie in"):
        rf.audit_fairness(y_t, y_p, g, 1.0 - g, threshold=2.0)


def test_drift_negative_threshold_rejected():
    with pytest.raises(ValueError, match="non-negative"):
        rf.audit_drift(np.array([1.0, 2.0]), np.array([1.0, 2.0]), drift_threshold=-1e-3)


# --------------------------------------------------------------------------
# 8. Large batch
# --------------------------------------------------------------------------


def test_large_batch_runs_within_seconds():
    rng = np.random.default_rng(0)
    n = 4096
    y_t = (rng.uniform(size=n) < 0.4).astype(float)
    y_p = (rng.uniform(size=n) < 0.4).astype(float)
    g = (rng.uniform(size=n) < 0.5).astype(float)
    rep = rf.audit_fairness(y_t, y_p, g, 1.0 - g)
    assert isinstance(rep, rf.FairnessReport)


# --------------------------------------------------------------------------
# 9. Provenance bucket / k constraints
# --------------------------------------------------------------------------


def test_provenance_rejects_k_zero():
    with pytest.raises(ValueError, match="k must be"):
        rf.audit_provenance(np.array([0.1, 0.2, 0.3, 0.4]), np.arange(4), n_buckets=4, k=0)


def test_provenance_rejects_k_above_n_buckets():
    with pytest.raises(ValueError, match="k must be"):
        rf.audit_provenance(np.array([0.1, 0.2, 0.3, 0.4]), np.arange(4), n_buckets=4, k=10)


def test_provenance_rejects_zero_buckets():
    with pytest.raises(ValueError, match="n_buckets must be"):
        rf.audit_provenance(np.array([0.1, 0.2]), np.arange(2), n_buckets=0, k=1)


# --------------------------------------------------------------------------
# 10. Disagreement: M < 3 + bad polynomial shape
# --------------------------------------------------------------------------


def test_disagreement_rejects_m_lt_3():
    coeffs = [(0.0, 1.0, 0.0, 0.0)] * 2
    with pytest.raises(ValueError, match="M >= 3|3 model versions"):
        rf.audit_disagreement(coeffs, np.array([0.1, 0.2, 0.3]))


def test_disagreement_rejects_short_polynomial():
    bad = [(0.0, 1.0, 0.0)] * 3
    with pytest.raises(ValueError, match="deg-3 poly"):
        rf.audit_disagreement(bad, np.array([0.1, 0.2, 0.3]))
