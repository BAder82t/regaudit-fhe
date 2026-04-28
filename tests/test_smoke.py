"""Smoke + integration tests for all six audit primitives.

Each primitive is exercised on synthetic inputs to verify:
  - the oracle produces correct ground truth,
  - the depth-budgeted circuit runs without exceeding d=6,
  - oracle and circuit outputs agree within the polynomial-approximation
    tolerance documented in the patent specification.
"""

from __future__ import annotations

import numpy as np
import pytest

import regaudit_fhe as rf


RNG = np.random.default_rng(20260426)


def test_version_and_modules():
    assert rf.__version__ == "0.0.7"
    for name in ["egf_imss", "etk_fpa_hbc", "esc_cia",
                 "ecp_qssp", "ew1_cdsf", "ecmd_jps"]:
        assert hasattr(rf, name)


def test_audit_aliases_resolve():
    assert rf.audit_fairness is rf.fairness_circuit_d6
    assert rf.audit_provenance is rf.topk_provenance_circuit_d6
    assert rf.audit_concordance is rf.c_index_circuit_d6
    assert rf.audit_calibration is rf.conformal_circuit_d6
    assert rf.audit_drift is rf.w1_circuit_d6
    assert rf.audit_disagreement is rf.disagreement_circuit_d6


def test_egf_imss_disparity_zero_when_groups_match():
    y_true = np.array([1, 0, 1, 0, 1, 0, 1, 0], dtype=float)
    y_pred = np.array([1, 0, 1, 0, 1, 0, 1, 0], dtype=float)
    group_a = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
    group_b = 1.0 - group_a
    report = rf.audit_fairness(y_true, y_pred, group_a, group_b, threshold=0.1)
    assert report.threshold_breached is False
    assert abs(report.demographic_parity_diff) < 1e-9
    assert abs(report.equal_opportunity_diff) < 1e-9


def test_egf_imss_detects_disparity():
    y_true = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
    y_pred = np.array([1, 1, 1, 1, 0, 0, 1, 1], dtype=float)
    group_a = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
    group_b = 1.0 - group_a
    report = rf.audit_fairness(y_true, y_pred, group_a, group_b, threshold=0.1)
    oracle = rf.fairness_oracle(y_true, y_pred, group_a, group_b, threshold=0.1)
    assert report.threshold_breached == oracle.threshold_breached
    assert abs(report.demographic_parity_diff
               - oracle.demographic_parity_diff) < 1e-6


def test_etk_fpa_hbc_topk_matches_oracle():
    n_rows = 64
    attributions = np.abs(RNG.standard_normal(n_rows))
    row_ids = np.arange(n_rows)
    n_buckets = 8
    k = 3
    oracle = rf.topk_provenance_oracle(attributions, row_ids, n_buckets, k)
    circuit = rf.audit_provenance(attributions, row_ids, n_buckets, k)
    assert sorted(circuit.topk_indices) == sorted(oracle.topk_indices)
    assert np.allclose(circuit.bucket_aggregates, oracle.bucket_aggregates)


def test_esc_cia_returns_valid_c_index():
    """The plaintext c-index circuit uses sign-poly-d3 to enumerate
    encrypted-domain pair signs, so its counts and ratio approximate
    the integer-counting oracle within sign-polynomial noise. We
    require monotone bounds and a c-index within 0.25 absolute of
    the oracle.
    """
    n = 32
    risk = RNG.standard_normal(n)
    time = np.abs(RNG.standard_normal(n)) * 100
    event = (RNG.uniform(size=n) < 0.7).astype(float)
    oracle = rf.c_index_oracle(risk, time, event)
    circuit = rf.audit_concordance(risk, time, event)
    assert 0.0 <= circuit.c_index <= 1.0
    assert 0.0 <= circuit.concordant_pairs <= n * (n - 1)
    assert 0.0 <= circuit.comparable_pairs <= n * (n - 1)
    assert abs(circuit.c_index - oracle.c_index) <= 0.25


def test_ecp_qssp_membership_matches_oracle():
    K = 16
    scores = RNG.uniform(size=K)
    quantiles = np.full(K, 0.5)
    oracle = rf.conformal_oracle(scores, quantiles)
    circuit = rf.audit_calibration(scores, quantiles)
    agree = float(np.mean(circuit.membership == oracle.membership))
    assert agree >= 0.85, f"membership agreement {agree} below 0.85"


def test_ew1_cdsf_zero_when_distributions_match():
    bins = 16
    p = RNG.uniform(size=bins)
    q = p.copy()
    report = rf.audit_drift(p, q, drift_threshold=0.005)
    assert report.distance < 1e-9
    assert report.drift_bit is False


def test_ew1_cdsf_detects_drift():
    bins = 16
    p = np.zeros(bins); p[2] = 1.0
    q = np.zeros(bins); q[12] = 1.0
    cvm_ref = rf.ew1_cdsf.cvm_oracle(p, q)
    report = rf.audit_drift(p, q, drift_threshold=0.005)
    assert report.distance > 0.0
    assert report.drift_bit is True
    assert abs(report.distance - cvm_ref) < 1e-9


def test_ecmd_jps_three_models_zero_when_identical():
    coeffs = (0.0, 1.0, 0.0, 0.0)
    models = [coeffs, coeffs, coeffs]
    x = np.linspace(-0.5, 0.5, 32)
    report = rf.audit_disagreement(models, x, threshold=0.01)
    assert report.pairwise_variance < 1e-9
    assert report.breach is False


def test_ecmd_jps_detects_disagreement():
    models = [
        (0.0, 1.0, 0.0, 0.0),
        (0.0, 0.5, 0.0, 0.0),
        (0.0, 1.5, 0.0, 0.0),
    ]
    x = np.linspace(-0.5, 0.5, 32)
    report = rf.audit_disagreement(models, x, threshold=0.001)
    assert report.pairwise_variance > 0.0
    assert report.breach is True


def test_ecmd_jps_rejects_M_lt_3():
    with pytest.raises(ValueError):
        rf.audit_disagreement([(0, 1, 0, 0), (0, 0.5, 0, 0)],
                              np.linspace(0, 1, 8), threshold=0.01)


def test_envelope_roundtrip_passes_receipt_check():
    y_true = np.array([1, 0, 1, 0, 1, 0, 1, 0], dtype=float)
    y_pred = np.array([1, 0, 1, 0, 1, 0, 1, 0], dtype=float)
    group_a = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
    group_b = 1.0 - group_a
    report = rf.audit_fairness(y_true, y_pred, group_a, group_b)
    env = rf.envelope("fairness", report)
    assert rf.verify_receipt(env) is True
    parsed = rf.AuditEnvelope.from_dict(env.to_dict())
    assert rf.verify_receipt(parsed) is True
    parsed.regulations = parsed.regulations + ["TAMPER"]
    assert rf.verify_receipt(parsed) is False


def test_envelope_carries_correct_regulations_per_primitive():
    cases = [
        ("fairness", rf.audit_fairness(
            np.array([1.0, 0.0]), np.array([1.0, 0.0]),
            np.array([1.0, 0.0]), np.array([0.0, 1.0]))),
        ("drift", rf.audit_drift(np.array([1.0, 2.0]), np.array([1.0, 2.0]))),
        ("calibration", rf.audit_calibration(
            np.array([0.1, 0.4]), np.array([0.5, 0.5]))),
    ]
    for primitive, report in cases:
        env = rf.envelope(primitive, report)
        assert env.regulations == rf.REGULATION_MAP[primitive]


def test_depth_budget_respected_on_all_primitives():
    """Each primitive's circuit must complete without raising
    DepthBudgetExceeded (the SlotVec constructor enforces this)."""
    y = np.array([1.0, 0.0, 1.0, 0.0])
    rf.audit_fairness(y, y, y, 1.0 - y)

    rf.audit_provenance(np.abs(RNG.standard_normal(16)),
                        np.arange(16), n_buckets=4, k=2)

    rf.audit_concordance(RNG.standard_normal(8),
                         np.abs(RNG.standard_normal(8)),
                         np.ones(8))

    rf.audit_calibration(RNG.uniform(size=8), np.full(8, 0.5))

    rf.audit_drift(np.array([1.0, 2.0, 3.0, 4.0]),
                   np.array([2.0, 2.0, 3.0, 3.0]),
                   drift_threshold=0.005)

    rf.audit_disagreement(
        [(0, 1, 0, 0), (0, 0.9, 0, 0), (0, 1.1, 0, 0)],
        np.linspace(-0.5, 0.5, 16),
        threshold=0.01,
    )
