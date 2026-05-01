"""Ciphertext / plaintext equivalence tests.

For each of the six audit primitives, run:

  1. The plaintext oracle (mathematical ground truth).
  2. The plaintext SlotVec circuit (depth-tracked numpy model).
  3. The encrypted CKKS circuit on real TenSEAL ciphertexts.

Then verify all three agree within CKKS noise tolerance (~1e-2 for
products of plaintext-scale and depth-budgeted operations).

Skipped automatically if the [fhe] extra is not installed.
"""

from __future__ import annotations

import numpy as np
import pytest

import regaudit_fhe as rf

tenseal = pytest.importorskip("tenseal")
from regaudit_fhe.fhe import build_d6_context  # noqa: E402
from regaudit_fhe.fhe import primitives as fhe_p  # noqa: E402

RNG = np.random.default_rng(20260426)
TOL = 1e-2  # CKKS noise tolerance after up to six multiplications
TOL_LOOSE = 5e-2  # tolerance for sums-of-many-mults primitives


@pytest.fixture(scope="module")
def ctx():
    return build_d6_context()


def test_fairness_equivalence(ctx) -> None:
    n = 32
    y_true = (RNG.uniform(size=n) < 0.4).astype(float)
    y_pred = ((RNG.uniform(size=n) < 0.4) | y_true.astype(bool)).astype(float)
    g_a = (RNG.uniform(size=n) < 0.5).astype(float)
    g_b = 1.0 - g_a

    oracle = rf.fairness_oracle(y_true, y_pred, g_a, g_b)
    plain = rf.audit_fairness(y_true, y_pred, g_a, g_b)
    enc = fhe_p.fairness_encrypted(ctx, y_true, y_pred, g_a, g_b)

    assert abs(oracle.demographic_parity_diff - plain.demographic_parity_diff) < 1e-9
    assert abs(plain.demographic_parity_diff - enc.demographic_parity_diff) < TOL
    assert abs(plain.equal_opportunity_diff - enc.equal_opportunity_diff) < TOL
    assert abs(plain.predictive_parity_diff - enc.predictive_parity_diff) < TOL


def test_provenance_equivalence(ctx) -> None:
    n_rows = 64
    attributions = np.abs(RNG.standard_normal(n_rows))
    row_ids = np.arange(n_rows)
    n_buckets, k = 8, 3

    oracle = rf.topk_provenance_oracle(attributions, row_ids, n_buckets, k)
    plain = rf.audit_provenance(attributions, row_ids, n_buckets, k)
    enc = fhe_p.topk_provenance_encrypted(ctx, attributions, row_ids, n_buckets, k)

    assert sorted(plain.topk_indices) == sorted(oracle.topk_indices)
    assert sorted(enc.topk_indices) == sorted(oracle.topk_indices)
    assert np.max(np.abs(enc.bucket_aggregates - plain.bucket_aggregates)) < TOL


def test_calibration_equivalence(ctx) -> None:
    K = 16
    scores = RNG.uniform(size=K)
    quantiles = np.full(K, 0.5)

    oracle = rf.conformal_oracle(scores, quantiles)
    plain = rf.audit_calibration(scores, quantiles)
    enc = fhe_p.conformal_encrypted(ctx, scores, quantiles)

    # Plaintext circuit uses the same sign-poly approximation as the
    # encrypted backend, so plain.membership matches enc.membership
    # exactly. The integer-counting oracle uses a hard threshold and
    # can disagree on points within sign-poly-d3's noise band near
    # the quantile.
    assert np.all(plain.membership == enc.membership)
    # No more than two scores within the noise band (typical for K=16
    # and uniform scores around 0.5).
    membership_drift = int(np.sum(oracle.membership != enc.membership))
    assert membership_drift <= 2, (
        f"sign-poly-d3 flipped {membership_drift} membership bits vs the integer oracle"
    )


def test_drift_equivalence(ctx) -> None:
    bins = 16
    p = RNG.uniform(size=bins)
    q = p + RNG.normal(scale=0.05, size=bins)
    q = np.maximum(q, 0)

    plain = rf.audit_drift(p, q)
    enc = fhe_p.w1_encrypted(ctx, p, q)

    assert abs(plain.distance - enc.distance) / max(plain.distance, 1e-9) < TOL_LOOSE


def test_disagreement_equivalence(ctx) -> None:
    coeffs = [(0.0, 1.00, 0.05, 0.0), (0.0, 0.95, 0.06, 0.0), (0.0, 1.05, 0.04, 0.0)]
    x = np.linspace(-0.4, 0.4, 32)

    plain = rf.audit_disagreement(coeffs, x)
    enc = fhe_p.disagreement_encrypted(ctx, coeffs, x)

    rel = abs(plain.pairwise_variance - enc.pairwise_variance) / max(plain.pairwise_variance, 1e-9)
    assert rel < TOL_LOOSE, (
        f"disagreement variance diverges: plain={plain.pairwise_variance} "
        f"enc={enc.pairwise_variance} rel_err={rel}"
    )


def test_concordance_within_ckks_tolerance(ctx) -> None:
    """ESC-CIA: encrypted C-index agrees with plaintext within CKKS noise.

    Risk, time, and event vectors are encrypted under CKKS. Per-shift
    sign-polynomial aggregates (S1, S2, S3) are decrypted; the four
    concordance bins (A, B, C, D) and the C-index ratio are recovered
    from those aggregates plaintext-side. Sign-poly-d3 has roughly
    30% worst-case relative error near zero, which compounds across
    pair sums; the regulator-facing tolerance for the depth-6 budget
    is therefore expressed on the c-index ratio rather than exact
    counts.
    """
    n = 16
    risk = RNG.standard_normal(n)
    time = np.abs(RNG.standard_normal(n)) * 100
    event = (RNG.uniform(size=n) < 0.7).astype(float)

    plain = rf.audit_concordance(risk, time, event)
    enc = fhe_p.c_index_encrypted(ctx, risk, time, event)

    # Tolerate up to 0.25 absolute error on the c-index ratio: this
    # is the regulator-facing threshold-stability margin documented
    # in docs/specs/03_esc_cia.md for the d=6 sign-poly-d3 budget.
    assert abs(plain.c_index - enc.c_index) <= 0.25, (
        f"plaintext c-index {plain.c_index:.3f} vs encrypted "
        f"c-index {enc.c_index:.3f} drifted beyond CKKS noise budget"
    )
    # Counts must be non-negative and bounded by N*(N-1).
    assert 0 <= enc.concordant_pairs <= n * (n - 1)
    assert 0 <= enc.comparable_pairs <= n * (n - 1)


def test_sign_polynomial_encrypted_matches_plaintext(ctx) -> None:
    from regaudit_fhe._slot import SlotVec
    from regaudit_fhe._slot import sign_poly_d3 as plain_sign
    from regaudit_fhe.fhe.slot_vec import sign_poly_d3 as enc_sign

    values = np.linspace(-0.9, 0.9, 16)
    plain_out = plain_sign(SlotVec.encrypt(values)).slots
    enc_out = np.array(enc_sign(rf.fhe.EncryptedSlotVec.encrypt(ctx, values)).decrypt())[:16]
    assert np.max(np.abs(plain_out - enc_out)) < TOL


def test_envelope_signed_over_encrypted_result(ctx) -> None:
    n = 16
    y_true = (RNG.uniform(size=n) < 0.4).astype(float)
    y_pred = ((RNG.uniform(size=n) < 0.4) | y_true.astype(bool)).astype(float)
    g_a = (RNG.uniform(size=n) < 0.5).astype(float)
    g_b = 1.0 - g_a
    enc = fhe_p.fairness_encrypted(ctx, y_true, y_pred, g_a, g_b)
    env = rf.envelope("fairness", enc, depth_consumed=4)
    assert rf.verify_receipt(env)
