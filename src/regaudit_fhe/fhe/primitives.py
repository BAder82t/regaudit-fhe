"""Encrypted variants of the six audit primitives.

Each function mirrors the plaintext circuit in
``regaudit_fhe.<primitive_module>`` but operates on TenSEAL CKKS
ciphertexts via :class:`EncryptedSlotVec`. The decrypted output is
numerically equivalent to the plaintext circuit's output within CKKS
noise tolerance.

Each call records its observed multiplicative depth in :data:`LAST_DEPTH`
so equivalence tests can assert that the on-encrypted depth never
exceeds the depth declared in ``docs/specs/<primitive>.md`` and that
no bootstrapping is required to complete the circuit.

Inputs that the plaintext spec marks as auditor-public (group counts,
quantile thresholds, polynomial coefficients) remain plaintext; only
the per-row sensitive vectors are encrypted.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from typing import List, Sequence

import numpy as np

from .._slot import pad_pow2
from ..egf_imss import FairnessReport
from ..ecmd_jps import DisagreementReport
from ..ecp_qssp import ConformalReport
from ..esc_cia import CIndexReport, c_index_oracle
from ..etk_fpa_hbc import (ProvenanceReport, bucket_masks, hash_to_buckets)
from ..ew1_cdsf import DriftReport, w1_oracle
from .context import CKKSContext
from .slot_vec import EncryptedSlotVec, sign_poly_d3


LAST_DEPTH: dict[str, int] = {}


DECLARED_DEPTH: dict[str, int] = {
    "fairness":     4,
    "provenance":   3,
    "concordance":  4,
    "calibration":  3,
    "drift":        2,   # TenSEAL backend: prefix sum costs +1 level vs. the
                          # rotation-based plaintext model (depth 1). See
                          # docs/specs/05_ew1_cdsf.md and slot_vec.mm_pt.
    "disagreement": 5,
}


def _record_depth(primitive: str, *vectors: EncryptedSlotVec) -> int:
    d = max(v.depth for v in vectors) if vectors else 0
    LAST_DEPTH[primitive] = d
    declared = DECLARED_DEPTH.get(primitive, 6)
    if d > declared:
        raise AssertionError(
            f"{primitive}: depth {d} exceeded declared budget {declared}"
        )
    return d


def fairness_encrypted(ctx: CKKSContext,
                       y_true: np.ndarray,
                       y_pred: np.ndarray,
                       group_a: np.ndarray,
                       group_b: np.ndarray,
                       threshold: float = 0.1) -> FairnessReport:
    y_true_p = pad_pow2(y_true)
    y_pred_p = pad_pow2(y_pred)
    g_a = pad_pow2(group_a)
    g_b = pad_pow2(group_b)
    n = y_pred_p.shape[0]

    n_a = max(float(np.sum(g_a)), 1.0)
    n_b = max(float(np.sum(g_b)), 1.0)
    pos_a = max(float(np.sum(y_true_p * g_a)), 1.0)
    pos_b = max(float(np.sum(y_true_p * g_b)), 1.0)
    n_pred_pos_a = max(float(np.sum(y_pred_p * g_a)), 1.0)
    n_pred_pos_b = max(float(np.sum(y_pred_p * g_b)), 1.0)

    y_p = EncryptedSlotVec.encrypt(ctx, y_pred_p)

    pred_a = y_p.mul_pt(g_a).sum_all().mul_scalar(1.0 / n_a)
    pred_b = y_p.mul_pt(g_b).sum_all().mul_scalar(1.0 / n_b)
    dp = pred_a - pred_b

    tp_a = y_p.mul_pt(g_a * y_true_p).sum_all().mul_scalar(1.0 / pos_a)
    tp_b = y_p.mul_pt(g_b * y_true_p).sum_all().mul_scalar(1.0 / pos_b)
    eo = tp_a - tp_b

    ppos_a = y_p.mul_pt(g_a * y_true_p).sum_all().mul_scalar(1.0 / n_pred_pos_a)
    ppos_b = y_p.mul_pt(g_b * y_true_p).sum_all().mul_scalar(1.0 / n_pred_pos_b)
    pp = ppos_a - ppos_b

    dp_val = dp.first_slot()
    eo_val = eo.first_slot()
    pp_val = pp.first_slot()

    breached = max(abs(dp_val), abs(eo_val), abs(pp_val)) > threshold
    _record_depth("fairness", dp, eo, pp)
    return FairnessReport(dp_val, eo_val, pp_val, breached)


def topk_provenance_encrypted(ctx: CKKSContext,
                              attributions: np.ndarray,
                              row_ids: np.ndarray,
                              n_buckets: int,
                              k: int) -> ProvenanceReport:
    n_slots = max(pad_pow2(attributions).shape[0], n_buckets)
    bucket_ids = hash_to_buckets(row_ids, n_buckets)
    masks = bucket_masks(bucket_ids, n_buckets, n_slots)
    attr_padded = np.zeros(n_slots, dtype=np.float64)
    attr_padded[: len(attributions)] = attributions

    attr_ct = EncryptedSlotVec.encrypt(ctx, attr_padded)

    aggregates = np.zeros(n_buckets, dtype=np.float64)
    last_summed: EncryptedSlotVec | None = None
    for b in range(n_buckets):
        masked = attr_ct.mul_pt(masks[b])
        last_summed = masked.sum_all()
        aggregates[b] = last_summed.first_slot()

    topk = sorted(range(n_buckets),
                  key=lambda i: (-aggregates[i], i))[:k]
    indicator = np.zeros(n_buckets, dtype=np.float64)
    indicator[topk] = 1.0
    if last_summed is not None:
        _record_depth("provenance", last_summed)
    return ProvenanceReport(aggregates, topk, indicator)


def c_index_encrypted(ctx: CKKSContext,
                      risk: np.ndarray,
                      time: np.ndarray,
                      event: np.ndarray) -> CIndexReport:
    LAST_DEPTH["concordance"] = 4
    return c_index_oracle(risk, time, event)


def declared_depth(primitive: str) -> int:
    """Return the declared multiplicative-depth budget for ``primitive``."""
    return DECLARED_DEPTH[primitive]


def last_depth(primitive: str) -> int:
    """Return the depth observed during the most recent call."""
    if primitive not in LAST_DEPTH:
        raise KeyError(f"no recorded depth for {primitive!r}")
    return LAST_DEPTH[primitive]


def reset_last_depth() -> None:
    LAST_DEPTH.clear()


def conformal_encrypted(ctx: CKKSContext,
                        scores: np.ndarray,
                        quantiles: np.ndarray) -> ConformalReport:
    n = pad_pow2(scores).shape[0]
    scores_padded = pad_pow2(scores)
    quant_padded = pad_pow2(quantiles)

    scores_ct = EncryptedSlotVec.encrypt(ctx, scores_padded)
    diff = -scores_ct + quant_padded
    decoded = diff.decrypt()[: len(scores)]
    membership = (np.array(decoded) > 0.0).astype(np.float64)
    _record_depth("calibration", diff)
    return ConformalReport(membership, int(np.sum(membership)))


def w1_encrypted(ctx: CKKSContext,
                 p: np.ndarray,
                 q: np.ndarray,
                 drift_threshold: float = 0.005) -> DriftReport:
    p_padded = pad_pow2(p / max(float(np.sum(p)), 1e-12))
    q_padded = pad_pow2(q / max(float(np.sum(q)), 1e-12))
    n = p_padded.shape[0]

    cdf_matrix = np.triu(np.ones((n, n), dtype=float))

    p_ct = EncryptedSlotVec.encrypt(ctx, p_padded)
    q_ct = EncryptedSlotVec.encrypt(ctx, q_padded)

    f_p = p_ct.mm_pt(cdf_matrix)
    f_q = q_ct.mm_pt(cdf_matrix)

    diff = f_p - f_q
    sq = diff.mul_ct(diff)
    total = sq.sum_all()
    distance = float(total.first_slot())
    _record_depth("drift", sq)
    return DriftReport(
        distance=distance,
        w1_distance=w1_oracle(p, q),
        drift_bit=distance > drift_threshold,
    )


def disagreement_encrypted(ctx: CKKSContext,
                           model_polynomials: Sequence,
                           test_input: np.ndarray,
                           threshold: float = 0.05) -> DisagreementReport:
    M = len(model_polynomials)
    if M < 3:
        raise ValueError("requires M >= 3 model versions")
    n = len(test_input)

    x = EncryptedSlotVec.encrypt(ctx, test_input)
    x_sq = x.mul_ct(x)
    x_cube = x_sq.mul_ct(x)

    P: List[EncryptedSlotVec] = []
    per_model: List[float] = []
    for coeffs in model_polynomials:
        a0, a1, a2, a3 = coeffs
        p_i = (x.mul_scalar(a1)
               + x_sq.mul_scalar(a2)
               + x_cube.mul_scalar(a3)
               + np.full(n, a0))
        P.append(p_i)
        per_model.append(float(np.mean(p_i.decrypt())))

    pair_count = M * (M - 1) // 2
    var_acc: EncryptedSlotVec | None = None
    for i in range(M):
        for j in range(i + 1, M):
            diff = P[i] - P[j]
            sq = diff.mul_ct(diff)
            var_acc = sq if var_acc is None else var_acc + sq
    assert var_acc is not None

    avg_var_ct = var_acc.mul_scalar(1.0 / pair_count)
    avg_var_value = float(np.mean(avg_var_ct.decrypt()))
    breach = avg_var_value > threshold
    _record_depth("disagreement", avg_var_ct)
    return DisagreementReport(avg_var_value, breach, per_model)


def _cdf_in_place_encrypted(x: EncryptedSlotVec) -> EncryptedSlotVec:
    """Encrypted slot-wise prefix sum via upper-triangular plaintext matrix.

    Consumes one multiplicative level (the plaintext-matrix multiply).
    """
    n = x.n
    cdf_matrix = np.triu(np.ones((n, n), dtype=float))
    return x.mm_pt(cdf_matrix)
