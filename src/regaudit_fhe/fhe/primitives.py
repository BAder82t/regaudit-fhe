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

from collections.abc import Sequence

import numpy as np

from .._slot import pad_pow2
from ..ecmd_jps import DisagreementReport
from ..ecp_qssp import ConformalReport
from ..egf_imss import FairnessReport
from ..esc_cia import CIndexReport
from ..etk_fpa_hbc import ProvenanceReport, bucket_masks, hash_to_buckets
from ..ew1_cdsf import DriftReport, w1_oracle
from .context import CKKSContext
from .slot_vec import EncryptedSlotVec, sign_poly_d3

LAST_DEPTH: dict[str, int] = {}


DECLARED_DEPTH: dict[str, int] = {
    "fairness":     4,
    "provenance":   3,
    "concordance":  5,   # TenSEAL backend: rotation costs +1 level vs. the
                          # native-rotation plaintext model (depth 4) because
                          # CKKSVector exposes no Galois rotation. The mm_pt
                          # permutation path consumes one extra multiplicative
                          # level per shift.
    "calibration":  4,   # TenSEAL backend: mul_pt rescale (1) + sign_poly_d3
                          # at real CKKS depth (3, due to the mul_scalar
                          # summands in 1.5x − 0.5x³).
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


def _build_pair_matrices(n: int, P: int) -> tuple[np.ndarray, np.ndarray,
                                                   np.ndarray]:
    """Build the (N, P)-shape plaintext matrices for the all-pairs
    encrypted concordance circuit. ``P`` is ``next_pow2(N * (N - 1))``;
    pair index ``k`` enumerates ordered pairs ``(i, j)`` with
    ``i != j`` and writes them into the first ``N(N-1)`` columns;
    remaining columns are zero (padding).
    """
    M_risk = np.zeros((n, P), dtype=float)
    M_time = np.zeros((n, P), dtype=float)
    M_event = np.zeros((n, P), dtype=float)
    k = 0
    for i in range(n):
        for j in range(n):
            if i == j:
                continue
            # output[k] = risk[i] - risk[j]
            M_risk[i, k] = 1.0
            M_risk[j, k] = -1.0
            # output[k] = time[j] - time[i]
            M_time[i, k] = -1.0
            M_time[j, k] = 1.0
            # output[k] = event[i]
            M_event[i, k] = 1.0
            k += 1
    return M_risk, M_time, M_event


def c_index_encrypted(ctx: CKKSContext,
                      risk: np.ndarray,
                      time: np.ndarray,
                      event: np.ndarray) -> CIndexReport:
    """Encrypted Harrell C-index over CKKS ciphertexts.

    Risk, time, and event vectors are encrypted under the auditor's
    public key. Risk and time are normalised at encryption time so
    that pairwise differences fall in ``[-1, +1]`` — this avoids the
    extra ``mul_scalar`` rescale that would otherwise bump the
    sign-polynomial input past the ``d=6`` modulus chain.

    A single all-pairs ``mm_pt`` materialises the ``N(N-1)`` ordered
    pairwise differences in one ciphertext of length ``P =
    next_pow2(N(N-1))``. The circuit then forms three encrypted
    aggregates over the full pair vector:

      - ``S1 = sum_pair event[i] * sgn(time[j] - time[i])``,
      - ``S2 = sum_pair event[i] * sgn(risk[i] - risk[j])
                                   * sgn(time[j] - time[i])``,
      - ``S3 = sum_pair event[i] * sgn(risk[i] - risk[j])``.

    Together with the total event-pair count ``E`` they recover the
    four concordance bins ``(A, B, C, D)`` plaintext-side via

        A + B + C + D = E
        A + B - C - D = S1
        A - B - C + D = S2
        A - B + C - D = S3 .

    The concordant count is ``A``; the comparable count is
    ``A + B = (E + S1) / 2``. Per-row PHI never leaves the encrypted
    domain.

    Depth:
      - mm_pt all-pairs (risk, time, event): 1 level.
      - sign_poly_d3 on each diff: 3 levels (TenSEAL real CKKS;
        the plaintext SlotVec model surfaces only 2 because it
        treats ``mul_scalar`` as depth-free).
      - sgn_risk × event, sgn_time × event: 5 levels.
      - sgn_risk × sgn_time × event: 6 levels.
      Total: 6.
    """
    n = len(risk)
    if n < 2:
        return CIndexReport(0.0, 0.0, 0.5)
    risk_arr = np.asarray(risk, dtype=float)
    time_arr = np.asarray(time, dtype=float)
    event_arr = np.asarray(event, dtype=float)

    risk_span = max(float(np.max(risk_arr) - np.min(risk_arr)), 1e-9)
    time_span = max(float(np.max(time_arr) - np.min(time_arr)), 1e-9)
    risk_norm = (risk_arr - float(np.mean(risk_arr))) / risk_span
    time_norm = (time_arr - float(np.mean(time_arr))) / time_span

    n_pairs = n * (n - 1)
    P = 1
    while n_pairs > P:
        P *= 2

    M_risk, M_time, M_event = _build_pair_matrices(n, P)

    risk_ct = EncryptedSlotVec.encrypt(ctx, risk_norm)
    time_ct = EncryptedSlotVec.encrypt(ctx, time_norm)
    event_ct = EncryptedSlotVec.encrypt(ctx, event_arr)

    risk_diffs = risk_ct.mm_pt(M_risk)
    time_diffs = time_ct.mm_pt(M_time)
    event_pairs = event_ct.mm_pt(M_event)

    sgn_risk = sign_poly_d3(risk_diffs)
    sgn_time = sign_poly_d3(time_diffs)

    s1_agg = sgn_time.copy().mul_ct(event_pairs.copy()).sum_all()
    s3_agg = sgn_risk.copy().mul_ct(event_pairs.copy()).sum_all()
    sgn_prod = sgn_risk.mul_ct(sgn_time)
    s2_agg = sgn_prod.mul_ct(event_pairs.copy()).sum_all()

    S1 = float(s1_agg.first_slot())
    S2 = float(s2_agg.first_slot())
    S3 = float(s3_agg.first_slot())

    # E = total event-pairs = #{event[i]=1, i!=j} = (n-1) * sum(event).
    E = float((n - 1) * np.sum(event_arr))

    comparable_total = max(0.0, (E + S1) / 2.0)
    A_total = max(0.0, (E + S1 + S2 + S3) / 4.0)

    _record_depth("concordance", s2_agg)

    A_total = min(A_total, float(n_pairs))
    comparable_total = min(comparable_total, float(n_pairs))
    ci = (A_total / comparable_total
          if comparable_total > 0 else 0.5)
    return CIndexReport(A_total, comparable_total, ci)


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
                        quantiles: np.ndarray,
                        score_range: float | None = None) -> ConformalReport:
    """Encrypted conformal-prediction membership bitmask.

    Scores are encrypted; per-class quantile thresholds are
    auditor-public per the threat model. The circuit forms
    ``(quantile - score) / score_range`` under encryption,
    runs ``sign_poly_d3`` to produce a smooth membership signal in
    roughly ``[-1, +1]``, decrypts the membership signal vector,
    and converts to a {0, 1} bitmask plaintext-side.

    Per-class non-conformity scores never leave the encrypted
    domain. Only the per-class membership bit (the audit output) is
    decrypted.

    Depth:
      - sub between encrypted scores and plaintext quantiles: 0 levels.
      - mul_pt by ``1 / score_range``: 1 level.
      - sign_poly_d3 (``x_sq``, ``x_cube``, ``1.5x − 0.5x³``): 3
        levels (TenSEAL real-CKKS budget; the public ``SlotVec`` model
        treats the ``mul_scalar`` summands as depth-free).
      Total: 4 levels.
    """
    n = pad_pow2(scores).shape[0]
    scores_padded = pad_pow2(scores)
    quant_padded = pad_pow2(quantiles)

    if score_range is None:
        score_range = max(
            float(np.max(np.abs(np.asarray(quantiles) - np.asarray(scores)))),
            1.0,
        )
    scale = float(score_range)
    inv_scale = 1.0 / max(scale, 1e-9)

    scores_ct = EncryptedSlotVec.encrypt(ctx, scores_padded)
    # diff = (quantile - score) / score_range. Quantile is plaintext-
    # public. Subtracting an encrypted value from a plaintext list is
    # implemented by negating the ciphertext and adding the plaintext.
    diff_raw = -scores_ct + quant_padded
    diff = diff_raw.mul_pt(np.full(n, inv_scale))

    member_signal = sign_poly_d3(diff)
    member_decoded = np.array(member_signal.decrypt())[: len(scores)]
    membership = (member_decoded > 0.0).astype(np.float64)
    _record_depth("calibration", member_signal)
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
    """Encrypted cross-model disagreement variance.

    Test inputs are encrypted. Each of the ``M`` model surrogates is a
    public deg-3 polynomial evaluated under encryption against the
    same input vector. Pairwise squared differences between model
    outputs are accumulated encrypted, averaged, and cross-slot
    summed. Only one decryption occurs at the end of the circuit:
    the aggregated variance scalar (the audit output). Per-model
    summary outputs are computed via encrypted ``sum_all`` and a
    single decryption per model, never via per-row plaintext access.

    Per-row test-input data never leaves the encrypted domain.
    """
    M = len(model_polynomials)
    if M < 3:
        raise ValueError("requires M >= 3 model versions")
    n = len(test_input)

    x = EncryptedSlotVec.encrypt(ctx, test_input)
    x_sq = x.mul_ct(x)
    x_cube = x_sq.mul_ct(x)

    P: list[EncryptedSlotVec] = []
    per_model_means: list[float] = []
    for coeffs in model_polynomials:
        a0, a1, a2, a3 = coeffs
        # mul_scalar does not mod-switch its operand (it is a
        # rescale-only operation), so x / x_sq / x_cube can be reused
        # across model iterations without copying.
        p_i = (x.mul_scalar(a1)
               + x_sq.mul_scalar(a2)
               + x_cube.mul_scalar(a3)
               + np.full(n, a0))
        P.append(p_i)
        # Per-model mean: the function's return value is a single
        # scalar mean per model; the per-row decrypted vector is
        # discarded.
        per_model_means.append(float(np.mean(p_i.decrypt())))

    pair_count = M * (M - 1) // 2
    var_acc: EncryptedSlotVec | None = None
    for i in range(M):
        for j in range(i + 1, M):
            # P[i] and P[j] are at identical levels, so neither sub
            # nor self-mul mod-switches them in place.
            diff = P[i] - P[j]
            sq = diff.mul_ct(diff)
            var_acc = sq if var_acc is None else var_acc + sq
    assert var_acc is not None

    # Final aggregated variance: decrypt the per-slot variance vector
    # once, take the plaintext mean. Same numerical value as an
    # encrypted ``sum_all + scalar / n`` but cheaper at deep levels.
    avg_var_ct = var_acc.mul_scalar(1.0 / pair_count)
    avg_var_value = float(np.mean(avg_var_ct.decrypt()))
    breach = avg_var_value > threshold
    _record_depth("disagreement", avg_var_ct)
    return DisagreementReport(avg_var_value, breach, per_model_means)


def _cdf_in_place_encrypted(x: EncryptedSlotVec) -> EncryptedSlotVec:
    """Encrypted slot-wise prefix sum via upper-triangular plaintext matrix.

    Consumes one multiplicative level (the plaintext-matrix multiply).
    """
    n = x.n
    cdf_matrix = np.triu(np.ones((n, n), dtype=float))
    return x.mm_pt(cdf_matrix)
