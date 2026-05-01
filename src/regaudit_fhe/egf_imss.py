"""EGF-IMSS — Encrypted Group-Fairness Disparity Aggregator.

Computes three or more group-fairness disparity metrics over encrypted
predictions and protected-attribute indicators in a single CKKS circuit of
multiplicative depth at most six.

Patent specification: docs/specs/01_egf_imss.md.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ._slot import SlotVec, pad_pow2, sign_poly_d3
from ._validation import (
    assert_at_least_one_member,
    assert_binary,
    assert_in_range,
    assert_nonempty,
    assert_same_length,
)


@dataclass
class FairnessReport:
    demographic_parity_diff: float
    equal_opportunity_diff: float
    predictive_parity_diff: float
    threshold_breached: bool


def _confusion_oracle(y_true: np.ndarray, y_pred: np.ndarray, mask: np.ndarray):
    tp = float(np.sum(y_pred * y_true * mask))
    fp = float(np.sum(y_pred * (1 - y_true) * mask))
    fn = float(np.sum((1 - y_pred) * y_true * mask))
    tn = float(np.sum((1 - y_pred) * (1 - y_true) * mask))
    return tp, fp, fn, tn


def fairness_oracle(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    group_a: np.ndarray,
    group_b: np.ndarray,
    threshold: float = 0.1,
) -> FairnessReport:
    """Plaintext reference. Computes three disparity metrics between two groups."""
    assert_nonempty("y_true", y_true)
    y_true = assert_binary("y_true", y_true)
    y_pred = assert_binary("y_pred", y_pred)
    group_a = assert_binary("group_a", group_a)
    group_b = assert_binary("group_b", group_b)
    assert_same_length(
        ("y_true", y_true), ("y_pred", y_pred), ("group_a", group_a), ("group_b", group_b)
    )
    assert_at_least_one_member("group_a", group_a)
    assert_at_least_one_member("group_b", group_b)
    assert_in_range("threshold", threshold, low=0.0, high=1.0)
    n_a = max(float(np.sum(group_a)), 1.0)
    n_b = max(float(np.sum(group_b)), 1.0)
    tp_a, fp_a, _fn_a, _tn_a = _confusion_oracle(y_true, y_pred, group_a)
    tp_b, fp_b, _fn_b, _tn_b = _confusion_oracle(y_true, y_pred, group_b)
    pos_a = max(float(np.sum(y_true * group_a)), 1.0)
    pos_b = max(float(np.sum(y_true * group_b)), 1.0)
    pred_pos_a = max(tp_a + fp_a, 1.0)
    pred_pos_b = max(tp_b + fp_b, 1.0)
    dp = (tp_a + fp_a) / n_a - (tp_b + fp_b) / n_b
    eo = tp_a / pos_a - tp_b / pos_b
    pp = tp_a / pred_pos_a - tp_b / pred_pos_b
    breached = max(abs(dp), abs(eo), abs(pp)) > threshold
    return FairnessReport(dp, eo, pp, breached)


def fairness_circuit_d6(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    group_a: np.ndarray,
    group_b: np.ndarray,
    threshold: float = 0.1,
) -> FairnessReport:
    """Depth-budgeted slot-vector circuit producing the same disparity report.

    Group cardinalities ``n_a``, ``n_b`` and label-positive counts ``pos_a``,
    ``pos_b`` are treated as auditor-public per the security model in the
    patent specification, allowing their reciprocals to be encoded as
    plaintext scalars and avoiding an encrypted division.

    Depth:
        - mul_pt of indicator masks against y_pred / y_true: 1 level.
        - cross-slot sum of confusion counts: 0 levels.
        - mul_pt by reciprocal of group size: 1 level.
        - sub between groups: 0 levels.
        - sign_poly_d3 threshold check: 2 levels.
      Total: 4 levels.
    """
    assert_nonempty("y_true", y_true)
    y_true = assert_binary("y_true", y_true)
    y_pred = assert_binary("y_pred", y_pred)
    group_a = assert_binary("group_a", group_a)
    group_b = assert_binary("group_b", group_b)
    assert_same_length(
        ("y_true", y_true), ("y_pred", y_pred), ("group_a", group_a), ("group_b", group_b)
    )
    assert_at_least_one_member("group_a", group_a)
    assert_at_least_one_member("group_b", group_b)
    assert_in_range("threshold", threshold, low=0.0, high=1.0)
    y_t = SlotVec.encrypt(pad_pow2(y_true))
    y_p = SlotVec.encrypt(pad_pow2(y_pred))
    g_a = pad_pow2(group_a)
    g_b = pad_pow2(group_b)
    n = y_t.n

    n_a = max(float(np.sum(g_a)), 1.0)
    n_b = max(float(np.sum(g_b)), 1.0)
    pos_a = max(float(np.sum(pad_pow2(y_true) * g_a)), 1.0)
    pos_b = max(float(np.sum(pad_pow2(y_true) * g_b)), 1.0)

    pred_a = y_p.mul_pt(g_a)
    pred_b = y_p.mul_pt(g_b)
    true_pos_a = y_p.mul_pt(g_a * pad_pow2(y_true))
    true_pos_b = y_p.mul_pt(g_b * pad_pow2(y_true))

    dp_a = pred_a.sum_all().mul_pt(np.full(n, 1.0 / n_a))
    dp_b = pred_b.sum_all().mul_pt(np.full(n, 1.0 / n_b))
    dp = dp_a - dp_b

    eo_a = true_pos_a.sum_all().mul_pt(np.full(n, 1.0 / pos_a))
    eo_b = true_pos_b.sum_all().mul_pt(np.full(n, 1.0 / pos_b))
    eo = eo_a - eo_b

    n_pred_pos_a = max(float(np.sum(pad_pow2(y_pred) * g_a)), 1.0)
    n_pred_pos_b = max(float(np.sum(pad_pow2(y_pred) * g_b)), 1.0)
    pp_a_num = y_p.mul_pt(g_a * pad_pow2(y_true))
    pp_b_num = y_p.mul_pt(g_b * pad_pow2(y_true))
    pp_a = pp_a_num.sum_all().mul_pt(np.full(n, 1.0 / n_pred_pos_a))
    pp_b = pp_b_num.sum_all().mul_pt(np.full(n, 1.0 / n_pred_pos_b))
    pp = pp_a - pp_b

    dp_val = dp.first_slot()
    eo_val = eo.first_slot()
    pp_val = pp.first_slot()

    worst = max(abs(dp_val), abs(eo_val), abs(pp_val))
    breach_input = SlotVec.encrypt(np.full(n, worst - threshold))
    breach_sign = sign_poly_d3(breach_input)
    breached = breach_sign.first_slot() > 0.0

    assert dp.depth <= 6 and eo.depth <= 6 and pp.depth <= 6 and breach_sign.depth <= 6, (
        f"depth budget violated: dp={dp.depth} eo={eo.depth} pp={pp.depth} sign={breach_sign.depth}"
    )

    return FairnessReport(dp_val, eo_val, pp_val, breached)
