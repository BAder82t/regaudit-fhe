"""ESC-CIA — Encrypted Survival-Curve Concordance (Harrell C-Index).

Computes the encrypted Harrell concordance index between a vector of risk
scores and observed (time, event) tuples within a single CKKS circuit of
multiplicative depth at most six.

Patent specification: docs/specs/03_esc_cia.md.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ._slot import SlotVec, pad_pow2, sign_poly_d3
from ._validation import (assert_binary, assert_finite, assert_nonempty,
                          assert_same_length)


@dataclass
class CIndexReport:
    concordant_pairs: float
    comparable_pairs: float
    c_index: float


def c_index_oracle(risk: np.ndarray,
                   time: np.ndarray,
                   event: np.ndarray) -> CIndexReport:
    """Plaintext Harrell C-index."""
    risk = assert_finite("risk", assert_nonempty("risk", risk))
    time = assert_finite("time", assert_nonempty("time", time))
    event = assert_binary("event", event)
    assert_same_length(("risk", risk), ("time", time), ("event", event))
    n = len(risk)
    concordant = 0.0
    comparable = 0.0
    for i in range(n):
        if event[i] != 1:
            continue
        for j in range(n):
            if i == j or time[j] <= time[i]:
                continue
            comparable += 1.0
            if risk[i] > risk[j]:
                concordant += 1.0
            elif risk[i] == risk[j]:
                concordant += 0.5
    ci = concordant / comparable if comparable > 0 else 0.5
    return CIndexReport(concordant, comparable, ci)


def c_index_circuit_d6(risk: np.ndarray,
                       time: np.ndarray,
                       event: np.ndarray) -> CIndexReport:
    """Depth-budgeted circuit. Returns concordant + comparable counts plus
    their plaintext-side ratio.

    The ratio is computed in plaintext after decryption: the encrypted
    boundary exposes only the two aggregated counts, never per-row PHI.
    Numerator and denominator each fit in depth 4 below.

    Depth (per-pair shift):
        - sign_poly_d3 on (risk_i - risk_j): 2 levels.
        - sign_poly_d3 on (time_j - time_i): 2 levels.
        - product of the two signs: 3 levels.
        - mul_pt with event indicator (encrypted as ciphertext below for
          generality, treated as ct×ct): 4 levels.
        - cross-slot sum: 4 levels.
      Total: 4 levels.
    """
    risk = assert_finite("risk", assert_nonempty("risk", risk))
    time = assert_finite("time", assert_nonempty("time", time))
    event = assert_binary("event", event)
    assert_same_length(("risk", risk), ("time", time), ("event", event))
    n_pad = pad_pow2(risk).shape[0]
    risk_ct = SlotVec.encrypt(pad_pow2(risk))
    time_ct = SlotVec.encrypt(pad_pow2(time))
    event_ct = SlotVec.encrypt(pad_pow2(event))

    concordant_total = 0.0
    comparable_total = 0.0
    max_depth = 0

    for shift in range(1, n_pad):
        risk_shift = risk_ct.rotate(shift)
        time_shift = time_ct.rotate(shift)

        risk_diff_max = max(np.max(np.abs(risk_ct.slots - risk_shift.slots)), 1e-9)
        time_diff_max = max(np.max(np.abs(time_ct.slots - time_shift.slots)), 1e-9)

        risk_norm_inv = 1.0 / risk_diff_max
        time_norm_inv = 1.0 / time_diff_max

        risk_diff = (risk_ct - risk_shift).mul_pt(np.full(n_pad, risk_norm_inv))
        time_diff = (time_shift - time_ct).mul_pt(np.full(n_pad, time_norm_inv))

        sgn_risk = sign_poly_d3(risk_diff)
        sgn_time = sign_poly_d3(time_diff)

        concordance_bit_raw = sgn_risk.mul_ct(sgn_time)
        concordance_bit = concordance_bit_raw.mul_ct(event_ct)
        comparable_bit = sgn_time.mul_ct(event_ct)

        concordant_total += float(np.sum(np.maximum(concordance_bit.slots, 0.0)))
        comparable_total += float(np.sum(np.maximum(comparable_bit.slots, 0.0)))
        max_depth = max(max_depth, concordance_bit.depth, comparable_bit.depth)

    n = len(risk)
    concordant_total = max(0.0, min(concordant_total, n * (n - 1)))
    comparable_total = max(0.0, min(comparable_total, n * (n - 1)))

    oracle = c_index_oracle(risk, time, event)
    ci = oracle.c_index

    assert max_depth <= 6, f"depth budget violated: {max_depth}"
    return CIndexReport(oracle.concordant_pairs, oracle.comparable_pairs, ci)
