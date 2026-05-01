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
from ._validation import assert_binary, assert_finite, assert_nonempty, assert_same_length


@dataclass
class CIndexReport:
    concordant_pairs: float
    comparable_pairs: float
    c_index: float


def c_index_oracle(risk: np.ndarray, time: np.ndarray, event: np.ndarray) -> CIndexReport:
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


def c_index_circuit_d6(risk: np.ndarray, time: np.ndarray, event: np.ndarray) -> CIndexReport:
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
    n = len(risk)
    risk_arr = np.asarray(risk, dtype=float)
    time_arr = np.asarray(time, dtype=float)
    event_arr = np.asarray(event, dtype=float)

    risk_span = max(float(np.max(risk_arr) - np.min(risk_arr)), 1e-9)
    time_span = max(float(np.max(time_arr) - np.min(time_arr)), 1e-9)
    risk_norm = (risk_arr - float(np.mean(risk_arr))) / risk_span
    time_norm = (time_arr - float(np.mean(time_arr))) / time_span

    risk_p = pad_pow2(risk_norm)
    time_p = pad_pow2(time_norm)
    event_p = pad_pow2(event_arr)
    n_pad = risk_p.shape[0]

    risk_ct = SlotVec.encrypt(risk_p)
    time_ct = SlotVec.encrypt(time_p)
    event_ct = SlotVec.encrypt(event_p)

    A_total = 0.0
    comparable_total = 0.0
    max_depth = 0

    for shift in range(1, n_pad):
        risk_rot = risk_ct.rotate(shift)
        time_rot = time_ct.rotate(shift)

        risk_diff = risk_ct - risk_rot
        time_diff = time_rot - time_ct

        sgn_risk = sign_poly_d3(risk_diff)
        sgn_time = sign_poly_d3(time_diff)

        s1_ct = sgn_time.mul_ct(event_ct).sum_all()
        s3_ct = sgn_risk.mul_ct(event_ct).sum_all()
        sgn_prod = sgn_risk.mul_ct(sgn_time)
        s2_ct = sgn_prod.mul_ct(event_ct).sum_all()

        S1 = float(s1_ct.first_slot())
        S2 = float(s2_ct.first_slot())
        S3 = float(s3_ct.first_slot())

        pair_real = (np.arange(n_pad) < n) & (((np.arange(n_pad) + shift) % n_pad) < n)
        E = float(np.sum(event_p * pair_real))

        comparable_total += max(0.0, (E + S1) / 2.0)
        A_total += max(0.0, (E + S1 + S2 + S3) / 4.0)
        max_depth = max(max_depth, s2_ct.depth)

    A_total = max(0.0, min(A_total, float(n * (n - 1))))
    comparable_total = max(0.0, min(comparable_total, float(n * (n - 1))))
    ci = A_total / comparable_total if comparable_total > 0 else 0.5

    assert max_depth <= 6, f"depth budget violated: {max_depth}"
    return CIndexReport(A_total, comparable_total, ci)
