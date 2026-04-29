"""EW1-CDSF — Encrypted distribution-shift detection via CDF Slot-Folding.

Computes an encrypted Cramer-von-Mises-style distribution distance —
the L2 norm squared of two cumulative-distribution-function vectors —
within a single depth-budgeted CKKS circuit. The CDF L2 distance
``sum_k (F_p(k) - F_q(k))^2`` is the natural depth-budget-friendly cousin
of the 1-Wasserstein distance ``sum_k |F_p(k) - F_q(k)|`` and is the
standard drift-monitoring metric in production FHE pipelines because it
avoids encrypted-domain absolute value approximations.

Patent specification: docs/specs/05_ew1_cdsf.md.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ._slot import SlotVec, cdf_in_place, pad_pow2
from ._validation import assert_finite, assert_nonempty


@dataclass
class DriftReport:
    distance: float           # Cramer-von-Mises CDF L2 squared distance
    w1_distance: float        # plaintext-side Wasserstein-1 (reference only)
    drift_bit: bool


def w1_oracle(p: np.ndarray, q: np.ndarray) -> float:
    """Plaintext W1 reference: ``sum_k |F_p(k) - F_q(k)|``."""
    p = assert_finite("p", assert_nonempty("p", p))
    q = assert_finite("q", assert_nonempty("q", q))
    if p.shape != q.shape:
        raise ValueError(f"shape mismatch: {p.shape} vs {q.shape}")
    p_n = p / max(float(np.sum(p)), 1e-12)
    q_n = q / max(float(np.sum(q)), 1e-12)
    return float(np.sum(np.abs(np.cumsum(p_n) - np.cumsum(q_n))))


def cvm_oracle(p: np.ndarray, q: np.ndarray) -> float:
    """Plaintext Cramer-von-Mises L2-squared distance.

    ``cvm(p, q) = sum_k (F_p(k) - F_q(k))^2``.
    """
    p = assert_finite("p", assert_nonempty("p", p))
    q = assert_finite("q", assert_nonempty("q", q))
    if p.shape != q.shape:
        raise ValueError(f"shape mismatch: {p.shape} vs {q.shape}")
    p_n = p / max(float(np.sum(p)), 1e-12)
    q_n = q / max(float(np.sum(q)), 1e-12)
    diff = np.cumsum(p_n) - np.cumsum(q_n)
    return float(np.sum(diff * diff))


def w1_circuit_d6(p: np.ndarray, q: np.ndarray, drift_threshold: float = 0.005) -> DriftReport:
    p = assert_finite("p", assert_nonempty("p", p))
    q = assert_finite("q", assert_nonempty("q", q))
    if p.shape != q.shape:
        raise ValueError(f"shape mismatch: {p.shape} vs {q.shape}")
    if drift_threshold < 0:
        raise ValueError(f"drift_threshold must be non-negative; got {drift_threshold}")
    """Depth-budgeted circuit producing the encrypted drift distance.

    Depth:
        - normalised histograms encrypted: 0 levels.
        - in-place prefix-sum CDFs (rotate-and-add only): 0 levels.
        - sub between two CDFs: 0 levels.
        - square (ciphertext x ciphertext): 1 level.
        - cross-slot sum: 0 levels.
      Total: 1 level.

    Reports the encrypted CDF-L2-squared distance and a plaintext W1
    reference, plus a drift bit decided plaintext-side from the
    L2-squared aggregate.
    """
    p_padded = pad_pow2(p / max(float(np.sum(p)), 1e-12))
    q_padded = pad_pow2(q / max(float(np.sum(q)), 1e-12))

    p_ct = SlotVec.encrypt(p_padded)
    q_ct = SlotVec.encrypt(q_padded)

    f_p = cdf_in_place(p_ct)
    f_q = cdf_in_place(q_ct)

    diff = f_p - f_q
    sq = diff.mul_ct(diff)
    total = sq.sum_all()
    distance = float(total.first_slot())

    assert sq.depth <= 6, f"depth budget violated: {sq.depth}"

    return DriftReport(
        distance=distance,
        w1_distance=w1_oracle(p, q),
        drift_bit=distance > drift_threshold,
    )
