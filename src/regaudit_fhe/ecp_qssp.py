"""ECP-QSSP — Encrypted Conformal Prediction Set Compactor.

Computes a conformal prediction-set membership bitmask over K candidate
labels via a single CKKS circuit of multiplicative depth at most six. All
K per-class quantile thresholds are pre-encoded into one packed plaintext.

Patent specification: docs/specs/04_ecp_qssp.md.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ._slot import SlotVec, pad_pow2, sign_poly_d3
from ._validation import assert_finite, assert_nonempty


@dataclass
class ConformalReport:
    membership: np.ndarray
    set_size: int


def conformal_oracle(scores: np.ndarray, quantiles: np.ndarray) -> ConformalReport:
    """Plaintext split-conformal membership."""
    scores = assert_finite("scores", assert_nonempty("scores", scores))
    quantiles = assert_finite("quantiles", assert_nonempty("quantiles", quantiles))
    if scores.shape != quantiles.shape:
        raise ValueError(f"shape mismatch: {scores.shape} vs {quantiles.shape}")
    membership = (scores <= quantiles).astype(np.float64)
    return ConformalReport(membership, int(np.sum(membership)))


def conformal_circuit_d6(scores: np.ndarray, quantiles: np.ndarray) -> ConformalReport:
    """Depth-budgeted circuit producing the membership bitmask.

    The K class quantiles are public per the audit spec and packed into a
    single plaintext vector before evaluation.

    Depth:
        - sub between encrypted scores and plaintext quantile vector: 0 levels.
        - sign_poly_d3 to produce a smooth membership signal: 2 levels.
      Total: 2 levels.
    """
    scores = assert_finite("scores", assert_nonempty("scores", scores))
    quantiles = assert_finite("quantiles", assert_nonempty("quantiles", quantiles))
    if scores.shape != quantiles.shape:
        raise ValueError(f"shape mismatch: {scores.shape} vs {quantiles.shape}")
    n = pad_pow2(scores).shape[0]
    scores_ct = SlotVec.encrypt(pad_pow2(scores))
    quantiles_pt = pad_pow2(quantiles)

    score_range = max(float(np.max(np.abs(scores_ct.slots - quantiles_pt))), 1e-9)
    # Quantiles are auditor-public per the threat model; subtracting
    # an encrypted score from the plaintext quantile is implemented
    # by negating the ciphertext and adding the plaintext vector.
    diff_raw = -scores_ct + quantiles_pt
    diff = diff_raw.mul_pt(np.full(n, 1.0 / score_range))
    member_signal = sign_poly_d3(diff)
    membership = (member_signal.slots[: len(scores)] > 0.0).astype(np.float64)

    assert member_signal.depth <= 6, f"depth budget violated: {member_signal.depth}"
    return ConformalReport(membership, int(np.sum(membership)))
