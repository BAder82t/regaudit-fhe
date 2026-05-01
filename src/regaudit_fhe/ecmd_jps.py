"""ECMD-JPS — Encrypted Cross-Model Disagreement Score via Joint Polynomial Surrogate.

Computes an encrypted disagreement score across M ≥ 3 model versions
evaluated on a common encrypted input, using a joint polynomial surrogate
within a single CKKS circuit of multiplicative depth at most six.

Patent specification: docs/specs/06_ecmd_jps.md.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

from ._slot import SlotVec
from ._validation import assert_finite, assert_nonempty


@dataclass
class DisagreementReport:
    pairwise_variance: float
    breach: bool
    per_model_outputs: list[float]


def disagreement_oracle(
    per_model_predictions: np.ndarray, threshold: float = 0.05
) -> DisagreementReport:
    """Plaintext oracle. Input shape: (M,) for a single test point or (M, N).

    Returns the average pairwise squared difference across the M models.
    """
    p = np.asarray(per_model_predictions, dtype=np.float64)
    p = assert_finite("per_model_predictions", assert_nonempty("per_model_predictions", p))
    if p.ndim == 1:
        p = p[:, None]
    M = p.shape[0]
    if M < 3:
        raise ValueError("requires M >= 3 model versions")
    diff_sum_sq = 0.0
    for i in range(M):
        for j in range(i + 1, M):
            diff_sum_sq += float(np.mean((p[i] - p[j]) ** 2))
    avg = diff_sum_sq / (M * (M - 1) / 2)
    return DisagreementReport(
        pairwise_variance=avg,
        breach=avg > threshold,
        per_model_outputs=[float(np.mean(row)) for row in p],
    )


def disagreement_circuit_d6(
    model_polynomials: Sequence[np.ndarray], test_input: np.ndarray, threshold: float = 0.05
) -> DisagreementReport:
    """Depth-budgeted joint-polynomial circuit.

    Each model is represented as a degree-3 polynomial surrogate over the
    encrypted input vector. The circuit evaluates all M surrogates in slot
    lanes, accumulates the pairwise squared difference, and produces a
    threshold-bit via a final sign polynomial.

    ``model_polynomials`` is a sequence of length M, each item a length-4
    coefficient vector ``(a0, a1, a2, a3)`` for ``Pi(x) = a0 + a1 x + a2 x^2
    + a3 x^3`` evaluated slot-wise. Coefficients are auditor-public.

    Depth:
        - x^2 and x^3 of the encrypted input: 2 levels.
        - linear combination forming Pi(x) for each i: 3 levels.
        - (Pi - Pj): 3 levels.
        - square (Pi - Pj)^2: 4 levels.
        - sum over pairs and pair-count rescale: 5 levels.
      Total: 5 levels. The breach indicator is decided plaintext-side after
      auditor decryption to keep the on-encrypted depth strictly below six and
      to leave headroom for downstream commit-and-verify chaining.
    """
    test_input = assert_finite("test_input", assert_nonempty("test_input", test_input))
    if not model_polynomials:
        raise ValueError("model_polynomials must be non-empty")
    M = len(model_polynomials)
    for i, c in enumerate(model_polynomials):
        if len(c) != 4:
            raise ValueError(
                f"each surrogate must be a deg-3 poly (4 coefficients); model {i} has {len(c)}"
            )
    if M < 3:
        raise ValueError("requires M >= 3 model versions")
    n = len(test_input)
    x = SlotVec.encrypt(test_input)
    x_sq = x.mul_ct(x)
    x_cube = x_sq.mul_ct(x)

    P: list[SlotVec] = []
    per_model_outputs: list[float] = []
    for coeffs in model_polynomials:
        a0, a1, a2, a3 = coeffs
        p_i = x.mul_scalar(a1) + x_sq.mul_scalar(a2) + x_cube.mul_scalar(a3) + np.full(n, a0)
        P.append(p_i)
        per_model_outputs.append(float(np.mean(p_i.slots)))

    pair_count = M * (M - 1) // 2
    var_acc: SlotVec | None = None
    for i in range(M):
        for j in range(i + 1, M):
            diff = P[i] - P[j]
            sq = diff.mul_ct(diff)
            var_acc = sq if var_acc is None else var_acc + sq

    assert var_acc is not None
    avg_var_ct = var_acc.mul_scalar(1.0 / pair_count)
    avg_var_value = float(np.mean(avg_var_ct.slots))
    breach = avg_var_value > threshold

    assert avg_var_ct.depth <= 6, f"depth budget violated: {avg_var_ct.depth}"
    return DisagreementReport(avg_var_value, breach, per_model_outputs)
