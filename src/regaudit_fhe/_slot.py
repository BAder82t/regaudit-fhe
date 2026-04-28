"""Plaintext slot-vector model of a CKKS-packed ciphertext.

Tracks multiplicative depth so each audit primitive's circuit is verified to
fit in the d=6 budget without bootstrap. Operations match CKKS semantics:

- Add / Sub: free (no depth consumed).
- Plaintext-mul (mul_pt): consumes one level, matching a CKKS scalar/vector
  encode-then-multiply followed by rescale.
- Ciphertext-mul (mul_ct): consumes one level after relinearisation + rescale.
- Rotate: free.
- Cross-slot sum (sum_all): free in depth; uses log2(n) Halevi-Shoup
  rotate-and-add steps.

A plaintext numerical model is sufficient for the audit-primitive
contract: the encrypted execution path lives behind an optional
TenSEAL CKKS backend (``regaudit_fhe.fhe``) under the ``[fhe]`` extra
and uses identical algebraic structure.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

import numpy as np

MAX_DEPTH: int = 6


class DepthBudgetExceeded(RuntimeError):
    """Raised when a circuit exceeds its declared multiplicative-depth budget."""


@dataclass
class SlotVec:
    slots: np.ndarray
    depth: int = 0
    max_depth: int = MAX_DEPTH

    def __post_init__(self) -> None:
        self.slots = np.asarray(self.slots, dtype=np.float64)
        if self.depth > self.max_depth:
            raise DepthBudgetExceeded(
                f"depth {self.depth} exceeds budget {self.max_depth}"
            )

    @classmethod
    def encrypt(cls, values, max_depth: int = MAX_DEPTH) -> "SlotVec":
        return cls(slots=np.asarray(values, dtype=np.float64), depth=0, max_depth=max_depth)

    @property
    def n(self) -> int:
        return self.slots.shape[0]

    def __add__(self, other: Union["SlotVec", np.ndarray, float]) -> "SlotVec":
        if isinstance(other, SlotVec):
            return SlotVec(self.slots + other.slots,
                           max(self.depth, other.depth), self.max_depth)
        return SlotVec(self.slots + np.asarray(other), self.depth, self.max_depth)

    def __radd__(self, other) -> "SlotVec":
        return self.__add__(other)

    def __sub__(self, other: Union["SlotVec", np.ndarray, float]) -> "SlotVec":
        if isinstance(other, SlotVec):
            return SlotVec(self.slots - other.slots,
                           max(self.depth, other.depth), self.max_depth)
        return SlotVec(self.slots - np.asarray(other), self.depth, self.max_depth)

    def __neg__(self) -> "SlotVec":
        return SlotVec(-self.slots, self.depth, self.max_depth)

    def mul_pt(self, plaintext: Union[np.ndarray, float]) -> "SlotVec":
        """Plaintext-vector × ciphertext. One level consumed."""
        return SlotVec(self.slots * np.asarray(plaintext),
                       self.depth + 1, self.max_depth)

    def mul_scalar(self, scalar: float) -> "SlotVec":
        """Multiply every slot by a constant scalar.

        Free in depth. In a real CKKS deployment this corresponds to
        baking the constant into the next rescale or message scaling
        factor, so no level is consumed.
        """
        return SlotVec(self.slots * float(scalar), self.depth, self.max_depth)

    def mul_ct(self, other: "SlotVec") -> "SlotVec":
        """Ciphertext × ciphertext. One level consumed after relin + rescale."""
        return SlotVec(self.slots * other.slots,
                       max(self.depth, other.depth) + 1, self.max_depth)

    def rotate(self, k: int) -> "SlotVec":
        """Cyclic slot rotation by k positions. No depth consumed."""
        return SlotVec(np.roll(self.slots, -k), self.depth, self.max_depth)

    def sum_all(self) -> "SlotVec":
        """Sum of all slots, broadcast to every slot. Halevi-Shoup rotate-add tree.

        Requires n to be a power of two for clean halving.
        """
        out = self
        n = self.n
        if n & (n - 1) != 0:
            raise ValueError(f"sum_all requires power-of-two n; got {n}")
        step = 1
        while step < n:
            out = out + out.rotate(step)
            step *= 2
        return out

    def first_slot(self) -> float:
        return float(self.slots[0])


def sign_poly_d3(x: SlotVec) -> SlotVec:
    """Degree-3 sign polynomial on [-1, 1] excluding a small neighbourhood of 0.

    p(x) = (3/2) x - (1/2) x^3.

    Depth cost: 2 (one ct×ct for x^2, one ct×ct for x^3 = x^2 · x; the linear
    combination is free).
    """
    x_sq = x.mul_ct(x)            # depth + 1
    x_cube = x_sq.mul_ct(x)       # depth + 2
    return x.mul_scalar(1.5) + x_cube.mul_scalar(-0.5)


def abs_poly_d3(x: SlotVec) -> SlotVec:
    """|x| approximation via x · sign_poly_d3(x). Depth cost: 3."""
    return x.mul_ct(sign_poly_d3(x))


def sign_poly_d5(x: SlotVec) -> SlotVec:
    """Composed sign polynomial p(p(x)) where p(x) = (3/2)x - (1/2)x^3.

    Effectively degree 9 in x. Sharpens the deg-3 transition near zero,
    cutting worst-case |sign| error from ~30% to ~3% on [-1, 1] excluding
    a small neighbourhood of 0. Depth cost: 4.
    """
    return sign_poly_d3(sign_poly_d3(x))


def abs_poly_d5(x: SlotVec) -> SlotVec:
    """|x| ≈ x · sign_poly_d5(x). Depth cost: 5."""
    return x.mul_ct(sign_poly_d5(x))


def reciprocal_poly_d3(x: SlotVec) -> SlotVec:
    """Degree-3 polynomial fit to 1/x on [0.5, 1.5].

    Fit:   1/x ≈ 4 - 6 x + 4 x^2 - x^3   (Taylor expansion at x=1).

    Worst-case relative error ~6% on [0.5, 1.5]; suitable for audit-grade
    ratios that downstream cross a sign-polynomial threshold. Depth cost: 3.
    """
    x_sq = x.mul_ct(x)
    x_cube = x_sq.mul_ct(x)
    n = x.n
    return (x.mul_pt(np.full(n, -6.0))
            + x_sq.mul_pt(np.full(n, 4.0))
            + x_cube.mul_pt(np.full(n, -1.0))
            + np.full(n, 4.0))


def cdf_in_place(x: SlotVec) -> SlotVec:
    """Slot-wise cumulative sum via Halevi-Shoup rotate-and-mask prefix sum.

    Mathematically: ``out[k] = sum_{j <= k} x[j]``.

    Depth cost in this plaintext SlotVec model: 0 multiplications,
    because we simulate the wrap-around mask by writing zeros into
    the rotated array directly (free in numpy).

    Depth cost on a real CKKS backend: 1 plaintext multiplication
    consolidating all ``log2(n)`` rotate-and-mask steps into a single
    upper-triangular plaintext-matrix multiplication. The encrypted
    drift primitive (``regaudit_fhe.fhe.primitives.w1_encrypted``)
    pays this level explicitly via ``mm_pt`` and the equivalence
    test asserts the output matches this model within tolerance.
    """
    n = x.n
    if n & (n - 1) != 0:
        raise ValueError(f"cdf_in_place requires power-of-two n; got {n}")
    out = x
    step = 1
    while step < n:
        rotated = out.rotate(-step)
        rotated.slots[:step] = 0.0
        out = out + rotated
        step *= 2
    return out


def power_of_two_ceil(n: int) -> int:
    p = 1
    while p < n:
        p *= 2
    return p


def pad_pow2(values: np.ndarray, fill: float = 0.0) -> np.ndarray:
    n = len(values)
    target = power_of_two_ceil(n)
    if target == n:
        return np.asarray(values, dtype=np.float64)
    out = np.full(target, fill, dtype=np.float64)
    out[:n] = values
    return out
