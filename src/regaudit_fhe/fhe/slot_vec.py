"""EncryptedSlotVec — TenSEAL-backed analogue of regaudit_fhe._slot.SlotVec.

The API matches SlotVec exactly so an audit primitive written against
the plaintext SlotVec can be exercised on encrypted inputs by swapping
the import.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Union

import numpy as np

from .._slot import MAX_DEPTH, DepthBudgetExceeded


OP_COUNTERS: dict[str, int] = {
    "ct_ct_muls": 0,
    "ct_pt_muls": 0,
    "ct_scalar_muls": 0,
    "rotations": 0,
    "additions": 0,
    "subtractions": 0,
    "matmul_pt": 0,
}


def reset_op_counters() -> None:
    for k in OP_COUNTERS:
        OP_COUNTERS[k] = 0


def snapshot_op_counters() -> dict[str, int]:
    return dict(OP_COUNTERS)


@dataclass
class EncryptedSlotVec:
    ciphertext: "object"          # tenseal.CKKSVector
    n: int
    depth: int = 0
    max_depth: int = MAX_DEPTH

    def __post_init__(self) -> None:
        if self.depth > self.max_depth:
            raise DepthBudgetExceeded(
                f"depth {self.depth} exceeds budget {self.max_depth}"
            )

    @classmethod
    def encrypt(cls, ctx, values: Sequence[float],
                max_depth: int = MAX_DEPTH) -> "EncryptedSlotVec":
        from .context import CKKSContext
        if not isinstance(ctx, CKKSContext):
            raise TypeError("encrypt(ctx, values) requires a CKKSContext")
        vals = list(values)
        ct = ctx.encrypt_vector(vals)
        return cls(ciphertext=ct, n=len(vals),
                   depth=0, max_depth=max_depth)

    def decrypt(self) -> List[float]:
        return list(self.ciphertext.decrypt())[: self.n]

    def first_slot(self) -> float:
        return float(self.decrypt()[0])

    def __add__(self, other: Union["EncryptedSlotVec", np.ndarray, float, list]
                ) -> "EncryptedSlotVec":
        OP_COUNTERS["additions"] += 1
        if isinstance(other, EncryptedSlotVec):
            return EncryptedSlotVec(
                ciphertext=self.ciphertext + other.ciphertext,
                n=self.n,
                depth=max(self.depth, other.depth),
                max_depth=self.max_depth,
            )
        addend = _as_list(other, self.n)
        return EncryptedSlotVec(
            ciphertext=self.ciphertext + addend,
            n=self.n, depth=self.depth, max_depth=self.max_depth,
        )

    def __radd__(self, other) -> "EncryptedSlotVec":
        return self.__add__(other)

    def __sub__(self, other: Union["EncryptedSlotVec", np.ndarray, float, list]
                ) -> "EncryptedSlotVec":
        OP_COUNTERS["subtractions"] += 1
        if isinstance(other, EncryptedSlotVec):
            return EncryptedSlotVec(
                ciphertext=self.ciphertext - other.ciphertext,
                n=self.n,
                depth=max(self.depth, other.depth),
                max_depth=self.max_depth,
            )
        sub = _as_list(other, self.n)
        return EncryptedSlotVec(
            ciphertext=self.ciphertext - sub,
            n=self.n, depth=self.depth, max_depth=self.max_depth,
        )

    def __neg__(self) -> "EncryptedSlotVec":
        return EncryptedSlotVec(
            ciphertext=self.ciphertext * -1.0,
            n=self.n, depth=self.depth, max_depth=self.max_depth,
        )

    def mul_pt(self, plaintext) -> "EncryptedSlotVec":
        OP_COUNTERS["ct_pt_muls"] += 1
        pt = _as_list(plaintext, self.n)
        return EncryptedSlotVec(
            ciphertext=self.ciphertext * pt,
            n=self.n, depth=self.depth + 1, max_depth=self.max_depth,
        )

    def mul_scalar(self, scalar: float) -> "EncryptedSlotVec":
        OP_COUNTERS["ct_scalar_muls"] += 1
        return EncryptedSlotVec(
            ciphertext=self.ciphertext * float(scalar),
            n=self.n, depth=self.depth, max_depth=self.max_depth,
        )

    def mul_ct(self, other: "EncryptedSlotVec") -> "EncryptedSlotVec":
        OP_COUNTERS["ct_ct_muls"] += 1
        return EncryptedSlotVec(
            ciphertext=self.ciphertext * other.ciphertext,
            n=self.n,
            depth=max(self.depth, other.depth) + 1,
            max_depth=self.max_depth,
        )

    def rotate(self, k: int) -> "EncryptedSlotVec":
        OP_COUNTERS["rotations"] += 1
        raise NotImplementedError(
            "TenSEAL CKKSVector does not expose a rotate primitive. "
            "Encrypted variants of rotation-based primitives use a "
            "plaintext-matrix multiplication path instead — see "
            "regaudit_fhe.fhe.primitives for examples."
        )

    def sum_all(self) -> "EncryptedSlotVec":
        # TenSEAL .sum() expands internally to log2(n) rotate-and-add steps;
        # count those for benchmark reporting parity with rotation-based
        # backends.
        if self.n > 1:
            OP_COUNTERS["rotations"] += int(np.log2(self.n))
        return EncryptedSlotVec(
            ciphertext=self.ciphertext.sum(),
            n=self.n, depth=self.depth, max_depth=self.max_depth,
        )

    def mm_pt(self, matrix: "object") -> "EncryptedSlotVec":
        """Encrypted-vector × plaintext-matrix multiplication.

        Used by the CDF primitive to materialise prefix sums in a
        rotation-free manner. Consumes one multiplicative level.
        """
        import numpy as _np
        m = _np.asarray(matrix, dtype=float)
        OP_COUNTERS["matmul_pt"] += 1
        OP_COUNTERS["ct_pt_muls"] += 1
        # The TenSEAL plaintext-matrix multiply is internally a rotation
        # tree of log2(n) steps + n plaintext multiplies; we credit it
        # log2(n) rotations for benchmark accounting.
        if self.n > 1:
            OP_COUNTERS["rotations"] += int(_np.log2(self.n))
        return EncryptedSlotVec(
            ciphertext=self.ciphertext.mm(m.tolist()),
            n=m.shape[1] if m.ndim == 2 else self.n,
            depth=self.depth + 1,
            max_depth=self.max_depth,
        )


def _as_list(value, target_len: int) -> List[float]:
    if isinstance(value, np.ndarray):
        return [float(v) for v in value.tolist()]
    if isinstance(value, list):
        return [float(v) for v in value]
    if isinstance(value, tuple):
        return [float(v) for v in value]
    return [float(value)] * target_len


def sign_poly_d3(x: EncryptedSlotVec) -> EncryptedSlotVec:
    """Encrypted analogue of regaudit_fhe._slot.sign_poly_d3."""
    x_sq = x.mul_ct(x)
    x_cube = x_sq.mul_ct(x)
    return x.mul_scalar(1.5) + x_cube.mul_scalar(-0.5)
