"""TenSEAL CKKS context factory targeting the d=6 audit budget.

Default parameters yield 128-bit IND-CPA security for ``poly_modulus_degree
= 2^14`` with a ``coeff_modulus`` chain that supports six multiplicative
levels. Production deployments should select ``poly_modulus_degree =
2^15`` for higher precision and longer rotation-key sets.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .params import CKKSParams


@dataclass
class CKKSContext:
    context: object             # tenseal.Context
    scale: float
    poly_modulus_degree: int
    n_slots: int
    rotation_steps: tuple[int, ...]

    def encrypt_vector(self, values: Sequence[float]) -> object:
        import tenseal as ts
        return ts.ckks_vector(self.context, list(values))

    def decrypt_vector(self, ct: object) -> list[float]:
        return list(ct.decrypt())


def build_d6_context_from_params(params: CKKSParams) -> CKKSContext:
    """Build a CKKS context from a validated :class:`CKKSParams`.

    The CKKSParams constructor has already run every validation rule
    the library promises to enforce; this function only translates the
    validated record into an active TenSEAL context.
    """
    from .params import CKKSParams as _CKKSParams
    if not isinstance(params, _CKKSParams):
        raise TypeError("build_d6_context_from_params requires CKKSParams")
    return build_d6_context(
        poly_modulus_degree=params.ring_dim,
        scale_bits=params.scaling_mod_size,
        coeff_mod_bit_sizes=params.coeff_mod_bit_sizes,
        rotation_steps=params.rotation_steps,
    )


def build_d6_context(*,
                     poly_modulus_degree: int = 1 << 14,
                     scale_bits: int = 40,
                     coeff_mod_bit_sizes: Sequence[int] | None = None,
                     rotation_steps: Sequence[int] | None = None,
                     ) -> CKKSContext:
    """Construct a TenSEAL CKKS context for the audit primitives.

    The default ``poly_modulus_degree = 2**14`` (ring 16384) admits a
    coefficient modulus up to 438 bits at 128-bit IND-CPA security.
    The default ``coeff_mod_bit_sizes`` chain
    ``[60, 40, 40, 40, 40, 40, 40, 40, 60]`` totals 400 bits — one
    initial level, seven multiplicative levels, and a final level for
    output decryption. The audit primitives consume at most
    :data:`regaudit_fhe._slot.MAX_DEPTH` (= 6) multiplicative levels;
    the trailing prime keeps a margin of one rescale for noise
    headroom and to absorb the ``mul_scalar`` levels that TenSEAL's
    auto-rescale charges (and that the public ``SlotVec`` model does
    not surface).

    Rotation keys are pre-generated for the ``log2(n_slots)`` powers-
    of-two used by the cross-slot Halevi-Shoup summation, plus a small
    set of negative powers needed by the in-place CDF prefix-sum
    primitive.
    """
    import tenseal as ts

    if coeff_mod_bit_sizes is None:
        coeff_mod_bit_sizes = [60, 40, 40, 40, 40, 40, 40, 40, 60]

    n_slots = poly_modulus_degree // 2
    if rotation_steps is None:
        rs: list[int] = []
        step = 1
        while step < n_slots:
            rs.append(step)
            rs.append(-step)
            step *= 2
        rotation_steps = tuple(rs)

    ctx = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=poly_modulus_degree,
        coeff_mod_bit_sizes=list(coeff_mod_bit_sizes),
    )
    ctx.global_scale = float(2 ** scale_bits)
    ctx.generate_galois_keys()
    ctx.generate_relin_keys()

    return CKKSContext(
        context=ctx,
        scale=float(2 ** scale_bits),
        poly_modulus_degree=poly_modulus_degree,
        n_slots=n_slots,
        rotation_steps=tuple(rotation_steps),
    )
