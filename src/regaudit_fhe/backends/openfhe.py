"""OpenFHE encrypted-execution backend (skeleton).

This module is loaded only when the ``[fhe]`` extra is installed::

    pip install regaudit-fhe[fhe]

It mirrors the ``regaudit_fhe._slot.SlotVec`` algebra over OpenFHE's
``Ciphertext`` type. The skeleton below documents the integration
surface; concrete construction of ``CryptoContext`` parameters that
hit ``d=6``, ``N=2^15``, 128-bit security, and hybrid key-switching
``dnum=3`` is left to the deployment.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import openfhe  # noqa: F401  -- imported only for type checking

try:
    import openfhe  # type: ignore
    HAVE_OPENFHE = True
except Exception:
    HAVE_OPENFHE = False


def make_d6_context() -> Any:
    """Build a CKKS CryptoContext targeting d=6, N=2^15, 128-bit security.

    Returns the context plus the public key, secret key, and rotation
    keys required by every audit primitive (rotations 1..N-1 in powers
    of two for cross-slot summation; a small set of negative powers for
    in-place CDF prefix sums).
    """
    if not HAVE_OPENFHE:
        raise RuntimeError(
            "OpenFHE not installed. Run `pip install regaudit-fhe[fhe]`."
        )
    raise NotImplementedError(
        "Concrete OpenFHE wiring is part of the v0.1 milestone; the "
        "skeleton here documents the integration surface."
    )


@dataclass
class OpenFHESlotVec:
    """Encrypted analogue of regaudit_fhe._slot.SlotVec.

    Each method below maps one-to-one to a SlotVec method:

        SlotVec.encrypt              -> Encrypt
        SlotVec.__add__              -> EvalAdd
        SlotVec.__sub__              -> EvalSub
        SlotVec.mul_pt               -> EvalMult (plaintext, then Rescale)
        SlotVec.mul_scalar           -> EvalMult (scalar, no rescale)
        SlotVec.mul_ct               -> EvalMult + Relinearize + Rescale
        SlotVec.rotate               -> EvalRotate
        SlotVec.sum_all              -> log2(n) EvalRotate + EvalAdd
    """

    ciphertext: Any
    depth: int
    max_depth: int = 6

    def __post_init__(self) -> None:
        if self.depth > self.max_depth:
            raise RuntimeError(
                f"depth {self.depth} exceeds budget {self.max_depth}"
            )
