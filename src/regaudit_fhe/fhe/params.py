"""Validated CKKS parameter set.

Constructing a :class:`CKKSParams` runs every validation rule the
library promises to enforce at runtime:

  - 128-bit IND-CPA security at the chosen ``ring_dim``.
  - Modulus-chain depth large enough to evaluate the declared
    ``multiplicative_depth`` without bootstrapping.
  - Total ``log Q`` does not exceed the SEAL-validated bound for the
    chosen ``ring_dim``.
  - Scaling-factor management stable: every interior prime ≥ the
    scaling-factor size and the first / last primes ≥ the
    first-modulus size.
  - Rotation-key set is the minimal Halevi-Shoup power-of-two ladder
    plus any explicitly declared additional steps.
  - Precision-loss bound is below the regulator-facing tolerance.

A ``CKKSParams`` is a frozen, hashable record. Pass one to
:func:`regaudit_fhe.fhe.build_d6_context_from_params` to obtain a
working CKKS context whose hash matches the envelope's
``parameter_set_hash``.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

SECURITY_LEVELS = {
    "HEStd_128_classic": 128,
    "HEStd_192_classic": 192,
    "HEStd_256_classic": 256,
}


# SEAL-validated upper bounds on `log Q` (sum of coeff_mod_bit_sizes)
# for each ring dimension at 128-bit IND-CPA security. Below these
# bounds the parameter set is accepted; at or above, SEAL refuses.
SEAL_MAX_LOG_Q_128: dict[int, int] = {
    1024: 27,
    2048: 54,
    4096: 109,
    8192: 218,
    16384: 438,
    32768: 881,
    65536: 1762,
}


class ParameterValidationError(ValueError):
    """Raised when a CKKSParams instance fails a validation rule."""


@dataclass(frozen=True)
class CKKSParams:
    ring_dim: int = 1 << 15
    multiplicative_depth: int = 6
    scaling_mod_size: int = 40
    first_mod_size: int = 60
    security_level: str = "HEStd_128_classic"
    coeff_mod_bit_sizes: tuple[int, ...] = field(default_factory=tuple)
    rotation_steps: tuple[int, ...] = field(default_factory=tuple)
    extra_rotation_steps: tuple[int, ...] = field(default_factory=tuple)
    precision_loss_bound: float = 1e-2

    def __post_init__(self) -> None:
        coeffs = self.coeff_mod_bit_sizes or self._default_coeff_chain()
        rotations = self.rotation_steps or self._default_rotation_steps()
        rotations = tuple(sorted(set(rotations) | set(self.extra_rotation_steps)))
        object.__setattr__(self, "coeff_mod_bit_sizes", tuple(coeffs))
        object.__setattr__(self, "rotation_steps", rotations)
        self._validate()

    # ------------------------------------------------------------------
    # Defaults
    # ------------------------------------------------------------------

    def _default_coeff_chain(self) -> tuple[int, ...]:
        first = self.first_mod_size
        scaling = self.scaling_mod_size
        depth = self.multiplicative_depth
        return (first, *([scaling] * depth), first)

    def _default_rotation_steps(self) -> tuple[int, ...]:
        n_slots = self.ring_dim // 2
        out: list[int] = []
        step = 1
        while step < n_slots:
            out.append(step)
            out.append(-step)
            step *= 2
        return tuple(out)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self) -> None:
        self._check_ring_dim()
        self._check_security_level()
        self._check_depth_supports_chain()
        self._check_log_q_within_bound()
        self._check_scaling_management_stable()
        self._check_no_bootstrap_required()
        self._check_rotation_key_minimality()
        self._check_precision_loss_bound()

    def _check_ring_dim(self) -> None:
        if self.ring_dim < 4096 or self.ring_dim & (self.ring_dim - 1) != 0:
            raise ParameterValidationError(
                f"ring_dim must be a power of two ≥ 4096; got {self.ring_dim}"
            )
        if self.ring_dim < 16384:
            raise ParameterValidationError(
                f"ring_dim {self.ring_dim} cannot fit a depth-{self.multiplicative_depth} "
                "modulus chain at 128-bit security; minimum supported "
                "ring_dim is 16384."
            )

    def _check_security_level(self) -> None:
        if self.security_level not in SECURITY_LEVELS:
            raise ParameterValidationError(
                f"unknown security level {self.security_level!r}; "
                f"choose from {sorted(SECURITY_LEVELS)}"
            )
        if SECURITY_LEVELS[self.security_level] < 128:
            raise ParameterValidationError(
                "regaudit-fhe requires at least 128-bit IND-CPA security; "
                f"got {self.security_level}"
            )

    def _check_depth_supports_chain(self) -> None:
        if self.multiplicative_depth < 1 or self.multiplicative_depth > 6:
            raise ParameterValidationError(
                "multiplicative_depth must be in [1, 6]; the audit "
                "primitives are bounded by d=6 and reject deeper "
                "circuits to enforce the no-bootstrap guarantee."
            )
        # Chain must contain at least depth+1 primes (initial scale +
        # one prime per multiplicative level), plus a final 60-bit prime.
        required = self.multiplicative_depth + 2
        if len(self.coeff_mod_bit_sizes) < required:
            raise ParameterValidationError(
                f"coeff_mod_bit_sizes length {len(self.coeff_mod_bit_sizes)} "
                f"cannot evaluate depth {self.multiplicative_depth} circuits; "
                f"need at least {required} primes."
            )

    def _check_log_q_within_bound(self) -> None:
        log_q = sum(self.coeff_mod_bit_sizes)
        bound = SEAL_MAX_LOG_Q_128.get(self.ring_dim)
        if bound is None:
            raise ParameterValidationError(
                f"no SEAL log Q bound recorded for ring_dim {self.ring_dim}"
            )
        if log_q > bound:
            raise ParameterValidationError(
                f"sum of coeff_mod_bit_sizes ({log_q}) exceeds the "
                f"128-bit-secure bound {bound} for ring_dim "
                f"{self.ring_dim}"
            )

    def _check_scaling_management_stable(self) -> None:
        if self.first_mod_size < self.scaling_mod_size:
            raise ParameterValidationError(
                "first_mod_size must be ≥ scaling_mod_size to keep the "
                "scale stable across rescales."
            )
        # Interior primes (excluding first and last) carry the rescale
        # operation; each must accommodate one scaling factor without
        # underflow.
        interior = self.coeff_mod_bit_sizes[1:-1]
        if any(p < self.scaling_mod_size for p in interior):
            raise ParameterValidationError(
                "every interior modulus prime must be ≥ scaling_mod_size; "
                f"got {self.coeff_mod_bit_sizes}"
            )
        if self.coeff_mod_bit_sizes[0] < self.first_mod_size:
            raise ParameterValidationError("the leading prime must be ≥ first_mod_size")
        if self.coeff_mod_bit_sizes[-1] < self.first_mod_size:
            raise ParameterValidationError("the trailing prime must be ≥ first_mod_size")

    def _check_no_bootstrap_required(self) -> None:
        # Bootstrapping is only ever required if the modulus chain runs
        # out before the declared depth. Since we already verified the
        # chain length above, the no-bootstrap invariant follows. We
        # restate it explicitly so a reader can grep for it.
        consumed = self.multiplicative_depth
        available = len(self.coeff_mod_bit_sizes) - 2
        if consumed > available:
            raise ParameterValidationError(
                "modulus chain too short to evaluate the declared depth without bootstrapping."
            )

    def _check_rotation_key_minimality(self) -> None:
        n_slots = self.ring_dim // 2
        required = set()
        step = 1
        while step < n_slots:
            required.add(step)
            required.add(-step)
            step *= 2
        for step in self.extra_rotation_steps:
            required.add(int(step))
        actual = set(self.rotation_steps)
        missing = required - actual
        if missing:
            raise ParameterValidationError(
                f"rotation_steps is missing required Halevi-Shoup steps: {sorted(missing)}"
            )
        excess = actual - required
        if excess:
            # Excess rotation keys waste memory + leak information about
            # what circuits the operator anticipates running. We refuse
            # to silently accept them.
            raise ParameterValidationError(
                f"rotation_steps contains keys not derivable from the "
                f"Halevi-Shoup ladder + extra_rotation_steps: "
                f"{sorted(excess)}. Add them to extra_rotation_steps "
                "to acknowledge the broader key set."
            )

    def _check_precision_loss_bound(self) -> None:
        if not (0 < self.precision_loss_bound <= 1):
            raise ParameterValidationError(
                f"precision_loss_bound must lie in (0, 1]; got {self.precision_loss_bound}"
            )
        # Worst-case CKKS rescale-side precision loss after `d`
        # multiplications is bounded by `d * 2^-(scaling_mod_size)`. We
        # require this to stay below the declared precision_loss_bound.
        worst_case = self.multiplicative_depth * (2.0**-self.scaling_mod_size)
        if worst_case > self.precision_loss_bound:
            raise ParameterValidationError(
                f"declared scaling_mod_size {self.scaling_mod_size} is "
                f"too small: worst-case precision loss after depth "
                f"{self.multiplicative_depth} is {worst_case:g}, "
                f"exceeding precision_loss_bound "
                f"{self.precision_loss_bound:g}."
            )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "ring_dim": int(self.ring_dim),
            "multiplicative_depth": int(self.multiplicative_depth),
            "scaling_mod_size": int(self.scaling_mod_size),
            "first_mod_size": int(self.first_mod_size),
            "security_level": self.security_level,
            "coeff_mod_bit_sizes": list(self.coeff_mod_bit_sizes),
            "rotation_steps": list(self.rotation_steps),
            "extra_rotation_steps": list(self.extra_rotation_steps),
            "precision_loss_bound": float(self.precision_loss_bound),
        }

    def hash(self) -> str:
        body = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(body).hexdigest()

    def to_envelope_parameter_set(self):
        """Convert to the :class:`regaudit_fhe.ParameterSet` shape used
        by the audit envelope."""
        import contextlib

        from ..reports import ParameterSet

        backend_version = ""
        with contextlib.suppress(Exception):
            import tenseal as _ts

            backend_version = getattr(_ts, "__version__", "")
        return ParameterSet(
            backend="tenseal-ckks",
            poly_modulus_degree=self.ring_dim,
            security_bits=SECURITY_LEVELS[self.security_level],
            multiplicative_depth=self.multiplicative_depth,
            coeff_mod_bit_sizes=tuple(self.coeff_mod_bit_sizes),
            scaling_factor_bits=self.scaling_mod_size,
            backend_version=backend_version,
        )
