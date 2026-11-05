"""Validated CKKS parameter set.

Constructing a :class:`CKKSParams` runs every validation rule the
library promises to enforce at runtime:

  - The 128-bit level only: the chain must stay within SEAL's 128-bit limit
    for ``ring_dim``, and 192 or 256 are refused because the TenSEAL backend
    cannot enforce them. This is a table check, not a security estimate.
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
``parameter_set_hash``. Signing it (``to_envelope_parameter_set``) builds a
real context and reads the ring dimension and chain back from it.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .. import _backend_facts as _bf

SECURITY_LEVELS = {
    "HEStd_128_classic": 128,
    "HEStd_192_classic": 192,
    "HEStd_256_classic": 256,
}


# Upper bounds on `log Q` (sum of coeff_mod_bit_sizes) for each ring dimension at the 128-bit level, from the
# HomomorphicEncryption.org standard as SEAL ships it. Below these bounds the parameter set is accepted; above,
# SEAL refuses to build a context. SEAL has no entry for 65536 or above, so the library has none either: the
# backend cannot build a context there. `check_backend_support` compares this table with the installed SEAL.
SEAL_MAX_LOG_Q_128: dict[int, int] = {
    1024: 27,
    2048: 54,
    4096: 109,
    8192: 218,
    16384: 438,
    32768: 881,
}

# The levels the TenSEAL backend is shown to enforce when it builds a context. TenSEAL builds every context at
# SEAL's default 128-bit level and offers no way to request or read back another, so a signed claim of 192 or
# 256 bits cannot be enforced. Extend this only with a backend that is shown to refuse above the higher level.
BACKEND_ENFORCED_LEVELS = frozenset({"HEStd_128_classic"})

# SEAL refuses any coefficient prime above this many bits.
MAX_PRIME_BITS = _bf.MAX_PRIME_BITS


class ParameterValidationError(ValueError):
    """Raised when a CKKSParams instance fails a validation rule."""


def _is_prime(n: int) -> bool:
    """Deterministic Miller-Rabin, exact below 3.3e24, so exact for every coefficient prime SEAL can use."""
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _enough_primes(bit_size: int, factor: int, count: int) -> bool:
    """Whether at least ``count`` primes of exactly ``bit_size`` bits are 1 modulo ``factor`` (= 2N).

    SEAL builds a chain by taking, for each bit size, the largest such primes first, and refuses the chain
    when it runs out before the lower bound ``2**(bit_size - 1)``.
    """
    value = (1 << bit_size) - factor + 1
    lower = 1 << (bit_size - 1)
    found = 0
    while value > lower and found < count:
        if _is_prime(value):
            found += 1
        value -= factor
    return found >= count


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
        self._check_chain_is_buildable()

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
        if self.security_level not in BACKEND_ENFORCED_LEVELS:
            raise ParameterValidationError(
                f"{self.security_level} is refused: the TenSEAL backend cannot enforce it. It builds its context at "
                "SEAL's default 128-bit level and offers no way to request or read back another, so a signed claim "
                f"of {SECURITY_LEVELS[self.security_level]} bits would be unsupported. Use HEStd_128_classic"
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

    def _check_chain_is_buildable(self) -> None:
        chain = self.coeff_mod_bit_sizes
        if any(isinstance(p, bool) or not isinstance(p, int) for p in chain):
            raise ParameterValidationError(
                f"every coefficient prime size must be an int; got {chain}"
            )
        if any(p < 2 or p > MAX_PRIME_BITS for p in chain):
            raise ParameterValidationError(
                f"every coefficient prime size must be at least 2 and at most {MAX_PRIME_BITS} bits "
                f"(SEAL refuses a larger prime); got {chain}"
            )
        for bits, count in sorted(Counter(chain).items()):
            if not _enough_primes(bits, 2 * self.ring_dim, count):
                raise ParameterValidationError(
                    f"ring_dim {self.ring_dim} has too few distinct primes of {bits} bits for this chain "
                    f"(it needs {count}); SEAL would refuse to build it"
                )

    def check_backend_support(self) -> _bf.ReadBack:
        """Refuse unless the installed backend builds exactly these parameters and enforces the claimed level.

        Builds one real context (no Galois keys) and reads the ring dimension and chain back from it. Raises
        :class:`regaudit_fhe.fhe.BackendUnverified` when TenSEAL is missing, when the level cannot be shown
        to be enforced, when the recorded table differs from the installed SEAL, or when the backend refuses
        or changes the parameters.
        """
        _bf.require_level(SECURITY_LEVELS[self.security_level])
        installed = _bf.installed_max_log_q_128(self.ring_dim)
        recorded = SEAL_MAX_LOG_Q_128.get(self.ring_dim)
        if installed <= 0 or recorded != installed:
            raise _bf.BackendUnverified(
                f"the recorded 128-bit limit for ring dimension {self.ring_dim} ({recorded}) is not the installed "
                f"SEAL's ({installed or 'no entry'}); it has to be revalidated before a parameter set is signed"
            )
        return _bf.constructed(self.ring_dim, tuple(self.coeff_mod_bit_sizes))

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
        """Convert to the :class:`regaudit_fhe.ParameterSet` shape used by the audit envelope.

        The ring dimension and chain are read back from a context the installed backend constructed, and the
        level is signed only when the backend is shown to enforce it. Without TenSEAL, or when either cannot
        be shown, this raises :class:`regaudit_fhe.fhe.BackendUnverified` and nothing is signed.
        """
        from ..reports import ParameterSet

        back = self.check_backend_support()
        return ParameterSet(
            backend="tenseal-ckks",
            poly_modulus_degree=back.ring_dim,
            security_bits=SECURITY_LEVELS[self.security_level],
            multiplicative_depth=self.multiplicative_depth,
            coeff_mod_bit_sizes=back.chain,
            scaling_factor_bits=self.scaling_mod_size,
            backend_version=_bf.facts().tenseal_version,
        )
