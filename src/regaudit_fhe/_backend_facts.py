"""What the installed TenSEAL and SEAL build can be shown to do, read from the build itself.

A signed ``parameter_set`` states a ring dimension, a coefficient chain and a security level. This module is
how the producer paths find out what is true instead of copying a default or a label:

* the ring dimension and chain are read back from a context the backend actually constructed;
* the 128-bit limits come from the installed SEAL (``CoeffModulus.MaxBitCount``), not from a copy;
* the security level the backend enforces is shown by building contexts at and just above each level's limit.
  TenSEAL builds every context at SEAL's default level and offers no way to request or read back another, so
  the only level that can be shown is whatever the build refuses above. Nothing here is a security estimate.

Anything that cannot be shown raises :class:`BackendUnverified`. Callers must not fall back to a default.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any

# The smallest ring the library supports, and so the one the probe uses: contexts here build in milliseconds.
PROBE_RING_DIM = 1 << 14
# SEAL refuses any coefficient prime above this many bits.
MAX_PRIME_BITS = 60


class BackendUnverified(ValueError):
    """The installed backend cannot be shown to enforce or expose what a signed claim needs."""


@dataclass(frozen=True)
class SealFacts:
    tenseal_version: str
    seal_version: tuple[int, int]  # major, minor compiled into the installed library
    enforced_security_bits: int  # 0 when no level could be shown


@dataclass(frozen=True)
class ReadBack:
    ring_dim: int
    chain: tuple[int, ...]  # every prime, including SEAL's special one
    scale: float | None


def _import_tenseal() -> Any:
    try:
        import tenseal
        import tenseal.sealapi  # a submodule: `import tenseal` alone does not load it
    except Exception as exc:  # not installed, or a broken build
        raise BackendUnverified(
            f"TenSEAL is not installed or exposes no SEAL API ({exc}); no parameter set is signed"
        ) from exc
    return tenseal


def _chain_with_total(total: int) -> list[int]:
    """A chain of primes of at most 60 bits whose sizes add up to exactly ``total``."""
    count = -(-total // MAX_PRIME_BITS)
    base, extra = divmod(total, count)
    return [base + 1] * extra + [base] * (count - extra)


def _builds(ts: Any, ring_dim: int, chain: list[int]) -> bool:
    try:
        ts.context(
            ts.SCHEME_TYPE.CKKS, poly_modulus_degree=ring_dim, coeff_mod_bit_sizes=list(chain)
        )
    except Exception:
        return False
    return True


def _enforced_bits(ts: Any) -> int:
    """The highest level L such that a chain exactly at L's limit builds and one bit more is refused."""
    sealapi = ts.sealapi
    levels = sealapi.SEC_LEVEL_TYPE
    shown = 0
    for bits, level in ((128, levels.TC128), (192, levels.TC192), (256, levels.TC256)):
        limit = int(sealapi.CoeffModulus.MaxBitCount(PROBE_RING_DIM, level))
        if limit <= 0:
            continue
        if _builds(ts, PROBE_RING_DIM, _chain_with_total(limit)) and not _builds(
            ts, PROBE_RING_DIM, _chain_with_total(limit + 1)
        ):
            shown = max(shown, bits)
    return shown


@functools.lru_cache(maxsize=1)
def _facts_cached() -> SealFacts:
    ts = _import_tenseal()
    try:
        header = ts.sealapi.Serialization.SEALHeader()
        version = (int(header.version_major), int(header.version_minor))
        bits = _enforced_bits(ts)
    except BackendUnverified:
        raise
    except Exception as exc:
        raise BackendUnverified(f"cannot read the installed SEAL build ({exc})") from exc
    return SealFacts(str(getattr(ts, "__version__", "")), version, bits)


def facts() -> SealFacts:
    return _facts_cached()


def reset_cache() -> None:
    _facts_cached.cache_clear()
    constructed.cache_clear()


def require_level(bits: int) -> SealFacts:
    f = facts()
    if f.enforced_security_bits < bits:
        shown = f"{f.enforced_security_bits} bits" if f.enforced_security_bits else "no level"
        raise BackendUnverified(
            f"the installed backend cannot be shown to enforce {bits} bits (it was shown to enforce {shown}), "
            "so a claim of that level is not signed"
        )
    return f


def installed_max_log_q_128(ring_dim: int) -> int:
    """SEAL's own 128-bit log Q limit for ``ring_dim``, or 0 when the installed SEAL has no entry for it."""
    ts = _import_tenseal()
    try:
        return int(
            ts.sealapi.CoeffModulus.MaxBitCount(int(ring_dim), ts.sealapi.SEC_LEVEL_TYPE.TC128)
        )
    except Exception as exc:
        raise BackendUnverified(
            f"cannot read SEAL's limit for ring dimension {ring_dim} ({exc})"
        ) from exc


def read_back(ctx: Any) -> ReadBack:
    """The ring dimension, full chain and scale of a context the backend constructed."""
    _import_tenseal()
    try:
        parms = ctx.seal_context().data.key_context_data().parms()
        scheme = parms.scheme()
        if str(getattr(scheme, "name", scheme)).split(".")[-1] != "CKKS":
            raise BackendUnverified("the context is not a CKKS context")
        ring = int(parms.poly_modulus_degree())
        chain = tuple(int(m.bit_count()) for m in parms.coeff_modulus())
    except BackendUnverified:
        raise
    except Exception as exc:
        raise BackendUnverified(
            f"cannot read the parameters of {type(ctx).__name__} from a TenSEAL context ({exc}); "
            "they are not taken from a default"
        ) from exc
    try:
        scale: float | None = float(ctx.global_scale)
    except Exception:
        scale = None
    return ReadBack(ring, chain, scale)


@functools.lru_cache(maxsize=16)
def constructed(ring_dim: int, chain: tuple[int, ...]) -> ReadBack:
    """Build a real context with these parameters and read them back. Cheap: no Galois or relinearisation keys."""
    ts = _import_tenseal()
    try:
        ctx = ts.context(
            ts.SCHEME_TYPE.CKKS, poly_modulus_degree=ring_dim, coeff_mod_bit_sizes=list(chain)
        )
    except Exception as exc:
        raise BackendUnverified(
            f"the installed SEAL refuses ring dimension {ring_dim} with chain {chain} ({exc})"
        ) from exc
    back = read_back(ctx)
    if back.ring_dim != ring_dim or back.chain != tuple(chain):
        raise BackendUnverified(
            f"the backend built ring dimension {back.ring_dim} with chain {back.chain}, "
            f"which is different from the {ring_dim} and {tuple(chain)} that were asked for"
        )
    return back
