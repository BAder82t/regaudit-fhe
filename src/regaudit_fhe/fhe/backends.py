"""Pluggable FHE backend registry.

Until now the encrypted execution path was hardwired to TenSEAL: a
verifier reading the envelope's ``backend`` tag had exactly one value to
expect, and there was no in-library way to discover what else could run
the audit circuits. This module turns the backend into a first-class,
discoverable object so a second CKKS implementation (OpenFHE) — or a
future one — can register itself and be selected by name.

A backend bundles the three things the audit primitives need:

  - a **context factory** (``build_context``) that returns a ready CKKS
    context for the d=6 audit budget,
  - the **slot-vector class** (``slotvec_cls``) whose algebra the six
    primitives are written against (add / sub / mul_pt / mul_scalar /
    mul_ct / rotate / sum_all / mm_pt / first_slot / decrypt), and
  - the **parameter-set tag** that is stamped into the signed envelope so
    a verifier can pin which implementation produced the result.

Backends declare ``available`` from whether their native dependency
imports, mirroring the ``[fhe]`` extra gate used for TenSEAL. Selecting
an unavailable backend raises a clear, actionable error rather than an
opaque ``ImportError`` deep in a circuit.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any


class BackendError(RuntimeError):
    """Raised when a requested FHE backend is unknown or unavailable."""


@dataclass(frozen=True)
class FHEBackend:
    """A registered CKKS backend the audit primitives can run against.

    ``slotvec_cls`` must expose the :class:`EncryptedSlotVec` interface;
    ``sign_poly`` is the backend's degree-3 sign-polynomial helper. Both
    are resolved lazily through small thunks so importing this registry
    never imports a heavy (or absent) native dependency.
    """

    name: str
    description: str
    available: bool
    _build_context: Callable[..., Any]
    _slotvec_cls: Callable[[], type]
    _sign_poly: Callable[[], Callable[[Any], Any]]
    experimental: bool = False

    def require(self) -> None:
        if not self.available:
            raise BackendError(
                f"FHE backend {self.name!r} is not available: its native "
                f"dependency is not installed. {self.description}"
            )

    def build_context(self, **kwargs: Any) -> Any:
        self.require()
        return self._build_context(**kwargs)

    @property
    def slotvec_cls(self) -> type:
        self.require()
        return self._slotvec_cls()

    @property
    def sign_poly(self) -> Callable[[Any], Any]:
        self.require()
        return self._sign_poly()


_REGISTRY: dict[str, FHEBackend] = {}


def register_backend(backend: FHEBackend) -> None:
    _REGISTRY[backend.name] = backend


def get_backend(name: str) -> FHEBackend:
    """Return the registered backend ``name`` or raise :class:`BackendError`."""
    try:
        backend = _REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY)) or "(none registered)"
        raise BackendError(f"unknown FHE backend {name!r}; registered: {known}") from None
    return backend


def available_backends() -> list[str]:
    """Names of registered backends whose native dependency is importable."""
    return sorted(name for name, b in _REGISTRY.items() if b.available)


def all_backends() -> list[FHEBackend]:
    """Every registered backend, available or not (for diagnostics / docs)."""
    return [_REGISTRY[name] for name in sorted(_REGISTRY)]


def default_backend() -> FHEBackend:
    """The preferred available backend.

    TenSEAL is preferred when present (it is the verified reference
    implementation); otherwise the first available backend by name. Raises
    :class:`BackendError` when no backend's native dependency is installed.
    """
    if "tenseal-ckks" in _REGISTRY and _REGISTRY["tenseal-ckks"].available:
        return _REGISTRY["tenseal-ckks"]
    for name in available_backends():
        return _REGISTRY[name]
    raise BackendError(
        "no FHE backend is available; install one with "
        "`pip install regaudit-fhe[fhe]` (TenSEAL) or the OpenFHE extra."
    )


# ---------------------------------------------------------------------------
# Built-in registrations
# ---------------------------------------------------------------------------


def _tenseal_available() -> bool:
    try:
        import tenseal  # noqa: F401
    except Exception:
        return False
    return True


def _tenseal_build_context(**kwargs: Any) -> Any:
    from .context import build_d6_context

    return build_d6_context(**kwargs)


def _tenseal_slotvec_cls() -> type:
    from .slot_vec import EncryptedSlotVec

    return EncryptedSlotVec


def _tenseal_sign_poly() -> Callable[[Any], Any]:
    from .slot_vec import sign_poly_d3

    return sign_poly_d3


def _register_builtin_backends() -> None:
    register_backend(
        FHEBackend(
            name="tenseal-ckks",
            description="TenSEAL CKKS (install with `pip install regaudit-fhe[fhe]`).",
            available=_tenseal_available(),
            _build_context=_tenseal_build_context,
            _slotvec_cls=_tenseal_slotvec_cls,
            _sign_poly=_tenseal_sign_poly,
            experimental=False,
        )
    )

    # OpenFHE registers itself from its own module to keep its (heavier,
    # optional) import off this module's import path. If the adapter is
    # unimportable for any reason it simply stays unregistered.
    with contextlib.suppress(Exception):
        from . import openfhe as _openfhe

        _openfhe.register()


def supported_matrix_kinds(name: str) -> Sequence[str]:
    """Which ``mm_pt`` matrix shapes a backend supports.

    TenSEAL supports arbitrary rectangular plaintext matrices natively;
    the experimental OpenFHE adapter currently supports only square
    matrices (the diagonal method), which covers every primitive except
    encrypted concordance. Exposed so callers / tests can skip
    unsupported (backend, primitive) pairs explicitly instead of hitting
    a runtime error mid-circuit.
    """
    if name == "openfhe-ckks":
        return ("square",)
    return ("square", "rectangular")


_register_builtin_backends()
