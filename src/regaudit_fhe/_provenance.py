"""Consistency of the self-reported backend and parameter-set evidence in an envelope.

Everything here is a *self-consistency* check on values the signer chose. It can show
that an envelope contradicts itself (the top-level ``backend`` differs from
``parameter_set.backend``, or ``parameter_set_hash`` is not the hash of the
``parameter_set`` it sits next to). It cannot show that any FHE computation ran: a
signer can sign a consistent claim of ``tenseal-ckks`` over a plaintext run.

Three outcomes keep absent evidence apart from a demonstrated contradiction:

* ``CONSISTENT``: every checkable relationship holds.
* ``UNVERIFIABLE``: the envelope lacks the evidence for a safe decision (for example a
  ``parameter_set`` without a ``backend`` field, or one whose shape the hash scheme of
  this library does not describe). Nothing is invented and nothing is refused.
* ``CONTRADICTION``: two signed values that must agree do not.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from typing import Any

from .canonical import CanonicalError
from .reports import ParameterSet, canonical_json, sha256_hex

CONSISTENT = "CONSISTENT"
UNVERIFIABLE = "UNVERIFIABLE"
CONTRADICTION = "CONTRADICTION"

_PARAMETER_SET_KEYS = frozenset(ParameterSet().to_dict())


def check_provenance(env: Any) -> tuple[str, str]:
    """Return ``(status, detail)`` for ``env``'s backend and parameter-set evidence."""
    backend = getattr(env, "backend", None)
    pset = getattr(env, "parameter_set", None)
    declared_hash = getattr(env, "parameter_set_hash", None)
    if not isinstance(pset, dict) or not pset:
        return UNVERIFIABLE, "no parameter_set to compare against"

    status = CONSISTENT
    detail = ""

    inner = pset.get("backend")
    if isinstance(inner, str) and isinstance(backend, str):
        if inner != backend:
            return CONTRADICTION, f"backend {backend!r} contradicts parameter_set.backend {inner!r}"
    else:
        status, detail = UNVERIFIABLE, "parameter_set carries no backend to compare"

    if isinstance(declared_hash, str) and declared_hash:
        try:
            actual = sha256_hex(canonical_json(pset))
        except (CanonicalError, TypeError, ValueError):
            return UNVERIFIABLE, "parameter_set cannot be canonicalised for hashing"
        if actual != declared_hash:
            if set(pset) == _PARAMETER_SET_KEYS:
                return CONTRADICTION, "parameter_set_hash is not the hash of parameter_set"
            # A parameter_set of another shape may be hashed by a scheme this library does not know.
            return UNVERIFIABLE, "parameter_set has a shape whose hash scheme is unknown"
    else:
        status, detail = UNVERIFIABLE, "no parameter_set_hash to compare against"
    return status, detail
