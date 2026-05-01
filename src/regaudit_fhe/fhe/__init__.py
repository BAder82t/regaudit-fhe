"""Encrypted execution backend.

Loaded only when the ``[fhe]`` extra is installed::

    pip install regaudit-fhe[fhe]

Provides a real CKKS encrypted backend (TenSEAL) for the six audit
primitives. The encrypted variants mirror the plaintext SlotVec
primitives one-to-one, so a regulator can verify that the encrypted
computation produces the same numerical result as the public reference
within CKKS noise tolerance.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

try:
    import tenseal as _tenseal  # noqa: F401

    _HAVE_TENSEAL = True
except Exception:
    _HAVE_TENSEAL = False


def _require_tenseal() -> None:
    if not _HAVE_TENSEAL:
        raise RuntimeError("TenSEAL is not installed. Run `pip install regaudit-fhe[fhe]`.")


from . import primitives  # noqa: E402
from .context import (  # noqa: E402
    CKKSContext,
    build_d6_context,
    build_d6_context_from_params,
)
from .params import (  # noqa: E402
    SEAL_MAX_LOG_Q_128,
    SECURITY_LEVELS,
    CKKSParams,
    ParameterValidationError,
)
from .slot_vec import EncryptedSlotVec  # noqa: E402

__all__ = [
    "SEAL_MAX_LOG_Q_128",
    "SECURITY_LEVELS",
    "CKKSContext",
    "CKKSParams",
    "EncryptedSlotVec",
    "ParameterValidationError",
    "build_d6_context",
    "build_d6_context_from_params",
    "primitives",
]
