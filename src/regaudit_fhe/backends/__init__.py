"""Encrypted-execution backends for the regaudit-fhe primitives.

The default plaintext backend lives in ``regaudit_fhe._slot``. Real
encrypted execution is delegated to a backend implementation that
mirrors the same SlotVec algebra over an actual CKKS implementation
(OpenFHE, Lattigo via FFI, Concrete-ML, ...).

Importing a backend never executes encryption automatically; use
``set_backend(...)`` to switch.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from typing import Any, Optional


_active: Optional[Any] = None


def set_backend(backend: Any) -> None:
    """Install a backend object exposing the SlotVec-equivalent algebra."""
    global _active
    _active = backend


def get_backend() -> Optional[Any]:
    return _active


__all__ = ["set_backend", "get_backend"]
