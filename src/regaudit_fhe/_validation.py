"""Input validation guards used by every audit primitive.

Each guard raises ``ValueError`` with a primitive-specific message so
that tests and downstream callers can match the failure mode without
parsing tracebacks. The cost of validation is negligible against the
cost of a corrupted audit envelope.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from typing import Any

import numpy as np


def assert_finite(name: str, value: Any) -> np.ndarray:
    """Reject NaN, ±Inf, and non-numeric arrays before they enter the
    encrypted boundary. Returns the value as a float64 numpy array.

    NaN / Inf in CKKS would silently corrupt ciphertexts; in the
    plaintext model they would propagate to the audit envelope and
    falsify every downstream regulatory threshold check.
    """
    arr = np.asarray(value, dtype=np.float64)
    if not np.all(np.isfinite(arr)):
        raise ValueError(
            f"{name} contains non-finite values (NaN or Inf); "
            "audit primitives reject these at the boundary to prevent "
            "silent envelope corruption."
        )
    return arr


def assert_binary(name: str, value: Any) -> np.ndarray:
    """Reject vectors that are not strictly 0/1."""
    arr = assert_finite(name, value)
    unique = np.unique(arr)
    if not np.all(np.isin(unique, np.array([0.0, 1.0]))):
        raise ValueError(
            f"{name} must be a binary vector with entries in {{0, 1}}; "
            f"got distinct values {sorted(unique.tolist())}."
        )
    return arr


def assert_nonempty(name: str, value: Any) -> np.ndarray:
    arr = np.asarray(value)
    if arr.size == 0:
        raise ValueError(f"{name} must be non-empty.")
    return arr


def assert_same_length(*pairs: tuple) -> None:
    """Each pair is ``(name, array)``. Raises if their lengths differ."""
    lengths = {name: len(np.asarray(arr)) for name, arr in pairs}
    if len(set(lengths.values())) > 1:
        items = ", ".join(f"{n}={length}" for n, length in lengths.items())
        raise ValueError(f"input length mismatch: {items}")


def assert_in_range(name: str, value: float, *, low: float, high: float) -> float:
    if not np.isfinite(value):
        raise ValueError(f"{name} must be finite; got {value!r}")
    if value < low or value > high:
        raise ValueError(f"{name} must lie in [{low}, {high}]; got {value}")
    return float(value)


def assert_at_least_one_member(group_name: str, group: Any) -> None:
    arr = np.asarray(group, dtype=np.float64)
    if float(np.sum(arr)) <= 0:
        raise ValueError(
            f"{group_name} has zero members; fairness disparity "
            "metrics are undefined when one group is empty."
        )
