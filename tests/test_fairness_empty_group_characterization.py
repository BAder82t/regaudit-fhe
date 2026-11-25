"""A fairness audit with an EMPTY group is refused on every execution path (decision D4, 2026-11-25).

The plaintext reference ``fairness_oracle``, the depth-budgeted slot circuit ``fairness_circuit_d6`` and the encrypted
primitive ``fairness_encrypted`` all raise ``ValueError`` for a group with no members, with the same message. Before
the decision the encrypted primitive clamped the denominator and returned numbers that were those of a group with zero
counts, not of the audit's own definition. A disparity between two groups is undefined when one of them is empty, so
the encrypted path now refuses it too. Zero positives inside a non-empty group is a different case: all paths still
clamp that denominator the same way.

Run it as a script to print what each path does::

    PYTHONPATH=src python tests/test_fairness_empty_group_characterization.py

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import numpy as np
import pytest

from regaudit_fhe.egf_imss import fairness_circuit_d6, fairness_oracle

Y_TRUE = np.array([1.0, 0.0, 1.0, 1.0, 0.0, 1.0, 0.0, 0.0])
Y_PRED = np.array([1.0, 0.0, 1.0, 0.0, 0.0, 1.0, 1.0, 0.0])
GROUP_A = np.array([1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0])
EMPTY_B = np.zeros(8)


def _encrypted(*args: object) -> object:
    pytest.importorskip("tenseal")
    from regaudit_fhe.fhe import build_d6_context
    from regaudit_fhe.fhe import primitives as fhe_p

    ctx = build_d6_context(poly_modulus_degree=1 << 14)
    return fhe_p.fairness_encrypted(ctx, *args)  # type: ignore[arg-type]


def outcome(call) -> str:
    """``raises ValueError: <message>`` or ``returns <report>``; never raises."""
    try:
        return f"returns {call()!r}"
    except ValueError as exc:
        return f"raises ValueError: {exc}"


def paths() -> dict[str, str]:
    return {
        "plaintext oracle": outcome(lambda: fairness_oracle(Y_TRUE, Y_PRED, GROUP_A, EMPTY_B)),
        "slot circuit (d6)": outcome(lambda: fairness_circuit_d6(Y_TRUE, Y_PRED, GROUP_A, EMPTY_B)),
        "encrypted (TenSEAL)": outcome(lambda: _encrypted(Y_TRUE, Y_PRED, GROUP_A, EMPTY_B)),
    }


def test_every_path_refuses_an_empty_group_b() -> None:
    pytest.importorskip("tenseal")
    for name, result in paths().items():
        assert result.startswith("raises ValueError"), f"{name}: {result}"
        assert "group_b has zero members" in result, f"{name}: {result}"


def test_every_path_refuses_an_empty_group_a() -> None:
    pytest.importorskip("tenseal")
    empty_a = np.zeros(8)
    group_b = np.array([1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0])
    for name, call in {
        "plaintext oracle": lambda: fairness_oracle(Y_TRUE, Y_PRED, empty_a, group_b),
        "slot circuit (d6)": lambda: fairness_circuit_d6(Y_TRUE, Y_PRED, empty_a, group_b),
        "encrypted (TenSEAL)": lambda: _encrypted(Y_TRUE, Y_PRED, empty_a, group_b),
    }.items():
        result = outcome(call)
        assert result.startswith("raises ValueError") and "group_a has zero members" in result, (
            f"{name}: {result}"
        )


def test_the_encrypted_path_checks_before_it_encrypts_anything() -> None:
    """The refusal comes from the input check, not from a later numeric failure, and needs no key material."""
    pytest.importorskip("tenseal")
    from regaudit_fhe.fhe import primitives as fhe_p

    class NoContext:  # any use of the context would raise AttributeError or TypeError, not ValueError
        pass

    with pytest.raises((ValueError, TypeError)) as seen:
        fhe_p.fairness_encrypted(NoContext(), Y_TRUE, Y_PRED, GROUP_A, EMPTY_B)  # type: ignore[arg-type]
    assert isinstance(seen.value, ValueError) and "group_b has zero members" in str(seen.value)


def test_a_group_with_no_positives_is_still_answered_the_same_on_every_path() -> None:
    """Out of scope for D4: a non-empty group with no label-positive rows is clamped identically everywhere."""
    pytest.importorskip("tenseal")
    y_true = np.array([1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
    group_a = np.array([1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0])
    group_b = np.array([0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0])  # non-empty, zero positives
    plain = fairness_oracle(y_true, Y_PRED, group_a, group_b)
    enc = _encrypted(y_true, Y_PRED, group_a, group_b)
    assert abs(enc.demographic_parity_diff - plain.demographic_parity_diff) < 1e-3
    assert abs(enc.equal_opportunity_diff - plain.equal_opportunity_diff) < 1e-3


if __name__ == "__main__":
    for name, result in paths().items():
        print(f"{name}: {result}")
