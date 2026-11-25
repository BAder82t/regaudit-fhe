"""Characterization of one inconsistency: a fairness audit with an EMPTY group, per execution path (P3-04 finding).

The plaintext reference ``fairness_oracle`` and the depth-budgeted slot circuit ``fairness_circuit_d6`` refuse a group
with no members (``assert_at_least_one_member``). The encrypted primitive ``fairness_encrypted`` runs no such check and
clamps every denominator with ``max(sum, 1.0)``, so the same input returns numbers there. The numbers are those of a
group with zero counts, not of the audit's own definition.

Nothing here says which behaviour is right and nothing changes the computation. The first test records, without
asserting either answer, what each path does today. The second states the consistency a maintainer may want and is
``xfail`` (non-strict): it passes once the paths agree, in either direction.

Run it as a script to print the reproduction::

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


def test_each_path_has_a_recorded_outcome_for_an_empty_group() -> None:
    pytest.importorskip("tenseal")
    seen = paths()
    for name, result in seen.items():
        print(f"{name}: {result}")  # visible with -s; the test asserts no particular answer
        assert result.startswith(("returns", "raises ValueError"))


@pytest.mark.xfail(
    reason="the encrypted path clamps an empty group instead of refusing it, as the plaintext oracle does",
    strict=False,
)
def test_all_paths_give_the_same_kind_of_answer_for_an_empty_group() -> None:
    pytest.importorskip("tenseal")
    kinds = {result.split(":")[0].split(" ")[0] for result in paths().values()}
    assert len(kinds) == 1


if __name__ == "__main__":
    for name, result in paths().items():
        print(f"{name}: {result}")
