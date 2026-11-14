"""Comprehensive ciphertext / plaintext equivalence matrix.

For every primitive the matrix asserts four properties:

    1. abs(fhe_result - plaintext_result) <= tolerance.
    2. depth_consumed <= declared_depth.
    3. No bootstrapping was used.
    4. Runtime within a bound relative to a reference workload timed on the same machine.

Plus a regulatory-threshold-stability check: with inputs near the
breach threshold, the encrypted and plaintext circuits must agree on
the boolean breach decision. CKKS noise that does not change a
regulatory threshold decision is acceptable; noise that flips a
decision is not, and tests will fail loudly if it does.

Skipped automatically if the [fhe] extra is not installed.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import numpy as np
import pytest

import regaudit_fhe as rf

tenseal = pytest.importorskip("tenseal")
from regaudit_fhe.fhe import build_d6_context  # noqa: E402
from regaudit_fhe.fhe import primitives as fhe_p  # noqa: E402

RNG = np.random.default_rng(20260426)
EQUIVALENCE_TOL = 5e-2  # CKKS noise after up to six multiplications
# How runtime is checked (F-021)
# -------------------------------
# Not in seconds. A bound in seconds measures the machine as much as the code: the encrypted concordance took 6.4 s on a
# laptop, 11.5 s on a 2-core Linux VM and 30 to 52 s on hosted macOS runners, against a bound of 15 s times a CI slack of
# 2.0, so unrelated pull requests failed at random.
#
# The reference workload is a fixed piece of the same kind of work the primitives do: on the same CKKS context, square a
# 4096-value vector (one ciphertext multiplication with relinearisation and rescale) and sum its slots (a rotate-and-add
# tree), REFERENCE_ROUNDS times, on a fresh copy each round so no level is used up. It is timed in the same process as the
# primitive, with time.perf_counter, which is monotonic and has the highest available resolution.
#
# The check divides the primitive's time by the reference's time. A machine that is uniformly slower slows both, so the
# ratio stays put; a primitive whose own work grows makes the ratio grow, and fails. Scheduling on a shared runner only ever
# adds time to a measurement, never removes it, so each of the two is measured more than once, interleaved (reference, call,
# reference, call, reference), and the fastest of each is used. Taking the fastest reference is also the conservative
# choice: a reference slowed by a scheduling spike would make the ratio smaller and could hide a regression, and the
# minimum cannot be inflated that way. What the ratio cannot see is a slowdown of the CKKS library itself that affects the
# reference and the primitives alike; that is a dependency change, reviewed as such, and the absolute times are printed in
# every failure message.
#
# Wall time, not CPU time: TenSEAL spreads some operations over threads, so CPU time grows with the number of cores, and the
# ratios then differed between machines (drift 0.4 by wall time, 2.6 to 2.9 by CPU time).
#
# RUNTIME_RATIO per case is the largest ratio seen in any run on 2026-11-14 (macOS arm64 CPython 3.12, three runs; Linux
# x86-64 CPython 3.12 and 3.13, three runs). The check allows RUNTIME_RATIO_MARGIN times that, and never less than
# RUNTIME_RATIO_FLOOR, so a call much cheaper than the reference is not judged on timer resolution. A primitive that becomes
# five times more expensive fails on both platforms (measured for concordance, and pinned by
# test_the_runtime_check_fails_a_primitive_five_times_slower_than_its_ratio).
RUNTIME_RATIO_MARGIN = 2.5
RUNTIME_RATIO_FLOOR = 0.5
REFERENCE_ROUNDS = 8
RUNTIME_REPEATS = 2  # timed calls per check; the first also serves as the warm-up
# Extra headroom if ever needed, for example on an unusual machine. The default is 1.0 everywhere, CI included.
RUNTIME_SLACK = float(os.environ.get("REGAUDIT_RUNTIME_SLACK", "1.0"))


@pytest.fixture(scope="module")
def ctx():
    return build_d6_context()


def _reference_s(ctx) -> float:
    """Wall seconds for a fixed workload on ``ctx``: one ciphertext multiplication (with relinearisation and rescale) and one
    rotate-and-add sum, REFERENCE_ROUNDS times, on a fresh vector each round so no level is used up."""
    v = tenseal.ckks_vector(ctx.context, np.linspace(-1.0, 1.0, 4096).tolist())
    start = time.perf_counter()
    for _ in range(REFERENCE_ROUNDS):
        (v * v).sum()
    return time.perf_counter() - start


def _runtime_bound_ratio(case: Case) -> float:
    return max(RUNTIME_RATIO_FLOOR, case.runtime_ratio * RUNTIME_RATIO_MARGIN) * RUNTIME_SLACK


def _measure_ratio(ctx, call: Callable[[], Any]) -> tuple[float, float, float]:
    """(ratio, fastest call in seconds, fastest reference in seconds), interleaved as described above."""
    _reference_s(ctx)  # warm up the reference's own code paths
    references, calls = [_reference_s(ctx)], []
    for _ in range(RUNTIME_REPEATS):
        start = time.perf_counter()
        call()
        calls.append(time.perf_counter() - start)
        references.append(_reference_s(ctx))
    fastest_call, fastest_reference = min(calls), min(references)
    return fastest_call / fastest_reference, fastest_call, fastest_reference


def _check_runtime(case: Case, ctx, args: dict[str, Any]) -> None:
    ratio, seconds, reference = _measure_ratio(ctx, lambda: case.encrypted(ctx, **args))
    bound = _runtime_bound_ratio(case)
    assert ratio <= bound, (
        f"{case.name}: encrypted call took {seconds:.2f} s, {ratio:.2f} times the reference workload "
        f"({reference:.2f} s); the bound is {bound:.2f} times"
    )


@dataclass
class Case:
    name: str
    declared_depth: int
    runtime_ratio: (
        float  # wall time of the encrypted call / wall time of the reference workload, as measured
    )
    abs_tol: float
    plaintext: Callable[..., Any]
    encrypted: Callable[..., Any]
    extract: Callable[[Any], float]
    inputs: Callable[[], dict[str, Any]]
    breach_field: str
    breach_inputs: Callable[[], dict[str, Any]]


def _fairness_inputs() -> dict[str, Any]:
    n = 32
    y_true = (RNG.uniform(size=n) < 0.4).astype(float)
    y_pred = ((RNG.uniform(size=n) < 0.4) | y_true.astype(bool)).astype(float)
    g_a = (RNG.uniform(size=n) < 0.5).astype(float)
    return {
        "y_true": y_true,
        "y_pred": y_pred,
        "group_a": g_a,
        "group_b": 1.0 - g_a,
        "threshold": 0.1,
    }


def _fairness_breach_inputs() -> dict[str, Any]:
    """Construct y_pred with disparity exactly at the threshold."""
    y_true = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
    y_pred = np.array([1, 1, 1, 0, 1, 0, 0, 0], dtype=float)
    g_a = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
    return {
        "y_true": y_true,
        "y_pred": y_pred,
        "group_a": g_a,
        "group_b": 1.0 - g_a,
        "threshold": 0.25,
    }


def _provenance_inputs() -> dict[str, Any]:
    return {
        "attributions": np.abs(RNG.standard_normal(64)),
        "row_ids": np.arange(64),
        "n_buckets": 8,
        "k": 3,
    }


def _concordance_inputs() -> dict[str, Any]:
    # Smaller cohort than the other primitives because the encrypted
    # all-pairs Harrell C-index materialises an N(N-1)-length pair
    # vector under encryption; runtime grows quadratically in N.
    n = 16
    return {
        "risk": RNG.standard_normal(n),
        "time": np.abs(RNG.standard_normal(n)) * 100,
        "event": (RNG.uniform(size=n) < 0.7).astype(float),
    }


def _calibration_inputs() -> dict[str, Any]:
    K = 16
    return {"scores": RNG.uniform(size=K), "quantiles": np.full(K, 0.5)}


def _drift_inputs() -> dict[str, Any]:
    p = RNG.uniform(size=16)
    q = p + RNG.normal(scale=0.05, size=16)
    return {"p": p, "q": np.maximum(q, 0)}


def _drift_breach_inputs() -> dict[str, Any]:
    """Two well-separated histograms that should fire the drift bit."""
    p = np.zeros(16)
    p[2] = 1.0
    q = np.zeros(16)
    q[12] = 1.0
    return {"p": p, "q": q, "drift_threshold": 0.005}


def _disagreement_inputs() -> dict[str, Any]:
    coeffs = [(0.0, 1.00, 0.05, 0.0), (0.0, 0.95, 0.06, 0.0), (0.0, 1.05, 0.04, 0.0)]
    return {"model_polynomials": coeffs, "test_input": np.linspace(-0.4, 0.4, 32)}


def _disagreement_breach_inputs() -> dict[str, Any]:
    coeffs = [(0.0, 1.0, 0.0, 0.0), (0.0, 1.5, 0.0, 0.0), (0.0, 0.5, 0.0, 0.0)]
    return {
        "model_polynomials": coeffs,
        "test_input": np.linspace(-0.4, 0.4, 32),
        "threshold": 0.001,
    }


def _calibration_breach_inputs() -> dict[str, Any]:
    """Half the scores below their quantile (in set), half above."""
    K = 8
    scores = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9])
    quantiles = np.full(K, 0.5)
    return {"scores": scores, "quantiles": quantiles}


CASES = [
    Case(
        name="fairness",
        declared_depth=4,
        runtime_ratio=0.72,
        abs_tol=EQUIVALENCE_TOL,
        plaintext=rf.audit_fairness,
        encrypted=fhe_p.fairness_encrypted,
        extract=lambda r: r.demographic_parity_diff,
        inputs=_fairness_inputs,
        breach_field="threshold_breached",
        breach_inputs=_fairness_breach_inputs,
    ),
    Case(
        name="provenance",
        declared_depth=3,
        runtime_ratio=0.82,
        abs_tol=EQUIVALENCE_TOL,
        plaintext=rf.audit_provenance,
        encrypted=fhe_p.topk_provenance_encrypted,
        extract=lambda r: float(np.max(r.bucket_aggregates)),
        inputs=_provenance_inputs,
        breach_field=None,
        breach_inputs=_provenance_inputs,
    ),
    Case(
        name="concordance",
        declared_depth=5,
        runtime_ratio=8.7,
        # The encrypted Harrell C-index reconstructs four concordance
        # bins from three sign-poly aggregates per shift. With
        # ``sign_poly_d3``'s ~30% worst-case error near zero,
        # accumulated count drift can shift the C-index ratio by up
        # to ~0.25 absolute. The plaintext circuit uses the same
        # sign-poly approximation so the gap to the encrypted
        # circuit is small (mostly CKKS additive noise); the gap to
        # the integer-counting oracle can be larger.
        abs_tol=0.25,
        plaintext=rf.audit_concordance,
        encrypted=fhe_p.c_index_encrypted,
        extract=lambda r: r.c_index,
        inputs=_concordance_inputs,
        breach_field=None,
        breach_inputs=_concordance_inputs,
    ),
    Case(
        name="calibration",
        declared_depth=4,
        runtime_ratio=0.05,
        # set_size can drift by ±2 from sign-poly-d3 noise on scores
        # near the quantile threshold; absolute tolerance scales with
        # K (16 here).
        abs_tol=2.0,
        plaintext=rf.audit_calibration,
        encrypted=fhe_p.conformal_encrypted,
        extract=lambda r: float(r.set_size),
        inputs=_calibration_inputs,
        breach_field=None,
        breach_inputs=_calibration_breach_inputs,
    ),
    Case(
        name="drift",
        declared_depth=2,
        runtime_ratio=0.76,
        abs_tol=EQUIVALENCE_TOL,
        plaintext=rf.audit_drift,
        encrypted=fhe_p.w1_encrypted,
        extract=lambda r: r.distance,
        inputs=_drift_inputs,
        breach_field="drift_bit",
        breach_inputs=_drift_breach_inputs,
    ),
    Case(
        name="disagreement",
        declared_depth=5,
        runtime_ratio=0.19,
        abs_tol=EQUIVALENCE_TOL,
        plaintext=rf.audit_disagreement,
        encrypted=fhe_p.disagreement_encrypted,
        extract=lambda r: r.pairwise_variance,
        inputs=_disagreement_inputs,
        breach_field="breach",
        breach_inputs=_disagreement_breach_inputs,
    ),
]


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_equivalence_value_within_tolerance(case: Case, ctx) -> None:
    """abs(fhe_result - plaintext_result) <= tolerance."""
    args = case.inputs()
    plain = case.plaintext(**args)
    enc = case.encrypted(ctx, **args)
    diff = abs(case.extract(plain) - case.extract(enc))
    assert diff <= case.abs_tol, (
        f"{case.name}: |plain − enc| = {diff} exceeds tolerance {case.abs_tol}"
    )


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_depth_within_declared_budget(case: Case, ctx) -> None:
    """depth_consumed <= declared_depth."""
    fhe_p.reset_last_depth()
    case.encrypted(ctx, **case.inputs())
    consumed = fhe_p.last_depth(case.name)
    declared = fhe_p.declared_depth(case.name)
    assert consumed <= declared, (
        f"{case.name}: depth_consumed = {consumed} > declared_depth = {declared}"
    )
    assert declared <= 6, f"{case.name}: declared_depth = {declared} exceeds the d=6 budget"


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_no_bootstrapping(case: Case, ctx) -> None:
    """No bootstrapping was used.

    The TenSEAL backend never auto-bootstraps; the platform never calls
    bootstrap on a CKKSVector. The strongest in-process check is that
    depth_consumed stays at or below the d=6 budget — exceeding it
    would force a bootstrap or raise a SEAL "scale out of bounds" error
    at runtime.
    """
    fhe_p.reset_last_depth()
    case.encrypted(ctx, **case.inputs())
    consumed = fhe_p.last_depth(case.name)
    assert consumed <= 6, (
        f"{case.name}: depth_consumed = {consumed} would require "
        f"bootstrapping the d=6 modulus chain"
    )
    src = fhe_p.__file__
    with open(src) as fh:
        body = fh.read()
    callsites = [line for line in body.splitlines() if "bootstrap(" in line or ".bootstrap" in line]
    assert not callsites, (
        f"Encrypted primitives must not call any bootstrap method; found in {src}: {callsites}"
    )


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_runtime_within_documented_bound(case: Case, ctx) -> None:
    """Runtime within the bound, relative to the reference workload on this machine."""
    _check_runtime(case, ctx, case.inputs())


def _sleeping_case(case_ratio: float, times: float, reference: float) -> Case:
    """A stand-in primitive whose call takes ``times`` its documented ratio of the reference workload."""
    template = CASES[0]
    return Case(
        **{
            **template.__dict__,
            "name": f"stand-in at {times}x",
            "runtime_ratio": case_ratio,
            "encrypted": lambda ctx, **_: time.sleep(times * case_ratio * reference),
        }
    )


def test_the_runtime_check_fails_a_primitive_five_times_slower_than_its_ratio(ctx) -> None:
    """Negative test: the check must still catch a regression. A stand-in whose call takes five times its documented ratio
    of the reference fails; the same stand-in at its documented ratio passes."""
    reference = min(_reference_s(ctx) for _ in range(2))
    _check_runtime(_sleeping_case(0.4, 1.0, reference), ctx, {})
    with pytest.raises(AssertionError, match="times the reference workload"):
        _check_runtime(_sleeping_case(0.4, 5.0, reference), ctx, {})


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_threshold_decision_is_stable_under_encryption(case: Case, ctx) -> None:
    """Plaintext and encrypted circuits agree on the breach decision.

    This is the regulator-facing question: can CKKS noise change a
    regulatory threshold decision? For each primitive that exposes a
    boolean breach indicator we run inputs designed to land on or near
    the threshold and confirm both circuits return the same boolean.
    """
    if case.breach_field is None:
        pytest.skip(f"{case.name} has no boolean breach indicator")
    args = case.breach_inputs()
    plain = case.plaintext(**args)
    enc = case.encrypted(ctx, **args)
    pv = getattr(plain, case.breach_field)
    ev = getattr(enc, case.breach_field)
    assert pv == ev, (
        f"{case.name}: encryption flipped a regulatory threshold "
        f"decision (plain={pv!r} vs enc={ev!r}) — this is a "
        f"correctness regression, not noise."
    )


def test_full_matrix_summary(ctx) -> None:
    """One report-style assertion that every primitive cleared the
    matrix on a single random seed. This is the test a reviewer reads
    first to verify coverage. Runtime is checked once per primitive, in
    test_runtime_within_documented_bound, with repeated interleaved timing;
    timing it again here, from a single call, would only add noise."""
    rows: list[dict[str, Any]] = []
    for case in CASES:
        fhe_p.reset_last_depth()
        args = case.inputs()
        plain = case.plaintext(**args)
        enc = case.encrypted(ctx, **args)
        rows.append(
            {
                "primitive": case.name,
                "abs_diff": abs(case.extract(plain) - case.extract(enc)),
                "tolerance": case.abs_tol,
                "depth_consumed": fhe_p.last_depth(case.name),
                "declared_depth": fhe_p.declared_depth(case.name),
            }
        )
    failures: list[str] = []
    for r in rows:
        if r["abs_diff"] > r["tolerance"]:
            failures.append(
                f"{r['primitive']}: |diff|={r['abs_diff']:.4g} exceeds tol={r['tolerance']}"
            )
        if r["depth_consumed"] > r["declared_depth"]:
            failures.append(
                f"{r['primitive']}: depth {r['depth_consumed']} > declared {r['declared_depth']}"
            )
    assert not failures, "matrix failures:\n  " + "\n  ".join(failures)
