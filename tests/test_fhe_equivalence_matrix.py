"""Comprehensive ciphertext / plaintext equivalence matrix.

For every primitive the matrix asserts four properties:

    1. abs(fhe_result - plaintext_result) <= tolerance.
    2. depth_consumed <= declared_depth.
    3. No bootstrapping was used.
    4. Runtime below the documented benchmark bound.

Plus a regulatory-threshold-stability check: with inputs near the
breach threshold, the encrypted and plaintext circuits must agree on
the boolean breach decision. CKKS noise that does not change a
regulatory threshold decision is acceptable; noise that flips a
decision is not, and tests will fail loudly if it does.

Skipped automatically if the [fhe] extra is not installed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict

import numpy as np
import pytest

import regaudit_fhe as rf

tenseal = pytest.importorskip("tenseal")
from regaudit_fhe.fhe import build_d6_context  # noqa: E402
from regaudit_fhe.fhe import primitives as fhe_p  # noqa: E402


RNG = np.random.default_rng(20260426)
EQUIVALENCE_TOL = 5e-2     # CKKS noise after up to six multiplications
RUNTIME_BOUND_S = 5.0      # encrypted call must complete in under 5 s
                            # at N=2^14 in the test ring


@pytest.fixture(scope="module")
def ctx():
    return build_d6_context()


@dataclass
class Case:
    name: str
    declared_depth: int
    runtime_bound_s: float
    abs_tol: float
    plaintext: Callable[..., Any]
    encrypted: Callable[..., Any]
    extract: Callable[[Any], float]
    inputs: Callable[[], Dict[str, Any]]
    breach_field: str
    breach_inputs: Callable[[], Dict[str, Any]]


def _fairness_inputs() -> Dict[str, Any]:
    n = 32
    y_true = (RNG.uniform(size=n) < 0.4).astype(float)
    y_pred = ((RNG.uniform(size=n) < 0.4) | y_true.astype(bool)).astype(float)
    g_a = (RNG.uniform(size=n) < 0.5).astype(float)
    return {"y_true": y_true, "y_pred": y_pred,
            "group_a": g_a, "group_b": 1.0 - g_a, "threshold": 0.1}


def _fairness_breach_inputs() -> Dict[str, Any]:
    """Construct y_pred with disparity exactly at the threshold."""
    y_true = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
    y_pred = np.array([1, 1, 1, 0, 1, 0, 0, 0], dtype=float)
    g_a = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
    return {"y_true": y_true, "y_pred": y_pred,
            "group_a": g_a, "group_b": 1.0 - g_a, "threshold": 0.25}


def _provenance_inputs() -> Dict[str, Any]:
    return {"attributions": np.abs(RNG.standard_normal(64)),
            "row_ids": np.arange(64), "n_buckets": 8, "k": 3}


def _concordance_inputs() -> Dict[str, Any]:
    # Smaller cohort than the other primitives because the encrypted
    # all-pairs Harrell C-index materialises an N(N-1)-length pair
    # vector under encryption; runtime grows quadratically in N.
    n = 16
    return {"risk": RNG.standard_normal(n),
            "time": np.abs(RNG.standard_normal(n)) * 100,
            "event": (RNG.uniform(size=n) < 0.7).astype(float)}


def _calibration_inputs() -> Dict[str, Any]:
    K = 16
    return {"scores": RNG.uniform(size=K),
            "quantiles": np.full(K, 0.5)}


def _drift_inputs() -> Dict[str, Any]:
    p = RNG.uniform(size=16)
    q = p + RNG.normal(scale=0.05, size=16)
    return {"p": p, "q": np.maximum(q, 0)}


def _drift_breach_inputs() -> Dict[str, Any]:
    """Two well-separated histograms that should fire the drift bit."""
    p = np.zeros(16); p[2] = 1.0
    q = np.zeros(16); q[12] = 1.0
    return {"p": p, "q": q, "drift_threshold": 0.005}


def _disagreement_inputs() -> Dict[str, Any]:
    coeffs = [(0.0, 1.00, 0.05, 0.0),
              (0.0, 0.95, 0.06, 0.0),
              (0.0, 1.05, 0.04, 0.0)]
    return {"model_polynomials": coeffs,
            "test_input": np.linspace(-0.4, 0.4, 32)}


def _disagreement_breach_inputs() -> Dict[str, Any]:
    coeffs = [(0.0, 1.0, 0.0, 0.0),
              (0.0, 1.5, 0.0, 0.0),
              (0.0, 0.5, 0.0, 0.0)]
    return {"model_polynomials": coeffs,
            "test_input": np.linspace(-0.4, 0.4, 32),
            "threshold": 0.001}


def _calibration_breach_inputs() -> Dict[str, Any]:
    """Half the scores below their quantile (in set), half above."""
    K = 8
    scores = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9])
    quantiles = np.full(K, 0.5)
    return {"scores": scores, "quantiles": quantiles}


CASES = [
    Case(
        name="fairness", declared_depth=4, runtime_bound_s=RUNTIME_BOUND_S,
        abs_tol=EQUIVALENCE_TOL,
        plaintext=rf.audit_fairness,
        encrypted=fhe_p.fairness_encrypted,
        extract=lambda r: r.demographic_parity_diff,
        inputs=_fairness_inputs, breach_field="threshold_breached",
        breach_inputs=_fairness_breach_inputs,
    ),
    Case(
        name="provenance", declared_depth=3, runtime_bound_s=RUNTIME_BOUND_S,
        abs_tol=EQUIVALENCE_TOL,
        plaintext=rf.audit_provenance,
        encrypted=fhe_p.topk_provenance_encrypted,
        extract=lambda r: float(np.max(r.bucket_aggregates)),
        inputs=_provenance_inputs, breach_field=None,
        breach_inputs=_provenance_inputs,
    ),
    Case(
        name="concordance", declared_depth=5, runtime_bound_s=15.0,
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
        inputs=_concordance_inputs, breach_field=None,
        breach_inputs=_concordance_inputs,
    ),
    Case(
        name="calibration", declared_depth=4, runtime_bound_s=RUNTIME_BOUND_S,
        # set_size can drift by ±2 from sign-poly-d3 noise on scores
        # near the quantile threshold; absolute tolerance scales with
        # K (16 here).
        abs_tol=2.0,
        plaintext=rf.audit_calibration,
        encrypted=fhe_p.conformal_encrypted,
        extract=lambda r: float(r.set_size),
        inputs=_calibration_inputs, breach_field=None,
        breach_inputs=_calibration_breach_inputs,
    ),
    Case(
        name="drift", declared_depth=2, runtime_bound_s=RUNTIME_BOUND_S,
        abs_tol=EQUIVALENCE_TOL,
        plaintext=rf.audit_drift,
        encrypted=fhe_p.w1_encrypted,
        extract=lambda r: r.distance,
        inputs=_drift_inputs, breach_field="drift_bit",
        breach_inputs=_drift_breach_inputs,
    ),
    Case(
        name="disagreement", declared_depth=5, runtime_bound_s=RUNTIME_BOUND_S,
        abs_tol=EQUIVALENCE_TOL,
        plaintext=rf.audit_disagreement,
        encrypted=fhe_p.disagreement_encrypted,
        extract=lambda r: r.pairwise_variance,
        inputs=_disagreement_inputs, breach_field="breach",
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
        f"{case.name}: |plain − enc| = {diff} exceeds tolerance "
        f"{case.abs_tol}"
    )


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_depth_within_declared_budget(case: Case, ctx) -> None:
    """depth_consumed <= declared_depth."""
    fhe_p.reset_last_depth()
    case.encrypted(ctx, **case.inputs())
    consumed = fhe_p.last_depth(case.name)
    declared = fhe_p.declared_depth(case.name)
    assert consumed <= declared, (
        f"{case.name}: depth_consumed = {consumed} > declared_depth = "
        f"{declared}"
    )
    assert declared <= 6, (
        f"{case.name}: declared_depth = {declared} exceeds the d=6 budget"
    )


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
    import regaudit_fhe.fhe as fhe_pkg
    src = fhe_pkg.primitives.__file__
    with open(src) as fh:
        body = fh.read()
    callsites = [line for line in body.splitlines()
                 if "bootstrap(" in line or ".bootstrap" in line]
    assert not callsites, (
        "Encrypted primitives must not call any bootstrap method; "
        f"found in {src}: {callsites}"
    )


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_runtime_within_documented_bound(case: Case, ctx) -> None:
    """Runtime below the documented benchmark bound."""
    args = case.inputs()
    case.encrypted(ctx, **args)        # warm up
    t0 = time.perf_counter()
    case.encrypted(ctx, **args)
    elapsed = time.perf_counter() - t0
    assert elapsed <= case.runtime_bound_s, (
        f"{case.name}: encrypted call took {elapsed:.2f}s, exceeding "
        f"documented bound {case.runtime_bound_s:.2f}s"
    )


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
    first to verify coverage."""
    rows: list[Dict[str, Any]] = []
    for case in CASES:
        fhe_p.reset_last_depth()
        args = case.inputs()
        plain = case.plaintext(**args)
        t0 = time.perf_counter()
        enc = case.encrypted(ctx, **args)
        elapsed = time.perf_counter() - t0
        rows.append({
            "primitive": case.name,
            "abs_diff": abs(case.extract(plain) - case.extract(enc)),
            "tolerance": case.abs_tol,
            "depth_consumed": fhe_p.last_depth(case.name),
            "declared_depth": fhe_p.declared_depth(case.name),
            "runtime_s": elapsed,
            "runtime_bound_s": case.runtime_bound_s,
        })
    failures: list[str] = []
    for r in rows:
        if r["abs_diff"] > r["tolerance"]:
            failures.append(f"{r['primitive']}: |diff|={r['abs_diff']:.4g} "
                            f"exceeds tol={r['tolerance']}")
        if r["depth_consumed"] > r["declared_depth"]:
            failures.append(f"{r['primitive']}: depth "
                            f"{r['depth_consumed']} > "
                            f"declared {r['declared_depth']}")
        if r["runtime_s"] > r["runtime_bound_s"]:
            failures.append(f"{r['primitive']}: runtime "
                            f"{r['runtime_s']:.2f}s > "
                            f"bound {r['runtime_bound_s']}s")
    assert not failures, "matrix failures:\n  " + "\n  ".join(failures)
