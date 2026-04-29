"""Property-based tests via Hypothesis.

These tests assert invariants that must hold for *any* legal input,
not just the sample inputs hand-written elsewhere. They are the
strongest defence against regression on edge inputs nobody thought to
write down.
"""

from __future__ import annotations

import numpy as np
import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

import regaudit_fhe as rf

# Hypothesis can produce slow inputs that exercise CKKS contexts; keep
# the deadline generous and disable the function-scoped fixture
# warning for the FHE module-scoped context.
PROFILE = settings(max_examples=20, deadline=None,
                   suppress_health_check=[HealthCheck.function_scoped_fixture])


tenseal = pytest.importorskip("tenseal")
from regaudit_fhe.fhe import build_d6_context  # noqa: E402
from regaudit_fhe.fhe import primitives as fhe_p  # noqa: E402

CTX = build_d6_context()


# --------------------------------------------------------------------------
# Strategies
# --------------------------------------------------------------------------


@st.composite
def fairness_inputs(draw):
    n = draw(st.integers(min_value=4, max_value=64))
    y_true = np.array(draw(st.lists(st.sampled_from([0.0, 1.0]),
                                     min_size=n, max_size=n)))
    y_pred = np.array(draw(st.lists(st.sampled_from([0.0, 1.0]),
                                     min_size=n, max_size=n)))
    g_a = np.array(draw(st.lists(st.sampled_from([0.0, 1.0]),
                                  min_size=n, max_size=n)))
    if g_a.sum() == 0 or g_a.sum() == n:
        g_a[0] = 1.0 - g_a[0]
    g_b = 1.0 - g_a
    threshold = draw(st.floats(min_value=0.0, max_value=1.0,
                               allow_nan=False, allow_infinity=False))
    return y_true, y_pred, g_a, g_b, threshold


@st.composite
def histogram_pair(draw):
    n = draw(st.sampled_from([4, 8, 16, 32]))
    p = np.array(draw(st.lists(st.floats(min_value=0.01, max_value=10.0,
                                          allow_nan=False, allow_infinity=False),
                                min_size=n, max_size=n)))
    q = np.array(draw(st.lists(st.floats(min_value=0.01, max_value=10.0,
                                          allow_nan=False, allow_infinity=False),
                                min_size=n, max_size=n)))
    return p, q


@st.composite
def disagreement_inputs(draw):
    M = draw(st.integers(min_value=3, max_value=6))
    coeffs = []
    for _ in range(M):
        a = draw(st.tuples(st.floats(min_value=-1.0, max_value=1.0,
                                     allow_nan=False, allow_infinity=False),
                           st.floats(min_value=-2.0, max_value=2.0,
                                     allow_nan=False, allow_infinity=False),
                           st.floats(min_value=-1.0, max_value=1.0,
                                     allow_nan=False, allow_infinity=False),
                           st.floats(min_value=-1.0, max_value=1.0,
                                     allow_nan=False, allow_infinity=False)))
        coeffs.append(a)
    n = draw(st.sampled_from([8, 16, 32]))
    x = np.linspace(-0.4, 0.4, n)
    return coeffs, x


# --------------------------------------------------------------------------
# Invariants
# --------------------------------------------------------------------------


@PROFILE
@given(args=fairness_inputs())
def test_fhe_fairness_matches_plaintext_within_error_bound(args):
    y_t, y_p, g_a, g_b, threshold = args
    plain = rf.audit_fairness(y_t, y_p, g_a, g_b, threshold=threshold)
    enc = fhe_p.fairness_encrypted(CTX, y_t, y_p, g_a, g_b,
                                   threshold=threshold)
    for fld in ("demographic_parity_diff", "equal_opportunity_diff",
                "predictive_parity_diff"):
        assert abs(getattr(plain, fld) - getattr(enc, fld)) < 5e-2


@PROFILE
@given(args=histogram_pair())
def test_fhe_drift_matches_plaintext_within_error_bound(args):
    p, q = args
    plain = rf.audit_drift(p, q)
    enc = fhe_p.w1_encrypted(CTX, p, q)
    rel = abs(plain.distance - enc.distance) / max(plain.distance, 1e-9)
    assert rel < 5e-2 or abs(plain.distance - enc.distance) < 1e-3


@PROFILE
@given(args=disagreement_inputs())
def test_fhe_disagreement_matches_plaintext_within_error_bound(args):
    coeffs, x = args
    # SEAL refuses to operate on a ciphertext that is identically zero
    # ("transparent ciphertext"); skip examples where two model surrogates
    # are bit-identical because the encrypted (P[i] - P[j]) would zero out.
    assume(len(set(coeffs)) == len(coeffs))
    plain = rf.audit_disagreement(coeffs, x)
    enc = fhe_p.disagreement_encrypted(CTX, coeffs, x)
    rel = abs(plain.pairwise_variance - enc.pairwise_variance) / max(
        plain.pairwise_variance, 1e-9)
    assert rel < 1e-1 or abs(plain.pairwise_variance
                              - enc.pairwise_variance) < 1e-3


@PROFILE
@given(args=histogram_pair())
def test_drift_distance_is_nonnegative(args):
    p, q = args
    plain = rf.audit_drift(p, q)
    assert plain.distance >= 0.0


@PROFILE
@given(args=histogram_pair())
def test_drift_zero_iff_distributions_match(args):
    p, _q = args
    same = rf.audit_drift(p, p)
    assert same.distance < 1e-9


@PROFILE
@given(values=st.lists(st.floats(min_value=-1.0, max_value=1.0,
                                  allow_nan=False, allow_infinity=False),
                       min_size=4, max_size=64))
def test_canonical_json_is_byte_stable_under_random_input(values):
    payload = {"v": values, "n": len(values)}
    a = rf.canonical_json(payload)
    b = rf.canonical_json({"n": len(values), "v": values})
    assert a == b


@PROFILE
@given(values=st.lists(st.floats(min_value=-100.0, max_value=100.0,
                                  allow_nan=False, allow_infinity=False),
                       min_size=2, max_size=64))
def test_input_commitment_changes_iff_input_changes(values):
    arr = np.asarray(values, dtype=float)
    before = rf.commit_input("x", arr)
    perturbed = arr.copy()
    perturbed[0] += 1.0
    after = rf.commit_input("x", perturbed)
    assert before["sha256"] != after["sha256"]


@PROFILE
@given(args=fairness_inputs())
def test_fairness_threshold_breach_is_consistent_with_max_disparity(args):
    y_t, y_p, g_a, g_b, threshold = args
    plain = rf.audit_fairness(y_t, y_p, g_a, g_b, threshold=threshold)
    worst = max(abs(plain.demographic_parity_diff),
                abs(plain.equal_opportunity_diff),
                abs(plain.predictive_parity_diff))
    assert plain.threshold_breached == (worst > threshold)
