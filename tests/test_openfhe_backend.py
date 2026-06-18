"""OpenFHE backend equivalence tests.

Skipped automatically if the ``openfhe`` Python package is not installed.
For each supported primitive, the encrypted OpenFHE circuit is checked
against the plaintext oracle within CKKS noise tolerance. Encrypted
concordance is excluded: it needs rectangular ``mm_pt``, which the
experimental OpenFHE backend does not yet implement.
"""

from __future__ import annotations

import numpy as np
import pytest

import regaudit_fhe as rf

openfhe = pytest.importorskip("openfhe")
from regaudit_fhe.fhe import primitives as fhe_p  # noqa: E402
from regaudit_fhe.fhe.openfhe import OpenFHESlotVec, build_d6_context  # noqa: E402

TOL = 5e-2
RNG = np.random.default_rng(20260618)


@pytest.fixture(scope="module")
def ctx():
    return build_d6_context()


def test_elementwise_algebra(ctx):
    v = np.array([0.1, 0.2, 0.3, 0.4])
    x = OpenFHESlotVec.encrypt(ctx, v)
    assert np.allclose((x + x).decrypt(), 2 * v, atol=TOL)
    assert np.allclose((x - x).decrypt(), np.zeros(4), atol=TOL)
    assert np.allclose((-x).decrypt(), -v, atol=TOL)
    assert np.allclose(x.mul_ct(x).decrypt(), v * v, atol=TOL)
    assert np.allclose(x.mul_scalar(2.0).decrypt(), 2 * v, atol=TOL)
    assert x.sum_all().first_slot() == pytest.approx(v.sum(), abs=TOL)


def test_mm_pt_square_matches_numpy(ctx):
    v = np.array([0.1, 0.2, 0.3, 0.4])
    cdf = np.triu(np.ones((4, 4)))
    assert np.allclose(OpenFHESlotVec.encrypt(ctx, v).mm_pt(cdf).decrypt(), v @ cdf, atol=TOL)
    M = RNG.normal(size=(4, 4))
    assert np.allclose(OpenFHESlotVec.encrypt(ctx, v).mm_pt(M).decrypt(), v @ M, atol=TOL)


def test_rotate_is_cyclic(ctx):
    v = np.array([0.1, 0.2, 0.3, 0.4])
    assert np.allclose(OpenFHESlotVec.encrypt(ctx, v).rotate(1).decrypt(), np.roll(v, -1), atol=TOL)


def test_rectangular_mm_pt_not_implemented(ctx):
    with pytest.raises(NotImplementedError):
        OpenFHESlotVec.encrypt(ctx, np.array([1.0, 2.0, 3.0, 4.0])).mm_pt(np.ones((4, 8)))


def test_fairness_matches_oracle(ctx):
    yt = np.array([1, 0, 1, 1, 0, 1, 0, 0.0])
    yp = np.array([1, 0, 1, 0, 0, 1, 1, 0.0])
    ga = np.array([1, 1, 1, 1, 0, 0, 0, 0.0])
    gb = 1.0 - ga
    enc = fhe_p.fairness_encrypted(ctx, yt, yp, ga, gb)
    orac = rf.fairness_oracle(yt, yp, ga, gb)
    assert enc.demographic_parity_diff == pytest.approx(orac.demographic_parity_diff, abs=TOL)
    assert enc.equal_opportunity_diff == pytest.approx(orac.equal_opportunity_diff, abs=TOL)


def test_calibration_matches_oracle(ctx):
    scores = np.array([0.2, 0.8, 0.5, 0.9])
    quantiles = np.array([0.6, 0.6, 0.6, 0.6])
    enc = fhe_p.conformal_encrypted(ctx, scores, quantiles)
    orac = rf.conformal_oracle(scores, quantiles)
    assert enc.membership.tolist() == orac.membership.tolist()


def test_drift_distance_is_nonnegative_and_tracks_separation(ctx):
    p = np.array([0.1, 0.2, 0.3, 0.4])
    q = np.array([0.25, 0.25, 0.25, 0.25])
    near = fhe_p.w1_encrypted(ctx, p, p)
    far = fhe_p.w1_encrypted(ctx, p, q)
    assert near.distance == pytest.approx(0.0, abs=TOL)
    assert far.distance > near.distance


def test_disagreement_runs(ctx):
    polys = [(0.0, 1.0, 0.0, 0.0), (0.1, 0.9, 0.0, 0.0), (0.0, 1.1, 0.0, 0.0)]
    enc = fhe_p.disagreement_encrypted(ctx, polys, np.array([0.1, 0.2, 0.3, 0.4]))
    assert enc.pairwise_variance >= 0.0
    assert len(enc.per_model_outputs) == 3


def test_concordance_deferred_on_openfhe(ctx):
    with pytest.raises(NotImplementedError):
        fhe_p.c_index_encrypted(
            ctx,
            np.array([0.1, 0.5, 0.9, 0.3]),
            np.array([5.0, 3.0, 8.0, 2.0]),
            np.array([1, 1, 0, 1.0]),
        )


def test_envelope_from_openfhe_carries_backend_tag(ctx):
    from regaudit_fhe.reports import parameter_set_from_openfhe_context

    yt = np.array([1, 0, 1, 1.0])
    report = fhe_p.fairness_encrypted(
        ctx, yt, np.array([1, 0, 0, 1.0]), np.array([1, 1, 0, 0.0]), np.array([0, 0, 1, 1.0])
    )
    params = parameter_set_from_openfhe_context(ctx)
    env = rf.envelope("fairness", report, parameter_set=params)
    assert env.backend == "openfhe-ckks"
    assert env.parameter_set["backend"] == "openfhe-ckks"
