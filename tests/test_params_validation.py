"""CKKSParams validation rules.

Each rule documented in docs/THREAT_MODEL.md must be enforced at
construction time. These tests assert the rejection paths.
"""

from __future__ import annotations

import pytest

from regaudit_fhe.fhe import CKKSParams, ParameterValidationError


def test_default_params_accept():
    p = CKKSParams()
    assert p.ring_dim == 1 << 15
    assert p.multiplicative_depth == 6
    assert p.security_level == "HEStd_128_classic"
    assert p.scaling_mod_size == 40
    assert p.first_mod_size == 60
    # Defaults expand into the standard 8-prime chain.
    assert len(p.coeff_mod_bit_sizes) == 8
    assert p.coeff_mod_bit_sizes[0] == 60
    assert p.coeff_mod_bit_sizes[-1] == 60
    assert p.hash()


def test_ring_dim_must_be_power_of_two():
    with pytest.raises(ParameterValidationError, match="power of two"):
        CKKSParams(ring_dim=12000)


def test_ring_dim_too_small_for_depth_six():
    with pytest.raises(ParameterValidationError, match="ring_dim"):
        CKKSParams(ring_dim=8192)


def test_security_level_below_128_rejected():
    with pytest.raises(ParameterValidationError, match="HEStd_64_classic|HEStd_80"):
        CKKSParams(security_level="HEStd_64_classic")


def test_unknown_security_level_rejected():
    with pytest.raises(ParameterValidationError, match="unknown security level"):
        CKKSParams(security_level="totally-fake")


def test_depth_outside_one_to_six_rejected():
    with pytest.raises(ParameterValidationError, match="multiplicative_depth"):
        CKKSParams(multiplicative_depth=0)
    with pytest.raises(ParameterValidationError, match="multiplicative_depth"):
        CKKSParams(multiplicative_depth=7)


def test_chain_too_short_rejected():
    with pytest.raises(ParameterValidationError, match="evaluate depth"):
        CKKSParams(coeff_mod_bit_sizes=(60, 40, 60))


def test_log_q_above_seal_bound_rejected():
    with pytest.raises(ParameterValidationError, match="exceeds"):
        CKKSParams(ring_dim=1 << 14,
                   coeff_mod_bit_sizes=(60, 60, 60, 60, 60, 60, 60, 60, 60))


def test_first_mod_size_smaller_than_scaling_rejected():
    with pytest.raises(ParameterValidationError, match="scale stable"):
        CKKSParams(first_mod_size=40, scaling_mod_size=50)


def test_interior_prime_below_scaling_size_rejected():
    with pytest.raises(ParameterValidationError, match="interior modulus"):
        CKKSParams(coeff_mod_bit_sizes=(60, 40, 30, 40, 40, 40, 40, 60))


def test_rotation_step_excess_requires_acknowledgement():
    base = CKKSParams()
    excess_step = 7
    bloated = tuple(sorted(set(base.rotation_steps) | {excess_step}))
    p = CKKSParams.__new__(CKKSParams)
    object.__setattr__(p, "ring_dim", base.ring_dim)
    object.__setattr__(p, "multiplicative_depth", base.multiplicative_depth)
    object.__setattr__(p, "scaling_mod_size", base.scaling_mod_size)
    object.__setattr__(p, "first_mod_size", base.first_mod_size)
    object.__setattr__(p, "security_level", base.security_level)
    object.__setattr__(p, "coeff_mod_bit_sizes", base.coeff_mod_bit_sizes)
    object.__setattr__(p, "rotation_steps", bloated)
    object.__setattr__(p, "extra_rotation_steps", ())
    object.__setattr__(p, "precision_loss_bound", base.precision_loss_bound)
    with pytest.raises(ParameterValidationError, match="not derivable"):
        p._validate()


def test_extra_rotation_steps_are_accepted():
    p = CKKSParams(extra_rotation_steps=(7, -7))
    assert 7 in p.rotation_steps and -7 in p.rotation_steps


def test_precision_loss_bound_too_tight_rejected():
    with pytest.raises(ParameterValidationError, match="precision loss"):
        CKKSParams(scaling_mod_size=20, precision_loss_bound=1e-9)


def test_precision_loss_bound_outside_unit_interval_rejected():
    with pytest.raises(ParameterValidationError, match="precision_loss_bound"):
        CKKSParams(precision_loss_bound=2.0)


def test_to_envelope_parameter_set_round_trip():
    p = CKKSParams()
    eps = p.to_envelope_parameter_set()
    assert eps.poly_modulus_degree == p.ring_dim
    assert eps.security_bits == 128
    assert eps.multiplicative_depth == p.multiplicative_depth
    assert eps.coeff_mod_bit_sizes == tuple(p.coeff_mod_bit_sizes)


def test_hash_is_deterministic_and_changes_with_params():
    a = CKKSParams()
    b = CKKSParams()
    assert a.hash() == b.hash()
    c = CKKSParams(ring_dim=1 << 16)
    assert c.hash() != a.hash()


def test_build_context_from_validated_params():
    pytest_importorskip = pytest.importorskip
    pytest_importorskip("tenseal")
    from regaudit_fhe.fhe import build_d6_context_from_params

    p = CKKSParams(ring_dim=1 << 14,
                   multiplicative_depth=6,
                   scaling_mod_size=40,
                   first_mod_size=60)
    ctx = build_d6_context_from_params(p)
    assert ctx.poly_modulus_degree == p.ring_dim
