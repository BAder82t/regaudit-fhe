"""B-12: a signed parameter set must not claim more than the backend can substantiate.

The producer paths are `CKKSParams`, `build_d6_context`, `parameter_set_from_ckks_context` and
`parameter_set_from_openfhe_context`. Each case is shown three ways where it matters: the valid input is
accepted, the unsupported claim is refused, and a guard-off control shows that removing the guard is what
lets the claim through. Tests that need TenSEAL skip without it. The fake-backend tests do not.
"""

from __future__ import annotations

import itertools
from types import SimpleNamespace

import pytest

from regaudit_fhe import _backend_facts as bf
from regaudit_fhe import reports
from regaudit_fhe.fhe import params as params_mod
from regaudit_fhe.fhe.params import CKKSParams, ParameterValidationError
from regaudit_fhe.reports import ParameterSet

CHAIN_8 = (60, 40, 40, 40, 40, 40, 40, 60)


@pytest.fixture(autouse=True)
def _fresh_backend_facts():
    bf.reset_cache()
    yield
    bf.reset_cache()


# ---------------------------------------------------------------------------
# A fake TenSEAL, so the fail-closed logic is tested with and without the real one
# ---------------------------------------------------------------------------

TABLE = {  # max log Q per (level, ring dim), as in SEAL's hestdparms.h
    128: {16384: 438, 32768: 881},
    192: {16384: 305, 32768: 611},
    256: {16384: 237, 32768: 476},
}


def fake_tenseal(*, enforce: int | None, version: str = "0.0.0-fake", seal=(4, 3)):
    """A stand-in with TenSEAL's surface. `enforce` is the level its context() refuses above, or None for none."""

    class Parms:
        def __init__(self, n, chain):
            self._n, self._chain = n, chain

        def scheme(self):
            return "CKKS"

        def poly_modulus_degree(self):
            return self._n

        def coeff_modulus(self):
            return [SimpleNamespace(bit_count=lambda b=b: b) for b in self._chain]

    class Ctx:
        def __init__(self, n, chain):
            self._p = Parms(n, chain)
            self.global_scale = float(2**40)

        def seal_context(self):
            key = SimpleNamespace(parms=lambda: self._p)
            return SimpleNamespace(data=SimpleNamespace(key_context_data=lambda: key))

    def context(scheme, *, poly_modulus_degree, coeff_mod_bit_sizes, **_):
        chain = tuple(coeff_mod_bit_sizes)
        if enforce is not None:
            limit = TABLE[enforce].get(poly_modulus_degree, 0)
            if sum(chain) > limit:
                raise RuntimeError("encryption parameters are not set correctly")
        return Ctx(poly_modulus_degree, chain)

    levels = SimpleNamespace(TC128=128, TC192=192, TC256=256)
    return SimpleNamespace(
        __version__=version,
        SCHEME_TYPE=SimpleNamespace(CKKS="CKKS"),
        context=context,
        sealapi=SimpleNamespace(
            SEC_LEVEL_TYPE=levels,
            CoeffModulus=SimpleNamespace(MaxBitCount=lambda n, lvl: TABLE[lvl].get(n, 0)),
            Serialization=SimpleNamespace(
                SEALHeader=lambda: SimpleNamespace(version_major=seal[0], version_minor=seal[1])
            ),
        ),
    ), Ctx


def use(monkeypatch, fake):
    monkeypatch.setattr(bf, "_import_tenseal", lambda: fake)
    bf.reset_cache()


# ---------------------------------------------------------------------------
# What the backend is shown to enforce
# ---------------------------------------------------------------------------


def test_a_backend_that_refuses_above_the_128_bit_limit_is_shown_to_enforce_128(monkeypatch):
    fake, _ = fake_tenseal(enforce=128)
    use(monkeypatch, fake)
    f = bf.facts()
    assert f.enforced_security_bits == 128 and f.seal_version == (4, 3)
    assert f.tenseal_version == "0.0.0-fake"


@pytest.mark.parametrize("level", [192, 256])
def test_a_backend_that_enforces_a_higher_level_is_shown_to_enforce_it(monkeypatch, level):
    fake, _ = fake_tenseal(enforce=level)
    use(monkeypatch, fake)
    assert bf.facts().enforced_security_bits == level


def test_a_backend_that_builds_anything_is_shown_to_enforce_nothing(monkeypatch):
    fake, _ = fake_tenseal(enforce=None)
    use(monkeypatch, fake)
    assert bf.facts().enforced_security_bits == 0
    with pytest.raises(bf.BackendUnverified, match="cannot be shown to enforce"):
        bf.require_level(128)
    with pytest.raises(bf.BackendUnverified, match="cannot be shown to enforce"):
        CKKSParams().to_envelope_parameter_set()


def test_without_tenseal_nothing_is_signed(monkeypatch):
    def missing():
        raise bf.BackendUnverified("TenSEAL is not installed")

    monkeypatch.setattr(bf, "_import_tenseal", missing)
    bf.reset_cache()
    with pytest.raises(bf.BackendUnverified, match="not installed"):
        CKKSParams().to_envelope_parameter_set()
    with pytest.raises(bf.BackendUnverified, match="not installed"):
        reports.parameter_set_from_ckks_context(SimpleNamespace(poly_modulus_degree=16384))


def test_the_default_128_set_is_signed_from_the_constructed_context(monkeypatch):
    fake, _ = fake_tenseal(enforce=128)
    use(monkeypatch, fake)
    eps = CKKSParams().to_envelope_parameter_set()
    assert (eps.backend, eps.poly_modulus_degree, eps.security_bits) == ("tenseal-ckks", 32768, 128)
    assert eps.coeff_mod_bit_sizes == CHAIN_8 and eps.backend_version == "0.0.0-fake"
    expected = ParameterSet(
        backend="tenseal-ckks", poly_modulus_degree=32768, security_bits=128, multiplicative_depth=6,
        coeff_mod_bit_sizes=CHAIN_8, scaling_factor_bits=40, backend_version="0.0.0-fake",
    )  # fmt: skip
    assert eps.hash() == expected.hash()


@pytest.mark.parametrize("installed", [880, 882, 0])
def test_a_recorded_table_that_differs_from_the_installed_seal_is_not_signed_from(
    monkeypatch, installed
):
    fake, _ = fake_tenseal(enforce=128)
    use(monkeypatch, fake)
    monkeypatch.setattr(bf, "installed_max_log_q_128", lambda ring: installed)
    with pytest.raises(bf.BackendUnverified, match="revalidated"):
        CKKSParams().to_envelope_parameter_set()


def test_a_backend_that_builds_a_different_chain_than_asked_is_refused(monkeypatch):
    fake, _ = fake_tenseal(enforce=128)
    use(monkeypatch, fake)
    bf.facts()  # the probe runs against the honest backend and is cached
    real = fake.context
    fake.context = lambda s, **kw: real(
        s, **{**kw, "coeff_mod_bit_sizes": [60, 60]}
    )  # then it builds something else
    bf.constructed.cache_clear()
    with pytest.raises(bf.BackendUnverified, match="different"):
        CKKSParams().to_envelope_parameter_set()


# ---------------------------------------------------------------------------
# CKKSParams: claims the backend cannot enforce, ring dimensions SEAL has no table for, unbuildable chains
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", ["HEStd_192_classic", "HEStd_256_classic"])
def test_192_and_256_are_refused_because_the_backend_cannot_enforce_them(level):
    with pytest.raises(ParameterValidationError, match="cannot enforce"):
        CKKSParams(security_level=level)
    with pytest.raises(ParameterValidationError, match="cannot enforce"):
        CKKSParams(ring_dim=1 << 14, security_level=level)


def test_the_128_level_is_accepted():
    assert CKKSParams(security_level="HEStd_128_classic").security_level == "HEStd_128_classic"
    assert CKKSParams(ring_dim=1 << 14).ring_dim == 16384


@pytest.mark.parametrize("ring", [1 << 16, 1 << 17])
def test_ring_dimensions_with_no_seal_table_entry_are_refused(ring):
    with pytest.raises(ParameterValidationError, match="no SEAL log Q bound"):
        CKKSParams(ring_dim=ring)


def test_the_recorded_table_stops_at_the_last_ring_dimension_seal_has():
    assert max(params_mod.SEAL_MAX_LOG_Q_128) == 32768


def test_a_prime_above_60_bits_is_refused():
    with pytest.raises(ParameterValidationError, match="at most 60 bits"):
        CKKSParams(
            ring_dim=1 << 14,
            first_mod_size=61,
            coeff_mod_bit_sizes=(61, 40, 40, 40, 40, 40, 40, 61),
        )


@pytest.mark.parametrize(
    "bad", [(60, 40.0, 40, 40, 40, 40, 40, 60), (60, 40, 40, 40, 40, 40, 40.5, 60)]
)
def test_chain_entries_must_be_ints(bad):
    with pytest.raises(ParameterValidationError, match="must be an int"):
        CKKSParams(ring_dim=1 << 14, coeff_mod_bit_sizes=bad)


def test_a_chain_the_ring_has_too_few_primes_for_is_refused():
    with pytest.raises(ParameterValidationError, match="distinct primes"):
        CKKSParams(
            ring_dim=1 << 14, scaling_mod_size=20
        )  # six 20-bit primes: only a few exist for N = 2^14


def test_the_prime_availability_rule_agrees_with_a_direct_count():
    assert params_mod._enough_primes(60, 1 << 15, 6)  # 2N = 32768
    assert not params_mod._enough_primes(20, 1 << 15, 6)
    assert params_mod._enough_primes(20, 1 << 15, 1)
    assert not params_mod._enough_primes(15, 1 << 15, 1)  # below 2N: no prime can be 1 mod 2N


# Guard-off controls: with the guard removed the same input is accepted, so the guard is what refuses it.


def test_control_without_the_enforcement_set_a_192_claim_is_accepted(monkeypatch):
    monkeypatch.setattr(
        params_mod, "BACKEND_ENFORCED_LEVELS", frozenset(params_mod.SECURITY_LEVELS)
    )
    assert CKKSParams(security_level="HEStd_192_classic").security_level == "HEStd_192_classic"
    assert CKKSParams(security_level="HEStd_256_classic").security_level == "HEStd_256_classic"


def test_control_with_the_old_table_entry_65536_is_accepted(monkeypatch):
    monkeypatch.setitem(params_mod.SEAL_MAX_LOG_Q_128, 65536, 1762)
    assert CKKSParams(ring_dim=1 << 16).ring_dim == 65536


def test_control_without_the_prime_checks_the_unbuildable_chains_are_accepted(monkeypatch):
    monkeypatch.setattr(CKKSParams, "_check_chain_is_buildable", lambda self: None)
    assert CKKSParams(
        ring_dim=1 << 14, first_mod_size=61, coeff_mod_bit_sizes=(61, 40, 40, 40, 40, 40, 40, 61)
    )
    assert CKKSParams(ring_dim=1 << 14, scaling_mod_size=20)


# ---------------------------------------------------------------------------
# parameter_set_from_ckks_context: read the real context, never a stand-in or a default
# ---------------------------------------------------------------------------


def test_a_stand_in_object_is_no_longer_signed_as_a_context(monkeypatch):
    fake, _ = fake_tenseal(enforce=128)
    use(monkeypatch, fake)
    stand_in = SimpleNamespace(poly_modulus_degree=16384, scale=float(2**40), n_slots=8192)
    with pytest.raises(bf.BackendUnverified, match="cannot read the parameters"):
        reports.parameter_set_from_ckks_context(stand_in)


def test_the_chain_is_read_from_the_context_not_defaulted(monkeypatch):
    fake, _ = fake_tenseal(enforce=128)
    use(monkeypatch, fake)
    real = (60, 50, 50, 50, 50, 50, 50, 60)
    ctx = fake.context(fake.SCHEME_TYPE.CKKS, poly_modulus_degree=16384, coeff_mod_bit_sizes=real)
    ps = reports.parameter_set_from_ckks_context(ctx)
    assert ps.coeff_mod_bit_sizes == real and sum(real) == 420
    assert (ps.poly_modulus_degree, ps.security_bits, ps.scaling_factor_bits) == (16384, 128, 40)


@pytest.mark.parametrize("claim", [192, 256, 64, 127])
def test_a_security_level_other_than_the_enforced_one_is_refused(monkeypatch, claim):
    fake, _ = fake_tenseal(enforce=128)
    use(monkeypatch, fake)
    ctx = fake.context(
        fake.SCHEME_TYPE.CKKS, poly_modulus_degree=16384, coeff_mod_bit_sizes=CHAIN_8
    )
    with pytest.raises(ValueError, match="enforces 128"):
        reports.parameter_set_from_ckks_context(ctx, security_bits=claim)
    assert reports.parameter_set_from_ckks_context(ctx, security_bits=128).security_bits == 128


def test_a_context_with_a_lying_wrapper_attribute_is_refused(monkeypatch):
    fake, _ = fake_tenseal(enforce=128)
    use(monkeypatch, fake)
    raw = fake.context(
        fake.SCHEME_TYPE.CKKS, poly_modulus_degree=16384, coeff_mod_bit_sizes=CHAIN_8
    )
    wrapper = SimpleNamespace(context=raw, poly_modulus_degree=32768, scale=float(2**40))
    with pytest.raises(ValueError, match="disagrees with the context"):
        reports.parameter_set_from_ckks_context(wrapper)


def test_a_depth_the_chain_cannot_carry_is_refused(monkeypatch):
    fake, _ = fake_tenseal(enforce=128)
    use(monkeypatch, fake)
    raw = fake.context(
        fake.SCHEME_TYPE.CKKS, poly_modulus_degree=16384, coeff_mod_bit_sizes=(60, 40, 40, 60)
    )
    with pytest.raises(ValueError, match="multiplicative_depth"):
        reports.parameter_set_from_ckks_context(raw, multiplicative_depth=6)
    assert (
        reports.parameter_set_from_ckks_context(raw, multiplicative_depth=2).multiplicative_depth
        == 2
    )


# ---------------------------------------------------------------------------
# parameter_set_from_openfhe_context (B-12c). Not run against a real OpenFHE: stand-ins only.
# ---------------------------------------------------------------------------


def openfhe_stub(ring, *, n_slots=8192):
    return SimpleNamespace(
        cc=SimpleNamespace(GetRingDimension=lambda: ring), n_slots=n_slots, scale_bits=40
    )


def test_the_openfhe_ring_dimension_is_read_not_twice_the_batch_size():
    ps = reports.parameter_set_from_openfhe_context(openfhe_stub(32768, n_slots=8192))
    assert (
        ps.poly_modulus_degree == 32768
        and ps.backend == "openfhe-ckks"
        and ps.coeff_mod_bit_sizes == ()
    )
    assert (ps.security_bits, ps.scaling_factor_bits) == (128, 40)


@pytest.mark.parametrize("claim", [192, 256])
def test_openfhe_claims_above_the_requested_level_are_refused(claim):
    with pytest.raises(ValueError, match="requests 128"):
        reports.parameter_set_from_openfhe_context(openfhe_stub(16384), security_bits=claim)


@pytest.mark.parametrize(
    "ctx",
    [
        SimpleNamespace(cc=SimpleNamespace(), n_slots=8192, scale_bits=40),
        SimpleNamespace(n_slots=8192, scale_bits=40),
        openfhe_stub(0),
        openfhe_stub(1000),
        openfhe_stub(16384, n_slots=16384),  # a batch cannot be wider than half the ring
    ],
)
def test_openfhe_contexts_that_cannot_show_a_ring_dimension_are_refused(ctx):
    with pytest.raises(bf.BackendUnverified):
        reports.parameter_set_from_openfhe_context(ctx)


def test_control_with_the_old_mapping_the_ring_dimension_is_twice_the_batch_size(monkeypatch):
    monkeypatch.setattr(reports, "_openfhe_ring_dimension", lambda ctx: 2 * ctx.n_slots)
    old = reports.parameter_set_from_openfhe_context(openfhe_stub(32768, n_slots=8192))
    assert old.poly_modulus_degree == 16384  # the false value the guard removes


# ---------------------------------------------------------------------------
# Against the installed TenSEAL and SEAL
# ---------------------------------------------------------------------------


@pytest.fixture
def ts():
    return pytest.importorskip("tenseal")


def test_the_installed_build_is_described_by_what_it_reports(ts):
    f = bf.facts()
    assert f.enforced_security_bits == 128, (
        "the backend must be shown to enforce exactly SEAL's default level"
    )
    assert f.tenseal_version == ts.__version__ and f.seal_version[0] >= 4


def test_the_recorded_table_equals_the_installed_seal_table(ts):
    for ring, limit in params_mod.SEAL_MAX_LOG_Q_128.items():
        if ring >= 1 << 14:
            assert bf.installed_max_log_q_128(ring) == limit, (
                f"SEAL's 128-bit limit for N={ring} changed: revalidate"
            )
    assert bf.installed_max_log_q_128(1 << 16) == 0


def test_positive_default_params_sign_what_the_context_reads_back(ts):
    eps = CKKSParams().to_envelope_parameter_set()
    expected = ParameterSet(
        backend="tenseal-ckks", poly_modulus_degree=32768, security_bits=128, multiplicative_depth=6,
        coeff_mod_bit_sizes=CHAIN_8, scaling_factor_bits=40, backend_version=ts.__version__,
    )  # fmt: skip
    assert eps.hash() == expected.hash()


def test_positive_the_default_context_signs_its_real_values_and_keeps_its_hash(ts):
    from regaudit_fhe.fhe import build_d6_context

    ps = reports.parameter_set_from_ckks_context(build_d6_context())
    expected = ParameterSet(
        backend="tenseal-ckks", poly_modulus_degree=16384, security_bits=128, multiplicative_depth=6,
        coeff_mod_bit_sizes=(60, 40, 40, 40, 40, 40, 40, 40, 60), scaling_factor_bits=40,
        backend_version=ts.__version__,
    )  # fmt: skip
    assert ps.hash() == expected.hash()  # the old hard-coded chain is the real default chain


def test_b12a_a_context_from_params_signs_the_params_hash(ts):
    from regaudit_fhe.fhe import build_d6_context_from_params

    p = CKKSParams()
    ps = reports.parameter_set_from_ckks_context(build_d6_context_from_params(p))
    assert ps.coeff_mod_bit_sizes == CHAIN_8 and ps.hash() == p.to_envelope_parameter_set().hash()


def test_b12a_a_non_default_chain_is_signed_as_it_is(ts):
    from regaudit_fhe.fhe import build_d6_context

    real = (60, 50, 50, 50, 50, 50, 50, 60)
    ps = reports.parameter_set_from_ckks_context(build_d6_context(coeff_mod_bit_sizes=real))
    assert ps.coeff_mod_bit_sizes == real


def test_a_raw_tenseal_context_is_read_back_too(ts):
    raw = ts.context(
        ts.SCHEME_TYPE.CKKS, poly_modulus_degree=16384, coeff_mod_bit_sizes=list(CHAIN_8)
    )
    raw.global_scale = float(2**40)
    ps = reports.parameter_set_from_ckks_context(raw)
    assert (ps.poly_modulus_degree, ps.coeff_mod_bit_sizes, ps.security_bits) == (
        16384,
        CHAIN_8,
        128,
    )


@pytest.mark.parametrize("claim", [192, 256])
def test_a_192_or_256_claim_about_a_real_context_is_refused(ts, claim):
    raw = ts.context(
        ts.SCHEME_TYPE.CKKS, poly_modulus_degree=16384, coeff_mod_bit_sizes=list(CHAIN_8)
    )
    raw.global_scale = float(2**40)
    with pytest.raises(ValueError, match="enforces 128"):
        reports.parameter_set_from_ckks_context(raw, security_bits=claim)


def test_b12b_a_ring_without_a_seal_entry_is_refused_before_any_key_is_made(ts):
    from regaudit_fhe.fhe import build_d6_context

    with pytest.raises(bf.BackendUnverified, match="no entry"):
        build_d6_context(poly_modulus_degree=1 << 16)


@pytest.mark.parametrize("ring,limit", [(1 << 14, 438), (1 << 15, 881)])
def test_the_limit_is_where_the_real_backend_draws_it(ts, ring, limit):
    assert bf.constructed(ring, tuple(bf._chain_with_total(limit))).ring_dim == ring
    with pytest.raises(bf.BackendUnverified, match="refuses"):
        bf.constructed(ring, tuple(bf._chain_with_total(limit + 1)))


def test_the_context_builder_refuses_what_the_backend_refuses(ts):
    from regaudit_fhe.fhe import build_d6_context

    with pytest.raises(Exception, match="not set correctly|refuses"):
        build_d6_context(coeff_mod_bit_sizes=bf._chain_with_total(439))


def test_a_read_back_that_disagrees_with_the_request_is_refused(ts, monkeypatch):
    from regaudit_fhe.fhe import build_d6_context

    real_read = bf.read_back
    monkeypatch.setattr(
        bf,
        "read_back",
        lambda c: bf.ReadBack(16384, (60, 60), None) if c is not None else real_read(c),
    )
    with pytest.raises(bf.BackendUnverified, match="different"):
        build_d6_context(
            coeff_mod_bit_sizes=[60, 40, 40, 40, 40, 40, 40, 40, 60], poly_modulus_degree=16384
        )


def test_control_when_the_probe_shows_nothing_the_real_params_are_not_signed(ts, monkeypatch):
    monkeypatch.setattr(bf, "facts", lambda: bf.SealFacts(ts.__version__, (4, 3), 0))
    with pytest.raises(bf.BackendUnverified, match="cannot be shown to enforce"):
        CKKSParams().to_envelope_parameter_set()


GRID = list(
    itertools.product((1 << 14, 1 << 15), (1, 3, 6), (20, 30, 40, 50, 60), (40, 60), (60, 61))
)


def test_everything_the_library_accepts_the_real_backend_builds(ts):
    accepted = 0
    for ring, depth, scale, first, last in GRID:
        chain = (first, *([scale] * depth), last)
        try:
            p = CKKSParams(
                ring_dim=ring,
                multiplicative_depth=depth,
                scaling_mod_size=scale,
                first_mod_size=first,
                coeff_mod_bit_sizes=chain,
            )
        except ParameterValidationError:
            continue
        accepted += 1
        assert bf.constructed(ring, p.coeff_mod_bit_sizes).chain == p.coeff_mod_bit_sizes, (
            ring,
            chain,
        )
    assert accepted >= 20


@pytest.mark.parametrize(
    "ring,chain",
    [
        (1 << 14, (61, 40, 40, 40, 40, 40, 40, 61)),
        (1 << 14, (60, 20, 20, 20, 20, 20, 20, 60)),
        (1 << 15, (60, 20, 20, 20, 20, 20, 20, 60)),
        (1 << 15, (50, 20, 20, 50)),
    ],
)
def test_what_the_real_backend_refuses_the_library_refuses(ts, ring, chain):
    with pytest.raises(bf.BackendUnverified):
        bf.constructed(ring, chain)
    with pytest.raises(ParameterValidationError):
        CKKSParams(
            ring_dim=ring, multiplicative_depth=len(chain) - 2, scaling_mod_size=min(chain[1:-1]),
            first_mod_size=min(chain[0], chain[-1]), coeff_mod_bit_sizes=chain,
        )  # fmt: skip


def test_the_package_exposes_the_error_for_callers():
    from regaudit_fhe import fhe

    assert fhe.BackendUnverified is bf.BackendUnverified
