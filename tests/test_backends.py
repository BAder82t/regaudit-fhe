"""FHE backend registry tests (backend-agnostic; no native lib required)."""

from __future__ import annotations

import pytest

from regaudit_fhe.fhe import backends


def test_builtin_backends_registered():
    names = {b.name for b in backends.all_backends()}
    assert {"tenseal-ckks", "openfhe-ckks"} <= names


def test_get_unknown_backend_raises():
    with pytest.raises(backends.BackendError):
        backends.get_backend("does-not-exist")


def test_supported_matrix_kinds():
    assert backends.supported_matrix_kinds("tenseal-ckks") == ("square", "rectangular")
    assert backends.supported_matrix_kinds("openfhe-ckks") == ("square",)


def test_openfhe_is_marked_experimental():
    assert backends.get_backend("openfhe-ckks").experimental is True
    assert backends.get_backend("tenseal-ckks").experimental is False


def test_unavailable_backend_require_raises_actionable_error():
    fake = backends.FHEBackend(
        name="fake",
        description="not installable in tests.",
        available=False,
        _build_context=lambda **k: None,
        _slotvec_cls=lambda: object,
        _sign_poly=lambda: lambda x: x,
    )
    with pytest.raises(backends.BackendError) as exc:
        fake.require()
    assert "not available" in str(exc.value)


def test_default_backend_prefers_tenseal_when_available():
    if "tenseal-ckks" not in backends.available_backends():
        pytest.skip("no TenSEAL backend available")
    assert backends.default_backend().name == "tenseal-ckks"
