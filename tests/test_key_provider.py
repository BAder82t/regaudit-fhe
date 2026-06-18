"""KeyProvider / external key-custody seam tests."""

from __future__ import annotations

import numpy as np
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

import regaudit_fhe as rf
from regaudit_fhe.reports import CallableKeyProvider, KeyProvider


def _ed25519_pair():
    priv = Ed25519PrivateKey.generate()
    pub_pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return priv, pub_pem


def _report():
    return rf.fairness_oracle(
        np.array([1, 0, 1, 1.0]),
        np.array([1, 0, 0, 1.0]),
        np.array([1, 1, 0, 0.0]),
        np.array([0, 0, 1, 1.0]),
    )


def test_signer_and_callable_provider_both_satisfy_protocol():
    priv, pub_pem = _ed25519_pair()
    provider = CallableKeyProvider(
        issuer="acme", key_id="k1", public_pem=pub_pem, sign_callable=priv.sign
    )
    signer = rf.Signer.generate(issuer="acme", key_id="k2")
    assert isinstance(provider, KeyProvider)
    assert isinstance(signer, KeyProvider)


def test_external_provider_produces_verifiable_envelope():
    priv, pub_pem = _ed25519_pair()
    provider = CallableKeyProvider(
        issuer="acme-health", key_id="kms-1", public_pem=pub_pem, sign_callable=priv.sign
    )
    env = rf.envelope("fairness", _report(), signer=provider)
    assert env.issuer == "acme-health"
    assert env.receipt["key_id"] == "kms-1"
    assert rf.verify_receipt(env, trusted_keys={"kms-1": provider.public_key_pem()}, strict=True)


def test_provider_fails_closed_when_callable_returns_bad_signature():
    _priv, pub_pem = _ed25519_pair()
    other, _ = _ed25519_pair()
    # Callable signs with the WRONG key; provider must refuse to emit it.
    provider = CallableKeyProvider(
        issuer="acme", key_id="k1", public_pem=pub_pem, sign_callable=other.sign
    )
    with pytest.raises(ValueError):
        rf.envelope("fairness", _report(), signer=provider)


def test_provider_rejects_non_bytes_signature():
    _, pub_pem = _ed25519_pair()
    provider = CallableKeyProvider(
        issuer="acme", key_id="k1", public_pem=pub_pem, sign_callable=lambda b: "notbytes"
    )
    with pytest.raises(TypeError):
        provider.sign(b"body")


def test_provider_rejects_non_ed25519_public_key():
    rsa_pub = (
        generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    with pytest.raises(TypeError):
        CallableKeyProvider(
            issuer="acme", key_id="k1", public_pem=rsa_pub, sign_callable=lambda b: b""
        )
