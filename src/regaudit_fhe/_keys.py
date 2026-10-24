"""Public-key helpers shared by the trust store and the v2 envelope."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def load_ed25519_public_key(pem: str) -> Ed25519PublicKey:
    """Parse a PEM SubjectPublicKeyInfo; raise ``ValueError`` unless it is Ed25519."""
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError, TypeError) as exc:
        raise ValueError("not a valid PEM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    return key


def spki_fingerprint(pem: str) -> str:
    """SHA-256 (lowercase hex) of the SubjectPublicKeyInfo DER of an Ed25519 PEM key."""
    der = load_ed25519_public_key(pem).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()
