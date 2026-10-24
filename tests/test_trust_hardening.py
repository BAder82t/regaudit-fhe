"""Phase 1 trust-verification hardening.

Every refusal test is paired with a positive control that differs only in
the property under test, so a pass cannot come from the verifier simply
rejecting everything.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.reports import canonical_json, verify_signature
from regaudit_fhe.trust import (
    TimestampInvalid,
    TimestampUnverified,
    TrustStore,
    TrustStoreError,
)

TRUSTED = "TRUSTED"
SELF_SIGNED_ONLY = "SELF_SIGNED_ONLY"
INVALID = "INVALID"


def _report():
    return rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )


def _env(signer=None, *, key_id="k1", timestamp_authority=None):
    signer = signer or rf.Signer.generate(issuer="acme", key_id=key_id)
    env = rf.envelope("fairness", _report(), signer=signer, timestamp_authority=timestamp_authority)
    return env, signer


def _store(signer, **extra) -> TrustStore:
    return TrustStore.from_dict({"keys": {signer.key_id: signer.public_key_pem()}, **extra})


def _tsa_token(body: bytes) -> bytes:
    return b"TSA:" + hashlib.sha256(body).digest()


def _tsa():
    return rf.TimestampAuthority(issuer="https://tsa.example", sign_callable=_tsa_token)


def _tsa_verifier(body: bytes, token: bytes) -> bool:
    return token == _tsa_token(body)


# ---------------------------------------------------------------------------
# Self-signature validity is not issuer trust
# ---------------------------------------------------------------------------


def test_self_signed_without_trust_material_is_not_reported_trusted():
    env, _ = _env()
    out = rf.verify_envelope(env)
    assert out.trust_status == SELF_SIGNED_ONLY
    assert out.issuer_trusted is False
    # Legacy contract: integrity-only ``valid`` is preserved for v1 callers.
    assert out.valid is True


def test_trust_store_match_is_trusted():
    env, signer = _env()
    out = rf.verify_envelope(env, trust_store=_store(signer))
    assert out.trust_status == TRUSTED
    assert out.issuer_trusted is True
    assert out.valid is True


def test_tampered_body_is_invalid_not_self_signed():
    env, _ = _env()
    env.result["tampered"] = True
    out = rf.verify_envelope(env)
    assert out.trust_status == INVALID
    assert out.valid is False


def test_unknown_issuer_with_trust_store_is_invalid():
    env, _ = _env()
    other = rf.Signer.generate(issuer="mallory", key_id="k-other")
    out = rf.verify_envelope(env, trust_store=_store(other))
    assert out.trust_status == INVALID
    assert out.valid is False


# ---------------------------------------------------------------------------
# Revocation, pins, key substitution, embedded-key fallback
# ---------------------------------------------------------------------------


def test_revoked_key_rejected_by_verify_envelope():
    env, signer = _env()
    assert rf.verify_envelope(env, trust_store=_store(signer)).trust_status == TRUSTED
    out = rf.verify_envelope(env, trust_store=_store(signer, revoked=[signer.key_id]))
    assert out.trust_status == INVALID
    assert out.revoked is True
    assert out.valid is False


def test_verify_receipt_honours_revocation_via_trust_store():
    env, signer = _env()
    assert rf.verify_receipt(env, trust_store=_store(signer), strict=True) is True
    revoked = _store(signer, revoked=[signer.key_id])
    assert rf.verify_receipt(env, trust_store=revoked, strict=True) is False


def test_verify_receipt_accepts_trust_store_as_trusted_keys():
    """Passing a TrustStore where a legacy dict is expected must keep its
    revocation and pins, not silently drop them."""
    env, signer = _env()
    assert rf.verify_receipt(env, trusted_keys=_store(signer), strict=True) is True
    revoked = _store(signer, revoked=[signer.key_id])
    assert rf.verify_receipt(env, trusted_keys=revoked, strict=True) is False


def test_verify_receipt_strict_without_trust_material_refuses():
    env, _ = _env()
    assert rf.verify_receipt(env, strict=True) is False
    assert rf.verify_receipt(env, trust_store=None, trusted_keys=None, strict=True) is False


def test_pin_mismatch_rejected_and_match_accepted():
    env, signer = _env()
    good = _store(signer, parameter_set_pins={signer.key_id: env.parameter_set_hash})
    assert rf.verify_envelope(env, trust_store=good).trust_status == TRUSTED
    bad = _store(signer, parameter_set_pins={signer.key_id: "0" * 64})
    out = rf.verify_envelope(env, trust_store=bad)
    assert out.trust_status == INVALID
    assert out.valid is False
    assert rf.verify_receipt(env, trust_store=bad, strict=True) is False


def test_key_substitution_with_registered_key_id_is_rejected():
    """Attacker signs with their own key but claims the registered key_id."""
    _, trusted = _env()
    attacker = rf.Signer.generate(issuer="acme", key_id=trusted.key_id)
    forged, _ = _env(attacker)
    out = rf.verify_envelope(forged, trust_store=_store(trusted))
    # Checked against the registered key, so the attacker's signature fails.
    assert out.signature_valid is False
    assert out.trust_status == INVALID
    # Self-consistent under its own embedded key: only issuer trust stops it.
    assert rf.verify_envelope(forged).trust_status == SELF_SIGNED_ONLY
    assert out.valid is False


def test_embedded_key_cannot_override_trusted_key():
    """Swap the embedded PEM for the trusted one: the signature was made by
    the attacker, so it must fail against the trusted key, never fall back to
    the embedded one."""
    _, trusted = _env()
    attacker = rf.Signer.generate(issuer="acme", key_id=trusted.key_id)
    forged, _ = _env(attacker)
    forged.receipt["public_key_pem"] = trusted.public_key_pem()
    out = rf.verify_envelope(forged, trust_store=_store(trusted))
    assert out.signature_valid is False
    assert out.trust_status == INVALID


def test_embedded_pem_disagreeing_with_registered_key_is_rejected():
    """Signature is valid under the registered key, but the envelope claims a
    different embedded key. The envelope's self-description must match the
    registered issuer exactly, so this is refused (not merely tolerated)."""
    env, signer = _env()
    store = _store(signer)
    assert rf.verify_envelope(env, trust_store=store).trust_status == TRUSTED  # control
    env.receipt["public_key_pem"] = rf.Signer.generate(issuer="x").public_key_pem()
    out = rf.verify_envelope(env, trust_store=store)
    assert out.signature_valid is True  # still valid under the registered key
    assert out.issuer_trusted is False
    assert out.trust_status == INVALID
    assert out.valid is False
    with pytest.raises(rf.UntrustedIssuer):
        rf.verify_envelope_or_raise(env, trust_store=store)


def test_legacy_trusted_keys_mapping_still_enforces_key_match():
    env, signer = _env()
    ok = rf.verify_envelope(env, trusted_keys={signer.key_id: signer.public_key_pem()})
    assert ok.trust_status == TRUSTED
    bad = rf.verify_envelope(env, trusted_keys={"nope": signer.public_key_pem()})
    assert bad.trust_status == INVALID


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------


def test_no_timestamp_is_absent():
    env, signer = _env()
    out = rf.verify_envelope(env, trust_store=_store(signer))
    assert out.timestamp_status == "ABSENT"
    assert out.timestamp_valid is True


def test_timestamp_without_verifier_is_unverified_not_valid():
    env, signer = _env(timestamp_authority=_tsa())
    out = rf.verify_envelope(env, trust_store=_store(signer))
    assert out.timestamp_status == "UNVERIFIED"
    assert out.timestamp_valid is False


def test_policy_requiring_verified_timestamp_rejects_unverified():
    env, signer = _env(timestamp_authority=_tsa())
    store = _store(signer)
    ok = rf.verify_envelope(
        env, trust_store=store, tsa_verifier=_tsa_verifier, require_verified_timestamp=True
    )
    assert ok.timestamp_status == "VERIFIED"
    assert ok.trust_status == TRUSTED
    out = rf.verify_envelope(env, trust_store=store, require_verified_timestamp=True)
    assert out.timestamp_status == "UNVERIFIED"
    assert out.trust_status == INVALID
    assert out.valid is False


def test_forged_timestamp_token_fails_verification():
    env, signer = _env(timestamp_authority=_tsa())
    assert rf.verify_envelope(env, tsa_verifier=_tsa_verifier).timestamp_status == "VERIFIED"
    assert env.timestamp is not None
    env.timestamp["token_b64"] = base64.b64encode(b"forged").decode()
    out = rf.verify_envelope(env, trust_store=_store(signer), tsa_verifier=_tsa_verifier)
    assert out.timestamp_status == "FAILED"
    assert out.valid is False
    assert out.trust_status == INVALID


def test_raising_tsa_verifier_is_failed_not_verified():
    env, signer = _env(timestamp_authority=_tsa())

    def boom(body: bytes, token: bytes) -> bool:
        raise RuntimeError("tsa down")

    out = rf.verify_envelope(env, trust_store=_store(signer), tsa_verifier=boom)
    assert out.timestamp_status == "FAILED"
    assert out.valid is False


def test_timestamp_without_token_is_failed():
    env, signer = _env(timestamp_authority=_tsa())
    assert env.timestamp is not None
    env.timestamp.pop("token_b64")
    out = rf.verify_envelope(env, trust_store=_store(signer))
    assert out.timestamp_status == "FAILED"
    assert out.valid is False


def test_verified_timestamp_does_not_override_revocation():
    env, signer = _env(timestamp_authority=_tsa())
    store = _store(signer, revoked=[signer.key_id])
    out = rf.verify_envelope(
        env, trust_store=store, tsa_verifier=_tsa_verifier, require_verified_timestamp=True
    )
    assert out.timestamp_status == "VERIFIED"
    assert out.revoked is True
    assert out.trust_status == INVALID
    assert out.valid is False


def test_or_raise_unverified_timestamp_policy():
    env, signer = _env(timestamp_authority=_tsa())
    store = _store(signer)
    # Not required: passes, and reports the timestamp as unverified.
    out = rf.verify_envelope_or_raise(env, trust_store=store)
    assert out.timestamp_status == "UNVERIFIED"
    # Required but no verifier configured: refused for the intended reason.
    with pytest.raises(TimestampUnverified):
        rf.verify_envelope_or_raise(env, trust_store=store, require_verified_timestamp=True)
    # Required with a working verifier: accepted.
    out = rf.verify_envelope_or_raise(
        env, trust_store=store, tsa_verifier=_tsa_verifier, require_verified_timestamp=True
    )
    assert out.timestamp_status == "VERIFIED"


def test_or_raise_failed_timestamp_raises_invalid():
    env, signer = _env(timestamp_authority=_tsa())
    assert env.timestamp is not None
    env.timestamp["token_b64"] = base64.b64encode(b"forged").decode()
    with pytest.raises(TimestampInvalid):
        rf.verify_envelope_or_raise(env, trust_store=_store(signer), tsa_verifier=_tsa_verifier)


def test_timestamp_is_not_part_of_signed_body():
    """Documents the v1 format: the timestamp block is outside the signature,
    so it must never be treated as signed evidence."""
    env, _ = _env(timestamp_authority=_tsa())
    assert "timestamp" not in env.signed_body()


# ---------------------------------------------------------------------------
# Trust-store loading fails closed
# ---------------------------------------------------------------------------


def test_trust_store_from_json_missing_file_raises_trust_store_error(tmp_path: Path):
    with pytest.raises(TrustStoreError):
        TrustStore.from_json(tmp_path / "nope.json")


def test_trust_store_from_json_directory_raises_trust_store_error(tmp_path: Path):
    with pytest.raises(TrustStoreError):
        TrustStore.from_json(tmp_path)


def test_trust_store_from_json_malformed_raises(tmp_path: Path):
    p = tmp_path / "ts.json"
    p.write_text("{not json")
    with pytest.raises(TrustStoreError):
        TrustStore.from_json(p)


def test_trust_store_from_json_valid_loads(tmp_path: Path):
    _, signer = _env()
    p = tmp_path / "ts.json"
    p.write_text(json.dumps({"keys": {signer.key_id: signer.public_key_pem()}}))
    assert TrustStore.from_json(p).is_known(signer.key_id)


def test_canonical_signing_format_unchanged():
    """v1 compatibility: the signed body is exactly the canonical JSON of the
    envelope minus receipt and timestamp."""
    env, signer = _env()
    body = canonical_json(env.signed_body())
    assert hashlib.sha256(body).hexdigest() == env.receipt["sha256"]
    assert verify_signature(signer.public_key_pem(), body, env.receipt["signature_b64"])


# ---------------------------------------------------------------------------
# Review findings
# ---------------------------------------------------------------------------


def test_empty_trusted_keys_mapping_fails_closed():
    """An empty (e.g. failed-to-load) trust map is trust material that trusts
    nobody. It must not degrade to the self-signed path."""
    env, signer = _env()
    assert rf.verify_receipt(env, trusted_keys={signer.key_id: signer.public_key_pem()}) is True
    assert rf.verify_receipt(env, trusted_keys={}) is False
    assert rf.verify_receipt(env, trusted_keys={}, strict=True) is False
    assert rf.verify_envelope(env, trusted_keys={}).trust_status == INVALID


def test_require_signature_false_cannot_make_unsigned_envelope_valid_with_trust_material():
    env, signer = _env()
    store = _store(signer)
    env.receipt.pop("signature_b64")
    out = rf.verify_envelope(env, trust_store=store, require_signature=False)
    assert out.trust_status == INVALID
    assert out.valid is False
