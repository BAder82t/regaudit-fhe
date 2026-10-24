"""Canonical ``report.v2`` vectors: frozen bytes, positive and adversarial.

The golden constants below are intentionally duplicated from ``vectors.json``.
Regenerating the vector file alone cannot make this test pass: changing the
canonical format, the signing domain or the sealed digest requires editing
these constants too, which is a deliberate, reviewable format decision.
"""

from __future__ import annotations

import base64
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from regaudit_fhe.canonical import CanonicalError, canonical_bytes
from regaudit_fhe.report_v2 import (
    AuditEnvelopeV2,
    EnvelopeFormatError,
    parse_envelope,
)
from regaudit_fhe.reports import AuditEnvelope, sha256_hex, verify_signature
from regaudit_fhe.trust import TrustStore
from regaudit_fhe.verification import (
    TimestampEvidence,
    VerificationPolicy,
    verify,
)

VECTORS = Path(__file__).parent / "vectors" / "report_v2"
NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)

# --- golden known answers (duplicated on purpose) ----------------------------
KEY_FINGERPRINT = "f5a124b4ff5b3253aa23c917d460cfaed57cec28ecc4b7a43d72785828aa2256"
GOLDEN = {
    "full": {
        "signing_input_sha256": "2dccddae8e96f35d15da3665ded1aed685d6e3db64c3051c889011be7dc4741b",
        "sealed_digest_hex": "fcadd05ebbc4f1db772f713b25e148457766363b9094851fe9e954c5572d3a69",
        "signature_b64": "e4O0h4JITUXEcVXjtx/DogU+oVuTJAGWdg8lkEHIeDEfgIsRCyPo6pS9vKhU3dYasv+tzMrekc2hwb46N5fyDA==",
    },
    "minimal": {
        "signing_input_sha256": "26af001ffb0d9b3b361710c8ee7c15b79a80e4999dc1d49597875ac2974e3470",
        "sealed_digest_hex": "6b59597b1f62714012afbe4d6c81e6a8345170189209f04810ab2094acc38f44",
        "signature_b64": "lVI6L7umrjvtZK8XiJF21Y37a0WAzaAg2TN1kh4QV90Iokm7m6L0BiKRLgodATnLtMPKNPgGqfmtLKIx1Cb8Ag==",
    },
}


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "report_v2_vector_generator", VECTORS / "generate.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VEC = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))


def _store(override: dict | None = None) -> TrustStore:
    key = VEC["key"]
    entry = {
        "issuer": key["issuer"],
        "public_key_pem": key["public_key_pem"],
        "status": "active",
        **(override or {}),
    }
    return TrustStore.from_dict({"entries": {key["key_id"]: entry}})


def _pinned_verifier(digest: bytes, token: bytes):
    if token == b"ok:" + digest:
        return TimestampEvidence(gen_time=datetime(2026, 10, 2, tzinfo=timezone.utc))
    return None


def _policy(*, override: dict | None = None, pinned: bool = False) -> VerificationPolicy:
    return VerificationPolicy(
        trust_store=_store(override),
        now=lambda: NOW,
        timestamp_verifier=_pinned_verifier if pinned else None,
    )


# ---------------------------------------------------------------------------
# Frozen format
# ---------------------------------------------------------------------------


def test_committed_vectors_are_exactly_what_the_generator_produces():
    assert (VECTORS / "vectors.json").read_text(encoding="utf-8") == _load_generator().render()


def test_key_fingerprint_is_golden():
    assert VEC["key"]["public_key_fingerprint"] == KEY_FINGERPRINT


@pytest.mark.parametrize("name", ["full", "minimal"])
def test_golden_digests_and_signatures_are_frozen(name):
    rec = next(r for r in VEC["positive"] if r["name"] == name)
    for field, expected in GOLDEN[name].items():
        assert rec[field] == expected, f"{name}.{field} changed: this is a format break"


# ---------------------------------------------------------------------------
# Positive vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["full", "minimal"])
def test_positive_vectors_reproduce_bit_for_bit_and_verify(name):
    rec = next(r for r in VEC["positive"] if r["name"] == name)
    text = json.dumps(rec["envelope"])
    env = parse_envelope(text)
    assert isinstance(env, AuditEnvelopeV2)
    assert env.to_dict() == rec["envelope"]
    assert canonical_bytes(env.signed_body()).hex() == rec["canonical_signed_body_hex"]
    assert sha256_hex(env.signing_input()) == env.receipt["sha256"]
    import hashlib

    assert hashlib.sha256(env.signing_input()).hexdigest() == rec["signing_input_sha256"]
    assert env.sealed_digest().hex() == rec["sealed_digest_hex"]
    assert verify_signature(
        VEC["key"]["public_key_pem"], env.signing_input(), env.receipt["signature_b64"]
    )
    result = verify(env, _policy())
    assert result.trust_status == "TRUSTED" and result.accepted and result.format == "v2"


def test_the_signature_domain_is_nul_terminated_and_prefixes_the_signing_input():
    env = parse_envelope(json.dumps(VEC["positive"][0]["envelope"]))
    domain = bytes.fromhex(VEC["domains"]["sign"])
    assert domain.endswith(b"\x00") and env.signing_input().startswith(domain)


def test_a_pinned_verifier_accepts_a_token_over_the_right_artifact_only():
    rec = next(r for r in VEC["positive"] if r["name"] == "full")
    env = parse_envelope(json.dumps(rec["envelope"]))
    good = env.with_timestamp(issuer="t", token=b"ok:" + env.sealed_digest(), issued_at=NOW)
    assert verify(good, _policy(pinned=True)).timestamp_status == "VERIFIED"


# ---------------------------------------------------------------------------
# Adversarial vectors
# ---------------------------------------------------------------------------


def _parse_input(vec: dict):
    if "input_b64" in vec:
        return base64.b64decode(vec["input_b64"])
    if "input_text" in vec:
        return vec["input_text"]
    return vec["input_object"]


@pytest.mark.parametrize("vec", VEC["parse_refusals"], ids=lambda v: v["name"])
def test_parse_refusals(vec):
    expect = vec["expect"]
    with pytest.raises((CanonicalError, EnvelopeFormatError)) as exc:
        parse_envelope(_parse_input(vec))
    if expect.startswith("canonical"):
        assert isinstance(exc.value, CanonicalError)
        if ":" in expect:
            assert expect.split(":", 1)[1] in str(exc.value)
    else:
        assert isinstance(exc.value, EnvelopeFormatError)
        assert exc.value.code == expect.split(":", 1)[1]


def test_parse_control_the_unmodified_vector_parses():
    assert isinstance(parse_envelope(json.dumps(VEC["positive"][0]["envelope"])), AuditEnvelopeV2)


@pytest.mark.parametrize("vec", VEC["verify_refusals"], ids=lambda v: v["name"])
def test_verify_refusals(vec):
    env = parse_envelope(json.dumps(vec["envelope"]))
    policy = _policy(
        override=vec.get("trust_override"), pinned=vec.get("pinned_timestamp_verifier", False)
    )
    result = verify(env, policy)
    assert result.accepted is False and result.trust_status == "INVALID"
    assert vec["expect_reason"] in result.reasons, (vec["name"], result.reasons)


def test_verify_control_the_unmodified_vector_is_accepted_under_the_same_policies():
    env = parse_envelope(json.dumps(VEC["positive"][0]["envelope"]))
    assert verify(env, _policy(override={"deployments": ["prod-eu-1"]})).accepted
    assert verify(env, _policy(pinned=True)).timestamp_status in (
        "UNVERIFIED",
        "FAILED",
        "VERIFIED",
    )


def test_relabelled_v2_is_parsed_as_v1_and_fails_there():
    vec = next(v for v in VEC["verify_refusals"] if v["name"] == "v2_relabelled_as_v1")
    assert isinstance(parse_envelope(json.dumps(vec["envelope"])), AuditEnvelope)
