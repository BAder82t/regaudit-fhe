"""``report.v2`` envelope: signed identity, strict parsing, domain separation."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone

import numpy as np
import pytest
from cryptography.hazmat.primitives import serialization

import regaudit_fhe as rf
from regaudit_fhe.canonical import CanonicalError, canonical_bytes
from regaudit_fhe.report_v2 import (
    SCHEMA_V2,
    SEAL_DOMAIN,
    SIGN_DOMAIN,
    AuditEnvelopeV2,
    EnvelopeFormatError,
    envelope_v2,
    parse_envelope,
    public_key_fingerprint,
)
from regaudit_fhe.reports import AuditEnvelope, sha256_hex, verify_signature

RUN_ID = "3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f7"
ISSUED = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64


def _report():
    return rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )


def _signer(key_id="acme-1"):
    return rf.Signer.generate(issuer="acme-health", key_id=key_id)


def _env(signer=None, **kw) -> AuditEnvelopeV2:
    signer = signer or _signer()
    args = dict(
        deployment_id="prod-eu-1",
        audit_run_id=RUN_ID,
        issued_at=ISSUED,
        audience=["regulator-a"],
        model_commitment={"name": "model", "sha256": SHA_A},
        dataset_commitment={"name": "dataset", "sha256": "b" * 64},
    )
    args.update(kw)
    return envelope_v2("fairness", _report(), signer=signer, **args)


# ---------------------------------------------------------------------------
# Construction and signed identity
# ---------------------------------------------------------------------------


def test_envelope_v2_signs_complete_identity():
    signer = _signer()
    env = _env(signer)
    body = env.signed_body()
    assert body["schema"] == SCHEMA_V2 == body["schema_version"]
    assert body["issuer"] == "acme-health"
    assert body["key_id"] == "acme-1"
    assert body["public_key_fingerprint"] == public_key_fingerprint(signer.public_key_pem())
    assert body["deployment_id"] == "prod-eu-1"
    assert body["audit_run_id"] == RUN_ID
    assert body["audience"] == ["regulator-a"]
    assert body["model_commitment"] == {"name": "model", "sha256": SHA_A}
    assert body["dataset_commitment"]["name"] == "dataset"
    assert body["trust_policy_version"] == 1
    # The receipt carries no identity: nothing signed depends on unsigned fields.
    assert set(env.receipt) == {"sha256", "signature_alg", "signature_b64", "public_key_pem"}
    assert "receipt" not in body and "timestamps" not in body


def test_fingerprint_is_sha256_of_spki_der():
    signer = _signer()
    der = signer.public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert public_key_fingerprint(signer.public_key_pem()) == hashlib.sha256(der).hexdigest()


def test_signature_verifies_over_domain_separated_input():
    signer = _signer()
    env = _env(signer)
    sig = env.receipt["signature_b64"]
    assert env.signing_input() == SIGN_DOMAIN + canonical_bytes(env.signed_body())
    assert verify_signature(signer.public_key_pem(), env.signing_input(), sig)
    assert env.receipt["sha256"] == sha256_hex(env.signing_input())


def test_signature_is_not_valid_over_the_bare_canonical_body():
    """Domain separation: the v2 signature must not validate as a v1 signature."""
    signer = _signer()
    env = _env(signer)
    bare = canonical_bytes(env.signed_body())
    assert not verify_signature(signer.public_key_pem(), bare, env.receipt["signature_b64"])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issuer", "mallory"),
        ("key_id", "acme-2"),
        ("public_key_fingerprint", "c" * 64),
        ("deployment_id", "prod-us-1"),
        ("audit_run_id", "11111111-2222-4333-8444-555555555555"),
        ("audience", ["regulator-b"]),
        ("model_commitment", {"name": "model", "sha256": "d" * 64}),
        ("dataset_commitment", {"name": "dataset", "sha256": "d" * 64}),
        ("trust_policy_version", 2),
        ("issued_at", "2026-10-02T12:00:00+00:00"),
        ("primitive", "drift"),
    ],
)
def test_every_identity_field_is_covered_by_the_signature(field, value):
    signer = _signer()
    env = _env(signer)
    assert verify_signature(
        signer.public_key_pem(), env.signing_input(), env.receipt["signature_b64"]
    )
    data = env.to_dict()
    data[field] = value
    tampered = AuditEnvelopeV2.from_dict(data)
    assert not verify_signature(
        signer.public_key_pem(), tampered.signing_input(), tampered.receipt["signature_b64"]
    )


def test_optional_fields_are_omitted_not_null():
    env = _env(audience=None, model_commitment=None, dataset_commitment=None)
    body = env.signed_body()
    for key in ("audience", "model_commitment", "dataset_commitment", "dp"):
        assert key not in body


def test_audit_run_id_defaults_to_fresh_uuid4():
    a = envelope_v2("fairness", _report(), signer=_signer(), deployment_id="d")
    b = envelope_v2("fairness", _report(), signer=_signer(), deployment_id="d")
    assert a.audit_run_id != b.audit_run_id
    assert str(__import__("uuid").UUID(a.audit_run_id)) == a.audit_run_id


def test_builder_refuses_empty_deployment_and_bad_audience():
    with pytest.raises(EnvelopeFormatError):
        envelope_v2("fairness", _report(), signer=_signer(), deployment_id="")
    with pytest.raises(EnvelopeFormatError):
        envelope_v2("fairness", _report(), signer=_signer(), deployment_id="d", audience=[])
    with pytest.raises(EnvelopeFormatError):
        envelope_v2(
            "fairness", _report(), signer=_signer(), deployment_id="d", audit_run_id="not-a-uuid"
        )


# ---------------------------------------------------------------------------
# Strict parsing
# ---------------------------------------------------------------------------


def test_roundtrip_through_dict_and_json():
    env = _env()
    assert AuditEnvelopeV2.from_dict(env.to_dict()) == env
    assert parse_envelope(json.dumps(env.to_dict())) == env
    assert parse_envelope(json.dumps(env.to_dict()).encode()) == env


def _mutate(env, fn):
    data = copy.deepcopy(env.to_dict())
    fn(data)
    return data


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.update(extra_field=1),
        lambda d: d["receipt"].update(key_id="acme-1"),
        lambda d: d["receipt"].update(unexpected=1),
        lambda d: d["depth_budget"].update(extra=1),
        lambda d: d["input_commitments"][0].update(extra="x") if d["input_commitments"] else None,
    ],
    ids=["top-level", "receipt-key_id", "receipt-other", "depth_budget", "commitment"],
)
def test_unknown_fields_are_refused(mutation):
    env = _env(input_commitments=rf.commitments_for({"y": np.array([1, 2])}))
    assert AuditEnvelopeV2.from_dict(env.to_dict()) == env  # control
    with pytest.raises(EnvelopeFormatError) as exc:
        AuditEnvelopeV2.from_dict(_mutate(env, mutation))
    assert exc.value.code == "UNKNOWN_FIELD"


@pytest.mark.parametrize(
    "field",
    [
        "schema",
        "issuer",
        "key_id",
        "public_key_fingerprint",
        "deployment_id",
        "audit_run_id",
        "trust_policy_version",
        "receipt",
        "issued_at",
        "result",
    ],
)
def test_missing_required_fields_are_refused(field):
    data = _env().to_dict()
    del data[field]
    with pytest.raises(EnvelopeFormatError) as exc:
        AuditEnvelopeV2.from_dict(data)
    assert exc.value.code == "MISSING_FIELD"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issuer", ""),
        ("issuer", 5),
        ("key_id", None),
        ("deployment_id", ["x"]),
        ("audit_run_id", "3F2B1C4E-5A6D-4E7F-8091-A2B3C4D5E6F7"),
        ("audit_run_id", "3f2b1c4e5a6d4e7f8091a2b3c4d5e6f7"),
        ("public_key_fingerprint", "A" * 64),
        ("public_key_fingerprint", "a" * 63),
        ("trust_policy_version", True),
        ("trust_policy_version", -1),
        ("trust_policy_version", 1.5),
        ("audience", []),
        ("audience", ["a", "a"]),
        ("audience", ["a", ""]),
        ("audience", "regulator-a"),
        ("model_commitment", None),
        ("model_commitment", {"name": "m"}),
        ("model_commitment", {"name": "m", "sha256": "xyz"}),
        ("issued_at", "2026-10-01T12:00:00"),
        ("issued_at", "yesterday"),
        ("primitive", "unknown"),
        ("parameter_set_hash", "nothex"),
        ("regulations", "NYC_LL144"),
    ],
)
def test_bad_values_and_types_are_refused(field, value):
    data = _env().to_dict()
    data[field] = value
    with pytest.raises(EnvelopeFormatError) as exc:
        AuditEnvelopeV2.from_dict(data)
    assert exc.value.code in {"BAD_TYPE", "BAD_VALUE", "MISSING_FIELD"}


@pytest.mark.parametrize("schema", ["regaudit-fhe.report.v1", "regaudit-fhe.report.v3", "", None])
def test_v2_loader_refuses_other_schema_values(schema):
    data = _env().to_dict()
    data["schema"] = schema
    with pytest.raises(EnvelopeFormatError):
        AuditEnvelopeV2.from_dict(data)


def test_schema_and_schema_version_must_agree():
    data = _env().to_dict()
    data["schema_version"] = "regaudit-fhe.report.v1"
    with pytest.raises(EnvelopeFormatError):
        AuditEnvelopeV2.from_dict(data)


def test_receipt_algorithm_and_hashes_are_validated():
    for key, value in (("signature_alg", "RSA"), ("sha256", "zz"), ("signature_b64", "")):
        data = _env().to_dict()
        data["receipt"][key] = value
        with pytest.raises(EnvelopeFormatError):
            AuditEnvelopeV2.from_dict(data)


# ---------------------------------------------------------------------------
# Format dispatch
# ---------------------------------------------------------------------------


def test_parse_envelope_dispatches_on_schema():
    v2 = _env()
    assert isinstance(parse_envelope(v2.to_dict()), AuditEnvelopeV2)
    signer = _signer()
    v1 = rf.envelope("fairness", _report(), signer=signer)
    assert isinstance(parse_envelope(v1.to_dict()), AuditEnvelope)


@pytest.mark.parametrize("schema", ["regaudit-fhe.report.v9", "", None, 2])
def test_parse_envelope_refuses_unknown_schema(schema):
    data = _env().to_dict()
    data["schema"] = schema
    with pytest.raises(EnvelopeFormatError) as exc:
        parse_envelope(data)
    assert exc.value.code == "BAD_SCHEMA"


def test_parse_envelope_refuses_non_object_and_malformed_text():
    for text in ("[]", '"x"', "null", "{", ""):
        with pytest.raises((EnvelopeFormatError, CanonicalError)):
            parse_envelope(text)


def test_parse_envelope_refuses_duplicate_keys_in_text():
    text = json.dumps(_env().to_dict())
    assert parse_envelope(text)  # control
    dup = text[:-1] + ', "issuer": "mallory"}'
    with pytest.raises(CanonicalError, match="duplicate"):
        parse_envelope(dup)


def test_relabelled_v2_as_v1_does_not_parse_as_the_same_signed_artifact():
    """Downgrade: take a v2 artifact, change its schema label to v1."""
    env = _env()
    data = env.to_dict()
    data["schema"] = data["schema_version"] = "regaudit-fhe.report.v1"
    parsed = parse_envelope(data)  # the lenient v1 loader tolerates it...
    assert isinstance(parsed, AuditEnvelope)
    # ...but v1 verification covers different bytes, so the v2 signature cannot hold.
    assert not rf.verify_envelope(parsed).signature_valid


# ---------------------------------------------------------------------------
# Sealed digest (timestamp binding)
# ---------------------------------------------------------------------------


def test_sealed_digest_is_domain_separated_and_covers_signature_and_key():
    env = _env()
    digest = env.sealed_digest()
    assert len(digest) == 32
    expected = hashlib.sha256(
        SEAL_DOMAIN
        + canonical_bytes(
            {
                "signed_body": env.signed_body(),
                "signature_alg": env.receipt["signature_alg"],
                "signature_b64": env.receipt["signature_b64"],
            }
        )
    ).digest()
    assert digest == expected
    # not equal to the v1-style digest of the body alone
    assert digest != hashlib.sha256(canonical_bytes(env.signed_body())).digest()
    assert digest != hashlib.sha256(env.signing_input()).digest()


def test_sealed_digest_changes_with_signature_and_with_key_identity():
    a = _env(_signer())
    b = _env(_signer())  # different key, therefore different key fingerprint and signature
    assert a.sealed_digest() != b.sealed_digest()
    data = a.to_dict()
    data["receipt"]["signature_b64"] = b.receipt["signature_b64"]
    assert AuditEnvelopeV2.from_dict(data).sealed_digest() != a.sealed_digest()


def test_sealed_digest_ignores_timestamps_and_embedded_pem():
    env = _env()
    stamped = env.with_timestamp(issuer="tsa.example", token=b"tok", issued_at=ISSUED)
    assert stamped.timestamps and not env.timestamps
    assert stamped.sealed_digest() == env.sealed_digest()
    assert stamped.signing_input() == env.signing_input()
    data = env.to_dict()
    data["receipt"]["public_key_pem"] = _signer().public_key_pem()
    assert AuditEnvelopeV2.from_dict(data).sealed_digest() == env.sealed_digest()


def test_timestamps_roundtrip_and_are_strictly_parsed():
    env = _env().with_timestamp(issuer="tsa.example", token=b"tok", issued_at=ISSUED)
    assert AuditEnvelopeV2.from_dict(env.to_dict()) == env
    data = env.to_dict()
    data["timestamps"][0]["extra"] = 1
    with pytest.raises(EnvelopeFormatError):
        AuditEnvelopeV2.from_dict(data)
    data = env.to_dict()
    data["timestamps"] = {"issuer": "x"}
    with pytest.raises(EnvelopeFormatError):
        AuditEnvelopeV2.from_dict(data)


# ---------------------------------------------------------------------------
# Security review findings
# ---------------------------------------------------------------------------


def _b64_variant(text: str) -> str:
    """Same decoded bytes, different text: flip the unused trailing bits."""
    import base64

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    body = text.rstrip("=")
    pad = text[len(body) :]
    last = alphabet.index(body[-1])
    if pad == "==":
        alt = alphabet[last ^ 0b1111]
    elif pad == "=":
        alt = alphabet[last ^ 0b11]
    else:
        raise AssertionError("signature has no padding bits to vary")
    variant = body[:-1] + alt + pad
    assert base64.b64decode(variant, validate=True) == base64.b64decode(text)
    return variant


def test_non_canonical_base64_signature_is_refused():
    """Otherwise anyone could change the text, keep the signature valid, and
    change the sealed digest that timestamp tokens bind."""
    env = _env()
    sig = env.receipt["signature_b64"]
    data = env.to_dict()
    data["receipt"]["signature_b64"] = _b64_variant(sig)
    with pytest.raises(EnvelopeFormatError, match="canonical"):
        AuditEnvelopeV2.from_dict(data)
    assert AuditEnvelopeV2.from_dict(env.to_dict()) == env  # control


def test_signature_must_decode_to_exactly_64_bytes():
    import base64

    for raw in (b"", b"x" * 63, b"x" * 65):
        data = _env().to_dict()
        data["receipt"]["signature_b64"] = base64.b64encode(raw).decode()
        with pytest.raises(EnvelopeFormatError):
            AuditEnvelopeV2.from_dict(data)


def test_non_canonical_base64_timestamp_token_is_refused():
    env = _env().with_timestamp(issuer="t", token=b"ab", issued_at=ISSUED)  # 2 bytes -> "YWI="
    data = env.to_dict()
    data["timestamps"][0]["token_b64"] = "YWJ="  # decodes to the same bytes, non-canonical
    with pytest.raises(EnvelopeFormatError, match="canonical"):
        AuditEnvelopeV2.from_dict(data)
    assert AuditEnvelopeV2.from_dict(env.to_dict()) == env  # control


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), "\ud800", b"bytes", {1: "x"}],
    ids=["nan", "inf", "surrogate", "bytes", "int-key"],
)
def test_free_form_fields_are_canonically_checked_on_parse(value):
    data = _env().to_dict()
    data["result"] = {"x": value}
    with pytest.raises(EnvelopeFormatError):
        AuditEnvelopeV2.from_dict(data)


def test_deeply_nested_free_form_fields_raise_envelope_format_error():
    nested: object = "x"
    for _ in range(5000):
        nested = [nested]
    data = _env().to_dict()
    data["result"] = {"deep": nested}
    with pytest.raises(EnvelopeFormatError):
        AuditEnvelopeV2.from_dict(data)


@pytest.mark.parametrize(
    "bad",
    [
        "2026-10-01x12:00:00+00:00",  # arbitrary separator
        "20261001T120000Z",  # basic format
        "2026-10-01T12:00:00+00:00:30",  # offset with seconds
        "2026-10-01T12:00:00.1234567+00:00",  # more than microsecond precision
        "2026-10-01 12:00:00+00:00",  # space separator
        "2026-10-01T12:00:00",  # no offset
        "2026-10-01",
        "2026-13-01T12:00:00Z",
    ],
)
def test_issued_at_must_be_strict_rfc3339(bad):
    data = _env().to_dict()
    data["issued_at"] = bad
    with pytest.raises(EnvelopeFormatError):
        AuditEnvelopeV2.from_dict(data)


@pytest.mark.parametrize(
    "good",
    [
        "2026-10-01T12:00:00Z",
        "2026-10-01T12:00:00+00:00",
        "2026-10-01T12:00:00.123456+02:00",
        "2026-10-01t12:00:00z",
    ],
)
def test_strict_rfc3339_accepts_valid_forms(good):
    data = _env().to_dict()
    data["issued_at"] = good
    assert AuditEnvelopeV2.from_dict(data).issued_at == good


def test_with_timestamp_requires_an_aware_datetime():
    with pytest.raises(ValueError, match="aware"):
        _env().with_timestamp(issuer="t", token=b"x", issued_at=datetime(2026, 1, 1))


# ---------------------------------------------------------------------------
# Python-version independence of timestamp parsing (3.10 accepts only 3 or 6
# fractional digits in fromisoformat, so the fraction is normalised first)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "microsecond"),
    [
        ("2026-01-01T00:00:00Z", 0),
        ("2026-01-01T00:00:00.5Z", 500000),
        ("2026-01-01T00:00:00.12+00:00", 120000),
        ("2026-01-01T00:00:00.123Z", 123000),
        ("2026-01-01T00:00:00.1234+01:00", 123400),
        ("2026-01-01T00:00:00.123456Z", 123456),
    ],
)
def test_rfc3339_fractions_of_any_length_up_to_six_digits(text, microsecond):
    import regaudit_fhe._time as t

    assert t.parse_rfc3339(text).microsecond == microsecond


def test_rfc3339_hands_fromisoformat_only_six_digit_fractions(monkeypatch):
    import regaudit_fhe._time as t

    seen: list[str] = []
    real = t.datetime

    class Spy:
        @staticmethod
        def fromisoformat(text: str):
            seen.append(text)
            return real.fromisoformat(text)

    monkeypatch.setattr(t, "datetime", Spy)
    t.parse_rfc3339("2026-01-01T00:00:00.5Z")
    assert seen == ["2026-01-01T00:00:00.500000+00:00"]
