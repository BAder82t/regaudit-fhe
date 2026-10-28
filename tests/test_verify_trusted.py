"""verify_trusted(): TRUSTED / SELF_SIGNED_ONLY / INVALID, and strict parsing on every TRUSTED path.

Synthetic keys and data only. Each strictness test names the ambiguity it closes; the
"lenient parser still accepts it" assertions document that ``parse_envelope`` is unchanged
(a compatibility decision, see docs/MIGRATION_0.2.md).
"""

from __future__ import annotations

import copy
import json
import re

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.report_v2 import EnvelopeFormatError, parse_envelope, parse_envelope_strict


@pytest.fixture(scope="module")
def report():
    return rf.audit_drift(np.array([0.2, 0.3, 0.5]), np.array([0.25, 0.25, 0.5]))


@pytest.fixture(scope="module")
def signer():
    return rf.Signer.generate(issuer="acme", key_id="acme-1")


@pytest.fixture(scope="module")
def other():
    return rf.Signer.generate(issuer="mallory", key_id="mallory-1")


@pytest.fixture(scope="module")
def store(signer):
    return rf.TrustStore.from_dict({"keys": {"acme-1": signer.public_key_pem()}})


@pytest.fixture(scope="module")
def v1(report, signer):
    return rf.envelope("drift", report, signer=signer, regulations=["A", "B"])


@pytest.fixture(scope="module")
def v2(report, signer):
    return rf.envelope_v2("drift", report, signer=signer, deployment_id="dep-1")


# --------------------------------------------------------------------------- verdicts


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_a_report_signed_by_an_enrolled_key_is_trusted(fmt, v1, v2, store):
    env = v1 if fmt == "v1" else v2
    out = rf.verify_trusted(env.to_json(), store)
    assert out.verdict is rf.TrustVerdict.TRUSTED
    assert out.trusted is True
    assert out.result is not None and out.result.accepted


def test_input_forms_text_bytes_mapping_and_object_agree(v2, store):
    text = v2.to_json()
    for form in (text, text.encode(), json.loads(text), v2):
        assert rf.verify_trusted(form, store).trusted


def test_an_impostor_with_the_same_names_is_invalid_not_trusted(report, other, store):
    forged = rf.envelope_v2("drift", report, signer=other, deployment_id="dep-1")
    out = rf.verify_trusted(forged.to_json(), store)
    assert out.verdict is rf.TrustVerdict.INVALID and not out.trusted


def test_the_impostor_is_self_signed_only_without_a_trust_store(report, other):
    forged = rf.envelope_v2("drift", report, signer=other, deployment_id="dep-1")
    own = rf.verify_report(forged, rf.VerificationPolicy(allow_self_signed=True))
    assert own.trust_status == "SELF_SIGNED_ONLY" and not own.accepted


def test_a_trust_store_is_required_and_never_defaulted(v2):
    for missing in (None, {"acme-1": "pem"}, "store.json"):
        with pytest.raises(TypeError, match="TrustStore"):
            rf.verify_trusted(v2.to_json(), missing)  # type: ignore[arg-type]


def test_allow_self_signed_in_the_policy_cannot_loosen_the_check(report, other, store):
    forged = rf.envelope_v2("drift", report, signer=other, deployment_id="dep-1")
    policy = rf.VerificationPolicy(allow_self_signed=True)
    assert not rf.verify_trusted(forged.to_json(), store, policy=policy).trusted


def test_the_explicit_trust_store_overrides_the_one_in_the_policy(v2, other, store):
    wrong = rf.TrustStore.from_dict({"keys": {"acme-1": other.public_key_pem()}})
    policy = rf.VerificationPolicy(trust_store=wrong)
    assert rf.verify_trusted(v2.to_json(), store, policy=policy).trusted


def test_the_result_has_no_truth_value(v2, store):
    out = rf.verify_trusted(v2.to_json(), store)
    with pytest.raises(TypeError, match="no truth value"):
        bool(out)
    with pytest.raises(TypeError):
        if out:  # pragma: no cover
            pass


def test_revoked_key_and_audience_policy_still_apply(report, signer):
    revoked = rf.TrustStore.from_dict(
        {"keys": {"acme-1": signer.public_key_pem()}, "revoked": ["acme-1"]}
    )
    env = rf.envelope_v2("drift", report, signer=signer, deployment_id="d", audience=["verifier-a"])
    assert not rf.verify_trusted(env.to_json(), revoked).trusted
    live = rf.TrustStore.from_dict({"keys": {"acme-1": signer.public_key_pem()}})
    mine = rf.VerificationPolicy(verifier_id="verifier-a")
    elsewhere = rf.VerificationPolicy(verifier_id="verifier-b")
    assert rf.verify_trusted(env.to_json(), live, policy=mine).trusted
    assert not rf.verify_trusted(env.to_json(), live, policy=elsewhere).trusted


def test_a_changed_result_is_invalid(v2, store):
    data = v2.to_dict()
    data["result"]["distance"] = data["result"]["distance"] + 0.5
    out = rf.verify_trusted(json.dumps(data), store)
    assert out.verdict is rf.TrustVerdict.INVALID
    assert "HASH_MISMATCH" in out.reasons or "SIGNATURE_INVALID" in out.reasons


def test_the_json_form_of_the_verdict_never_says_trusted_for_a_refusal(report, other, store):
    forged = rf.envelope_v2("drift", report, signer=other, deployment_id="dep-1")
    d = rf.verify_trusted(forged.to_json(), store).to_dict()
    assert d["verdict"] == "INVALID" and d["trusted"] is False


# --------------------------------------------------------------------------- strict v1


def _variants(v1_env):
    base = v1_env.to_dict()
    out = {}
    v = copy.deepcopy(base)
    v["approved_by"] = "regulator"
    out["unknown top-level member"] = v
    v = copy.deepcopy(base)
    v["result"] = [[k, x] for k, x in base["result"].items()]
    out["result as a list of pairs"] = v
    v = copy.deepcopy(base)
    v["regulations"] = "AB"
    out["regulations as a string"] = v
    v = copy.deepcopy(base)
    del v["backend"]
    out["defaulted member omitted"] = v
    v = copy.deepcopy(base)
    v["dp"] = None
    out["null for an optional member"] = v
    v = copy.deepcopy(base)
    v["receipt"]["note"] = "unsigned"
    out["extra member in the unsigned receipt"] = v
    v = copy.deepcopy(base)
    v["timestamp"] = {"issuer": "t", "token_b64": "AA==", "issued_at": "x", "extra": 1}
    out["extra member in the unsigned timestamp"] = v
    v = copy.deepcopy(base)
    v["primitive"] = ["drift"]
    out["primitive of the wrong type"] = v
    return out


def test_every_v1_variant_verifies_leniently_and_is_refused_strictly(v1, store):
    """These all verified as TRUSTED before; the lenient parser still accepts them (unchanged)."""
    for name, data in _variants(v1).items():
        if name == "primitive of the wrong type":
            continue  # never verified: it is a signature/hash mismatch or crash, see below
        lenient = rf.verify_report(parse_envelope(data), rf.VerificationPolicy(trust_store=store))
        assert lenient.trust_status == "TRUSTED", name
        strict = rf.verify_trusted(json.dumps(data), store)
        assert strict.verdict is rf.TrustVerdict.INVALID and "MALFORMED_REPORT" in strict.reasons, (
            name
        )
        with pytest.raises(EnvelopeFormatError):
            parse_envelope_strict(data)


def test_hostile_primitive_type_is_a_refusal_not_a_crash(v1, store):
    data = _variants(v1)["primitive of the wrong type"]
    out = rf.verify_trusted(json.dumps(data), store)
    assert out.verdict is rf.TrustVerdict.INVALID


def test_duplicate_keys_nan_and_trailing_data_in_text_are_refused(v1, v2, store):
    for env in (v1, v2):
        text = env.to_json()
        dup = text.replace('"issuer": "acme"', '"issuer": "acme", "issuer": "acme"', 1)
        assert dup != text
        nan = re.sub(r'("distance": )[-0-9.e]+', r"\1NaN", text, count=1)
        for hostile in (dup, text.rstrip() + " {}", "\ufeff" + text, nan):
            assert hostile != text
            assert not rf.verify_trusted(hostile, store).trusted


def test_a_mapping_with_non_json_values_is_refused(v2, store):
    data = v2.to_dict()
    data["result"] = dict(data["result"], extra=(1, 2))
    assert not rf.verify_trusted(data, store).trusted
    data = v2.to_dict()
    data["result"] = dict(data["result"], extra=float("nan"))
    assert not rf.verify_trusted(data, store).trusted
    data = v2.to_dict()
    data["result"] = dict(data["result"], extra=np.float64(1.0))
    assert not rf.verify_trusted(data, store).trusted


def test_v2_defaulted_member_and_aliasing_are_refused(v2, store):
    data = v2.to_dict()
    data["timestamps"] = []
    assert not rf.verify_trusted(json.dumps(data), store).trusted
    data = v2.to_dict()
    data["audience"] = None
    assert not rf.verify_trusted(json.dumps(data), store).trusted


def test_relabelled_v2_as_v1_is_refused_at_parse_by_the_strict_path(v2, store):
    data = v2.to_dict()
    data["schema"] = data["schema_version"] = "regaudit-fhe.report.v1"
    assert isinstance(parse_envelope(data), rf.AuditEnvelope)  # lenient parser unchanged
    out = rf.verify_trusted(json.dumps(data), store)
    assert out.verdict is rf.TrustVerdict.INVALID and "MALFORMED_REPORT" in out.reasons


def test_the_strict_parser_accepts_what_the_library_writes(v1, v2):
    for env in (v1, v2):
        assert parse_envelope_strict(env.to_json()).to_dict() == env.to_dict()


def test_a_non_finite_result_is_never_trusted(report, signer, store):
    """A v1 body signed over NaN (reachable only by bypassing envelope validation) is refused."""
    import regaudit_fhe.reports as reports

    env = rf.envelope("drift", report, signer=signer)
    d = env.to_dict()
    d["result"]["distance"] = float("nan")
    body = {k: v for k, v in d.items() if k not in ("receipt", "timestamp")}
    raw = reports.canonical_json(body)  # allow_nan default: signs the literal NaN
    d["receipt"]["sha256"] = reports.sha256_hex(raw)
    import base64

    d["receipt"]["signature_b64"] = base64.b64encode(signer.sign(raw)).decode()
    lenient = rf.verify_report(
        rf.AuditEnvelope.from_dict(d), rf.VerificationPolicy(trust_store=store)
    )
    assert lenient.trust_status == "TRUSTED"  # the engine alone cannot see it
    assert not rf.verify_trusted(rf.AuditEnvelope.from_dict(d), store).trusted
