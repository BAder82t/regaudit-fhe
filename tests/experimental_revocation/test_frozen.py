"""Freeze checks: the draft-v1 schemas and golden vectors may not change without a version bump."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from . import proto
from .gen_fixtures import NOW, dump, golden_text, make_world

DIR = Path(__file__).resolve().parents[2] / "docs/proposals/revocation-list.v1"

PINNED = {
    "revocation-list.v1.schema.json": "409f578c881e34ddd45f28eb503f887180684d5c96fb7cfcf415ebf993259322",
    "authority-transition.v1.schema.json": "448d94a50d3b7217428e6a2036e5bd36f05910ae221e38f7d70ac6daf596fa0f",
    "authority-recovery.v1.schema.json": "91f7bff93ffea58f8a676603d385dafd7a419eee67894b44d58e569469882c65",
    "golden-vectors.json": "9968a55e896b8bd54df8817c99305352291c0a743a82c59619c695ff24bc0c50",
}


# Frozen proposal v2. The formats above did not change for it. Editing either file needs a deliberate re-pin.
PINNED_DOCUMENTS = {
    "docs/TRUST_REVOCATION_PROTOCOL_PROPOSAL.md": "7b87c13766da85e66d1728217566d6ac2431b6b5de289d0e6cd836101378a23e",
    "docs/proposals/revocation-list.v1/TEST_MATRIX.md": "7af04b04ec35ac90b16ed0bc2a45a348ec63f19d57cc999460d5f64ce8455e20",
}


@pytest.mark.parametrize("name", sorted(PINNED_DOCUMENTS))
def test_frozen_documents_match_their_pinned_digest(name):
    data = (DIR.parents[2] / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == PINNED_DOCUMENTS[name], f"{name} changed: re-pin deliberately"


@pytest.mark.parametrize("name", sorted(PINNED))
def test_frozen_files_match_their_pinned_digest(name):
    digest = hashlib.sha256((DIR / name).read_bytes()).hexdigest()
    assert digest == PINNED[name], f"{name} changed: a frozen proposal file needs a version bump"


def test_golden_vectors_are_exactly_what_the_generator_produces():
    assert (DIR / "golden-vectors.json").read_text() == golden_text()


def test_golden_vectors_verify_with_the_prototype():
    g = json.loads((DIR / "golden-vectors.json").read_text())
    w = make_world()
    anchor = proto.Anchor(w.issuer, g["keys"]["revocation_authority_1"]["public_key_pem"])
    assert anchor.fingerprint == g["keys"]["revocation_authority_1"]["fingerprint"]
    l1 = g["list_epoch1_retired"]
    res1 = proto.verify_list(dump(l1["document"]), anchor, w.store(), proto.RevocationState(), NOW)
    assert res1.accepted and res1.digest == l1["digest"]
    state = proto.commit(proto.RevocationState(), anchor, res1)
    l2 = g["list_epoch2_replaced_and_compromised"]
    res2 = proto.verify_list(
        dump(l2["document"]), anchor, w.store(w.old, w.new, w.third), state, NOW
    )
    assert res2.accepted and res2.digest == l2["digest"]
    enrolled = w.enrolled()
    tr = g["authority_transition"]
    t = proto.verify_transition(dump(tr["document"]), enrolled, None, NOW)
    assert t.accepted and t.digest == tr["digest"]
    rc = g["authority_recovery"]
    full = proto.commit(enrolled, enrolled.enrollments[w.issuer].anchor, res1)
    r = proto.verify_recovery(dump(rc["document"]), full, None, NOW)
    assert r.accepted and r.digest == rc["digest"]


def test_golden_signing_inputs_use_the_documented_domain_prefixes():
    g = json.loads((DIR / "golden-vectors.json").read_text())
    tr = g["authority_transition"]["document"]
    body = proto.canonical_bytes({k: v for k, v in tr.items() if k != "signatures"})
    assert (
        g["authority_transition"]["signing_input_from_sha256"]
        == hashlib.sha256(
            b"regaudit-fhe/revocation-authority-transition/v1/sign-from\x00" + body
        ).hexdigest()
    )
    rc = g["authority_recovery"]["document"]
    rbody = proto.canonical_bytes({k: v for k, v in rc.items() if k != "signatures"})
    assert (
        g["authority_recovery"]["signing_input_anchor_sha256"]
        == hashlib.sha256(
            b"regaudit-fhe/revocation-authority-recovery/v1/sign-anchor\x00" + rbody
        ).hexdigest()
    )
    lst = g["list_epoch1_retired"]["document"]
    lbody = proto.canonical_bytes({k: v for k, v in lst.items() if k != "signature"})
    assert (
        g["list_epoch1_retired"]["signing_input_sha256"]
        == hashlib.sha256(b"regaudit-fhe/revocation-list/v1/sign\x00" + lbody).hexdigest()
    )


# ----- the other two draft schemas agree with the prototype on structural tamper


def _validator(name):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((DIR / name).read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


TRANSITION_TAMPER = [
    lambda d: d.update(extra=1),
    lambda d: d.pop("valid_until"),
    lambda d: d["from_authority"].update(generation=0),
    lambda d: d["to_authority"].pop("public_key_pem"),
    lambda d: d["to_authority"].update(key_fingerprint="XYZ"),
    lambda d: d["signatures"].pop("to"),
    lambda d: d["signatures"]["from"].update(algorithm="rsa"),
    lambda d: d.update(schema="other"),
    lambda d: d.update(schema_version=2),
]

RECOVERY_TAMPER = [
    lambda d: d.update(extra=1),
    lambda d: d.update(recovery_epoch=0),
    lambda d: d.update(declares_compromised=[]),
    lambda d: d["declares_compromised"][0].update(key_fingerprint="short"),
    lambda d: d["new_authority"].pop("generation"),
    lambda d: d.update(rebase={"epoch": 0, "list_digest": "a" * 64}),
    lambda d: d["signatures"].pop("anchor"),
    lambda d: d["recovery_anchor"].update(key_fingerprint="nothex"),
    lambda d: d.update(schema="other"),
]


def test_transition_schema_and_prototype_agree():
    w = make_world()
    v = _validator("authority-transition.v1.schema.json")
    good = w.transition(w.rev, w.auth2)
    assert not list(v.iter_errors(good))
    proto.validate_transition_shape(good)
    for mutate in TRANSITION_TAMPER:
        bad = copy.deepcopy(good)
        mutate(bad)
        assert list(v.iter_errors(bad))
        if bad.get("schema_version") == 2:
            continue  # a version bump is well-formed; the verifier refuses it separately
        with pytest.raises(proto.ShapeError):
            proto.validate_transition_shape(bad)


def test_recovery_schema_and_prototype_agree():
    w = make_world()
    v = _validator("authority-recovery.v1.schema.json")
    good = w.recovery_stmt(w.auth2, rebase={"epoch": 1, "list_digest": "a" * 64})
    assert not list(v.iter_errors(good))
    proto.validate_recovery_shape(good)
    assert not list(v.iter_errors(w.recovery_stmt(w.auth2)))  # rebase null
    for mutate in RECOVERY_TAMPER:
        bad = copy.deepcopy(good)
        mutate(bad)
        assert list(v.iter_errors(bad))
        with pytest.raises(proto.ShapeError):
            proto.validate_recovery_shape(bad)
