"""Trust-store entries: key lifecycle, scope and validation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.trust import KeyEntry, TrustStore, TrustStoreError


def _signer(key_id="k1"):
    return rf.Signer.generate(issuer="acme", key_id=key_id)


def _entry(signer, **over):
    base = {"issuer": signer.issuer, "public_key_pem": signer.public_key_pem(), "status": "active"}
    base.update(over)
    return base


def _store(signer, **over) -> TrustStore:
    return TrustStore.from_dict({"entries": {signer.key_id: _entry(signer, **over)}})


def test_entries_form_loads_all_fields():
    s = _signer()
    store = _store(
        s,
        not_before="2026-01-01T00:00:00Z",
        deployments=["prod-eu-1"],
        primitives=["fairness"],
        parameter_set_pin="a" * 64,
    )
    e = store.entry(s.key_id)
    assert isinstance(e, KeyEntry)
    assert e.status == "active" and e.issuer == "acme"
    assert e.not_before == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert e.deployments == frozenset({"prod-eu-1"})
    assert e.primitives == frozenset({"fairness"})
    assert e.parameter_set_pin == "a" * 64
    # legacy accessors stay consistent for Phase 1 callers
    assert store.is_known(s.key_id) and store.expected_pem(s.key_id) == store.keys[s.key_id]
    assert store.expected_parameter_set_hash(s.key_id) == "a" * 64


def test_retired_and_compromised_states():
    s = _signer()
    r = _store(s, status="retired", retired_at="2026-06-01T00:00:00+00:00").entry(s.key_id)
    assert r is not None and r.status == "retired" and r.retired_at is not None
    c = _store(s, status="compromised", compromised_from="2026-07-01T00:00:00+00:00").entry(
        s.key_id
    )
    assert c is not None and c.status == "compromised" and c.compromised_from is not None
    unknown = _store(s, status="compromised").entry(s.key_id)
    assert unknown is not None and unknown.compromised_from is None  # unknown boundary


def test_retired_requires_retired_at():
    s = _signer()
    with pytest.raises(TrustStoreError):
        _store(s, status="retired")
    assert _store(s, status="retired", retired_at="2026-06-01T00:00:00Z")  # control


@pytest.mark.parametrize(
    "over",
    [
        {"status": "revoked"},
        {"status": "ACTIVE"},
        {"issuer": ""},
        {"not_before": "2026-01-01T00:00:00"},  # naive
        {"not_before": "last week"},
        {"deployments": []},
        {"deployments": "prod"},
        {"primitives": ["nope"]},
        {"parameter_set_pin": "short"},
        {"retired_at": "2026-06-01T00:00:00Z"},  # not allowed unless retired
        {"compromised_from": "2026-06-01T00:00:00Z"},  # not allowed unless compromised
        {"unexpected": 1},
        {"public_key_pem": "not a pem"},
    ],
)
def test_invalid_entries_are_refused(over):
    s = _signer()
    assert _store(s)  # control
    with pytest.raises(TrustStoreError):
        _store(s, **over)


def test_issuer_is_required_in_entries_form():
    s = _signer()
    entry = _entry(s)
    del entry["issuer"]
    with pytest.raises(TrustStoreError):
        TrustStore.from_dict({"entries": {s.key_id: entry}})


def test_entries_cannot_be_mixed_with_legacy_keys():
    s = _signer()
    with pytest.raises(TrustStoreError):
        TrustStore.from_dict(
            {"entries": {s.key_id: _entry(s)}, "keys": {s.key_id: s.public_key_pem()}}
        )
    with pytest.raises(TrustStoreError):
        TrustStore.from_dict({"entries": {s.key_id: _entry(s)}, "revoked": []})


def test_entries_must_be_a_nonempty_object():
    for bad in ({}, [], "x", None):
        with pytest.raises(TrustStoreError):
            TrustStore.from_dict({"entries": bad})


def test_as_of_is_parsed_and_validated():
    s = _signer()
    payload = {"entries": {s.key_id: _entry(s)}, "as_of": "2026-10-01T00:00:00Z"}
    assert TrustStore.from_dict(payload).as_of == datetime(2026, 10, 1, tzinfo=timezone.utc)
    payload["as_of"] = "soon"
    with pytest.raises(TrustStoreError):
        TrustStore.from_dict(payload)


def test_legacy_stores_synthesise_entries():
    s = _signer()
    store = TrustStore.from_dict(
        {
            "keys": {s.key_id: s.public_key_pem()},
            "parameter_set_pins": {s.key_id: "b" * 64},
        }
    )
    e = store.entry(s.key_id)
    assert e is not None and e.status == "active" and e.issuer is None
    assert e.parameter_set_pin == "b" * 64
    revoked = TrustStore.from_dict(
        {"keys": {s.key_id: s.public_key_pem()}, "revoked": [s.key_id]}
    ).entry(s.key_id)
    assert revoked is not None and revoked.status == "revoked" and revoked.compromised_from is None
    assert TrustStore.from_dict({"keys": {s.key_id: s.public_key_pem()}}).entry("other") is None


def test_json_file_roundtrip(tmp_path: Path):
    s = _signer()
    p = tmp_path / "ts.json"
    p.write_text(json.dumps({"entries": {s.key_id: _entry(s)}}))
    assert TrustStore.from_json(p).entry(s.key_id) is not None


def test_phase1_api_treats_non_active_keys_as_revoked():
    """Phase 1 helpers cannot evaluate chronology, so a retired or compromised
    key must never be accepted through them."""
    s = _signer()
    env = rf.envelope(
        "fairness",
        rf.audit_fairness(
            np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([0.0, 1.0])
        ),
        signer=s,
    )
    active = _store(s)
    assert rf.verify_envelope(env, trust_store=active).trust_status == "TRUSTED"
    for over in (
        {"status": "retired", "retired_at": "2026-06-01T00:00:00Z"},
        {"status": "compromised"},
    ):
        store = _store(s, **over)
        assert store.is_revoked(s.key_id)
        out = rf.verify_envelope(env, trust_store=store)
        assert out.trust_status == "INVALID" and out.revoked is True
        assert rf.verify_receipt(env, trust_store=store, strict=True) is False


# ---------------------------------------------------------------------------
# Security review findings
# ---------------------------------------------------------------------------


def test_same_key_under_two_key_ids_is_refused():
    """A compromised key must not be usable by relabelling it with another key_id."""
    s = _signer("k1")
    both = {
        "k1": _entry(s, status="compromised"),
        "k2": _entry(s, status="active"),
    }
    with pytest.raises(TrustStoreError, match="same public key"):
        TrustStore.from_dict({"entries": both})
    assert TrustStore.from_dict({"entries": {"k1": both["k1"]}})  # control


def test_duplicate_keys_are_detected_across_pem_formatting():
    s = _signer("k1")
    reformatted = s.public_key_pem().replace("\n", "\r\n") + "\r\n\r\n"
    with pytest.raises(TrustStoreError, match="same public key"):
        TrustStore.from_dict(
            {"entries": {"k1": _entry(s), "k2": _entry(s, public_key_pem=reformatted)}}
        )


def test_legacy_form_also_refuses_one_key_under_two_ids():
    s = _signer("k1")
    with pytest.raises(TrustStoreError, match="same public key"):
        TrustStore.from_dict({"keys": {"k1": s.public_key_pem(), "k2": s.public_key_pem()}})


def test_pem_must_parse_as_an_ed25519_public_key():
    s = _signer("k1")
    junk = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
    with pytest.raises(TrustStoreError):
        TrustStore.from_dict({"entries": {"k1": _entry(s, public_key_pem=junk)}})
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    ec_pem = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    with pytest.raises(TrustStoreError, match="Ed25519"):
        TrustStore.from_dict({"entries": {"k1": _entry(s, public_key_pem=ec_pem)}})


def test_trust_store_file_size_and_nesting_are_bounded(tmp_path: Path):
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 100000 + "]" * 100000)
    with pytest.raises(TrustStoreError):
        TrustStore.from_json(deep)
    big = tmp_path / "big.json"
    big.write_text('{"entries": {"k": "' + "a" * (5 * 1024 * 1024) + '"}}')
    with pytest.raises(TrustStoreError, match="size"):
        TrustStore.from_json(big)
