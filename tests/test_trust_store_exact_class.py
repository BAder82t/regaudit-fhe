"""A strict policy reads issuer binding from validated records, not from an object that can answer whatever it likes (F-09).

Malicious code in the verifier's own process, ``object.__setattr__`` for one, is outside the guarantee and is not tested here.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.trust import KeyEntry, TrustStoreError
from regaudit_fhe.verification import PolicyError, VerificationPolicy, verify

STRICT = ("confidential", "high-assurance", "secure-v1")
T = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
BOB = rf.Signer.generate(issuer="bob-lab", key_id="bob-1")
FORGED = rf.Signer(issuer="alice-bank", key_id="bob-1", private_key=BOB.private_key, public_key=BOB.public_key)
PEM = BOB.public_key_pem()
RESULT = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
ENTRIES = {"entries": {"bob-1": {"issuer": "bob-lab", "public_key_pem": PEM, "status": "active"}}}


def report(who=FORGED):
    return envelope_v2(
        "drift", RESULT, signer=who, deployment_id="p", audience=("reg",), issued_at=T,
        audit_run_id="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6d1",
    )  # fmt: skip


def strict(profile: str, store, tmp_path: Path) -> VerificationPolicy:
    return VerificationPolicy(
        profile=profile, trust_store=store, now=lambda: T, max_age=timedelta(hours=1), verifier_id="reg",
        replay_mode="record", replay_cache=SqliteReplayCache(tmp_path / f"{profile}.db"),
    )  # fmt: skip


class ClaimsBinding(rf.TrustStore):
    """A legacy store that says it binds issuers."""

    @property
    def binds_issuers(self) -> bool:
        return True


class LiesAboutEntry(rf.TrustStore):
    """An entries store whose lookup hides the enrolled issuer."""

    def entry(self, key_id):
        found = super().entry(key_id)
        return None if found is None else dataclasses.replace(found, issuer=None)


class Plain(rf.TrustStore):
    """Adds nothing at all: still not what a strict policy reads."""


def _build(cls, payload):
    base = rf.TrustStore.from_dict(payload)
    return cls(
        keys=base.keys, revoked=base.revoked, parameter_set_pins=base.parameter_set_pins, entries=base.entries,
        as_of=base.as_of,
    )  # fmt: skip


SUBCLASSES = {
    "claims binding on a legacy store": (ClaimsBinding, {"keys": {"bob-1": PEM}}),
    "lies about an entry": (LiesAboutEntry, ENTRIES),
    "adds nothing": (Plain, ENTRIES),
}


@pytest.mark.parametrize("name", sorted(SUBCLASSES))
@pytest.mark.parametrize("profile", STRICT)
def test_a_subclass_is_refused_under_a_strict_policy(name, profile, tmp_path):
    with pytest.raises(PolicyError, match="exactly a TrustStore"):
        strict(profile, _build(*SUBCLASSES[name]), tmp_path)


@pytest.mark.parametrize("profile", STRICT)
def test_replace_cannot_put_a_subclass_in(profile, tmp_path):
    pol = strict(profile, rf.TrustStore.from_dict(ENTRIES), tmp_path)
    with pytest.raises(PolicyError, match="exactly a TrustStore"):
        dataclasses.replace(pol, trust_store=_build(ClaimsBinding, {"keys": {"bob-1": PEM}}))


def test_verify_trusted_with_a_strict_policy_refuses_it(tmp_path):
    pol = strict("confidential", rf.TrustStore.from_dict(ENTRIES), tmp_path)
    with pytest.raises(PolicyError, match="exactly a TrustStore"):
        rf.verify_trusted(json.dumps(report().to_dict()), _build(LiesAboutEntry, ENTRIES), policy=pol)


class EvilEntry(KeyEntry):
    """Passes every check when the store is built, and answers differently later."""

    def __getattribute__(self, name):
        return object.__getattribute__(self, name)


class EqualsAnything(str):
    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

    __hash__ = str.__hash__


def test_a_key_entry_subclass_in_an_exact_store_does_not_count_as_bound(tmp_path):
    entry = EvilEntry(key_id="bob-1", public_key_pem=PEM, status="active", issuer="bob-lab")
    store = rf.TrustStore(keys={"bob-1": PEM}, entries={"bob-1": entry})
    assert type(store) is rf.TrustStore and not store.binds_issuers
    for profile in STRICT:
        with pytest.raises(PolicyError, match="states the issuer of each key"):
            strict(profile, store, tmp_path)


def test_an_issuer_that_compares_equal_to_anything_is_not_a_name():
    entry = KeyEntry(key_id="bob-1", public_key_pem=PEM, status="active", issuer=EqualsAnything("bob-lab"))
    with pytest.raises(TrustStoreError, match="issuer"):
        rf.TrustStore(keys={"bob-1": PEM}, entries={"bob-1": entry})


@pytest.mark.parametrize(
    "change",
    [
        {"status": type("S", (str,), {})("active")},
        {"public_key_pem": type("P", (str,), {})(PEM)},
        {"deployments": type("D", (frozenset,), {"__contains__": lambda self, item: True})({"x"})},
        {"primitives": type("D", (frozenset,), {"__contains__": lambda self, item: True})({"drift"})},
        {"parameter_set_pin": EqualsAnything("0" * 64)},
    ],
    ids=["status", "pem", "deployments", "primitives", "pin"],
)
def test_a_record_with_a_substituted_field_does_not_count_as_bound(change, tmp_path):
    entry = dataclasses.replace(
        KeyEntry(key_id="bob-1", public_key_pem=PEM, status="active", issuer="bob-lab"), **change
    )
    pins = {"bob-1": entry.parameter_set_pin} if entry.parameter_set_pin else {}
    store = rf.TrustStore(keys={"bob-1": PEM}, entries={"bob-1": entry}, parameter_set_pins=pins)
    assert not store.binds_issuers


def test_a_key_id_that_is_not_a_plain_string_does_not_count_as_bound():
    kid = type("K", (str,), {})("bob-1")
    entry = KeyEntry(key_id=kid, public_key_pem=PEM, status="active", issuer="bob-lab")
    assert not rf.TrustStore(keys={kid: PEM}, entries={kid: entry}).binds_issuers


# ------------------------------------------------------------------ what keeps working


@pytest.mark.parametrize("profile", STRICT)
def test_control_a_loaded_entries_store_is_accepted_and_the_guard_still_refuses_the_substitution(profile, tmp_path):
    store = rf.TrustStore.from_dict(ENTRIES)
    assert type(store) is rf.TrustStore and store.binds_issuers
    assert verify(report(FORGED), strict(profile, store, tmp_path)).blocking_reasons == ("ISSUER_MISMATCH",)
    res = verify(report(BOB), strict(profile, store, tmp_path))
    assert res.accepted and res.issuer_trusted


def test_control_a_store_from_a_file_enrolled_the_normal_way(tmp_path):
    (tmp_path / "t.json").write_text(json.dumps(ENTRIES))
    assert rf.TrustStore.from_json(tmp_path / "t.json").binds_issuers


def test_control_replace_on_a_store_recomputes_from_the_records():
    store = rf.TrustStore.from_dict(ENTRIES)
    assert dataclasses.replace(store).binds_issuers
    assert not rf.TrustStore.from_dict({"keys": {"bob-1": PEM}}).binds_issuers


def test_development_is_not_a_strict_boundary_and_is_unchanged():
    res = verify(report(BOB), VerificationPolicy(trust_store=_build(Plain, ENTRIES)))
    assert res.accepted


def test_the_lenient_verifier_does_not_believe_a_subclass_about_binding():
    env = rf.envelope("drift", RESULT, signer=FORGED)
    with pytest.warns(DeprecationWarning, match="states no issuer"):
        out = rf.verify_envelope(env, trust_store=_build(ClaimsBinding, {"keys": {"bob-1": PEM}}))
    assert out.trust_status == "TRUSTED" and not out.issuer_bound
