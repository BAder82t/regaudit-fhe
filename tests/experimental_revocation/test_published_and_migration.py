"""Reports signed by the published versions under every profile, and trust-store migration.

Rows V* and T* of the test matrix. ``published_vectors/by_*.json`` were signed by the published 0.1.0, 0.1.1, 0.2.0
and 0.2.1 wheels, downloaded from PyPI with their SHA-256 checked (see generate.py). The expected verdicts below are written from
docs/TRUST_SPEC.md and the proposal, not derived from the engine's output.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import regaudit_fhe as rf
from regaudit_fhe import _trust_lifecycle as lc
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import parse_envelope_strict
from regaudit_fhe.trust import TrustStore
from regaudit_fhe.verification import PolicyError, VerificationPolicy, verify

from . import trust_gate as tg
from .gen_fixtures import dump, make_world

VECTORS = Path(__file__).resolve().parent / "published_vectors"
VERSIONS = ("0.1.0", "0.1.1", "0.2.0", "0.2.1")
KINDS = ("v1", "v2-no-audience", "v2-audience")
PROFILES = ("development", "confidential", "high-assurance")
NOW = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)
ISSUED = "2026-11-02T09:00:00Z"
UNTIL = "2026-11-09T09:00:00Z"
BEFORE = "2026-09-01T00:00:00Z"
ISSUER = "vector-issuer"
KEY = "vec-key"


def vec(version: str) -> dict[str, Any]:
    return json.loads((VECTORS / f"by_{version}.json").read_text())


PEM = vec("0.2.0")["public_key_pem"]


def _entry(**kw: Any) -> dict[str, Any]:
    return {"entries": {KEY: {"issuer": ISSUER, "public_key_pem": PEM, "status": "active", **kw}}}


STORES: dict[str, dict[str, Any]] = {
    "bare": {KEY: PEM},
    "legacy-active": {"keys": {KEY: PEM}, "revoked": []},
    "legacy-revoked": {"keys": {KEY: PEM}, "revoked": [KEY]},
    "entries-active": _entry(),
    "entries-retired": _entry(status="retired", retired_at=BEFORE),
    "entries-compromised": _entry(status="compromised"),
}

# Key-state refusal per store form, for a report with no verified timestamp.
RETIRED = {"KEY_RETIRED_NO_CHRONOLOGY", "TRUST_STORE_FRESHNESS_UNPROVEN"}
COMPROMISED = {"KEY_COMPROMISED_NO_CHRONOLOGY"}
UNBOUND_FORMS = ("bare", "legacy-active", "legacy-revoked")
KEY_STATE: dict[str, set[str]] = {
    "bare": set(),
    "legacy-active": set(),
    "legacy-revoked": {"KEY_REVOKED"},
    "entries-active": set(),
    "entries-retired": RETIRED,
    "entries-compromised": COMPROMISED,
}


def expected(kind: str, profile: str, key_codes: set[str]) -> set[str]:
    """TRUST_SPEC 4, 7, 9.4 and C.2 item 13. The replay check runs last and only if nothing else blocked."""
    out = set(key_codes)
    if profile == "high-assurance":
        if kind == "v1":
            out |= {"LEGACY_V1_FORMAT", "AUDIENCE_MISMATCH"}
        elif kind == "v2-no-audience":
            out |= {"AUDIENCE_MISMATCH"}
    if profile != "development" and kind == "v1" and not out:
        out |= {"REPLAY_ID_MISSING"}
    return out


def policy(tmp_path: Path, profile: str, store: TrustStore) -> VerificationPolicy:
    kw: dict[str, Any] = {}
    if profile != "development":
        kw = {
            "max_age": timedelta(days=90),
            "replay_mode": "record",
            "verifier_id": "reg",
            "replay_cache": SqliteReplayCache(tmp_path / f"{profile}.db"),
        }
    return VerificationPolicy(
        profile=profile, trust_store=store, now=lambda: NOW, check_provenance=True, **kw
    )


def report(version: str, kind: str):
    return parse_envelope_strict(json.dumps(vec(version)["reports"][kind]))


def test_vectors_were_signed_by_the_version_they_are_named_after():
    for version in VERSIONS:
        data = vec(version)
        assert data["signed_by"] == version and data["public_key_pem"] == PEM
        for kind in KINDS:
            body = data["reports"][kind]
            assert body["algorithm_version"] == version


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("form", sorted(STORES))
@pytest.mark.parametrize("profile", PROFILES)
def test_V01_without_opt_in_every_published_report_keeps_its_verdict(
    tmp_path, version, kind, form, profile
):
    store = TrustStore.from_dict(STORES[form])
    if profile != "development" and form in UNBOUND_FORMS:
        # F-09, owner's ruling: these policies refuse a store that states no issuer, before any report is read.
        # test_T05 holds the same reports to this table on the migrated store.
        with pytest.raises(PolicyError, match="states the issuer of each key"):
            policy(tmp_path, profile, store)
        return
    pol = policy(tmp_path, profile, store)
    env = report(version, kind)
    d = tg.verify_with_revocation(
        env, pol, tg.RevocationContext(tg.MODE_OFF, tg.MemoryCasStore(), {})
    )
    want = expected(kind, profile, KEY_STATE[form])
    assert d.revocation is None
    assert d.result.policy_id == f"regaudit-fhe/{profile}/v1"
    assert d.result.integrity_valid
    assert set(d.result.blocking_reasons) == want, (version, kind, form, profile)
    assert d.result.accepted is (not want)


@pytest.mark.parametrize("version", VERSIONS)
def test_V05_a_parameter_set_pin_binds_the_signer_version_today_and_stays_that_way(tmp_path, version):
    """The hash covers library_version. Existing behaviour, recorded because it is the one version effect."""
    pinned_to = vec("0.2.0")["reports"]["v2-audience"]["parameter_set_hash"]
    store = TrustStore.from_dict(_entry(parameter_set_pin=pinned_to))
    res = verify(report(version, "v2-audience"), policy(tmp_path, "development", store))
    if version == "0.2.0":
        assert res.accepted
    else:
        assert not res.accepted and res.blocking_reasons == ("PIN_MISMATCH",)
    w = _world()
    ctx = _context(w, [], store)
    required = tmp_path / "required"
    required.mkdir()
    d = tg.verify_with_revocation(
        report(version, "v2-audience"), policy(required, "development", store), ctx
    )
    assert d.result.accepted is res.accepted
    assert d.result.blocking_reasons == res.blocking_reasons


# ------------------------------------------------------------------ opt-in


def _pin(w) -> tg.Pin:
    return tg.Pin(ISSUER, w.rev.public_key_pem(), "enr", baseline_epoch=0)


def _world():
    return make_world(ISSUER)


def _entry_for_list(w, status: str, effective_from: str | None) -> dict[str, Any]:
    from regaudit_fhe._keys import spki_fingerprint

    return {
        "key_id": KEY,
        "key_fingerprint": spki_fingerprint(PEM),
        "status": status,
        "effective_from": effective_from,
    }


def _context(w, listed: list[dict[str, Any]] | None, store: TrustStore):
    s = tg.MemoryCasStore()
    p = _pin(w)
    tg.enroll(s, p, now=NOW - timedelta(days=1))
    if listed is not None:
        doc = w.signed(1, listed, issued_at=ISSUED, valid_until=UNTIL)
        assert tg.ingest_list(s, p, dump(doc), store, NOW).accepted
    return tg.RevocationContext(tg.MODE_REQUIRED, s, {ISSUER: p})


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize(
    ("listed", "key_codes"),
    [
        ([], set()),
        ([("retired", BEFORE)], RETIRED),
        ([("compromised", None)], COMPROMISED),
    ],
    ids=["not-listed", "retired", "compromised"],
)
def test_V02_required_mode_with_fresh_data(tmp_path, version, kind, profile, listed, key_codes):
    w = _world()
    store = TrustStore.from_dict(_entry())
    ctx = _context(w, [_entry_for_list(w, *x) for x in listed], store)
    d = tg.verify_with_revocation(report(version, kind), policy(tmp_path, profile, store), ctx)
    want = expected(kind, profile, key_codes)
    assert set(d.result.blocking_reasons) == want
    assert d.result.accepted is (not want)
    assert d.result.policy_id == f"regaudit-fhe/{profile}+revocation-required/v1"


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("profile", PROFILES)
def test_V03_required_mode_with_no_data_refuses_every_published_report(
    tmp_path, version, kind, profile
):
    store = TrustStore.from_dict(_entry())
    ctx = _context(_world(), None, store)
    d = tg.verify_with_revocation(report(version, kind), policy(tmp_path, profile, store), ctx)
    assert not d.result.accepted and d.result.trust_status == "INVALID"
    assert "REVOCATION_DATA_ABSENT" in d.result.blocking_reasons
    assert d.result.integrity_valid  # origin is still established; current authorization is not


@pytest.mark.parametrize("form", ["bare", "legacy-active", "legacy-revoked"])
@pytest.mark.parametrize("mode", [tg.MODE_ADVISORY, tg.MODE_REQUIRED])
def test_V04_opting_in_with_a_legacy_store_is_a_configuration_error_not_a_verdict(
    tmp_path, form, mode
):
    store = TrustStore.from_dict(STORES[form])
    # F-09: confidential refuses this store on its own now, which is also a configuration error and not a verdict. Only
    # development reaches the gate's check, so that is where this asserts it.
    with pytest.raises(PolicyError, match="states the issuer of each key"):
        policy(tmp_path, "confidential", store)
    pol = policy(tmp_path, "development", store)
    ctx = tg.RevocationContext(mode, tg.MemoryCasStore(), {ISSUER: _pin(_world())})
    with pytest.raises(PolicyError, match="REVOCATION_STORE_UNSUPPORTED"):
        tg.verify_with_revocation(report("0.2.1", "v2-audience"), pol, ctx)


# ------------------------------------------------------------------ migration


def migrated(form: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    return tg.migrate_store(STORES[form], {KEY: ISSUER}, as_of="2026-11-02T00:00:00Z")


@pytest.mark.parametrize(
    ("form", "status"),
    [("bare", "active"), ("legacy-active", "active"), ("legacy-revoked", "compromised")],
)
def test_T01_legacy_forms_migrate_to_the_expected_state(form, status):
    out, rows = migrated(form)
    entry = TrustStore.from_dict(out).entries[KEY]
    assert entry.status == status and entry.compromised_from is None and entry.retired_at is None
    assert entry.issuer == ISSUER and rows[0]["to"] == status


def test_T02_legacy_revoked_is_never_retired():
    out, rows = migrated("legacy-revoked")
    entry = TrustStore.from_dict(out).entries[KEY]
    assert entry.status == "compromised" and entry.compromised_from is None
    assert rows[0]["reason_code_change"] == "KEY_REVOKED -> KEY_COMPROMISED_NO_CHRONOLOGY"


def test_T03_pins_survive_migration():
    pin = "a" * 64
    out, _ = tg.migrate_store(
        {"keys": {KEY: PEM}, "parameter_set_pins": {KEY: pin}},
        {KEY: ISSUER},
        as_of="2026-11-02T00:00:00Z",
    )
    assert TrustStore.from_dict(out).entries[KEY].parameter_set_pin == pin


@pytest.mark.parametrize(
    ("payload", "issuers", "text"),
    [
        (STORES["entries-active"], {KEY: ISSUER}, "already"),
        (STORES["bare"], {}, "never inferred"),
        (STORES["bare"], {KEY: ISSUER, "ghost": ISSUER}, "unknown"),
    ],
)
def test_T04_migration_refusals(payload, issuers, text):
    with pytest.raises(tg.MigrationRefused, match=text):
        tg.migrate_store(payload, issuers, as_of="2026-11-02T00:00:00Z")


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("form", ["bare", "legacy-active", "legacy-revoked"])
@pytest.mark.parametrize("profile", PROFILES)
def test_T05_migration_preserves_the_accept_or_refuse_outcome_for_the_right_issuer(
    tmp_path, version, kind, form, profile
):
    env = report(version, kind)
    source = tmp_path / "old.json"
    source.write_text(json.dumps(STORES[form]))
    lc.migrate(str(source), str(tmp_path / "new.json"), {KEY: ISSUER}, now=NOW)
    new = TrustStore.from_json(tmp_path / "new.json")
    if profile != "development":
        # Owner's ruling: a migrated issuer is a local operator's statement and must not be treated as authenticated
        # enrollment, so this store does not satisfy a strict policy. The accept-or-refuse table for these policies on an
        # entries store is V01's, on a store the migration did not write.
        with pytest.raises(PolicyError, match="ISSUER_ENROLLMENT_UNAUTHENTICATED"):
            policy(tmp_path, profile, new)
        return
    before = verify(env, policy(tmp_path, profile, TrustStore.from_dict(STORES[form])))
    after_dir = tmp_path / "after"
    after_dir.mkdir()
    after = verify(env, policy(after_dir, profile, new))
    expected_blocking = set(before.blocking_reasons)
    if "KEY_REVOKED" in expected_blocking:
        expected_blocking = (expected_blocking - {"KEY_REVOKED"}) | {"KEY_COMPROMISED_NO_CHRONOLOGY"}
        assert after.key_status == "compromised"
    assert after.accepted is (not expected_blocking)
    assert set(after.blocking_reasons) == expected_blocking


def test_T06_a_wrong_issuer_statement_changes_the_verdict_and_the_report_says_so():
    """This is why migration is opt-in: an issuer statement can newly refuse a report."""
    out, rows = tg.migrate_store(STORES["bare"], {KEY: "someone-else"}, as_of="2026-11-02T00:00:00Z")
    assert rows[0]["new_refusal_possible"] == "ISSUER_MISMATCH"
    env = report("0.2.1", "v2-audience")
    now = lambda: NOW  # noqa: E731
    assert verify(
        env, VerificationPolicy(trust_store=TrustStore.from_dict(STORES["bare"]), now=now)
    ).accepted
    res = verify(env, VerificationPolicy(trust_store=TrustStore.from_dict(out), now=now))
    assert not res.accepted and "ISSUER_MISMATCH" in res.blocking_reasons


def test_T07_migrated_store_works_with_the_lifecycle_commands(tmp_path):
    from regaudit_fhe import _trust_lifecycle as lc

    out, _ = migrated("legacy-active")
    path = tmp_path / "store.json"
    path.write_text(json.dumps(out))
    lc.retire(str(path), KEY, at=BEFORE, now=NOW)
    assert TrustStore.from_json(path).entries[KEY].status == "retired"


def test_T08_lifecycle_commands_still_refuse_the_legacy_forms(tmp_path):
    from regaudit_fhe import _trust_lifecycle as lc

    path = tmp_path / "store.json"
    path.write_text(json.dumps(STORES["legacy-active"]))
    before = path.read_bytes()
    with pytest.raises(rf.TrustStoreError):
        lc.retire(str(path), KEY, at=BEFORE, now=NOW)
    assert path.read_bytes() == before


def test_T09_after_migration_opting_in_works_and_a_local_only_state_stays(tmp_path):
    out, _ = migrated("legacy-revoked")
    store = TrustStore.from_dict(out)
    w = _world()
    ctx = _context(w, [], store)  # the issuer's list does not mention this key
    # A migrated store's record now survives from_dict, so a strict profile refuses it (owner's ruling): the gate is
    # reached under development.
    with pytest.raises(PolicyError, match="ISSUER_ENROLLMENT_UNAUTHENTICATED"):
        policy(tmp_path, "high-assurance", store)
    d = tg.verify_with_revocation(
        report("0.2.1", "v2-audience"), policy(tmp_path, "development", store), ctx
    )
    assert not d.result.accepted and "KEY_COMPROMISED_NO_CHRONOLOGY" in d.result.blocking_reasons
