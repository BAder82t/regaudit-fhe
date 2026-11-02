"""A well-formed ``trust migrate --issuer`` is a local operator's statement, not proof, and it stays identified as one.

By the owner's ruling, it must not be treated as authenticated issuer enrollment: every strict profile refuses such a store.

The record is in the store, as ``issuer_source`` on each entry, so it travels with the store and survives ``cp``, ``mv`` and
``from_dict``. Every published version therefore refuses a migrated store, which fails closed: an older verifier is a downgrade
limitation, by the owner's ruling, and the source store stays the way back (the qualification harness runs the wheels). Deleting the member
is an edit of local state, outside the guarantee: the test named limit pins that.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe._keys import spki_fingerprint
from regaudit_fhe._trust_lifecycle import migrate_store
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.trust import ISSUER_PROVENANCE_SUFFIX, KeyEntry, TrustStoreError
from regaudit_fhe.verification import PolicyError, VerificationPolicy, verify

T = datetime.now(timezone.utc).replace(microsecond=0)
SIGNER = rf.Signer.generate(issuer="acme", key_id="k")
PEM = SIGNER.public_key_pem()
RESULT = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
STRICT = ("confidential", "high-assurance", "secure-v1")
STRICT_KW = ["--max-age-seconds", "3600", "--replay-mode", "record", "--replay-db", "x.db", "--verifier-id", "reg"]


def report(run="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f1"):
    return envelope_v2(
        "drift", RESULT, signer=SIGNER, deployment_id="p", audience=("reg",), issued_at=T, audit_run_id=run
    )


def cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", *args], capture_output=True, text=True, timeout=120, cwd=cwd, check=False
    )


@pytest.fixture
def migrated(tmp_path: Path) -> Path:
    (tmp_path / "old.json").write_text(json.dumps({"keys": {"k": PEM}}))
    out = cli("trust", "migrate", "--source", "old.json", "--target", "new.json", "--issuer", "k=acme", cwd=tmp_path)
    assert out.returncode == 0, out.stderr
    (tmp_path / "out.json").write_text(out.stdout)
    (tmp_path / "r.json").write_text(json.dumps(report().to_dict()))
    return tmp_path


def strict(profile, store, tmp_path, **kw):
    return VerificationPolicy(
        profile=profile, trust_store=store, now=lambda: T + timedelta(minutes=1), max_age=timedelta(hours=1),
        verifier_id="reg", replay_mode="record", replay_cache=SqliteReplayCache(tmp_path / f"{profile}.db"), **kw,
    )  # fmt: skip


def side(path: Path) -> Path:
    return path.with_name(path.name + ISSUER_PROVENANCE_SUFFIX)


# ------------------------------------------------------------------ what the operator is told


def test_the_output_says_this_is_a_statement_and_not_a_binding(migrated):
    body = json.loads((migrated / "out.json").read_text())
    assert body["issuer_binding"] == "operator-declared" and body["authenticated_binding"] is False
    assert body["keys"][0]["issuer_binding"] == "operator-declared"
    assert body["keys"][0]["authenticated_binding"] is False
    assert "not proof" in body["notice"] and "ISSUER_ENROLLMENT_UNAUTHENTICATED" in body["notice"]


def test_a_dry_run_says_the_same_and_writes_nothing(tmp_path):
    (tmp_path / "old.json").write_text(json.dumps({"keys": {"k": PEM}}))
    out = cli(
        "trust", "migrate", "--source", "old.json", "--target", "new.json", "--issuer", "k=acme", "--dry-run",
        cwd=tmp_path,
    )  # fmt: skip
    assert json.loads(out.stdout)["authenticated_binding"] is False
    assert not (tmp_path / "new.json").exists() and not side(tmp_path / "new.json").exists()


@pytest.mark.parametrize("command", [("trust", "list"), ("trust", "status")])
def test_list_and_status_show_it(command, migrated):
    body = json.loads(cli(*command, "--store", "new.json", cwd=migrated).stdout)
    rows = body if isinstance(body, list) else body["keys"]
    assert rows[0]["issuer_source"] == "operator-declared"


@pytest.mark.parametrize("command", [("trust", "list"), ("trust", "status")])
def test_control_a_store_never_migrated_has_no_new_field(command, tmp_path):
    (tmp_path / "t.json").write_text(
        json.dumps({"entries": {"k": {"issuer": "acme", "public_key_pem": PEM, "status": "active"}}})
    )
    body = json.loads(cli(*command, "--store", "t.json", cwd=tmp_path).stdout)
    rows = body if isinstance(body, list) else body["keys"]
    assert "issuer_source" not in rows[0]


# ------------------------------------------------------------------ the record is in the store


def test_the_store_records_it_on_each_entry_and_there_is_one_record(migrated):
    doc = json.loads((migrated / "new.json").read_text())
    assert doc["entries"]["k"]["issuer_source"] == "operator-declared"
    assert set(doc) == {"entries", "as_of"}
    assert set(doc["entries"]["k"]) == {"issuer", "public_key_pem", "status", "issuer_source"}
    assert not side(migrated / "new.json").exists()


@pytest.mark.parametrize("profile", STRICT)
def test_a_copy_or_a_move_keeps_the_refusal(profile, migrated, tmp_path_factory):
    other = tmp_path_factory.mktemp("elsewhere")
    shutil.copy(migrated / "new.json", other / "copied.json")
    shutil.move(migrated / "new.json", other / "moved.json")
    for name in ("copied.json", "moved.json"):
        store = rf.TrustStore.from_json(other / name)
        assert store.issuer_declared == {"k"}
        with pytest.raises(PolicyError, match="ISSUER_ENROLLMENT_UNAUTHENTICATED"):
            strict(profile, store, other)


@pytest.mark.parametrize("profile", STRICT)
def test_from_dict_keeps_the_refusal(profile, migrated):
    store = rf.TrustStore.from_dict(json.loads((migrated / "new.json").read_text()))
    assert store.issuer_declared == {"k"}
    with pytest.raises(PolicyError, match="ISSUER_ENROLLMENT_UNAUTHENTICATED"):
        strict(profile, store, migrated)


@pytest.mark.parametrize("profile", STRICT)
def test_migrate_store_in_the_library_keeps_the_refusal(profile, tmp_path):
    out, rows = migrate_store({"keys": {"k": PEM}}, {"k": "acme"}, as_of="2026-11-02T00:00:00Z")
    assert rows[0]["issuer_binding"] == "operator-declared"
    with pytest.raises(PolicyError, match="ISSUER_ENROLLMENT_UNAUTHENTICATED"):
        strict(profile, rf.TrustStore.from_dict(out), tmp_path)


@pytest.mark.parametrize("value", ["authenticated", "", "OPERATOR-DECLARED", None, 1, True])
def test_another_value_is_refused_not_ignored(value):
    doc = {"entries": {"k": {"issuer": "acme", "public_key_pem": PEM, "status": "active", "issuer_source": value}}}
    with pytest.raises(TrustStoreError, match="issuer_source"):
        rf.TrustStore.from_dict(doc)


def test_direct_construction_is_held_to_the_same_record():
    declared = KeyEntry(key_id="k", public_key_pem=PEM, status="active", issuer="acme", issuer_source="operator-declared")
    assert rf.TrustStore(keys={"k": PEM}, entries={"k": declared}).issuer_declared == {"k"}
    other = dataclasses.replace(declared, issuer_source="authenticated")
    with pytest.raises(TrustStoreError, match="issuer_source"):
        rf.TrustStore(keys={"k": PEM}, entries={"k": other})
    with pytest.raises(TypeError):
        rf.TrustStore(keys={"k": PEM}, entries={"k": declared}, issuer_declared=frozenset())  # type: ignore[call-arg]


@pytest.mark.parametrize("profile", STRICT)
def test_replace_on_a_store_cannot_drop_it(profile, migrated):
    store = rf.TrustStore.from_json(migrated / "new.json")
    copy = dataclasses.replace(store)
    assert copy.issuer_declared == {"k"}
    with pytest.raises(PolicyError, match="ISSUER_ENROLLMENT_UNAUTHENTICATED"):
        strict(profile, copy, migrated)


# ------------------------------------------------------------------ a file from the pre-release candidate


@pytest.mark.parametrize("profile", STRICT)
def test_an_old_record_file_beside_a_store_cannot_weaken_anything(profile, migrated, tmp_path):
    """A candidate kept the record in that file, so the store beside it has no member saying so. It must not load as clean."""
    bare = {"entries": {"k": {"issuer": "acme", "public_key_pem": PEM, "status": "active"}}}
    (tmp_path / "s.json").write_text(json.dumps(bare))
    side(tmp_path / "s.json").write_text('{"kind":"operator-declared","key_ids":["k"]}')
    with pytest.raises(TrustStoreError, match="pre-release"):
        rf.TrustStore.from_json(tmp_path / "s.json")
    out = cli("verify", "-i", "r.json", "--trusted-keys", str(tmp_path / "s.json"), "--profile", profile, *STRICT_KW, cwd=migrated)
    assert out.returncode == 3 and "pre-release" in out.stderr


@pytest.mark.parametrize("body", ["{", "", "[]", "anything"])
def test_any_such_file_is_refused_whatever_it_holds(body, migrated):
    side(migrated / "new.json").write_text(body)
    with pytest.raises(TrustStoreError, match="pre-release"):
        rf.TrustStore.from_json(migrated / "new.json")


def test_a_path_that_is_not_a_file_is_refused_too_without_blocking(migrated):
    os.mkfifo(side(migrated / "new.json"))
    with pytest.raises(TrustStoreError, match="pre-release"):
        rf.TrustStore.from_json(migrated / "new.json")


def test_a_symlinked_store_is_checked_at_the_real_path(migrated, tmp_path):
    os.symlink(migrated / "new.json", tmp_path / "link.json")
    assert rf.TrustStore.from_json(tmp_path / "link.json").issuer_declared == {"k"}
    side(migrated / "new.json").write_text("x")
    with pytest.raises(TrustStoreError, match="pre-release"):
        rf.TrustStore.from_json(tmp_path / "link.json")


def test_migration_will_not_run_beside_such_a_file(tmp_path):
    (tmp_path / "old.json").write_text(json.dumps({"keys": {"k": PEM}}))
    side(tmp_path / "new.json").write_text("mine")
    out = cli("trust", "migrate", "--source", "old.json", "--target", "new.json", "--issuer", "k=acme", cwd=tmp_path)
    assert out.returncode == 2 and side(tmp_path / "new.json").read_text() == "mine"
    assert not (tmp_path / "new.json").exists()


# ------------------------------------------------------------------ the profiles


def _with_second_key(migrated):
    other = rf.Signer.generate(issuer="other", key_id="k2")
    (migrated / "k2.pub").write_text(other.public_key_pem())
    out = cli(
        "trust", "add", "--store", "new.json", "--key-id", "k2", "--issuer", "other", "--public-key", "k2.pub",
        "--fingerprint", spki_fingerprint(other.public_key_pem()), cwd=migrated,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr


@pytest.mark.parametrize("profile", STRICT)
def test_every_strict_profile_refuses_it_and_says_why(profile, migrated):
    store = rf.TrustStore.from_json(migrated / "new.json")
    assert store.binds_issuers and store.issuer_declared == {"k"}
    with pytest.raises(PolicyError, match="ISSUER_ENROLLMENT_UNAUTHENTICATED"):
        strict(profile, store, migrated)


@pytest.mark.parametrize("profile", STRICT)
def test_every_strict_profile_refuses_it_on_the_cli(profile, migrated):
    out = cli("verify", "-i", "r.json", "--trusted-keys", "new.json", "--profile", profile, *STRICT_KW, cwd=migrated)
    assert out.returncode == 2 and "ISSUER_ENROLLMENT_UNAUTHENTICATED" in out.stderr
    assert not out.stdout  # no issuer_trusted, no issuer_binding, nothing that reads as a binding


@pytest.mark.parametrize("profile", STRICT)
def test_a_strict_policy_cannot_be_moved_onto_it(profile, migrated, tmp_path):
    (tmp_path / "t.json").write_text(
        json.dumps({"entries": {"k": {"issuer": "acme", "public_key_pem": PEM, "status": "active"}}})
    )
    pol = strict(profile, rf.TrustStore.from_json(tmp_path / "t.json"), tmp_path)
    with pytest.raises(PolicyError, match="ISSUER_ENROLLMENT_UNAUTHENTICATED"):
        dataclasses.replace(pol, trust_store=rf.TrustStore.from_json(migrated / "new.json"))
    with pytest.raises(PolicyError, match="ISSUER_ENROLLMENT_UNAUTHENTICATED"):
        rf.verify_trusted(json.dumps(report().to_dict()), rf.TrustStore.from_json(migrated / "new.json"), policy=pol)


@pytest.mark.parametrize("profile", STRICT)
def test_a_store_with_one_migrated_key_is_refused_whole(profile, migrated):
    _with_second_key(migrated)
    store = rf.TrustStore.from_json(migrated / "new.json")
    assert store.issuer_declared == {"k"} and set(store.keys) == {"k", "k2"}
    with pytest.raises(PolicyError, match="ISSUER_ENROLLMENT_UNAUTHENTICATED"):
        strict(profile, store, migrated)


def test_development_accepts_it_and_says_what_it_is(migrated):
    res = verify(report(), VerificationPolicy(trust_store=rf.TrustStore.from_json(migrated / "new.json"), now=lambda: T))
    assert res.accepted and res.reasons == ("ISSUER_OPERATOR_DECLARED",)


def test_the_issuer_comparison_still_decides_in_development(migrated):
    store = rf.TrustStore.from_json(migrated / "new.json")
    who = rf.Signer(issuer="someone-else", key_id="k", private_key=SIGNER.private_key, public_key=SIGNER.public_key)
    env = envelope_v2(
        "drift", RESULT, signer=who, deployment_id="p", audience=("reg",), issued_at=T,
        audit_run_id="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f2",
    )  # fmt: skip
    res = verify(env, VerificationPolicy(trust_store=store, now=lambda: T))
    assert "ISSUER_MISMATCH" in res.blocking_reasons


def test_the_cli_in_development_labels_it_and_v2_says_so(migrated):
    out = cli("verify", "-i", "r.json", "--trusted-keys", "new.json", "--response-format", "v2", cwd=migrated)
    body = json.loads(out.stdout)
    assert out.returncode == 0 and body["issuer_binding"] == "operator_declared"
    assert body["reasons"] == ["ISSUER_OPERATOR_DECLARED"] and "not an authenticated binding" in out.stderr


def test_the_lenient_verifier_does_not_report_it_as_bound(migrated):
    env = rf.envelope("drift", RESULT, signer=SIGNER)
    out = rf.verify_envelope(env, trust_store=rf.TrustStore.from_json(migrated / "new.json"))
    assert out.trust_status == "TRUSTED" and not out.issuer_bound


def test_the_http_server_labels_it(migrated):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from regaudit_fhe.server import ServerConfig, build_app
    from tests._asgi import client_for

    cfg = ServerConfig(
        api_keys={}, dev_mode=True, max_body_bytes=1 << 20, rate_limit_per_min=600, request_timeout_s=10.0, cors_origins=(),
        profile="development", trust_store=rf.TrustStore.from_json(migrated / "new.json"),
    )  # fmt: skip
    client = client_for(build_app(config=cfg), base_url="http://127.0.0.1:8000")
    body = {"envelope": report().to_dict()}
    assert client.post("/v1/verify", json=body).json()["reasons"] == ["ISSUER_OPERATOR_DECLARED"]
    assert client.post("/v1/verify?response_format=v2", json=body).json()["issuer_binding"] == "operator_declared"


@pytest.mark.parametrize("form", ["migrated", "legacy"])
def test_the_http_server_will_not_start_under_secure_v1(form, migrated):
    pytest.importorskip("fastapi")
    from regaudit_fhe.server import ServerConfig, build_app

    store = (
        rf.TrustStore.from_json(migrated / "new.json")
        if form == "migrated"
        else rf.TrustStore.from_dict({"keys": {"k": PEM}})
    )
    cfg = ServerConfig(
        api_keys={}, dev_mode=True, max_body_bytes=1 << 20, rate_limit_per_min=600, request_timeout_s=10.0, cors_origins=(),
        profile="secure-v1", trust_store=store, max_age_s=3600, replay_mode="record",
        replay_cache=SqliteReplayCache(migrated / "http.db"),
    )  # fmt: skip
    with pytest.raises(PolicyError):
        build_app(config=cfg)


def test_a_revocation_view_with_a_change_keeps_the_record(migrated):
    from regaudit_fhe import _revocation as rv

    store = rf.TrustStore.from_json(migrated / "new.json")
    listed = [{"key_fingerprint": spki_fingerprint(PEM), "status": "retired", "effective_from": "2026-01-01T00:00:00Z"}]
    view = rv.apply_entries(store, listed)
    assert view.entry("k").status == "retired" and view.issuer_declared == {"k"}


def test_a_revocation_view_keeps_the_label(migrated):
    from regaudit_fhe import _revocation as rv

    store = rf.TrustStore.from_json(migrated / "new.json")
    assert rv.apply_entries(store, []).issuer_declared == {"k"}


def test_a_lifecycle_edit_keeps_the_label(migrated):
    out = cli("trust", "retire", "--store", "new.json", "--key-id", "k", cwd=migrated)
    assert out.returncode == 0, out.stderr
    assert rf.TrustStore.from_json(migrated / "new.json").issuer_declared == {"k"}


# ------------------------------------------------------------------ control: normal enrollment


@pytest.mark.parametrize("profile", STRICT)
def test_control_trust_add_keeps_working_and_nothing_calls_it_authenticated(profile, tmp_path):
    """Whether trust add counts as authenticated enrollment is the owner's open question. It keeps working, as normal
    enrollment, and no output claims more. A hand-written entries store is the same file and cannot be told apart."""
    (tmp_path / "k.pub").write_text(PEM)
    out = cli(
        "trust", "add", "--store", "t.json", "--key-id", "k", "--issuer", "acme", "--public-key", "k.pub",
        "--fingerprint", spki_fingerprint(PEM), cwd=tmp_path,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    body = json.loads(out.stdout)
    assert body["authenticated_binding"] is False and body["issuer_binding"] == "store_entry"
    store = rf.TrustStore.from_json(tmp_path / "t.json")
    assert not store.issuer_declared
    res = verify(report(), strict(profile, store, tmp_path))
    assert res.accepted and res.reasons == ()
    (tmp_path / "r.json").write_text(json.dumps(report("3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f3").to_dict()))
    (tmp_path / "s.json").write_text(json.dumps(report("3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f4").to_dict()))
    v2 = cli(
        "verify", "-i", "s.json", "--trusted-keys", "t.json", "--profile", profile, *STRICT_KW, "--response-format", "v2",
        cwd=tmp_path,
    )  # fmt: skip
    assert v2.returncode == 0, v2.stderr
    assert json.loads(v2.stdout)["issuer_binding"] == "store_entry"


# ------------------------------------------------------------------ limits, as stated


@pytest.mark.parametrize("profile", STRICT)
def test_limit_deliberately_deleting_the_member_is_an_edit_of_local_state(profile, migrated):
    """By the owner's ruling this is outside the guarantee: nothing here can detect it, and the store is then accepted."""
    doc = json.loads((migrated / "new.json").read_text())
    del doc["entries"]["k"]["issuer_source"]
    (migrated / "new.json").write_text(json.dumps(doc))
    store = rf.TrustStore.from_json(migrated / "new.json")
    assert not store.issuer_declared
    assert verify(report(), strict(profile, store, migrated)).accepted


def test_limit_the_source_store_stays_the_way_back(migrated):
    assert json.loads((migrated / "old.json").read_text()) == {"keys": {"k": PEM}}
    assert rf.TrustStore.from_json(migrated / "old.json").keys["k"] == rf.TrustStore.from_dict({"keys": {"k": PEM}}).keys["k"]
