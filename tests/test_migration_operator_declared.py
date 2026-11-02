"""A well-formed ``trust migrate --issuer`` is a local operator's statement, not proof, and it stays identified as one.

The label sits beside the store because every published version refuses an unknown member in the store itself (published_wheel
evidence is in the qualification harness). It is a label: the tests named limit say what it does not do.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe._keys import spki_fingerprint
from regaudit_fhe._trust_lifecycle import MigrationRefused, migrate
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.trust import ISSUER_PROVENANCE_SUFFIX, TrustStoreError
from regaudit_fhe.verification import PolicyError, VerificationPolicy, verify

T = datetime.now(timezone.utc).replace(microsecond=0)
SIGNER = rf.Signer.generate(issuer="acme", key_id="k")
PEM = SIGNER.public_key_pem()
RESULT = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
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
    assert "not proof" in body["notice"] and "secure-v1 refuses" in body["notice"]


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


def test_the_label_file_says_what_it_is(migrated):
    doc = json.loads(side(migrated / "new.json").read_text())
    assert doc["kind"] == "operator-declared" and doc["authenticated"] is False and doc["key_ids"] == ["k"]
    assert doc["source_sha256"] == hashlib.sha256((migrated / "old.json").read_bytes()).hexdigest()


# ------------------------------------------------------------------ the store stays readable


def test_the_store_file_holds_only_what_published_versions_read(migrated):
    doc = json.loads((migrated / "new.json").read_text())
    assert set(doc) == {"entries", "as_of"}
    assert set(doc["entries"]["k"]) == {"issuer", "public_key_pem", "status"}


# ------------------------------------------------------------------ the profiles


def test_secure_v1_refuses_it_with_the_label_as_the_reason(migrated):
    store = rf.TrustStore.from_json(migrated / "new.json")
    assert store.binds_issuers and store.issuer_declared == {"k"}
    with pytest.raises(PolicyError, match="recorded as a local operator's statement"):
        strict("secure-v1", store, migrated)


def test_secure_v1_refuses_it_on_the_cli(migrated):
    out = cli("verify", "-i", "r.json", "--trusted-keys", "new.json", "--profile", "secure-v1", *STRICT_KW, cwd=migrated)
    assert out.returncode == 2 and "local operator's statement" in out.stderr and not out.stdout


def test_a_store_with_one_migrated_key_is_refused_whole(migrated):
    other = rf.Signer.generate(issuer="other", key_id="k2")
    (migrated / "k2.pub").write_text(other.public_key_pem())
    out = cli(
        "trust", "add", "--store", "new.json", "--key-id", "k2", "--issuer", "other", "--public-key", "k2.pub",
        "--fingerprint", spki_fingerprint(other.public_key_pem()), cwd=migrated,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    store = rf.TrustStore.from_json(migrated / "new.json")
    assert store.issuer_declared == {"k"}
    with pytest.raises(PolicyError, match="local operator's statement"):
        strict("secure-v1", store, migrated)


@pytest.mark.parametrize("profile", ["confidential", "high-assurance", "development"])
def test_the_existing_profiles_accept_it_and_label_it(profile, migrated):
    store = rf.TrustStore.from_json(migrated / "new.json")
    pol = (
        VerificationPolicy(trust_store=store, now=lambda: T)
        if profile == "development"
        else strict(profile, store, migrated)
    )
    res = verify(report(), pol)
    assert res.accepted and res.issuer_trusted and res.reasons == ("ISSUER_OPERATOR_DECLARED",)


@pytest.mark.parametrize("profile", ["confidential", "high-assurance"])
def test_the_issuer_comparison_still_decides_on_a_labelled_store(profile, migrated):
    store = rf.TrustStore.from_json(migrated / "new.json")
    who = rf.Signer(issuer="someone-else", key_id="k", private_key=SIGNER.private_key, public_key=SIGNER.public_key)
    env = envelope_v2(
        "drift", RESULT, signer=who, deployment_id="p", audience=("reg",), issued_at=T,
        audit_run_id="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f2",
    )  # fmt: skip
    assert verify(env, strict(profile, store, migrated)).blocking_reasons == ("ISSUER_MISMATCH",)


def test_the_cli_labels_it_and_v2_says_so(migrated):
    out = cli("verify", "-i", "r.json", "--trusted-keys", "new.json", "--response-format", "v2", cwd=migrated)
    body = json.loads(out.stdout)
    assert out.returncode == 0 and body["issuer_binding"] == "operator_declared"
    assert body["reasons"] == ["ISSUER_OPERATOR_DECLARED"] and "not an authenticated binding" in out.stderr


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


def test_a_revocation_view_keeps_the_label(migrated):
    from regaudit_fhe import _revocation as rv

    store = rf.TrustStore.from_json(migrated / "new.json")
    assert rv.apply_entries(store, []).issuer_declared == {"k"}


def test_a_lifecycle_edit_keeps_the_label(migrated):
    out = cli("trust", "retire", "--store", "new.json", "--key-id", "k", cwd=migrated)
    assert out.returncode == 0, out.stderr
    assert rf.TrustStore.from_json(migrated / "new.json").issuer_declared == {"k"}


# ------------------------------------------------------------------ control: normal enrollment


def test_control_trust_add_is_not_labelled_and_secure_v1_takes_it(tmp_path):
    (tmp_path / "k.pub").write_text(PEM)
    out = cli(
        "trust", "add", "--store", "t.json", "--key-id", "k", "--issuer", "acme", "--public-key", "k.pub",
        "--fingerprint", spki_fingerprint(PEM), cwd=tmp_path,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    store = rf.TrustStore.from_json(tmp_path / "t.json")
    assert not store.issuer_declared
    res = verify(report(), strict("secure-v1", store, tmp_path))
    assert res.accepted and res.reasons == ()


# ------------------------------------------------------------------ the writing order, and a broken label


def test_an_existing_label_file_is_not_overwritten(tmp_path):
    (tmp_path / "old.json").write_text(json.dumps({"keys": {"k": PEM}}))
    side(tmp_path / "new.json").write_text("mine")
    out = cli("trust", "migrate", "--source", "old.json", "--target", "new.json", "--issuer", "k=acme", cwd=tmp_path)
    assert out.returncode == 2 and side(tmp_path / "new.json").read_text() == "mine"
    assert not (tmp_path / "new.json").exists()


def test_a_failure_writing_the_store_leaves_neither_file(tmp_path, monkeypatch):
    from regaudit_fhe import _trust_lifecycle as lc

    (tmp_path / "old.json").write_text(json.dumps({"keys": {"k": PEM}}))
    real = lc._write_new

    def failing(path, data, mode):
        if not path.endswith(ISSUER_PROVENANCE_SUFFIX):
            raise OSError("disk full")
        real(path, data, mode)

    monkeypatch.setattr(lc, "_write_new", failing)
    with pytest.raises(OSError, match="disk full"):
        migrate(str(tmp_path / "old.json"), str(tmp_path / "new.json"), {"k": "acme"}, now=T)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["old.json"]


def test_a_kill_between_the_two_writes_leaves_no_store_without_its_label(tmp_path):
    """A real process, killed in the window: the label is written first."""
    (tmp_path / "old.json").write_text(json.dumps({"keys": {"k": PEM}}))
    code = (
        "import os,signal,sys;from datetime import datetime,timezone\n"
        "from regaudit_fhe import _trust_lifecycle as lc\n"
        "real=lc._write_new\n"
        "def w(p,d,m):\n"
        "    if not p.endswith(lc.ISSUER_PROVENANCE_SUFFIX): os.kill(os.getpid(),signal.SIGKILL)\n"
        "    real(p,d,m)\n"
        "lc._write_new=w\n"
        "lc.migrate(sys.argv[1],sys.argv[2],{'k':'acme'},now=datetime.now(timezone.utc))\n"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code, str(tmp_path / "old.json"), str(tmp_path / "new.json")],
        capture_output=True, timeout=120, check=False,
    )  # fmt: skip
    assert out.returncode == -9
    assert not (tmp_path / "new.json").exists() and side(tmp_path / "new.json").exists()
    with pytest.raises(MigrationRefused, match="never overwrites"):
        migrate(str(tmp_path / "old.json"), str(tmp_path / "new.json"), {"k": "acme"}, now=T)


@pytest.mark.parametrize("body", ["{", "[]", '{"kind":"other","key_ids":["k"]}', '{"kind":"operator-declared"}', '{"kind":"operator-declared","key_ids":[1]}'])
def test_a_broken_label_file_is_refused_not_ignored(body, migrated):
    side(migrated / "new.json").write_text(body)
    with pytest.raises(TrustStoreError, match="issuer provenance"):
        rf.TrustStore.from_json(migrated / "new.json")
    assert cli("verify", "-i", "r.json", "--trusted-keys", "new.json", cwd=migrated).returncode == 3


def test_a_label_path_that_is_not_a_regular_file_is_refused_without_blocking(migrated):
    side(migrated / "new.json").unlink()
    os.mkfifo(side(migrated / "new.json"))
    with pytest.raises(TrustStoreError, match="regular file"):
        rf.TrustStore.from_json(migrated / "new.json")


def test_a_symlinked_store_finds_its_label(migrated):
    os.symlink(migrated / "new.json", migrated / "link.json")
    assert rf.TrustStore.from_json(migrated / "link.json").issuer_declared == {"k"}


def test_a_key_listed_but_gone_from_the_store_is_ignored(migrated):
    doc = json.loads(side(migrated / "new.json").read_text())
    doc["key_ids"].append("removed")
    side(migrated / "new.json").write_text(json.dumps(doc))
    assert rf.TrustStore.from_json(migrated / "new.json").issuer_declared == {"k"}


def test_direct_construction_cannot_name_a_key_it_does_not_hold():
    with pytest.raises(TrustStoreError, match="issuer_declared"):
        rf.TrustStore(keys={"k": PEM}, issuer_declared=frozenset({"k"}))


# ------------------------------------------------------------------ limits, as stated


def test_limit_deleting_the_label_removes_the_label(migrated):
    """Not authentication in either direction. secure-v1 can only refuse what is recorded."""
    side(migrated / "new.json").unlink()
    store = rf.TrustStore.from_json(migrated / "new.json")
    assert not store.issuer_declared
    assert verify(report(), strict("secure-v1", store, migrated)).accepted


def test_limit_from_dict_has_no_file_to_look_beside(migrated):
    store = rf.TrustStore.from_dict(json.loads((migrated / "new.json").read_text()))
    assert not store.issuer_declared
