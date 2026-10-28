"""End-to-end CLI workflow on real processes, synthetic keys only:

    keygen -> (issuer) audit --signing-key -> (verifier) trust add -> verify

Exit 0 from ``verify`` means TRUSTED and nothing else. Self-signed evidence is never
trusted automatically, and no command enrols a key from a report.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

DRIFT = {"p": [0.2, 0.3, 0.5], "q": [0.25, 0.25, 0.5]}


def cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=cwd,
        check=False,
    )


@pytest.fixture
def work(tmp_path: Path) -> Path:
    (tmp_path / "in.json").write_text(json.dumps(DRIFT))
    return tmp_path


def _keygen(work: Path, name: str = "k", key_id: str = "acme-2026") -> dict:
    proc = cli(
        "keygen", "--key-id", key_id, "--issuer", "acme",
        "--private-key", f"{name}.pem", "--public-key", f"{name}.pub", cwd=work,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _sign(work: Path, name: str = "k", key_id: str = "acme-2026", out: str = "report.json"):
    return cli(
        "audit", "drift", "-i", "in.json", "-o", out,
        "--signing-key", f"{name}.pem", "--key-id", key_id, "--issuer", "acme",
        "--deployment-id", "prod-1", cwd=work,
    )  # fmt: skip


def _trust_add(work: Path, info: dict, name: str = "k", store: str = "store.json", fp=None):
    return cli(
        "trust", "add", "--store", store, "--key-id", info["key_id"], "--issuer", "acme",
        "--public-key", f"{name}.pub", "--fingerprint", fp or info["fingerprint_sha256"], cwd=work,
    )  # fmt: skip


def _verify(work: Path, *extra: str, report: str = "report.json"):
    return cli("verify", "-i", report, *extra, cwd=work)


# --------------------------------------------------------------------------- the happy path


def test_full_workflow_ends_in_trusted_exit_zero(work):
    info = _keygen(work)
    assert _sign(work).returncode == 0
    assert json.loads((work / "report.json").read_text())["schema"] == "regaudit-fhe.report.v2"
    added = _trust_add(work, info)
    assert added.returncode == 0, added.stderr
    proc = _verify(work, "--trusted-keys", "store.json")
    assert proc.returncode == 0, proc.stderr
    verdict = json.loads(proc.stdout)
    assert verdict["trust_status"] == "TRUSTED" and verdict["accepted"] is True
    listed = json.loads(cli("trust", "list", "--store", "store.json", cwd=work).stdout)
    assert listed == [
        {
            "key_id": "acme-2026",
            "issuer": "acme",
            "status": "active",
            "fingerprint_sha256": info["fingerprint_sha256"],
        }
    ]


def test_the_signed_report_binds_the_input_by_commitment(work):
    _keygen(work)
    assert _sign(work).returncode == 0
    commitments = json.loads((work / "report.json").read_text())["input_commitments"]
    assert [c["name"] for c in commitments] == ["p", "q"]


def test_keygen_files_have_safe_modes_and_never_overwrite(work):
    _keygen(work)
    if os.name == "posix":
        assert stat.S_IMODE((work / "k.pem").stat().st_mode) == 0o600
    before = (work / "k.pem").read_bytes()
    again = cli(
        "keygen", "--key-id", "x", "--issuer", "y",
        "--private-key", "k.pem", "--public-key", "other.pub", cwd=work,
    )  # fmt: skip
    assert again.returncode == 2 and (work / "k.pem").read_bytes() == before
    assert not (work / "other.pub").exists()
    clash = cli(
        "keygen", "--key-id", "x", "--issuer", "y",
        "--private-key", "new.pem", "--public-key", "k.pub", cwd=work,
    )  # fmt: skip
    assert clash.returncode == 2 and not (work / "new.pem").exists()


# --------------------------------------------------------------------------- never trust by default


def test_a_signed_report_is_not_trusted_until_the_verifier_enrols_the_key(work):
    info = _keygen(work)
    assert _sign(work).returncode == 0
    self_signed = _verify(work, "--allow-self-signed")
    assert self_signed.returncode == 1
    assert json.loads(self_signed.stdout)["trust_status"] == "SELF_SIGNED_ONLY"
    assert _verify(work).returncode == 2  # no trust material at all
    assert info["key_id"] == "acme-2026"
    assert not (work / "store.json").exists()  # nothing was enrolled automatically


def test_a_store_enrolling_a_different_key_under_the_same_name_does_not_trust(work):
    _keygen(work, name="real")
    other = _keygen(work, name="other")
    assert _sign(work, name="real").returncode == 0
    assert _trust_add(work, other, name="other").returncode == 0
    proc = _verify(work, "--trusted-keys", "store.json")
    assert proc.returncode == 1
    verdict = json.loads(proc.stdout)
    assert verdict["trust_status"] == "INVALID" and verdict["accepted"] is False
    assert "not accepted: INVALID" in proc.stderr


def test_a_tampered_report_exits_one(work):
    info = _keygen(work)
    _sign(work)
    assert _trust_add(work, info).returncode == 0
    data = json.loads((work / "report.json").read_text())
    data["result"]["distance"] += 0.25
    (work / "report.json").write_text(json.dumps(data))
    proc = _verify(work, "--trusted-keys", "store.json")
    assert proc.returncode == 1 and json.loads(proc.stdout)["trust_status"] == "INVALID"


def test_a_non_canonical_report_is_refused_with_exit_two_and_empty_stdout(work):
    info = _keygen(work)
    _sign(work)
    _trust_add(work, info)
    data = json.loads((work / "report.json").read_text())
    data["approved_by"] = "regulator"
    (work / "report.json").write_text(json.dumps(data))
    proc = _verify(work, "--trusted-keys", "store.json")
    assert proc.returncode == 2 and proc.stdout == "" and "malformed report" in proc.stderr


def test_duplicate_keys_in_the_report_text_are_refused(work):
    info = _keygen(work)
    _sign(work)
    _trust_add(work, info)
    text = (work / "report.json").read_text()
    (work / "report.json").write_text(
        text.replace('"issuer": "acme"', '"issuer": "acme", "issuer": "x"', 1)
    )
    assert _verify(work, "--trusted-keys", "store.json").returncode == 2


# --------------------------------------------------------------------------- enrolment is deliberate


def test_enrolment_needs_the_matching_fingerprint_and_writes_nothing_otherwise(work):
    info = _keygen(work)
    bad = _trust_add(work, info, fp="0" * 64)
    assert bad.returncode == 2 and "fingerprint mismatch" in bad.stderr
    assert not (work / "store.json").exists()
    upper = _trust_add(work, info, fp=info["fingerprint_sha256"].upper())
    assert upper.returncode == 0  # case-insensitive hex


def test_enrolment_never_replaces_or_converts_an_existing_store(work):
    info = _keygen(work)
    assert _trust_add(work, info).returncode == 0
    snapshot = (work / "store.json").read_bytes()
    dup = _trust_add(work, info)
    assert dup.returncode == 2 and "already enrolled" in dup.stderr
    assert (work / "store.json").read_bytes() == snapshot
    second = _keygen(work, name="k2", key_id="acme-2027")
    assert _trust_add(work, second, name="k2").returncode == 0
    assert len(json.loads((work / "store.json").read_text())["entries"]) == 2
    # the same key under a second id is refused by the store's own uniqueness rule
    again = cli(
        "trust", "add", "--store", "store.json", "--key-id", "alias", "--issuer", "acme",
        "--public-key", "k.pub", "--fingerprint", info["fingerprint_sha256"], cwd=work,
    )  # fmt: skip
    assert again.returncode == 2 and (work / "store.json").read_bytes() != b""
    legacy = work / "legacy.json"
    legacy.write_text(json.dumps({"keys": {"a": (work / "k.pub").read_text()}}))
    refused = cli(
        "trust", "add", "--store", "legacy.json", "--key-id", "b", "--issuer", "acme",
        "--public-key", "k2.pub", "--fingerprint", second["fingerprint_sha256"], cwd=work,
    )  # fmt: skip
    assert refused.returncode == 3 and "refusing to convert" in refused.stderr


def test_there_is_no_command_that_enrols_from_a_report(work):
    proc = cli("trust", "add", "--store", "s.json", "--from-report", "report.json", cwd=work)
    assert proc.returncode == 2 and not (work / "s.json").exists()


# --------------------------------------------------------------------------- signing guards


def test_signing_needs_every_option_and_a_private_key(work):
    _keygen(work)
    partial = cli("audit", "drift", "-i", "in.json", "--signing-key", "k.pem", cwd=work)
    assert partial.returncode == 2 and "--key-id" in partial.stderr and partial.stdout == ""
    aud = cli("audit", "drift", "-i", "in.json", "--audience", "v", cwd=work)
    assert aud.returncode == 2
    missing = _sign(work, name="nope")
    assert missing.returncode == 2 and "cannot read signing key" in missing.stderr


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_a_group_readable_private_key_is_refused(work):
    _keygen(work)
    (work / "k.pem").chmod(0o640)
    proc = _sign(work)
    assert (
        proc.returncode == 2 and "too open" in proc.stderr and not (work / "report.json").exists()
    )


def test_a_public_key_is_not_accepted_as_a_signing_key(work):
    _keygen(work)
    (work / "fake.pem").write_bytes((work / "k.pub").read_bytes())
    (work / "fake.pem").chmod(0o600)
    proc = _sign(work, name="fake")
    assert proc.returncode == 2 and "cannot load" in proc.stderr


def test_legacy_audit_output_is_unchanged_without_signing_options(work):
    proc = cli("audit", "drift", "-i", "in.json", cwd=work)
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["schema"] == "regaudit-fhe.report.v1"
    assert "SELF_SIGNED_ONLY" in proc.stderr
