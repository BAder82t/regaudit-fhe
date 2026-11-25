"""``verify``: contradictory replay options, the effective-profile notice, and ``--strict``.

Process-level, like tests/test_cli_verify_exit_codes.py. Exit 2 is the usage and
configuration error; nothing here may change a verdict.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe import cli
from regaudit_fhe.report_v2 import envelope_v2


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", "verify", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.fixture
def signer() -> rf.Signer:
    return rf.Signer.generate(issuer="acme", key_id="acme-1")


@pytest.fixture
def files(tmp_path: Path, signer: rf.Signer) -> tuple[str, str]:
    rep = rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )
    env = envelope_v2("fairness", rep, signer=signer, deployment_id="prod-eu-1")
    report = tmp_path / "report.json"
    report.write_text(json.dumps(env.to_dict()))
    entry = {"issuer": signer.issuer, "public_key_pem": signer.public_key_pem(), "status": "active"}
    store = tmp_path / "trust.json"
    store.write_text(json.dumps({"entries": {signer.key_id: entry}}))
    return str(report), str(store)


# --- replay: contradictory options ------------------------------------------------


def test_replay_db_with_explicit_mode_off_is_a_configuration_error(files, tmp_path):
    report, store = files
    db = tmp_path / "r.db"
    p = run("-i", report, "--trusted-keys", store, "--replay-db", str(db), "--replay-mode", "off")
    assert p.returncode == 2 and p.stdout == ""
    assert "replay protection is disabled" in p.stderr
    assert "--replay-mode check" in p.stderr and "record" in p.stderr
    assert not db.exists()  # nothing was created


def test_replay_db_with_effective_default_mode_off_is_a_configuration_error(files, tmp_path):
    report, store = files
    p = run("-i", report, "--trusted-keys", store, "--replay-db", str(tmp_path / "r.db"))
    assert p.returncode == 2 and p.stdout == ""
    assert "replay protection is disabled" in p.stderr and "--replay-mode" in p.stderr


@pytest.mark.parametrize("mode", ["check", "record"])
def test_replay_db_with_check_or_record_still_works(files, tmp_path, mode):
    report, store = files
    p = run(
        "-i",
        report,
        "--trusted-keys",
        store,
        "--replay-db",
        str(tmp_path / "r.db"),
        "--replay-mode",
        mode,
    )
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["accepted"] is True


def test_replay_mode_without_db_is_still_exit_2(files):
    report, store = files
    p = run("-i", report, "--trusted-keys", store, "--replay-mode", "record")
    assert p.returncode == 2 and p.stdout == "" and "--replay-db" in p.stderr


def test_no_replay_options_verdict_unchanged(files):
    report, store = files
    p = run("-i", report, "--trusted-keys", store)
    assert p.returncode == 0 and json.loads(p.stdout)["accepted"] is True


def test_replay_conflict_is_checked_before_any_store_is_opened(files, tmp_path):
    # A path that could not be opened would be exit 3; the contradiction is reported first, as exit 2.
    report, store = files
    p = run("-i", report, "--trusted-keys", store, "--replay-db", str(tmp_path / "no" / "x.db"))
    assert p.returncode == 2


# --- effective profile notice -----------------------------------------------------


def test_explicit_profile_prints_a_notice_on_stderr_only(files):
    report, store = files
    plain = run("-i", report, "--trusted-keys", store)
    explicit = run("-i", report, "--trusted-keys", store, "--profile", "development")
    assert plain.returncode == explicit.returncode == 0
    assert plain.stdout == explicit.stdout  # machine-readable output is untouched
    assert "development" in explicit.stderr and "not a high-assurance profile" in explicit.stderr


def test_default_non_tty_run_writes_only_the_claim_labels_to_stderr(files):
    report, store = files
    err = run("-i", report, "--trusted-keys", store).stderr
    assert err.startswith("claims:\n") and "verification profile in effect" not in err


def test_notice_is_shown_on_a_terminal_for_the_default_profile(files, monkeypatch, capsys):
    report, store = files
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True, raising=False)
    # capsys replaces sys.stderr; give the replacement a tty answer too.
    monkeypatch.setattr(type(sys.stderr), "isatty", lambda self: True, raising=False)
    rc = cli.main(["verify", "-i", report, "--trusted-keys", store])
    out, err = capsys.readouterr()
    assert rc == 0 and json.loads(out)["accepted"] is True
    assert "profile in effect: development" in err and "not a high-assurance profile" in err


def test_notice_names_a_stricter_profile_without_claiming_more(files):
    report, store = files
    p = run("-i", report, "--trusted-keys", store, "--profile", "confidential")
    # Refused here for missing options (exit 2), and the notice is not printed for a refused configuration.
    assert p.returncode == 2 and p.stdout == ""
