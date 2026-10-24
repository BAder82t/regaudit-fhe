"""``regaudit-fhe verify`` exit-code contract, asserted on real processes.

0  accepted under the configured policy
1  well-formed report refused by policy (including SELF_SIGNED_ONLY)
2  invalid input or command usage
3  required verification infrastructure unavailable or invalidly configured

stdout carries the JSON verdict (only for exit 0 and 1); diagnostics go to
stderr. Exit 2 and 3 print nothing on stdout.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.report_v2 import envelope_v2


def run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", "verify", *args],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=cwd,
        check=False,
    )


def _report():
    return rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )


@pytest.fixture
def signer() -> rf.Signer:
    return rf.Signer.generate(issuer="acme", key_id="acme-1")


def _write(path: Path, obj) -> str:
    path.write_text(json.dumps(obj) if not isinstance(obj, str) else obj)
    return str(path)


def _store_file(tmp_path: Path, signer: rf.Signer, **over) -> str:
    entry = {"issuer": signer.issuer, "public_key_pem": signer.public_key_pem(), "status": "active"}
    entry.update(over)
    return _write(tmp_path / "trust.json", {"entries": {signer.key_id: entry}})


def _v2_file(tmp_path: Path, signer: rf.Signer, name="report.json", **kw) -> str:
    env = envelope_v2("fairness", _report(), signer=signer, deployment_id="prod-eu-1", **kw)
    return _write(tmp_path / name, env.to_dict())


def _v1_file(tmp_path: Path, signer: rf.Signer) -> str:
    return _write(tmp_path / "v1.json", rf.envelope("fairness", _report(), signer=signer).to_dict())


def _verdict(proc: subprocess.CompletedProcess[str]) -> dict:
    return json.loads(proc.stdout)


# ---------------------------------------------------------------------------
# Exit 0: accepted
# ---------------------------------------------------------------------------


def test_exit_0_trusted_v2_report(tmp_path, signer):
    p = run("-i", _v2_file(tmp_path, signer), "--trusted-keys", _store_file(tmp_path, signer))
    assert p.returncode == 0, p.stderr
    v = _verdict(p)
    assert v["trust_status"] == "TRUSTED" and v["accepted"] is True and v["valid"] is True
    assert v["format"] == "v2" and v["trusted_issuer"] is True
    assert p.stderr.strip() == ""


def test_exit_0_trusted_legacy_v1_report_keeps_a_legacy_label(tmp_path, signer):
    p = run("-i", _v1_file(tmp_path, signer), "--trusted-keys", _store_file(tmp_path, signer))
    assert p.returncode == 0, p.stderr
    v = _verdict(p)
    assert v["format"] == "v1" and "LEGACY_V1_FORMAT" in v["reasons"]


# ---------------------------------------------------------------------------
# Exit 1: refused by policy (CHANGED: a consistent self-signed report used to exit 0)
# ---------------------------------------------------------------------------


def test_exit_1_self_signed_only_never_exits_0(tmp_path, signer):
    p = run("-i", _v2_file(tmp_path, signer), "--allow-self-signed")
    assert p.returncode == 1
    v = _verdict(p)
    assert v["trust_status"] == "SELF_SIGNED_ONLY"
    assert v["integrity_valid"] is True and v["accepted"] is False and v["valid"] is False
    assert v["trusted_issuer"] is False


def test_exit_1_legacy_v1_self_signed_report_no_longer_exits_0(tmp_path, signer):
    p = run("-i", _v1_file(tmp_path, signer), "--allow-self-signed")
    assert p.returncode == 1
    assert _verdict(p)["trust_status"] == "SELF_SIGNED_ONLY"


def test_allow_self_signed_does_not_override_a_trust_store(tmp_path, signer):
    other = rf.Signer.generate(issuer="mallory", key_id="mal-1")
    store = _store_file(tmp_path, signer)
    good = run("-i", _v2_file(tmp_path, signer), "--trusted-keys", store, "--allow-self-signed")
    assert good.returncode == 0  # control: the registered issuer is accepted
    bad = run(
        "-i",
        _v2_file(tmp_path, other, "other.json"),
        "--trusted-keys",
        store,
        "--allow-self-signed",
    )
    assert bad.returncode == 1
    v = _verdict(bad)
    assert v["trust_status"] == "INVALID" and "ISSUER_UNKNOWN" in v["reasons"]


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"status": "compromised"}, "KEY_COMPROMISED_NO_CHRONOLOGY"),
        ({"status": "retired", "retired_at": "2020-01-01T00:00:00Z"}, "KEY_RETIRED_NO_CHRONOLOGY"),
        ({"issuer": "someone-else"}, "ISSUER_MISMATCH"),
    ],
)
def test_exit_1_key_lifecycle_and_identity_refusals(tmp_path, signer, over, reason):
    report = _v2_file(tmp_path, signer)
    assert run("-i", report, "--trusted-keys", _store_file(tmp_path, signer)).returncode == 0
    p = run("-i", report, "--trusted-keys", _store_file(tmp_path, signer, **over))
    assert p.returncode == 1
    v = _verdict(p)
    assert v["accepted"] is False and reason in v["reasons"]
    assert v["reason"] == v["reasons"][0] or v["reason"] in v["reasons"]


def test_exit_1_tampered_report(tmp_path, signer):
    path = Path(_v2_file(tmp_path, signer))
    data = json.loads(path.read_text())
    data["result"]["tampered"] = True
    path.write_text(json.dumps(data))
    p = run("-i", str(path), "--trusted-keys", _store_file(tmp_path, signer))
    assert p.returncode == 1 and "HASH_MISMATCH" in _verdict(p)["reasons"]


def test_exit_1_report_older_than_max_age(tmp_path, signer):
    old = datetime.now(timezone.utc) - timedelta(days=10)
    report = _v2_file(tmp_path, signer, issued_at=old)
    store = _store_file(tmp_path, signer)
    assert run("-i", report, "--trusted-keys", store).returncode == 0
    p = run("-i", report, "--trusted-keys", store, "--max-age-seconds", "3600")
    assert p.returncode == 1 and "REPORT_TOO_OLD" in _verdict(p)["reasons"]


def test_exit_1_audience_mismatch(tmp_path, signer):
    report = _v2_file(tmp_path, signer, audience=["regulator-a"])
    store = _store_file(tmp_path, signer)
    assert (
        run("-i", report, "--trusted-keys", store, "--verifier-id", "regulator-a").returncode == 0
    )
    p = run("-i", report, "--trusted-keys", store, "--verifier-id", "regulator-b")
    assert p.returncode == 1 and "AUDIENCE_MISMATCH" in _verdict(p)["reasons"]


def test_exit_1_refuse_legacy_v1(tmp_path, signer):
    v1, store = _v1_file(tmp_path, signer), _store_file(tmp_path, signer)
    assert run("-i", v1, "--trusted-keys", store).returncode == 0
    p = run("-i", v1, "--trusted-keys", store, "--refuse-legacy-v1")
    assert p.returncode == 1 and _verdict(p)["trust_status"] == "INVALID"


def test_local_replay_record_then_refuse(tmp_path, signer):
    report = _v2_file(tmp_path, signer)
    store = _store_file(tmp_path, signer)
    db = str(tmp_path / "replay.db")
    args = ("-i", report, "--trusted-keys", store, "--replay-db", db, "--replay-mode", "record")
    first = run(*args)
    assert first.returncode == 0
    v = _verdict(first)
    assert v["consumption"] == "RECORDED_LOCAL" and v["replay_scope"] == "LOCAL_PERSISTENT"
    second = run(*args)
    assert second.returncode == 1 and "REPLAY_DETECTED" in _verdict(second)["reasons"]


# ---------------------------------------------------------------------------
# Exit 2: invalid input or usage (stdout stays empty)
# ---------------------------------------------------------------------------


def test_exit_2_strict_without_trust_material(tmp_path, signer):
    report = _v2_file(tmp_path, signer)
    p = run("-i", report, "--strict")
    assert p.returncode == 2 and p.stdout == "" and "trust" in p.stderr.lower()


def test_exit_2_no_trust_material_and_no_dev_flag(tmp_path, signer):
    p = run("-i", _v2_file(tmp_path, signer))
    assert p.returncode == 2 and p.stdout == ""
    assert "--trusted-keys" in p.stderr and "--allow-self-signed" in p.stderr


@pytest.mark.parametrize(
    "content",
    ["", "{", "[]", '{"schema": "regaudit-fhe.report.v9"}', '{"a": 1, "a": 2}', "NaN"],
    ids=["empty", "truncated", "array", "unknown-schema", "duplicate-keys", "nan"],
)
def test_exit_2_malformed_reports(tmp_path, signer, content):
    bad = tmp_path / "bad.json"
    bad.write_text(content)
    p = run("-i", str(bad), "--trusted-keys", _store_file(tmp_path, signer))
    assert p.returncode == 2 and p.stdout == "" and p.stderr.strip() != ""


def test_exit_2_missing_report_file(tmp_path, signer):
    p = run("-i", str(tmp_path / "nope.json"), "--trusted-keys", _store_file(tmp_path, signer))
    assert p.returncode == 2 and p.stdout == ""


def test_exit_2_unknown_profile_argument(tmp_path, signer):
    p = run("-i", _v2_file(tmp_path, signer), "--allow-self-signed", "--profile", "prod")
    assert p.returncode == 2 and p.stdout == ""  # argparse usage error


# ---------------------------------------------------------------------------
# Exit 3: infrastructure unavailable or invalidly configured
# (CHANGED: an unreadable/malformed --trusted-keys file used to exit 2)
# ---------------------------------------------------------------------------


def test_exit_3_missing_trust_store_file(tmp_path, signer):
    p = run("-i", _v2_file(tmp_path, signer), "--trusted-keys", str(tmp_path / "missing.json"))
    assert p.returncode == 3 and p.stdout == "" and "trust" in p.stderr.lower()


def test_exit_3_malformed_trust_store(tmp_path, signer):
    bad = tmp_path / "bad-trust.json"
    bad.write_text("{not json")
    p = run("-i", _v2_file(tmp_path, signer), "--trusted-keys", str(bad))
    assert p.returncode == 3 and p.stdout == ""


def test_exit_3_trust_store_that_is_a_directory(tmp_path, signer):
    p = run("-i", _v2_file(tmp_path, signer), "--trusted-keys", str(tmp_path))
    assert p.returncode == 3 and p.stdout == ""


def test_exit_3_unusable_replay_store(tmp_path, signer):
    p = run(
        "-i",
        _v2_file(tmp_path, signer),
        "--trusted-keys",
        _store_file(tmp_path, signer),
        "--replay-db",
        str(tmp_path),  # a directory
        "--replay-mode",
        "record",
    )
    assert p.returncode == 3 and p.stdout == ""


@pytest.mark.parametrize("profile", ["confidential", "high-assurance"])
def test_exit_3_dev_flag_is_refused_outside_development(tmp_path, signer, profile):
    p = run("-i", _v2_file(tmp_path, signer), "--allow-self-signed", "--profile", profile)
    assert p.returncode == 3 and p.stdout == ""
    assert "development" in p.stderr


def test_exit_3_production_profile_needs_its_infrastructure(tmp_path, signer):
    report, store = _v2_file(tmp_path, signer), _store_file(tmp_path, signer)
    db = str(tmp_path / "r.db")
    ok = run(
        "-i", report, "--trusted-keys", store, "--profile", "confidential",
        "--max-age-seconds", "3600", "--replay-db", db, "--replay-mode", "record",
    )  # fmt: skip
    assert ok.returncode == 0, ok.stderr
    missing_max_age = run(
        "-i", _v2_file(tmp_path, signer, "r2.json"), "--trusted-keys", store,
        "--profile", "confidential", "--replay-db", db, "--replay-mode", "record",
    )  # fmt: skip
    assert missing_max_age.returncode == 3 and missing_max_age.stdout == ""


# ---------------------------------------------------------------------------
# Security review findings (round 2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0", "-5", "1e300", "abc"])
def test_exit_2_for_unusable_max_age_values_without_a_traceback(tmp_path, signer, value):
    report, store = _v2_file(tmp_path, signer), _store_file(tmp_path, signer)
    assert run("-i", report, "--trusted-keys", store, "--max-age-seconds", "3600").returncode == 0
    p = run("-i", report, "--trusted-keys", store, "--max-age-seconds", value)
    assert p.returncode == 2 and p.stdout == "" and "Traceback" not in p.stderr


def test_exit_3_for_a_pathologically_nested_trust_store_without_a_traceback(tmp_path, signer):
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 100000 + "]" * 100000)
    p = run("-i", _v2_file(tmp_path, signer), "--trusted-keys", str(deep))
    assert p.returncode == 3 and p.stdout == "" and "Traceback" not in p.stderr


def test_exit_3_for_an_oversized_trust_store(tmp_path, signer):
    big = tmp_path / "big.json"
    big.write_text('{"entries": {"k": "' + "a" * (5 * 1024 * 1024) + '"}}')
    p = run("-i", _v2_file(tmp_path, signer), "--trusted-keys", str(big))
    assert p.returncode == 3 and p.stdout == "" and "Traceback" not in p.stderr


def test_exit_2_for_an_oversized_report_file(tmp_path, signer):
    big = tmp_path / "big-report.json"
    big.write_text('{"x": "' + "a" * (5 * 1024 * 1024) + '"}')
    p = run("-i", str(big), "--trusted-keys", _store_file(tmp_path, signer))
    assert p.returncode == 2 and p.stdout == "" and "Traceback" not in p.stderr


def test_oversized_report_is_never_read_into_memory(tmp_path, monkeypatch):
    from regaudit_fhe import cli

    big = tmp_path / "big-report.json"
    big.write_text("x" * (5 * 1024 * 1024))

    def must_not_read(self):
        raise AssertionError("an oversized report was read")

    monkeypatch.setattr(Path, "read_bytes", must_not_read)
    with pytest.raises(OSError, match="limit"):
        cli._read_report(str(big))
