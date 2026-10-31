"""``regaudit-fhe audit`` must refuse bad usage and bad input with a message and exit 2, never a traceback."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

GOOD = {
    "y_true": [1, 0, 1, 1],
    "y_pred": [1, 0, 0, 0],
    "group_a": [1, 1, 0, 0],
    "group_b": [0, 0, 1, 1],
}


def run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", "audit", *args],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=cwd,
        check=False,
    )


def _write(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_missing_input_option_is_a_usage_error(tmp_path):
    p = run("fairness", cwd=tmp_path)
    assert p.returncode == 2 and p.stdout == ""
    assert "--input" in p.stderr and "--schema" in p.stderr
    assert "Traceback" not in p.stderr


def test_unreadable_input_file(tmp_path):
    p = run("fairness", "-i", str(tmp_path / "absent.json"), cwd=tmp_path)
    assert p.returncode == 2 and p.stdout == ""
    assert "absent.json" in p.stderr and "Traceback" not in p.stderr


def test_input_that_is_not_json(tmp_path):
    p = run("fairness", "-i", _write(tmp_path / "x.json", "garbage"), cwd=tmp_path)
    assert p.returncode == 2 and p.stdout == ""
    assert "not valid JSON" in p.stderr and "Traceback" not in p.stderr


@pytest.mark.parametrize("text", ["[1]", "3", "null", '"s"'])
def test_input_that_is_not_an_object(tmp_path, text):
    p = run("fairness", "-i", _write(tmp_path / "x.json", text), cwd=tmp_path)
    assert p.returncode == 2 and p.stdout == ""
    assert "JSON object" in p.stderr and "Traceback" not in p.stderr


def test_mismatched_vector_lengths(tmp_path):
    bad = {**GOOD, "y_pred": [1, 0]}
    p = run("fairness", "-i", _write(tmp_path / "x.json", json.dumps(bad)), cwd=tmp_path)
    assert p.returncode == 2 and p.stdout == ""
    assert "length mismatch" in p.stderr and "Traceback" not in p.stderr


def test_unwritable_output(tmp_path):
    src = _write(tmp_path / "x.json", json.dumps(GOOD))
    p = run("fairness", "-i", src, "-o", str(tmp_path / "no" / "such" / "dir.json"), cwd=tmp_path)
    assert p.returncode == 2 and "cannot write" in p.stderr and "Traceback" not in p.stderr


def test_success_is_unchanged_and_says_the_report_is_self_signed(tmp_path):
    src = _write(tmp_path / "x.json", json.dumps(GOOD))
    p = run("fairness", "-i", src, cwd=tmp_path)
    assert p.returncode == 0
    assert json.loads(p.stdout)["schema"] == "regaudit-fhe.report.v1"  # stdout is still pure JSON
    assert "SELF_SIGNED_ONLY" in p.stderr and "ephemeral" in p.stderr
