"""The report.v2 signing path must apply the same input cost limits as the legacy path (0.1.1 limits, 0.2.0 CLI)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

BIG_PROVENANCE = {"attributions": [0.1], "row_ids": [1], "n_buckets": 4096, "k": 1}


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
    (tmp_path / "in.json").write_text(json.dumps(BIG_PROVENANCE))
    proc = cli(
        "keygen", "--key-id", "acme-2026", "--issuer", "acme",
        "--private-key", "k.pem", "--public-key", "k.pub", cwd=tmp_path,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    return tmp_path


def test_legacy_path_refuses_an_oversized_provenance_bucket_count(work: Path) -> None:
    proc = cli("audit", "provenance", "-i", "in.json", "-o", "out.json", cwd=work)
    assert proc.returncode == 2
    assert "max_provenance_buckets" in proc.stderr
    assert not (work / "out.json").exists()


def test_signed_path_refuses_it_too_before_any_allocation(work: Path) -> None:
    proc = cli(
        "audit", "provenance", "-i", "in.json", "-o", "out.json",
        "--signing-key", "k.pem", "--key-id", "acme-2026", "--issuer", "acme",
        "--deployment-id", "prod-1", cwd=work,
    )  # fmt: skip
    assert proc.returncode == 2
    assert "max_provenance_buckets" in proc.stderr
    assert not (work / "out.json").exists()
    assert proc.stdout == ""
