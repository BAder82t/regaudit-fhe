"""Which changed files make the ci.yml ``openfhe`` job run on a pull request, and how the workflow wires that in.

The job takes about 13 minutes and is the only place the OpenFHE backend is executed, so the rule that lets a pull
request skip it must err towards running. These tests pin that.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "openfhe_lane_needed.py"
CI = ROOT / ".github" / "workflows" / "ci.yml"

pytestmark = pytest.mark.skipif(
    not SCRIPT.is_file(), reason="scripts/ is not part of this checkout"
)


def _module():
    spec = importlib.util.spec_from_file_location("openfhe_lane_needed", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


needed = _module().lane_needed


@pytest.mark.parametrize(
    "path",
    [
        "src/regaudit_fhe/fhe/openfhe.py",
        "src/regaudit_fhe/fhe/primitives.py",
        "src/regaudit_fhe/egf_imss.py",
        "src/regaudit_fhe/cli.py",
        "tests/test_openfhe_backend.py",
        "tests/_gate_manifest.py",
        "tests/_gate_inventory.json",
        "tests/_gate_plugin.py",
        "scripts/openfhe-requirements.lock",
        "scripts/gate_inventory.py",
        "scripts/openfhe_lane_needed.py",
        "tests/test_openfhe_lane_paths.py",
        "pyproject.toml",
        ".github/workflows/ci.yml",
    ],
)
def test_a_change_that_can_affect_the_job_runs_it(path):
    assert needed([path]) is True


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "CHANGELOG.md",
        "docs/TEST_GATES.md",
        "docs/releases/ERRATUM_2026-11-19_REVIEW_WAIVER_WORDING.md",
        "portal/regaudit_portal/setup.py",
        "portal/tests/test_setup_no_leak.py",
        "examples/signed_envelope.py",
        "tests/test_cli_verify_configuration.py",
        ".github/workflows/portal.yml",
        ".github/workflows/codeql.yml",
        "scripts/server_floors.py",
        "whitepaper/paper.tex",
        "requirements-dev.txt",  # nothing in CI installs it (docs/SUPPLY_CHAIN.md); the job installs .[dev]
    ],
)
def test_a_change_that_cannot_affect_the_job_skips_it(path):
    assert needed([path]) is False


def test_one_relevant_file_among_many_irrelevant_ones_runs_the_job():
    assert needed(
        [
            "README.md",
            "docs/API.md",
            "portal/regaudit_portal/app.py",
            "src/regaudit_fhe/fhe/openfhe.py",
        ]
    )


def test_no_paths_at_all_runs_the_job_because_an_unreadable_change_set_is_not_an_empty_one():
    assert needed([]) is True
    assert needed(["", "  ", "\n"]) is True


def test_a_path_that_only_looks_like_a_relevant_one_does_not_count():
    assert (
        needed(["docs/src/notes.md", "portal/src/app.py", "mysrc/x.py", "tests/gate_notes.md"])
        is False
    )


def test_the_command_line_reads_stdin_and_prints_true_or_false():
    def run(text: str) -> str:
        done = subprocess.run(  # noqa: S603 - a fixed argv: this interpreter and a script in this repository
            [sys.executable, str(SCRIPT)],
            input=text,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        assert done.stderr == ""
        return done.stdout.strip()

    assert run("README.md\nportal/x.py\n") == "false"
    assert run("README.md\nsrc/regaudit_fhe/fhe/openfhe.py\n") == "true"
    assert run("") == "true"


# ----------------------------------------------------------------------------- how ci.yml uses it


def _jobs() -> dict:
    yaml = pytest.importorskip("yaml")
    if not CI.is_file():
        pytest.skip("workflows are not part of this checkout")
    return yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]


def test_the_openfhe_job_waits_for_the_changes_job_and_runs_only_when_it_says_so():
    jobs = _jobs()
    assert jobs["openfhe"]["needs"] == "changes"
    assert jobs["openfhe"]["if"] == "needs.changes.outputs.openfhe == 'true'"
    assert jobs["changes"]["outputs"] == {"openfhe": "${{ steps.scope.outputs.openfhe }}"}


def test_only_a_pull_request_can_skip_the_job_and_the_comparison_is_the_pull_request_s_own_changes():
    steps = _jobs()["changes"]["steps"]
    scope = next(s for s in steps if s.get("id") == "scope")
    run = scope["run"]
    assert 'if [ "$EVENT" = "pull_request" ]' in run and "answer=true" in run
    assert '"$BASE...$HEAD"' in run, (
        "three dots: what the pull request changed, not what the base gained since"
    )
    assert "set -euo pipefail" in run, (
        "a failed diff must fail the job, not read as 'nothing changed'"
    )
    assert scope["env"]["EVENT"] == "${{ github.event_name }}"
    checkout = next(s for s in steps if "actions/checkout" in str(s.get("uses", "")))
    assert checkout["with"]["fetch-depth"] == 0
