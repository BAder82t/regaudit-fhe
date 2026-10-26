"""The TestPyPI rehearsal workflow must not be able to reach production PyPI. Exists only on the rehearsal branch."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
REH = WORKFLOWS / "testpypi-rehearsal.yml"
pytestmark = pytest.mark.skipif(not REH.is_file(), reason="not the rehearsal branch")


def _wf():
    data = yaml.safe_load(REH.read_text(encoding="utf-8"))
    if True in data:
        data["on"] = data.pop(True)
    return data


def test_the_only_trigger_is_a_push_to_one_exact_branch():
    on = _wf()["on"]
    assert set(on) == {"push"}
    assert on["push"] == {"branches": ["rehearsal/testpypi-0.0.901"]}


def test_default_token_is_empty_and_only_publish_can_mint_an_oidc_token():
    wf = _wf()
    assert wf["permissions"] == {}
    ids = {
        n for n, j in wf["jobs"].items() if (j.get("permissions") or {}).get("id-token") == "write"
    }
    assert ids == {"publish"}


def test_the_only_environment_is_testpypi_and_production_is_never_named():
    wf = _wf()
    envs = {n: (j.get("environment") or {}) for n, j in wf["jobs"].items() if "environment" in j}
    assert list(envs) == ["publish"] and envs["publish"]["name"] == "testpypi"
    text = REH.read_text(encoding="utf-8")
    assert not re.search(r"environment:\s*\n?\s*(name:\s*)?pypi\b", text)
    assert "https://pypi.org/p/" not in text and "upload.pypi.org" not in text


def test_the_upload_step_targets_testpypi_only():
    steps = _wf()["jobs"]["publish"]["steps"]
    uploads = [s for s in steps if "gh-action-pypi-publish" in s.get("uses", "")]
    assert len(uploads) == 1
    assert uploads[0]["with"]["repository-url"] == "https://test.pypi.org/legacy/"
    assert uploads[0]["with"]["attestations"] is True


def test_every_third_party_action_is_pinned_and_the_build_is_the_shared_reusable_workflow():
    text = REH.read_text(encoding="utf-8")
    for ref in re.findall(r"^\s*(?:-\s*)?uses:\s*(\S+)", text, re.MULTILINE):
        assert ref.startswith("./") or re.search(r"@[0-9a-f]{40}$", ref), ref
    assert _wf()["jobs"]["build"]["uses"] == "./.github/workflows/release-build.yml"


def test_no_job_can_be_switched_off_or_continue_after_failure():
    for name, job in _wf()["jobs"].items():
        assert "if" not in job and "continue-on-error" not in job, name
        for step in job.get("steps", []):
            assert "if" not in step and "continue-on-error" not in step, name
