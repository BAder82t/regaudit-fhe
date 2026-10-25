"""Policy tests for the release workflows: the controls that protect publication stay in place.

They read the workflow files as data. They cannot prove how GitHub will behave (nothing is executed);
they stop a later edit from silently removing a control.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
PUBLISH = WORKFLOWS / "publish.yml"
BUILD = WORKFLOWS / "release-build.yml"
REHEARSAL = WORKFLOWS / "release-rehearsal.yml"
SHA = re.compile(r"@[0-9a-f]{40}(\s|$)")

pytestmark = pytest.mark.skipif(
    not PUBLISH.is_file(), reason="workflows are not part of this checkout"
)


def _load(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    # PyYAML reads the key `on` as the boolean True
    if True in data:
        data["on"] = data.pop(True)
    return data


def _uses(path: Path) -> list[str]:
    return re.findall(r"^\s*(?:-\s*)?uses:\s*(\S+)", path.read_text(encoding="utf-8"), re.MULTILINE)


def _run_blocks(wf: dict) -> list[str]:
    out = []
    for job in wf["jobs"].values():
        for step in job.get("steps", []):
            if "run" in step:
                out.append(step["run"])
    return out


def test_publish_is_triggered_only_by_a_strict_version_tag():
    on = _load(PUBLISH)["on"]
    assert set(on) == {"push"}, "no workflow_dispatch, schedule or pull_request trigger may publish"
    assert on["push"] == {"tags": ["v[0-9]+.[0-9]+.[0-9]+"]}


def test_default_token_has_no_permissions_in_every_release_workflow():
    for path in (PUBLISH, BUILD, REHEARSAL):
        assert _load(path)["permissions"] == {}, path.name


def test_only_the_publishing_jobs_can_mint_an_oidc_token():
    wf = _load(PUBLISH)
    with_id_token = {
        n for n, j in wf["jobs"].items() if (j.get("permissions") or {}).get("id-token") == "write"
    }
    assert with_id_token == {"sigstore", "publish"}
    for path in (BUILD, REHEARSAL):
        for name, job in _load(path)["jobs"].items():
            assert "id-token" not in (job.get("permissions") or {}), f"{path.name}:{name}"
            assert "environment" not in job, f"{path.name}:{name} must hold no credentials"


def test_pypi_upload_is_confined_to_one_protected_environment_job():
    wf = _load(PUBLISH)
    pub = wf["jobs"]["publish"]
    assert pub["environment"]["name"] == "pypi"
    assert pub["if"] == "github.event_name == 'push' && github.ref_type == 'tag'"
    assert {"guard", "build", "sigstore"} <= set(pub["needs"])
    uploaders = [
        n
        for n, j in wf["jobs"].items()
        if any("pypi-publish" in s.get("uses", "") for s in j.get("steps", []))
    ]
    assert uploaders == ["publish"]
    assert "pypi-publish" not in BUILD.read_text(encoding="utf-8")
    assert "pypi-publish" not in REHEARSAL.read_text(encoding="utf-8")


def test_the_guard_checks_tag_commit_and_default_branch():
    guard = "\n".join(_run_blocks({"jobs": {"guard": _load(PUBLISH)["jobs"]["guard"]}}))
    for needle in (
        'test "$EVENT" = "push"',
        'test "$REF_TYPE" = "tag"',
        "^v[0-9]+\\.[0-9]+\\.[0-9]+$",
        'git cat-file -t "refs/tags/$REF_NAME"',
        '"refs/tags/$REF_NAME^{commit}")" = "$EVENT_SHA"',
        "git merge-base --is-ancestor",
    ):
        assert needle in guard, needle
    assert "build" in _load(PUBLISH)["jobs"] and _load(PUBLISH)["jobs"]["build"]["needs"] == "guard"


def test_the_built_files_are_tested_and_their_identity_is_checked_before_upload():
    wf = _load(PUBLISH)
    text = PUBLISH.read_text(encoding="utf-8")
    assert wf["jobs"]["build"]["uses"] == "./.github/workflows/release-build.yml"
    assert wf["jobs"]["build"]["with"]["expected_tag"] == "${{ github.ref_name }}"
    pub_run = "\n".join(s.get("run", "") for s in wf["jobs"]["publish"]["steps"])
    assert "needs.build.outputs.wheel_sha256" in text and "needs.build.outputs.sdist_sha256" in text
    assert "sha256sum dist/*.whl" in pub_run and "sha256sum dist/*.tar.gz" in pub_run
    assert 'test "$REF_NAME" = "v$VERSION"' in pub_run
    build = BUILD.read_text(encoding="utf-8")
    for needle in (
        "check_release_metadata.py",
        "smoke_installed_wheel.py",
        "twine check",
        "pip-audit",
        "--import-mode=importlib",
    ):
        assert needle in build, needle
    assert '["3.10", "3.11", "3.12", "3.13"]' in build


def test_every_third_party_action_is_pinned_to_a_commit():
    for path in (PUBLISH, BUILD, REHEARSAL):
        for ref in _uses(path):
            if ref.startswith("./"):
                continue
            assert SHA.search(ref + "\n"), f"{path.name}: {ref} is not pinned to a 40-hex commit"


def test_no_workflow_expression_is_interpolated_into_a_shell_script():
    for path in (PUBLISH, BUILD, REHEARSAL):
        for block in _run_blocks(_load(path)):
            for expr in re.findall(r"\$\{\{(.*?)\}\}", block):
                assert expr.strip().startswith("matrix."), (
                    f"{path.name}: `${{{{{expr}}}}}` in a run block"
                )


def test_the_rehearsal_cannot_publish():
    wf = _load(REHEARSAL)
    assert set(wf["on"]) == {"pull_request", "workflow_dispatch"}
    assert list(wf["jobs"]) == ["rehearsal"]
    assert wf["jobs"]["rehearsal"]["uses"] == "./.github/workflows/release-build.yml"
    assert wf["jobs"]["rehearsal"]["with"]["expected_tag"] == ""
