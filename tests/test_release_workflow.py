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
PUBLISH = WORKFLOWS / "pypi-release.yml"
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
    assert set(wf["on"]) == {"push", "pull_request", "workflow_dispatch"}
    assert wf["on"]["push"] == {"branches": ["release/**"]}, (
        "branches only: a tag push must not run the rehearsal"
    )
    assert list(wf["jobs"]) == ["rehearsal"]
    assert wf["jobs"]["rehearsal"]["uses"] == "./.github/workflows/release-build.yml"
    assert wf["jobs"]["rehearsal"]["with"]["expected_tag"] == ""


# --- controls that an earlier version of these tests did not pin down ---------------------------------------

ALL = (PUBLISH, BUILD, REHEARSAL)


def _jobs(path: Path) -> dict:
    return _load(path)["jobs"]


def _all_steps(path: Path):
    for name, job in _jobs(path).items():
        for step in job.get("steps", []):
            yield name, step


def test_no_release_job_or_step_can_continue_after_a_failure():
    for path in ALL:
        text = path.read_text(encoding="utf-8")
        assert "continue-on-error" not in text, path.name
        assert not re.search(r"\b(always|failure|cancelled)\(\)", text), (
            f"{path.name}: status-check override"
        )
        for block in _run_blocks(_load(path)):
            assert "|| true" not in block and "|| :" not in block and "set +e" not in block, (
                path.name
            )


def test_the_job_dependency_graph_is_exactly_the_intended_one():
    rel = _jobs(PUBLISH)
    assert rel["guard"].get("needs") is None
    assert rel["build"]["needs"] == "guard"
    assert rel["sigstore"]["needs"] == "build"
    assert set(rel["publish"]["needs"]) == {"guard", "build", "sigstore"}
    assert set(rel["github-release"]["needs"]) == {"build", "sigstore", "publish"}
    build = _jobs(BUILD)
    assert build["build"].get("needs") is None
    for name in ("smoke", "audit", "sbom"):
        assert build[name]["needs"] == "build", name


def test_every_job_that_handles_the_artifacts_rechecks_their_digests():
    need = ("sha256sum dist/*.whl", "sha256sum dist/*.tar.gz", "WHEEL_SHA256", "SDIST_SHA256")
    for path, jobs in ((BUILD, ("smoke", "audit", "sbom")), (PUBLISH, ("sigstore", "publish"))):
        for job in jobs:
            blocks = "\n".join(s.get("run", "") for s in _jobs(path)[job]["steps"])
            for needle in need:
                assert needle in blocks, f"{path.name}:{job} lacks {needle!r}"


def test_the_metadata_check_receives_the_expected_tag_and_the_audit_is_strict():
    build = _jobs(BUILD)
    check = next(s for s in build["build"]["steps"] if s.get("name", "").startswith("Version, tag"))
    assert check["env"]["EXPECTED_TAG"] == "${{ inputs.expected_tag }}"
    assert 'check_release_metadata.py --dist dist --tag "$EXPECTED_TAG"' in check["run"]
    audit = "\n".join(s.get("run", "") for s in build["audit"]["steps"])
    assert "pip-audit --strict --vulnerability-service osv" in audit.replace(
        '"$RUNNER_TEMP/venv/bin/', ""
    ).replace('"', "") or ("--strict" in audit and "pip-audit" in audit)
    assert "--strict" in audit


def test_the_guard_fetches_the_tag_object_before_testing_its_type():
    guard = "\n".join(s.get("run", "") for s in _jobs(PUBLISH)["guard"]["steps"])
    assert guard.index("git fetch --force --no-tags origin") < guard.index("git cat-file -t")


def test_only_the_release_job_has_write_access_and_nothing_gets_attestation_write():
    text = PUBLISH.read_text(encoding="utf-8")
    assert "attestations: write" not in text
    writers = {
        n
        for n, j in _jobs(PUBLISH).items()
        if (j.get("permissions") or {}).get("contents") == "write"
    }
    assert writers == {"github-release"}
    assert _jobs(PUBLISH)["publish"]["permissions"] == {"contents": "read", "id-token": "write"}
    for path in (BUILD, REHEARSAL):
        for name, job in _jobs(path).items():
            assert (job.get("permissions") or {}) == {"contents": "read"}, f"{path.name}:{name}"


def test_the_sbom_tool_does_not_share_a_virtualenv_with_the_thing_it_describes():
    sbom = "\n".join(s.get("run", "") for s in _jobs(BUILD)["sbom"]["steps"])
    assert "$RUNNER_TEMP/subject" in sbom and "$RUNNER_TEMP/tool" in sbom
    assert '"$RUNNER_TEMP/subject/bin/python"' in sbom.split("environment --output-format")[1]


def test_the_release_workflow_is_the_only_one_named_for_the_pypi_trusted_publisher():
    assert PUBLISH.name == "pypi-release.yml"
    assert not (WORKFLOWS / "publish.yml").exists(), (
        "the former publish.yml must not come back under its old name"
    )


# --- gaps found by the second review's re-verification ---------------------------------------------------------


def test_no_gate_job_or_step_can_be_switched_off_with_an_if():
    """A job-level `if: false` would skip a gate without failing the caller."""
    for path in ALL:
        for name, job in _jobs(path).items():
            if path == PUBLISH and name == "publish":
                assert job["if"] == "github.event_name == 'push' && github.ref_type == 'tag'"
                continue
            assert "if" not in job, f"{path.name}:{name} has a job-level if"
            for step in job.get("steps", []):
                assert "if" not in step, f"{path.name}:{name}: step {step.get('name')!r} has an if"


def test_every_checkout_drops_credentials_and_the_guard_fetches_full_history():
    for path in ALL:
        for _name, step in _all_steps(path):
            if "actions/checkout@" in step.get("uses", ""):
                assert step["with"]["persist-credentials"] is False, path.name
    guard_checkout = next(
        s for s in _jobs(PUBLISH)["guard"]["steps"] if "checkout" in s.get("uses", "")
    )
    assert guard_checkout["with"]["fetch-depth"] == 0


def test_the_pypi_upload_step_asks_for_attestations_from_the_dist_directory_only():
    publish_step = next(
        s for s in _jobs(PUBLISH)["publish"]["steps"] if "pypi-publish" in s.get("uses", "")
    )
    assert publish_step["with"] == {"packages-dir": "dist", "attestations": True}


def test_the_smoke_step_forbids_the_checkout_and_no_run_block_swallows_a_failure():
    smoke = next(
        s for s in _jobs(BUILD)["smoke"]["steps"] if s.get("name", "").startswith("Smoke-test")
    )
    assert "--forbid-path" in smoke["run"]
    for path in ALL:
        for block in _run_blocks(_load(path)):
            assert not re.search(r";\s*true\b", block), path.name


def test_manifest_ships_what_the_sdist_needs_to_run_the_suite():
    manifest = (WORKFLOWS.parents[1] / "MANIFEST.in").read_text(encoding="utf-8")
    for needle in (
        "recursive-include tests",
        "recursive-include scripts",
        "recursive-include schemas",
        "include CHANGELOG.md",
    ):
        assert needle in manifest, needle
