"""Run the shell of the release workflow's guard and verification steps, for real, in scratch directories.

The step scripts are read out of the workflow YAML (so the text under test is the text GitHub would run) and
executed with ``bash`` against a throw-away git repository and fake distribution files. This checks the
logic of the checks; it is NOT a GitHub Actions run.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
PUBLISH = WORKFLOWS / "pypi-release.yml"
pytestmark = [
    pytest.mark.skipif(not PUBLISH.is_file(), reason="workflows are not part of this checkout"),
    pytest.mark.skipif(
        shutil.which("bash") is None or shutil.which("git") is None, reason="needs bash and git"
    ),
]


def _step(job: str, name: str) -> str:
    wf = yaml.safe_load(PUBLISH.read_text(encoding="utf-8"))
    for step in wf["jobs"][job]["steps"]:
        if step.get("name") == name:
            return step["run"]
    raise AssertionError(f"no step {name!r} in job {job!r}")


def _bash(script: str, cwd: Path, env: dict[str, str]):
    full = {"PATH": os.environ["PATH"], "HOME": str(cwd), "GIT_CONFIG_NOSYSTEM": "1", **env}
    return subprocess.run(  # noqa: S603 - fixed argv, scratch directories
        ["bash", "-c", script],  # noqa: S607
        cwd=cwd, env=full, capture_output=True, text=True, check=False,
    )  # fmt: skip


def _git(cwd: Path, *args: str) -> str:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(cwd),
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }  # fmt: skip
    out = subprocess.run(  # noqa: S603 - fixed argv, scratch directories
        ["git", *args],  # noqa: S607
        cwd=cwd, env=env, capture_output=True, text=True, check=True,
    )  # fmt: skip
    return out.stdout.strip()


@pytest.fixture
def repo(tmp_path):
    """origin (bare) with master, plus a clone; returns the clone and helper data."""
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "master", str(origin))
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(origin), str(work))
    _git(work, "checkout", "-q", "-b", "master")
    (work / "f").write_text("1")
    _git(work, "add", "f")
    _git(work, "commit", "-q", "-m", "one")
    _git(work, "push", "-q", "origin", "master")
    return work


def _guard_env(sha: str, **over: str) -> dict[str, str]:
    base = {
        "REF_TYPE": "tag", "REF_NAME": "v1.2.3", "EVENT": "push", "EVENT_SHA": sha, "DEFAULT_BRANCH": "master",
    }  # fmt: skip
    return {**base, **over}


GUARD = "the tag, the commit and the branch are acceptable"


def _guard(repo: Path, **over: str):
    _git(
        repo, "push", "-q", "--force", "origin", "--tags"
    )  # the runner fetches the tag from the remote
    return _bash(
        _step("guard", "Check the trigger, the tag and the commit"),
        repo,
        _guard_env(_git(repo, "rev-parse", "HEAD"), **over),
    )


def test_guard_accepts_an_annotated_tag_on_the_default_branch(repo):
    _git(repo, "tag", "-a", "v1.2.3", "-m", "release")
    r = _guard(repo)
    assert r.returncode == 0, r.stderr
    assert "is on master" in r.stdout


def test_guard_refuses_a_lightweight_tag(repo):
    _git(repo, "tag", "v1.2.3")
    assert _guard(repo).returncode != 0


def test_guard_refuses_a_tag_on_a_commit_that_is_not_on_the_default_branch(repo):
    _git(repo, "checkout", "-q", "-b", "feature")
    (repo / "g").write_text("2")
    _git(repo, "add", "g")
    _git(repo, "commit", "-q", "-m", "only on a branch")
    _git(repo, "tag", "-a", "v1.2.3", "-m", "release")
    assert _guard(repo).returncode != 0


@pytest.mark.parametrize(
    "over",
    [
        {"REF_TYPE": "branch"},
        {"EVENT": "workflow_dispatch"},
        {"REF_NAME": "v1.2.3rc1"},
        {"REF_NAME": "1.2.3"},
        {"REF_NAME": "v1.2"},
        {"EVENT_SHA": "0" * 40},
    ],
)
def test_guard_refuses_wrong_triggers_names_and_commits(repo, over):
    _git(repo, "tag", "-a", "v1.2.3", "-m", "release")
    _git(repo, "tag", "-a", "v1.2.3rc1", "-m", "release")
    _git(repo, "tag", "-a", "1.2.3", "-m", "release")
    _git(repo, "tag", "-a", "v1.2", "-m", "release")
    assert _guard(repo, **over).returncode != 0


def test_guard_refuses_a_tag_that_points_elsewhere_than_the_event_commit(repo):
    first = _git(repo, "rev-parse", "HEAD")
    (repo / "g").write_text("2")
    _git(repo, "add", "g")
    _git(repo, "commit", "-q", "-m", "two")
    _git(repo, "push", "-q", "origin", "master")
    _git(repo, "tag", "-a", "v1.2.3", "-m", "release", first)
    _git(repo, "push", "-q", "--force", "origin", "--tags")
    r = _bash(
        _step("guard", "Check the trigger, the tag and the commit"),
        repo,
        _guard_env(_git(repo, "rev-parse", "HEAD")),
    )
    assert r.returncode != 0


# --- the digest checks before upload ------------------------------------------------------------------------


def _dist(tmp_path: Path, version="0.1.0"):
    d = tmp_path / "dist"
    d.mkdir()
    wheel = d / f"regaudit_fhe-{version}-py3-none-any.whl"
    sdist = d / f"regaudit_fhe-{version}.tar.gz"
    wheel.write_bytes(b"wheel-bytes")
    sdist.write_bytes(b"sdist-bytes")
    return (
        tmp_path,
        hashlib.sha256(b"wheel-bytes").hexdigest(),
        hashlib.sha256(b"sdist-bytes").hexdigest(),
    )


def _verify(cwd, wheel_sha, sdist_sha, version="0.1.0", ref="v0.1.0"):
    env = {
        "WHEEL_SHA256": wheel_sha,
        "SDIST_SHA256": sdist_sha,
        "VERSION": version,
        "REF_NAME": ref,
    }
    return _bash(_step("publish", "Re-verify the files about to be uploaded"), cwd, env)


def test_publish_verification_accepts_the_files_that_were_built(tmp_path):
    cwd, w, s = _dist(tmp_path)
    r = _verify(cwd, w, s)
    assert r.returncode == 0, r.stderr


def test_publish_verification_refuses_a_swapped_wheel(tmp_path):
    cwd, w, s = _dist(tmp_path)
    (cwd / "dist" / "regaudit_fhe-0.1.0-py3-none-any.whl").write_bytes(b"evil")
    assert _verify(cwd, w, s).returncode != 0


def test_publish_verification_refuses_a_swapped_sdist(tmp_path):
    cwd, w, s = _dist(tmp_path)
    (cwd / "dist" / "regaudit_fhe-0.1.0.tar.gz").write_bytes(b"evil")
    assert _verify(cwd, w, s).returncode != 0


def test_publish_verification_refuses_an_extra_file(tmp_path):
    cwd, w, s = _dist(tmp_path)
    (cwd / "dist" / "extra.whl").write_bytes(b"x")
    assert _verify(cwd, w, s).returncode != 0


def test_publish_verification_refuses_a_tag_that_does_not_match_the_version(tmp_path):
    cwd, w, s = _dist(tmp_path)
    assert _verify(cwd, w, s, ref="v0.1.1").returncode != 0


def test_publish_verification_refuses_file_names_for_another_version(tmp_path):
    cwd, w, s = _dist(tmp_path, version="0.0.9")
    assert _verify(cwd, w, s, version="0.1.0").returncode != 0
