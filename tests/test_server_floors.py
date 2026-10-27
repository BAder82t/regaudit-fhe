"""The server-floor CI job: the script that derives the floors from pyproject.toml, and the job that uses it."""

from __future__ import annotations

import importlib.util
import re
from importlib import metadata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "server_floors.py"
CI = ROOT / ".github" / "workflows" / "ci.yml"
if not SCRIPT.is_file():
    pytest.skip("scripts/ is not part of this checkout", allow_module_level=True)

_spec = importlib.util.spec_from_file_location("server_floors", SCRIPT)
sf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sf)


def _pyproject(tmp_path, server_lines):
    path = tmp_path / "pyproject.toml"
    body = "\n".join(f'  "{line}",' for line in server_lines)
    path.write_text(
        f'[project.optional-dependencies]\nserver = [\n{body}\n]\ndev = [\n  "pytest>=9",\n]\n'
    )
    return path


def test_floors_are_read_from_the_server_extra_only(tmp_path):
    path = _pyproject(
        tmp_path, ["fastapi>=0.143.0", "uvicorn[standard]>=0.54.0", "pydantic>=2.14.0"]
    )
    assert sf.server_floors(path) == {"fastapi": "0.143.0", "pydantic": "2.14.0"}
    assert sf.constraints(path) == "fastapi==0.143.0\npydantic==2.14.0\n"


def test_the_floors_follow_an_intentional_increase(tmp_path):
    path = _pyproject(tmp_path, ["fastapi>=0.150.1", "pydantic>=2.15.0"])
    assert sf.constraints(path) == "fastapi==0.150.1\npydantic==2.15.0\n"


@pytest.mark.parametrize(
    "lines", [["fastapi>=0.143.0"], ["pydantic>=2.14.0"], ["fastapi", "pydantic>=2.14.0"]]
)
def test_a_missing_minimum_is_refused(tmp_path, lines):
    with pytest.raises(SystemExit):
        sf.server_floors(_pyproject(tmp_path, lines))


def test_the_real_pyproject_declares_both_floors():
    floors = sf.server_floors()
    assert set(floors) == {"fastapi", "pydantic"} and all(
        re.match(r"\d+\.\d+", v) for v in floors.values()
    )


def test_check_fails_when_a_newer_version_is_installed(tmp_path, monkeypatch):
    path = _pyproject(tmp_path, ["fastapi>=0.143.0", "pydantic>=2.14.0"])
    real = sf._version
    monkeypatch.setattr(sf, "_version", lambda n: {"fastapi": "0.162.0"}.get(n) or real(n))
    problems = sf.check(path)
    assert any("fastapi: installed 0.162.0, declared minimum 0.143.0" in p for p in problems)


def test_check_passes_when_the_installed_versions_are_exactly_the_floors(tmp_path, monkeypatch):
    path = _pyproject(tmp_path, ["fastapi>=0.143.0", "pydantic>=2.14.0"])
    fake = {"fastapi": "0.143.0", "pydantic": "2.14.0", "pydantic-core": "2.50.0"}
    monkeypatch.setattr(sf, "_version", lambda n: fake[n])
    monkeypatch.setattr(sf, "pydantic_core_requirement", lambda: "2.50.0")
    assert sf.check(path) == []
    monkeypatch.setitem(fake, "pydantic-core", "2.50.1")
    assert any("pydantic-core" in p for p in sf.check(path))


def test_check_fails_when_a_package_is_missing(tmp_path, monkeypatch):
    path = _pyproject(tmp_path, ["fastapi>=0.143.0", "pydantic>=2.14.0"])

    def gone(name):
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(sf, "_version", gone)
    assert any("not installed" in p for p in sf.check(path))


def test_the_ci_job_installs_the_floors_from_pyproject_and_then_checks_them():
    yaml = pytest.importorskip("yaml")
    if not CI.is_file():
        pytest.skip("workflows are not part of this checkout")
    job = yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]["server-floor"]
    assert job["name"] == "server floors (py${{ matrix.python-version }})"
    assert job["strategy"]["matrix"]["python-version"] == ["3.10", "3.13"]
    runs = [s["run"] for s in job["steps"] if "run" in s]
    assert any("server_floors.py constraints" in r for r in runs)
    install = next(r for r in runs if r.startswith("pip install -e"))
    assert '-c "$RUNNER_TEMP/floors.txt"' in install and "server" in install
    assert runs.index(install) < next(
        i for i, r in enumerate(runs) if "server_floors.py check" in r
    )
    assert "pytest tests/" in runs[-1]
    assert all("if" not in s and "continue-on-error" not in s for s in job["steps"])
