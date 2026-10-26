"""One version, everywhere it is written down."""

from __future__ import annotations

import re
from importlib import metadata
from pathlib import Path

import pytest

import regaudit_fhe as rf
import regaudit_fhe.reports as reports

ROOT = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "no version in pyproject.toml"
    return match.group(1)


def test_library_version_constants_agree():
    assert rf.__version__ == reports.LIB_VERSION


def test_pyproject_version_matches_the_library():
    if not (ROOT / "pyproject.toml").is_file():
        pytest.skip("no pyproject.toml next to the tests")
    assert _pyproject_version() == rf.__version__


def test_installed_metadata_matches_the_library():
    installed: str | None
    try:
        installed = metadata.version("regaudit-fhe")
    except metadata.PackageNotFoundError:
        installed = None
    if installed is None:
        pytest.skip("regaudit-fhe is not installed")
    assert installed == rf.__version__


def test_new_envelopes_carry_the_library_version():
    import numpy as np

    report = rf.audit_fairness(
        np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([0.0, 1.0])
    )
    assert rf.envelope("fairness", report).algorithm_version == rf.__version__


def test_readme_example_shows_the_current_algorithm_version():
    readme = ROOT / "README.md"
    if not readme.is_file():
        pytest.skip("no README next to the tests")
    assert f'"algorithm_version": "{rf.__version__}"' in readme.read_text(encoding="utf-8")
