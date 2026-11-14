"""Fixtures: a synthetic configuration that the portal treats as an administrator's own, and a client for it; and,
for the administrator commands, an empty account, a way to run a command, and one issuer.

demo-setup's own output is a demonstration, which the portal keeps apart from that; tests about it call demo-setup.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import (  # noqa: F401 - children_start_with_default_stop_signals is a fixture, found by pytest here
    children_start_with_default_stop_signals,
    client_for,
    fake_home,
    issuer_signer,
    make_synthetic_portal,
)
from regaudit_portal.__main__ import main
from regaudit_portal.paths import default_config_folder


@pytest.fixture
def demo(tmp_path: Path) -> Path:
    return make_synthetic_portal(tmp_path / "demo")


@pytest.fixture
def client(demo: Path) -> TestClient:
    return client_for(demo / "portal-config.json")


@pytest.fixture
def home(tmp_path, monkeypatch):
    """An empty account with the folder above the standard configuration folder, as a real account has it."""
    home = fake_home(tmp_path, monkeypatch)
    parent = default_config_folder().parent
    parent.mkdir(parents=True)
    for place in (home, *[p for p in parent.parents if home in p.parents or p == home], parent):
        os.chmod(place, 0o755)  # noqa: S103 - what a real home folder has
    return home


@pytest.fixture
def run(capsys):
    def call(*argv: str) -> tuple[int, str, str]:
        capsys.readouterr()
        code = main([str(a) for a in argv])
        out, err = capsys.readouterr()
        return code, out, err

    return call


@pytest.fixture
def northwind():
    return issuer_signer("Northwind Ltd", "northwind-2026")
