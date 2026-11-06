"""Fixtures: a synthetic configuration that the portal treats as an administrator's own, and a client for it.

demo-setup's own output is a demonstration, which the portal keeps apart from that; tests about it call demo-setup.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import client_for, make_synthetic_portal


@pytest.fixture
def demo(tmp_path: Path) -> Path:
    return make_synthetic_portal(tmp_path / "demo")


@pytest.fixture
def client(demo: Path) -> TestClient:
    return client_for(demo / "portal-config.json")
