"""Fixtures: a synthetic demonstration directory, and a client for it."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import client_for
from regaudit_portal.demo import create


@pytest.fixture
def demo(tmp_path: Path) -> Path:
    return create(tmp_path / "demo")


@pytest.fixture
def client(demo: Path) -> TestClient:
    return client_for(demo / "portal-config.json")
