"""Test-gate hooks (markers, TenSEAL requirement, ledger). The logic lives in ``tests/_gate_plugin.py``."""

from tests._gate_plugin import pytest_addoption, pytest_configure

__all__ = ["pytest_addoption", "pytest_configure"]
