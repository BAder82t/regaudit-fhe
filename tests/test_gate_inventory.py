"""The checked-in test-gate inventory must equal what pytest collects, in both directions.

Needs the full set of extras (the inventory is generated with all of them), so it is outside the ``sdist`` and
``release-gate`` scopes. See ``docs/TEST_GATES.md``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_collection_and_the_checked_in_inventory_agree_in_both_directions():
    """Fails when a mandatory test is added, removed, renamed, re-parametrised or has its body changed without a
    reviewed update of tests/_gate_inventory.json (python scripts/gate_inventory.py --write)."""
    script = ROOT / "scripts" / "gate_inventory.py"
    if not script.exists():
        pytest.skip("scripts/ is not part of this checkout")
    for pkg in ("tenseal", "fastapi", "httpx", "yaml", "hypothesis", "uvicorn"):
        pytest.importorskip(pkg)
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, str(script), "--check"],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": os.pathsep.join([str(ROOT), str(ROOT / "src")])},
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-4000:]
