"""docs/WALKTHROUGH.md: its shell blocks run, in order, in an empty directory and exit as the page says."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "WALKTHROUGH.md"
if not DOC.is_file():
    pytest.skip("docs/WALKTHROUGH.md is not part of this checkout", allow_module_level=True)

BLOCK = re.compile(r"^```(\w+)\n(.*?)^```", re.S | re.M)
EXIT = re.compile(r"^exit=(\d+)$", re.M)


def _blocks() -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in BLOCK.finditer(DOC.read_text(encoding="utf-8"))]


def _runnable() -> str:
    # The install block needs the network; everything else is run.
    return "\n".join(
        code for lang, code in _blocks() if lang == "bash" and "pip install" not in code
    )


def _documented_exits() -> list[int]:
    return [int(m) for lang, code in _blocks() if lang == "text" for m in EXIT.findall(code)]


def test_walkthrough_documents_the_expected_exit_codes() -> None:
    # signed audit, wrong fingerprint, enrol, list, TRUSTED, SELF_SIGNED_ONLY, INVALID
    assert _documented_exits() == [0, 2, 0, 0, 0, 1, 1]


def test_walkthrough_commands_run_and_exit_as_documented(tmp_path: Path) -> None:
    bindir = Path(sys.executable).parent
    if not (bindir / "regaudit-fhe").exists():
        pytest.skip("regaudit-fhe console script is not installed next to this interpreter")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("REGAUDIT_FHE_", "PYTHON"))}
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    # `python` in the page must be this interpreter even if the venv has no `python` shim.
    shim = tmp_path / "shimbin"
    shim.mkdir()
    (shim / "python").symlink_to(sys.executable)
    env["PATH"] = f"{shim}{os.pathsep}{env['PATH']}"
    work = tmp_path / "work"
    work.mkdir()
    bash = shutil.which("bash")
    assert bash
    proc = subprocess.run(  # noqa: S603 - fixed argv; the script is this repository's own documentation
        [bash, "-c", _runnable()],
        capture_output=True,
        text=True,
        cwd=work,
        env=env,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert [int(x) for x in EXIT.findall(proc.stdout)] == _documented_exits()
    assert '"trust_status": "TRUSTED"' in (work / "verdict_trusted.json").read_text()
    assert '"trust_status": "SELF_SIGNED_ONLY"' in (work / "verdict_self.json").read_text()
    assert '"trust_status": "INVALID"' in (work / "verdict_tampered.json").read_text()
    assert oct((work / "issuer.key.pem").stat().st_mode & 0o777) == "0o600"
