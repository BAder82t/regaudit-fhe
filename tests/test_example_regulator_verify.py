"""examples/regulator_verify_signature.py: three distinct outcomes, and no claim it must not make."""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "regulator_verify_signature.py"
if not EXAMPLE.is_file():
    pytest.skip("examples/ is not part of this checkout", allow_module_level=True)


def _load():
    spec = importlib.util.spec_from_file_location("regulator_verify_example", EXAMPLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run() -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("REGAUDIT_FHE_")}
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), env.get("PYTHONPATH", "")])
    return subprocess.run(  # noqa: S603 - fixed argv; the script is this repository's own example
        [sys.executable, str(EXAMPLE)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
        env=env,
        timeout=120,
    )


def test_example_exits_zero_and_shows_three_distinct_outcomes() -> None:
    proc = _run()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert re.search(r"\(a\) enrolled issuer\n\s+trust_status: TRUSTED\s+accepted: True", out)
    assert re.search(
        r"\(b\) stranger, self-signed\n\s+trust_status: INVALID\s+accepted: False\s+"
        r"blocking_reasons: \['ISSUER_UNKNOWN'\]",
        out,
    )
    assert re.search(
        r"\(c\) enrolled issuer, edited after signing\n\s+trust_status: INVALID\s+accepted: False\s+"
        r"blocking_reasons: \[.*SIGNATURE_INVALID.*\]",
        out,
    )
    assert (
        out.count("TRUSTED") >= 1
        and "TRUSTED" not in out.split("(b) stranger")[1].split("(c)")[0].split("What this")[0]
    )


def test_example_statuses_are_computed_by_the_policy_not_assumed() -> None:
    # If the example were to trust the stranger, this fails: it reads the values the example computes.
    outcomes = {o.label[:3]: o for o in _load().run_scenarios()}
    assert (outcomes["(a)"].trust_status, outcomes["(a)"].accepted) == ("TRUSTED", True)
    assert (outcomes["(b)"].trust_status, outcomes["(b)"].accepted) == ("INVALID", False)
    assert outcomes["(b)"].blocking_reasons == ("ISSUER_UNKNOWN",)
    assert (outcomes["(c)"].trust_status, outcomes["(c)"].accepted) == ("INVALID", False)
    assert outcomes["(c)"].blocking_reasons != outcomes["(b)"].blocking_reasons


def test_example_makes_no_claim_it_must_not_make() -> None:
    proc = _run()
    text = (proc.stdout + EXAMPLE.read_text(encoding="utf-8")).lower()
    for phrase in ("certified", "compliant", "proves encryption", "production-ready", "audited by"):
        assert phrase not in text
    assert "plaintext" in proc.stdout and "does not show" in proc.stdout


def test_example_carries_the_label_and_the_invariant() -> None:
    proc = _run()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Encrypted execution not established." in proc.stdout
    assert (
        "A signed report can authenticate a claim without proving that claim is true."
        in proc.stdout
    )
    assert "declare a plaintext backend" in proc.stdout
    for phrase in (
        "encrypted audit",
        "computed under encryption",
        "fhe verified",
        "privacy preserved",
    ):
        assert phrase not in proc.stdout.lower()
    assert "These reports came from the plaintext path" not in proc.stdout
