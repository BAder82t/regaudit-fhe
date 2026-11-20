"""Every pytest run in CI carries a gate scope (or is a named, reasoned exemption).

``--gate`` is opt-in, so a workflow edit that drops it would silently remove all enforcement. This test reads
``.github/workflows/*.yml`` and fails when a ``pytest`` invocation has neither ``--gate`` (full scope) nor
``--gate-scope NAME`` with NAME defined in the manifest. It also checks the scopes are used and that no
workflow smuggles in a selection option. See ``docs/TEST_GATES.md`` for what it cannot enforce.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

from tests import _gate_manifest as manifest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

pytestmark = pytest.mark.skipif(
    not WORKFLOWS.is_dir(), reason="workflows are not part of this checkout"
)

# pytest runs the engine gate does not govern. Each needs a reason. The portal is a separate suite with its own
# conftest and its own skip allow-list (portal/ci/allowed_skips.txt, checked by portal/ci/check_skips.py).
UNGATED = {
    "portal/tests": "the portal suite is separate from the engine suite; its skips are checked by "
    "portal/ci/check_skips.py against portal/ci/allowed_skips.txt",
}

SELECTION = (
    "-k",
    "-m",
    "--deselect",
    "--lf",
    "--ff",
    "--sw",
    "--collect-only",
    "--co",
    "--setup-only",
)


def _commands(run: str) -> list[str]:
    joined = re.sub(r"\\\n\s*", " ", run)
    return [
        ln.strip() for ln in joined.splitlines() if ln.strip() and not ln.strip().startswith("#")
    ]


def _is_pytest(tokens: list[str]) -> bool:
    for i, tok in enumerate(tokens):
        if tok == "pytest" or tok.endswith("/pytest"):
            return True
        if tok == "-m" and i + 1 < len(tokens) and tokens[i + 1] == "pytest":
            return True
    return False


def invocations() -> list[dict[str, object]]:
    """Every pytest invocation in every workflow: workflow, job, step, command, tokens."""
    out: list[dict[str, object]] = []
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        for job_id, job in (doc.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                for cmd in _commands(str(step.get("run", ""))):
                    if re.match(r"^(python3?\s+-m\s+)?pip\s+install", cmd):
                        continue
                    try:
                        tokens = shlex.split(cmd, comments=False)
                    except ValueError:
                        tokens = cmd.split()
                    if _is_pytest(tokens):
                        out.append(
                            {
                                "workflow": wf.name,
                                "job": job_id,
                                "step": step.get("name", ""),
                                "command": cmd,
                                "tokens": tokens,
                            }
                        )
    return out


def scope_of(tokens: list[str]) -> str | None:
    """The gate scope a command declares: ``--gate`` -> full, ``--gate-scope X`` -> X, else None."""
    for i, tok in enumerate(tokens):
        if tok == "--gate-scope" and i + 1 < len(tokens):
            return tokens[i + 1]
        if tok.startswith("--gate-scope="):
            return tok.split("=", 1)[1]
    return "full" if "--gate" in tokens else None


def ungated_reason(cmd: str) -> str | None:
    for needle, reason in UNGATED.items():
        if needle in cmd:
            return reason
    return None


def coverage_matrix() -> list[tuple[str, str, str, str, str]]:
    """(workflow, job, command, scope, gated) for every pytest invocation."""
    rows = []
    for inv in invocations():
        scope = scope_of(inv["tokens"])  # type: ignore[arg-type]
        gated = "yes" if scope else "no"
        if scope is None and ungated_reason(str(inv["command"])):
            scope = "(exempt: separate portal suite)"
        rows.append(
            (str(inv["workflow"]), str(inv["job"]), str(inv["command"]), scope or "NONE", gated)
        )
    return rows


def test_the_scan_finds_the_known_pytest_runs():
    """Guards the scanner itself: if it finds nothing, the other tests would pass for the wrong reason."""
    inv = invocations()
    assert {"ci.yml", "release-build.yml", "portal.yml"} <= {str(i["workflow"]) for i in inv}
    assert len(inv) >= 6


def test_every_pytest_invocation_in_a_workflow_has_a_gate_scope_or_a_reasoned_exemption():
    bad = []
    for inv in invocations():
        scope = scope_of(inv["tokens"])  # type: ignore[arg-type]
        if scope is None and not ungated_reason(str(inv["command"])):
            bad.append(f"{inv['workflow']}:{inv['job']}: {inv['command']}")
    assert not bad, "pytest run without --gate or --gate-scope:\n" + "\n".join(bad)


def test_every_declared_scope_exists_in_the_manifest():
    for inv in invocations():
        scope = scope_of(inv["tokens"])  # type: ignore[arg-type]
        if scope:
            assert scope in manifest.SCOPES, (
                f"{inv['workflow']}:{inv['job']}: unknown scope {scope!r}"
            )


def test_every_manifest_scope_is_used_by_some_workflow_run():
    used = {scope_of(i["tokens"]) for i in invocations()}  # type: ignore[arg-type]
    assert set(manifest.SCOPES) <= used, set(manifest.SCOPES) - used


def _args_after_pytest(tokens: list[str]) -> list[str]:
    for i, tok in enumerate(tokens):
        if tok == "pytest" or tok.endswith("/pytest"):
            return tokens[i + 1 :]
        if tok == "-m" and i + 1 < len(tokens) and tokens[i + 1] == "pytest":
            return tokens[i + 2 :]
    return []


def test_a_gated_run_carries_no_selection_option():
    for inv in invocations():
        toks: list[str] = inv["tokens"]  # type: ignore[assignment]
        if scope_of(toks):
            args = _args_after_pytest(toks)
            hit = [t for t in args if t in SELECTION or t.startswith(("--deselect=", "-k=", "-m="))]
            assert not hit, f"{inv['workflow']}:{inv['job']}: {hit}"


def test_the_selection_check_would_see_a_filter():
    assert _args_after_pytest(["python", "-m", "pytest", "--gate", "-k", "x"]) == [
        "--gate",
        "-k",
        "x",
    ]
    assert _args_after_pytest(["pytest", "tests/", "-m", "not security_gate"])[1:] == [
        "-m",
        "not security_gate",
    ]


def test_the_exempt_runs_really_are_the_portal_suite_and_only_that():
    for inv in invocations():
        if scope_of(inv["tokens"]) is None:  # type: ignore[arg-type]
            assert "portal/tests" in str(inv["command"])
            assert inv["workflow"] == "portal.yml"


def test_no_workflow_sets_pytest_addopts():
    for wf in WORKFLOWS.glob("*.yml"):
        assert "PYTEST_ADDOPTS" not in wf.read_text(encoding="utf-8"), wf.name


def test_no_script_or_dockerfile_runs_pytest_outside_the_gate():
    hits = []
    candidates = [*ROOT.glob("scripts/*.sh"), ROOT / "Dockerfile", ROOT / "Makefile"]
    for path in candidates:
        if not path.is_file():
            continue
        for ln in path.read_text(encoding="utf-8").splitlines():
            if ln.strip().startswith("#"):
                continue
            if re.search(r"(^|[\s;&|(])(python3?\s+-m\s+)?pytest\b", ln) and "--gate" not in ln:
                hits.append(f"{path.name}: {ln.strip()}")
    assert not hits, hits
