"""pytest plugin for the test gate (see ``tests/_gate.py`` and ``docs/TEST_GATES.md``).

Always on, and harmless: it applies the ``security_gate`` / ``tenseal_required`` markers to the tests of the
modules the reviewed manifest lists, and it checks the TenSEAL requirement at start-up.

Active only with ``--gate`` (or ``REGAUDIT_GATE=1``): it records every outcome, writes the ledger
(``test-gate-ledger.json`` and ``.txt``) and turns the pytest exit status into a failure when a mandatory test
failed, was unexpectedly skipped, or is missing. ``--gate`` belongs on the FULL-suite run: a partial run
cannot satisfy the per-module floors.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any

import pytest

from tests import _gate

ROOT = Path(__file__).resolve().parents[1]

TIER_MARKERS = {_gate.TIER_SECURITY: "security_gate", _gate.TIER_TENSEAL: "tenseal_required"}


def _load_manifest() -> Any:
    override = os.environ.get("REGAUDIT_GATE_MANIFEST")
    if not override:
        from tests import _gate_manifest

        return _gate_manifest
    spec = importlib.util.spec_from_file_location("_regaudit_gate_manifest_override", override)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def pytest_addoption(parser: pytest.Parser) -> None:
    g = parser.getgroup("regaudit-gate", "test-gate accounting")
    g.addoption("--gate", action="store_true", default=False, help="enforce the test gate")
    g.addoption("--gate-dir", default="test-gate", help="directory for the gate ledger files")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "security_gate: a mandatory security test. It must run and pass; a skip fails the gate "
        "unless tests/_gate_manifest.py declares it for this platform.",
    )
    config.addinivalue_line(
        "markers",
        "tenseal_required: needs TenSEAL. Mandatory when REGAUDIT_REQUIRE_TENSEAL=1.",
    )
    enabled = bool(config.getoption("--gate")) or os.environ.get("REGAUDIT_GATE") == "1"
    state = GatePlugin(config, enabled)
    config.pluginmanager.register(state, "regaudit-gate-state")
    # TenSEAL-required mode: refuse to start, loudly, rather than let every FHE test skip.
    if state.env.require_tenseal and "tenseal" in state.env.missing:
        raise pytest.UsageError(
            "REGAUDIT_REQUIRE_TENSEAL=1 but TenSEAL cannot be imported. Install the 'fhe' extra "
            "(pip install -e '.[dev,server,fhe]'). Tests that need TenSEAL must not skip in this mode."
        )


class GatePlugin:
    """Holds the run's records. Registered by ``pytest_configure`` so its hooks see this config."""

    def __init__(self, config: pytest.Config, enabled: bool) -> None:
        self.config = config
        self.enabled = enabled
        self.env = _gate.detect_environment(ROOT)
        self.manifest = _load_manifest()
        self.phases: dict[str, list[tuple[str, str]]] = {}
        self.module_records: dict[str, _gate.Outcome] = {}
        self.tier_of: dict[str, str | None] = {}
        self.collected: dict[str, int] = {}
        self.ledger: dict[str, Any] | None = None
        self.paths: tuple[Path, Path] | None = None

    def tier_for_module(self, module: str) -> str | None:
        if module in self.manifest.SECURITY_GATE_MODULES:
            return _gate.TIER_SECURITY
        if module in self.manifest.TENSEAL_REQUIRED_MODULES:
            return _gate.TIER_TENSEAL
        return None

    def pytest_collection_modifyitems(self, items: list[pytest.Item]) -> None:
        for item in items:
            module = item.nodeid.split("::", 1)[0]
            self.collected[module] = self.collected.get(module, 0) + 1
            tier = self.tier_for_module(module)
            if tier:
                item.add_marker(getattr(pytest.mark, TIER_MARKERS[tier]))
            # An explicit decorator on a test (or its module) also makes it mandatory.
            if item.get_closest_marker("security_gate"):
                tier = _gate.TIER_SECURITY
            self.tier_of[item.nodeid] = tier

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if not self.enabled:
            return
        if hasattr(report, "wasxfail"):
            outcome = "xfailed" if report.skipped else "passed"
        else:
            outcome = report.outcome
        if report.when != "call" and outcome == "passed":
            return
        self.phases.setdefault(report.nodeid, []).append(
            (outcome, _reason(report) if outcome in ("skipped", "xfailed") else "")
        )

    def pytest_collectreport(self, report: pytest.CollectReport) -> None:
        if not self.enabled or report.outcome == "passed" or not report.nodeid.endswith(".py"):
            return
        self.module_records[report.nodeid] = _gate.Outcome(
            nodeid=report.nodeid,
            outcome="skipped" if report.outcome == "skipped" else "failed",
            reason=_reason(report),
            tier=self.tier_for_module(report.nodeid),
            module_level=True,
        )

    def outcomes(self) -> list[_gate.Outcome]:
        rank = {"passed": 0, "skipped": 1, "xfailed": 2, "failed": 3}
        out = list(self.module_records.values())
        for nodeid, phases in self.phases.items():
            worst = max(phases, key=lambda p: rank[p[0]])
            out.append(_gate.Outcome(nodeid, worst[0], worst[1], tier=self.tier_of.get(nodeid)))
        return out

    @pytest.hookimpl(tryfirst=True)
    def pytest_sessionfinish(self, session: pytest.Session) -> None:
        if not self.enabled:
            return
        self.ledger = _gate.evaluate(self.outcomes(), self.collected, self.manifest, self.env)
        self.paths = _gate.write_ledger(self.ledger, Path(self.config.getoption("--gate-dir")))
        if self.ledger["verdict"] == "FAIL" and int(session.exitstatus) == 0:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(self, terminalreporter: Any) -> None:
        if not self.enabled or self.ledger is None:
            return
        terminalreporter.write_line("")
        terminalreporter.write_line(_gate.render_text(self.ledger))
        if self.paths:
            terminalreporter.write_line(f"ledger: {self.paths[0]}")


def _reason(report: Any) -> str:
    lr = report.longrepr
    if isinstance(lr, tuple) and len(lr) == 3:
        return str(lr[2]).removeprefix("Skipped: ")
    return str(lr or "")
