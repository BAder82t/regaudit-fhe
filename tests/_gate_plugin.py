"""pytest plugin for the test gate (see ``tests/_gate.py`` and ``docs/TEST_GATES.md``).

Always on, and harmless: it applies the ``security_gate`` / ``tenseal_required`` markers to the tests of the
modules the reviewed manifest lists, and it checks the TenSEAL requirement at start-up.

Active only with ``--gate`` (full scope) or ``--gate-scope NAME`` (or ``REGAUDIT_GATE=1``, full scope). Then it:

* refuses, before running anything, an invocation that can stop the required tests from running: a selection
  option (``-k``, ``-m``, ``--deselect``, ``--lf``, ``--ff``, ``--sw``), ``--collect-only``, ``--setup-only``,
  ``--setup-plan``, xdist;
* records what pytest actually collected (after its own selection), deselected and executed;
* compares that, by test identity and body hash, with the checked-in inventory for the scope;
* writes the ledger (``test-gate-ledger.json`` and ``.txt``) and turns the exit status into a failure when
  anything the scope requires is missing, deselected, not executed, changed, failed or unexpectedly skipped.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import Any

import pytest

from tests import _gate
from tests import _gate_identity as ident

ROOT = Path(__file__).resolve().parents[1]

TIER_MARKERS = {_gate.TIER_SECURITY: "security_gate", _gate.TIER_TENSEAL: "tenseal_required"}

FULL_SCOPE = "full"

# Options that can stop the declared tests from running. (option dest, flag shown to the user, "falsy" means off)
REFUSED_OPTIONS = (
    ("keyword", "-k"),
    ("markexpr", "-m"),
    ("deselect", "--deselect"),
    ("lf", "--lf"),
    ("failedfirst", "--ff"),
    ("stepwise", "--sw"),
    ("stepwise_skip", "--sw-skip"),
    ("collectonly", "--collect-only"),
    ("setuponly", "--setup-only"),
    ("setupplan", "--setup-plan"),
)


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


def _inventory_path(manifest: Any) -> Path:
    override = os.environ.get("REGAUDIT_GATE_INVENTORY") or getattr(
        manifest, "INVENTORY_PATH", None
    )
    return Path(override) if override else ident.DEFAULT_INVENTORY


def pytest_addoption(parser: pytest.Parser) -> None:
    g = parser.getgroup("regaudit-gate", "test-gate accounting")
    g.addoption(
        "--gate",
        action="store_true",
        default=False,
        help="enforce the test gate for the full suite",
    )
    g.addoption(
        "--gate-scope",
        default=None,
        metavar="NAME",
        help="enforce the test gate for the named partial scope defined in tests/_gate_manifest.py",
    )
    g.addoption("--gate-dir", default="test-gate", help="directory for the gate ledger files")


def _selected_scope(config: pytest.Config) -> str | None:
    scope = config.getoption("--gate-scope")
    if scope:
        return str(scope)
    if config.getoption("--gate") or os.environ.get("REGAUDIT_GATE") == "1":
        return FULL_SCOPE
    return None


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
    state = GatePlugin(config, _selected_scope(config))
    config.pluginmanager.register(state, "regaudit-gate-state")
    # TenSEAL-required mode: refuse to start, loudly, rather than let every FHE test skip.
    if state.env.require_tenseal and "tenseal" in state.env.missing:
        raise pytest.UsageError(
            "REGAUDIT_REQUIRE_TENSEAL=1 but TenSEAL cannot be imported. Install the 'fhe' extra "
            "(pip install -e '.[dev,server,fhe]'). Tests that need TenSEAL must not skip in this mode."
        )
    if state.enabled:
        state.refuse_unsafe_invocation()


class GatePlugin:
    """Holds the run's records. Registered by ``pytest_configure`` so its hooks see this config."""

    def __init__(self, config: pytest.Config, scope: str | None) -> None:
        self.config = config
        self.scope = scope
        self.enabled = scope is not None
        self.env = _gate.detect_environment(ROOT)
        self.manifest = _load_manifest()
        self.phases: dict[str, list[tuple[str, str]]] = {}
        self.module_records: dict[str, _gate.Outcome] = {}
        self.tier_of: dict[str, str | None] = {}
        self.collected: dict[str, int] = {}
        self.selected: list[str] = []
        self.deselected: list[str] = []
        self.hashes: dict[str, str] = {}
        self.modules_seen: set[str] = set()
        self.collection_errors: list[str] = []
        self.ledger: dict[str, Any] | None = None
        self.paths: tuple[Path, Path] | None = None
        self.inventory: dict[str, Any] | None = None
        self.scope_modules: set[str] | None = None

    # -- invocation -------------------------------------------------------------------------------

    def invocation(self) -> dict[str, Any]:
        cfg = self.config
        opts = {flag: cfg.getoption(dest, default=None) for dest, flag in REFUSED_OPTIONS}
        return {
            "args": list(cfg.invocation_params.args),
            "scope": self.scope,
            "pytest_addopts_env": os.environ.get("PYTEST_ADDOPTS", ""),
            "maxfail": cfg.getoption("maxfail", default=0),
            "selection_options": {k: v for k, v in opts.items() if v},
            "paths_given": [str(a) for a in cfg.args],
        }

    def refuse_unsafe_invocation(self) -> None:
        """Fail before anything runs when an option can stop the declared tests from running."""
        problems = []
        for dest, flag in REFUSED_OPTIONS:
            value = self.config.getoption(dest, default=None)
            if value:
                problems.append(flag)
        numproc = self.config.getoption("numprocesses", default=None)
        if numproc:
            problems.append("-n (xdist)")
        if any("::" in str(a) for a in self.config.args):
            problems.append("a node id argument")
        if self.scope not in getattr(self.manifest, "SCOPES", {}):
            known = ", ".join(sorted(getattr(self.manifest, "SCOPES", {})))
            self._refuse(f"unknown gate scope {self.scope!r}; the manifest defines: {known}")
        if problems:
            self._refuse(
                f"the test gate (scope {self.scope!r}) refuses this invocation because "
                f"{', '.join(problems)} can stop required tests from running. "
                "Run the scope without selection options, or run pytest without --gate for a partial run."
            )
        try:
            self.inventory = ident.load_inventory(_inventory_path(self.manifest))
        except (OSError, ValueError) as exc:
            self._refuse(f"cannot read the test-gate inventory: {exc}")
        scope_inv = self.inventory.get("scopes", {}).get(str(self.scope))
        if scope_inv is None:
            self._refuse(
                f"scope {self.scope!r} is not in the test-gate inventory; run scripts/gate_inventory.py --write"
            )
        self.scope_modules = set(scope_inv["modules"])

    def _refuse(self, message: str) -> None:
        ledger = {
            "schema": _gate.SCHEMA,
            "verdict": "FAIL",
            "scope": {"name": self.scope, "defined": False},
            "invocation": self.invocation(),
            "environment": self.env.facts(),
            "violations": [{"code": "INVOCATION_REFUSED", "nodeid": "-", "message": message}],
        }
        text = f"TEST GATE: FAIL\nINVOCATION_REFUSED: {message}\n"
        directory = Path(self.config.getoption("--gate-dir"))
        try:
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "test-gate-ledger.json").write_text(
                json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            (directory / "test-gate-ledger.txt").write_text(text, encoding="utf-8")
        except OSError:
            # Best effort: the refusal below is the real output. A ledger that cannot be written (read-only or
            # missing directory) must not hide it or replace it with a different error.
            pass
        raise pytest.UsageError(f"TEST GATE: FAIL: INVOCATION_REFUSED: {message}")

    # -- collection -------------------------------------------------------------------------------

    def tier_for_module(self, module: str) -> str | None:
        if module in self.manifest.SECURITY_GATE_MODULES:
            return _gate.TIER_SECURITY
        if module in self.manifest.TENSEAL_REQUIRED_MODULES:
            return _gate.TIER_TENSEAL
        return None

    def run_tier(self, module: str) -> str | None:
        """The tier a module has IN THIS RUN: a module the active scope does not require is optional here."""
        tier = self.tier_for_module(module)
        if tier is None or self.scope_modules is None:
            return tier
        return tier if module in self.scope_modules else None

    def pytest_collection_modifyitems(self, items: list[pytest.Item]) -> None:
        # Markers only. The gate's own counting happens in pytest_collection_finish, after every selection
        # option has been applied (counting here, before pytest's own deselection, was the original defect).
        for item in items:
            module = item.nodeid.split("::", 1)[0]
            tier = self.tier_for_module(module)
            if tier:
                item.add_marker(getattr(pytest.mark, TIER_MARKERS[tier]))
            run_tier = self.run_tier(module)
            # An explicit decorator on a test (or its module) also makes it mandatory.
            if item.get_closest_marker("security_gate") and tier is None:
                run_tier = _gate.TIER_SECURITY
            self.tier_of[item.nodeid] = run_tier

    def _record_hash(self, item: pytest.Item) -> None:
        module, rest = ident.split_nodeid(item.nodeid)
        if not self.enabled or self.tier_for_module(module) is None:
            return
        func = getattr(item, "obj", None)
        self.hashes[f"{module}::{ident.function_key(rest)}"] = (
            ident.cached_source_hash(func) if func is not None else "unavailable"
        )

    def pytest_deselected(self, items: list[pytest.Item]) -> None:
        self.deselected += [i.nodeid for i in items]
        for item in items:
            self._record_hash(item)

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        # After every selection option has run: this is what pytest will actually execute.
        for item in session.items:
            self.selected.append(item.nodeid)
            module = ident.split_nodeid(item.nodeid)[0]
            self.collected[module] = self.collected.get(module, 0) + 1
            self._record_hash(item)

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
        if not self.enabled or not report.nodeid.endswith(".py"):
            return
        self.modules_seen.add(report.nodeid)
        if report.outcome == "passed":
            return
        if report.outcome != "skipped":
            self.collection_errors.append(report.nodeid)
        self.module_records[report.nodeid] = _gate.Outcome(
            nodeid=report.nodeid,
            outcome="skipped" if report.outcome == "skipped" else "failed",
            reason=_reason(report),
            tier=self.run_tier(report.nodeid),
            module_level=True,
        )

    # -- verdict ----------------------------------------------------------------------------------

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
        assert self.inventory is not None
        stopped = ""
        if getattr(session, "shouldstop", ""):
            stopped = str(session.shouldstop)
        elif getattr(session, "shouldfail", ""):
            stopped = str(session.shouldfail)
        facts = _gate.RunFacts(
            scope=str(self.scope),
            inventory=self.inventory,
            selected=self.selected,
            deselected=self.deselected,
            hashes=self.hashes,
            modules_seen=self.modules_seen,
            collection_errors=self.collection_errors,
            stopped=stopped,
            invocation=self.invocation(),
        )
        self.ledger = _gate.evaluate(
            self.outcomes(), self.collected, self.manifest, self.env, facts
        )
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
