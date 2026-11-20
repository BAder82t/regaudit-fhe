"""Test-gate accounting: classify every test outcome and decide whether the gate passes.

This module is pure logic (no pytest import) so that the gate can be tested without a pytest session.
``tests/_gate_plugin.py`` feeds it the outcomes of a real run; ``tests/_gate_manifest.py`` is the reviewed
data it checks them against. See ``docs/TEST_GATES.md``.

Every test outcome lands in exactly one ledger category:

====================================  =============================================================
``required_passed``                   a mandatory test (security tier, or the TenSEAL tier when
                                      ``REGAUDIT_REQUIRE_TENSEAL=1``) executed and passed
``required_failed``                   a mandatory test failed, errored or was xfailed
``required_unexpected_skipped``       a mandatory test was skipped and the manifest does not declare
                                      that skip for this platform (this fails the gate)
``intentional_skipped``               a skip the manifest declares for this environment (platform,
                                      optional backend, partial checkout). A mandatory test may only
                                      appear here through a rule marked ``gate_ok``
``blocked_by_dependency``             an optional test skipped because an optional dependency is not
                                      installed, as the manifest declares
``optional_passed`` / ``optional_failed``  everything else that ran
``optional_undeclared_skipped``       an optional test skipped for a reason no manifest rule covers
                                      (reported; fails the gate only in strict mode)
====================================  =============================================================

A mandatory module that is missing from the run, or that collected fewer tests than the manifest's
floor, also fails the gate: deleting a security test cannot pass silently.
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform as _platform
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tests import _gate_identity as ident

SCHEMA = "regaudit-test-gate-ledger/2"

TIER_SECURITY = "security"
TIER_TENSEAL = "tenseal"

# Optional packages whose absence is classified (and reported) rather than assumed.
PROBED_MODULES = ("tenseal", "openfhe", "fastapi", "httpx", "uvicorn", "yaml", "hypothesis")


@dataclass
class Outcome:
    """One test (or one module that could not be collected) after all of its phases."""

    nodeid: str
    outcome: str  # passed | failed | skipped | xfailed
    reason: str = ""
    tier: str | None = None  # TIER_SECURITY, TIER_TENSEAL or None (optional test)
    module_level: bool = False  # a collection-time skip: the module's tests were never collected

    @property
    def module(self) -> str:
        return self.nodeid.split("::", 1)[0]


@dataclass
class Environment:
    platform: str
    os_name: str
    python: tuple[int, int, int]
    missing: frozenset[str]  # PROBED_MODULES that cannot be imported
    versions: dict[str, str | None]
    is_root: bool
    require_tenseal: bool
    strict_optional_skips: bool
    root: Path
    ci: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def facts(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "os_name": self.os_name,
            "python": ".".join(map(str, self.python)),
            "implementation": _platform.python_implementation(),
            "machine": _platform.machine(),
            "modules": self.versions,
            "running_as_root": self.is_root,
            "require_tenseal": self.require_tenseal,
            "strict_optional_skips": self.strict_optional_skips,
            "ci": self.ci,
        }


def detect_environment(root: Path, env: dict[str, str] | None = None) -> Environment:
    env = os.environ if env is None else env
    versions: dict[str, str | None] = {}
    missing = set()
    for name in PROBED_MODULES:
        try:
            spec = importlib.util.find_spec(name)
        except (ImportError, ValueError):
            spec = None
        if spec is None:
            versions[name] = None
            missing.add(name)
            continue
        try:
            from importlib import metadata

            dist = {"yaml": "PyYAML"}.get(name, name)
            versions[name] = metadata.version(dist)
        except Exception:
            versions[name] = "installed (version unknown)"
    geteuid = getattr(os, "geteuid", None)
    return Environment(
        platform=sys.platform,
        os_name=os.name,
        python=(sys.version_info[0], sys.version_info[1], sys.version_info[2]),
        missing=frozenset(missing),
        versions=versions,
        is_root=bool(geteuid and geteuid() == 0),
        require_tenseal=env.get("REGAUDIT_REQUIRE_TENSEAL", "") == "1",
        strict_optional_skips=env.get("REGAUDIT_GATE_STRICT_SKIPS", "") == "1",
        root=root,
        ci=bool(env.get("CI")),
    )


# ---------------------------------------------------------------------------------------------------
# Expected-skip rules
# ---------------------------------------------------------------------------------------------------

KIND_PLATFORM = "platform"
KIND_OPTIONAL_BACKEND = "optional-backend"
KIND_LAYOUT = "layout"
KIND_ENVIRONMENT = "environment"
KIND_DEPENDENCY = "dependency"
INTENTIONAL_KINDS = (KIND_PLATFORM, KIND_OPTIONAL_BACKEND, KIND_LAYOUT, KIND_ENVIRONMENT)


def condition_holds(cond: dict[str, Any], env: Environment) -> bool:
    """Every key of ``cond`` must hold. An empty condition never holds: a rule must say when."""
    if not cond:
        return False
    for key, want in cond.items():
        if key == "platform_not":
            ok = not any(env.platform.startswith(p) for p in want)
        elif key == "platform_is":
            ok = any(env.platform.startswith(p) for p in want)
        elif key == "os_name_not":
            ok = env.os_name not in want
        elif key == "python_lt":
            ok = env.python[:2] < tuple(want)
        elif key == "missing":
            ok = all(m in env.missing for m in want)
        elif key == "running_as_root":
            ok = env.is_root is bool(want)
        elif key == "absent_path":
            ok = all(not (env.root / p).exists() for p in want)
        elif key == "absent_executable":
            import shutil

            ok = all(shutil.which(p) is None for p in want)
        elif key == "absent_attr":
            ok = all(not hasattr(os, p) for p in want)
        elif key == "absent_file":
            ok = all(not os.path.exists(p) for p in want)
        elif key == "data_dependent":
            ok = bool(want)  # the skip depends on generated data, not on the environment
        else:
            raise ValueError(f"unknown condition key {key!r}")
        if not ok:
            return False
    return True


@dataclass
class Classified:
    nodeid: str
    outcome: str
    reason: str
    tier: str | None
    category: str
    rule: str | None = None
    kind: str | None = None
    blocked_by: str | None = None
    note: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v not in (None, "")}


_IMPORT_RE = re.compile(r"could not import '([A-Za-z0-9_.]+)'")


def blocked_module(reason: str, rules: list[dict[str, Any]]) -> str | None:
    m = _IMPORT_RE.search(reason)
    if m:
        return m.group(1).split(".")[0]
    for r in rules:
        if r.get("blocked_by") and re.search(r["reason"], reason):
            return str(r["blocked_by"])
    return None


def match_rule(
    o: Outcome, rules: list[dict[str, Any]], env: Environment, *, scoped_only: bool = False
) -> dict[str, Any] | None:
    """First rule whose reason, nodeid and condition all hold for this skip.

    ``scoped_only`` (used for a mandatory test) ignores every rule that does not name test identities: a rule
    written for one test can never excuse another, whatever its reason text matches.
    """
    for r in rules:
        if scoped_only and not ident.rule_is_scoped(r):
            continue
        if not re.search(r["reason"], o.reason):
            continue
        if not ident.rule_names_nodeid(r, o.nodeid):
            continue
        if condition_holds(r["when"], env):
            return r
    return None


def classify(o: Outcome, rules: list[dict[str, Any]], env: Environment) -> Classified:
    base = dict(nodeid=o.nodeid, outcome=o.outcome, reason=o.reason, tier=o.tier)
    required = o.tier == TIER_SECURITY or (o.tier == TIER_TENSEAL and env.require_tenseal)
    if o.outcome == "passed":
        return Classified(**base, category="required_passed" if required else "optional_passed")
    if o.outcome in ("failed", "xfailed"):
        return Classified(**base, category="required_failed" if required else "optional_failed")
    # skipped
    blocked = blocked_module(o.reason, rules)
    rule = match_rule(o, rules, env, scoped_only=required)
    if required:
        # The TenSEAL tier never accepts a skip caused by TenSEAL itself being absent.
        excusable = bool(rule) and rule["kind"] in (KIND_PLATFORM, KIND_ENVIRONMENT)
        if (
            rule
            and excusable
            and rule.get("gate_ok")
            and not (o.tier == TIER_TENSEAL and blocked == "tenseal")
        ):
            return Classified(
                **base,
                category="intentional_skipped",
                rule=rule["id"],
                kind=rule["kind"],
                note="mandatory test; skip is declared for this platform",
            )
        return Classified(**base, category="required_unexpected_skipped", blocked_by=blocked)
    if rule is None:
        return Classified(**base, category="optional_undeclared_skipped", blocked_by=blocked)
    if rule["kind"] == KIND_DEPENDENCY:
        # In TenSEAL-required mode a TenSEAL skip is a violation even for an optional test.
        return Classified(
            **base,
            category="blocked_by_dependency",
            rule=rule["id"],
            kind=rule["kind"],
            blocked_by=blocked or rule.get("blocked_by"),
        )
    return Classified(
        **base,
        category="intentional_skipped",
        rule=rule["id"],
        kind=rule["kind"],
        blocked_by=blocked,
    )


# ---------------------------------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------------------------------


@dataclass
class RunFacts:
    """What one pytest session actually did, as recorded by the plugin (pure data, so it can be unit-tested)."""

    scope: str
    inventory: dict[str, Any]
    selected: list[str]  # node ids pytest was going to run, AFTER its own selection options
    deselected: list[str]  # node ids pytest's selection options removed
    hashes: dict[
        str, str
    ]  # "module::function-key" -> body hash, for every collected test of a mandatory module
    modules_seen: set[str]  # test modules pytest tried to collect (any outcome)
    collection_errors: list[str] = field(default_factory=list)
    stopped: str = ""  # why the session ended early ("" = it did not)
    invocation: dict[str, Any] = field(default_factory=dict)


COUNT_KEYS = (
    "required_passed",
    "required_failed",
    "required_unexpected_skipped",
    "intentional_skipped",
    "blocked_by_dependency",
    "optional_undeclared_skipped",
    "optional_passed",
    "optional_failed",
)


def evaluate(
    outcomes: list[Outcome],
    collected_per_module: dict[str, int],
    manifest: Any,
    env: Environment,
    run: RunFacts | None = None,
) -> dict[str, Any]:
    """Build the ledger (a plain dict, JSON-serialisable) and its verdict.

    With ``run`` (what the plugin passes) the mandatory tests are checked by identity against the inventory and the
    per-module floors are diagnostics only. Without it the floors are the only check (the classifier unit tests).
    """
    rules = list(manifest.EXPECTED_SKIPS)
    classified = [classify(o, rules, env) for o in outcomes]
    counts = dict.fromkeys(COUNT_KEYS, 0)
    for c in classified:
        counts[c.category] += 1

    violations: list[dict[str, Any]] = []

    def violate(code: str, nodeid: str, message: str) -> None:
        violations.append({"code": code, "nodeid": nodeid, "message": message})

    for c in classified:
        if c.category == "required_failed":
            violate("REQUIRED_FAILED", c.nodeid, f"mandatory test did not pass ({c.outcome})")
        elif c.category == "required_unexpected_skipped":
            why = f"blocked by missing '{c.blocked_by}'. " if c.blocked_by else ""
            violate(
                "REQUIRED_UNEXPECTEDLY_SKIPPED",
                c.nodeid,
                f"mandatory test skipped: {c.reason!r}. {why}"
                "No manifest rule declares this skip for this platform.",
            )
        elif c.category == "optional_undeclared_skipped" and env.strict_optional_skips:
            violate(
                "OPTIONAL_SKIP_NOT_DECLARED",
                c.nodeid,
                f"skip {c.reason!r} is not declared in the expected-skip manifest (strict mode)",
            )

    # A skipped TenSEAL-dependent test is a violation in TenSEAL-required mode wherever it sits.
    if env.require_tenseal:
        if "tenseal" in env.missing:
            violate(
                "TENSEAL_REQUIRED_BUT_MISSING",
                "-",
                "REGAUDIT_REQUIRE_TENSEAL=1 and TenSEAL cannot be imported",
            )
        for c in classified:
            if (
                c.outcome == "skipped"
                and c.blocked_by == "tenseal"
                and c.category != "required_unexpected_skipped"
            ):
                violate(
                    "TENSEAL_TEST_SKIPPED",
                    c.nodeid,
                    f"TenSEAL-dependent test skipped under REGAUDIT_REQUIRE_TENSEAL=1: {c.reason!r}",
                )

    # Mandatory modules: present, collected, and at least the reviewed number of tests.
    module_rows = []
    by_module: dict[str, list[Classified]] = {}
    for c in classified:
        by_module.setdefault(c.nodeid.split("::", 1)[0], []).append(c)
    tiers = [(TIER_SECURITY, manifest.SECURITY_GATE_MODULES)]
    if env.require_tenseal:
        tiers.append((TIER_TENSEAL, manifest.TENSEAL_REQUIRED_MODULES))
    in_scope: set[str] | None = None
    if run is not None:
        in_scope = set(run.inventory.get("scopes", {}).get(run.scope, {}).get("modules", []))
    for tier, mods in tiers:
        for module, meta in sorted(mods.items()):
            if in_scope is not None and module not in in_scope:
                continue  # a partial scope does not require (or report floors for) the modules it leaves out
            collected = collected_per_module.get(module, 0)
            floor = int(meta["min_tests"])
            rows = by_module.get(module, [])
            passed = sum(1 for c in rows if c.category == "required_passed")
            status = "ok"
            if collected < floor:
                status = "missing-or-short"
            if collected < floor and run is None:
                violate(
                    "REQUIRED_TESTS_MISSING",
                    module,
                    f"{tier} module collected {collected} test(s); the manifest floor is {floor}. "
                    "A mandatory test was deleted, deselected or the module could not be collected.",
                )
            row = {
                "module": module,
                "tier": tier,
                "min_tests": floor,
                "collected": collected,
                "passed": passed,
                "status": status,
                "why": meta.get("why", ""),
            }
            module_rows.append(row)

    # Backend qualification: only executed, passing tests qualify a backend.
    backends = qualification(classified, collected_per_module, manifest, env)

    scope_block: dict[str, Any] | None = None
    if run is not None:
        scope_block = _scope_checks(run, classified, manifest, env, violate)

    ledger = {
        "schema": SCHEMA,
        "verdict": "FAIL" if violations else "PASS",
        "scope": scope_block,
        "invocation": run.invocation if run is not None else {},
        "environment": env.facts(),
        "counts": counts,
        "total_outcomes": len(classified),
        "mandatory_modules": module_rows,
        "backends": backends,
        "skips": [c.to_json() for c in classified if c.outcome == "skipped"],
        "violations": violations,
        "untested_notes": list(manifest.UNTESTED_NOTES),
    }
    return ledger


def _head(items: list[str], n: int = 3) -> str:
    more = f" (+{len(items) - n} more)" if len(items) > n else ""
    return ", ".join(items[:n]) + more


def _scope_checks(
    run: RunFacts,
    classified: list[Classified],
    manifest: Any,
    env: Environment,
    violate: Any,
) -> dict[str, Any]:
    """Identity checks of one run against the inventory. Returns the ``scope`` block of the ledger."""
    inv = run.inventory
    scope_inv = inv.get("scopes", {}).get(run.scope)
    meta = getattr(manifest, "SCOPES", {}).get(run.scope)
    if scope_inv is None or meta is None:
        violate(
            "UNKNOWN_SCOPE",
            "-",
            f"scope {run.scope!r} is not defined in the manifest and the inventory",
        )
        return {"name": run.scope, "defined": False}

    selected, deselected = set(run.selected), set(run.deselected)
    by_id = {c.nodeid: c for c in classified}
    required_tiers = {TIER_SECURITY} | ({TIER_TENSEAL} if env.require_tenseal else set())

    expected: list[str] = []
    expected_modules: list[str] = []
    for module in scope_inv["modules"]:
        entry = inv["modules"].get(module)
        if entry is None or entry["tier"] not in required_tiers:
            continue
        expected_modules.append(module)
        expected += [f"{module}::{i}" for i in entry["ids"]]
    expected_set = set(expected)

    not_collected = [n for n in expected if n not in selected and n not in deselected]
    was_deselected = [n for n in expected if n in deselected]
    not_executed = [n for n in expected if n in selected and n not in by_id]
    executed = [n for n in expected if n in by_id]
    passed = [n for n in executed if by_id[n].outcome == "passed"]
    failed = [n for n in executed if by_id[n].outcome in ("failed", "xfailed")]
    skipped = [n for n in executed if by_id[n].outcome == "skipped"]

    extra = sorted(
        n
        for n in selected | deselected
        if n.split("::", 1)[0] in expected_modules and n not in expected_set
    )

    body_changed = []
    for n in expected:
        if n not in selected and n not in deselected:
            continue
        module, rest = ident.split_nodeid(n)
        want = inv["modules"][module]["functions"].get(ident.function_key(rest))
        have = run.hashes.get(f"{module}::{ident.function_key(rest)}")
        if want != have:
            body_changed.append(n)

    modules_missing = []
    if scope_inv.get("full_suite"):
        modules_missing = [m for m in scope_inv.get("all_modules", []) if m not in run.modules_seen]

    if not_collected:
        violate(
            "REQUIRED_TESTS_MISSING",
            not_collected[0],
            f"{len(not_collected)} mandatory test(s) of scope {run.scope!r} were not collected "
            f"(deleted, renamed, in a module that could not be collected, or outside the paths given): "
            f"{_head(not_collected)}",
        )
    if was_deselected:
        violate(
            "REQUIRED_TESTS_DESELECTED",
            was_deselected[0],
            f"{len(was_deselected)} mandatory test(s) were deselected by a selection option: {_head(was_deselected)}",
        )
    if not_executed:
        violate(
            "REQUIRED_TESTS_NOT_EXECUTED",
            not_executed[0],
            f"{len(not_executed)} mandatory test(s) were collected but did not run (stopped early, "
            f"--setup-only, --collect-only): {_head(not_executed)}",
        )
    if extra:
        violate(
            "INVENTORY_UNEXPECTED_TESTS",
            extra[0],
            f"{len(extra)} test(s) in mandatory modules are not in the inventory; regenerate it with "
            f"scripts/gate_inventory.py --write and review the diff: {_head(extra)}",
        )
    if body_changed:
        violate(
            "TEST_BODY_CHANGED",
            body_changed[0],
            f"{len(body_changed)} mandatory test(s) have a different body from the inventory; a changed body needs "
            f"a reviewed inventory update: {_head(body_changed)}",
        )
    if modules_missing:
        violate(
            "SCOPE_MODULE_NOT_COLLECTED",
            modules_missing[0],
            f"scope {run.scope!r} claims the full suite but {len(modules_missing)} test module(s) were never "
            f"collected: {_head(modules_missing)}",
        )
    if run.deselected:
        violate(
            "DESELECTED_TESTS",
            run.deselected[0],
            f"{len(run.deselected)} test(s) were deselected; a gate run executes everything it collects",
        )
    for module in run.collection_errors:
        violate("COLLECTION_ERROR", module, "a test module failed to collect")
    if run.stopped:
        violate("RUN_STOPPED_EARLY", "-", f"the session ended early: {run.stopped}")

    skip_rows = []
    for n in skipped:
        c = by_id[n]
        skip_rows.append({"nodeid": n, "rule": c.rule, "category": c.category, "reason": c.reason})

    return {
        "name": run.scope,
        "description": meta["description"],
        "claims_full_suite": bool(scope_inv.get("full_suite")),
        "required_tiers": sorted(required_tiers),
        "modules_expected": len(expected_modules),
        "expected": len(expected),
        "collected": len(expected) - len(not_collected),
        "deselected": len(was_deselected),
        "executed": len(executed),
        "passed": len(passed),
        "failed": len(failed),
        "skipped": skip_rows,
        "missing_mandatory": {
            "not_collected": not_collected,
            "deselected": was_deselected,
            "not_executed": not_executed,
        },
        "unexpected_extra": extra,
        "body_changed": body_changed,
        "modules_not_collected": modules_missing,
        "total_selected": len(run.selected),
        "total_deselected": len(run.deselected),
    }


def qualification(
    classified: list[Classified],
    collected_per_module: dict[str, int],
    manifest: Any,
    env: Environment,
) -> dict[str, Any]:
    """A backend is 'executed' only if its test modules ran, all passed and none skipped."""
    out: dict[str, Any] = {}
    for name, meta in manifest.BACKEND_QUALIFICATION.items():
        mods = meta["modules"]
        rows = [c for c in classified if c.nodeid.split("::", 1)[0] in mods]
        passed = sum(1 for c in rows if c.outcome == "passed")
        bad = sum(1 for c in rows if c.outcome in ("failed", "xfailed"))
        skipped = sum(1 for c in rows if c.outcome == "skipped")
        importable = meta["module"] not in env.missing
        executed = importable and passed > 0 and bad == 0 and skipped == 0
        out[name] = {
            "package": meta["module"],
            "package_installed": importable,
            "tests_passed": passed,
            "tests_failed": bad,
            "tests_skipped": skipped,
            "status": "executed" if executed else "NOT QUALIFIED",
            "reason": "" if executed else meta["not_qualified_because"],
        }
    return out


def render_text(ledger: dict[str, Any]) -> str:
    e = ledger["environment"]
    c = ledger["counts"]
    lines = [
        "=" * 78,
        f"TEST GATE: {ledger['verdict']}",
        "=" * 78,
        f"environment: {e['platform']} python {e['python']} {e['machine']}"
        f" require_tenseal={e['require_tenseal']} root={e['running_as_root']}",
        "modules: " + ", ".join(f"{k}={v or 'MISSING'}" for k, v in e["modules"].items()),
    ]
    sc = ledger.get("scope")
    if sc and sc.get("defined", True):
        claim = (
            "the full suite" if sc["claims_full_suite"] else "a PARTIAL scope, not the full suite"
        )
        lines += [
            f"scope: {sc['name']} ({claim}): {sc['description']}",
            f"  expected={sc['expected']} collected={sc['collected']} deselected={sc['deselected']}"
            f" executed={sc['executed']} passed={sc['passed']} failed={sc['failed']}"
            f" skipped={len(sc['skipped'])}"
            f" missing={sum(len(v) for v in sc['missing_mandatory'].values())}"
            f" unexpected_extra={len(sc['unexpected_extra'])}",
        ]
    inv_args = ledger.get("invocation", {}).get("args")
    if inv_args is not None:
        lines.append("pytest args: " + " ".join(map(str, inv_args)))
    lines += [
        "",
        "ledger (each test outcome is in exactly one line):",
        f"  required, executed and passed .......... {c['required_passed']}",
        f"  required, FAILED ....................... {c['required_failed']}",
        f"  required, UNEXPECTEDLY SKIPPED ......... {c['required_unexpected_skipped']}",
        f"  intentionally skipped (declared) ....... {c['intentional_skipped']}",
        f"  blocked by unavailable dependency ...... {c['blocked_by_dependency']}",
        f"  optional skipped, not declared ......... {c['optional_undeclared_skipped']}",
        f"  optional passed ........................ {c['optional_passed']}",
        f"  optional failed ........................ {c['optional_failed']}",
        "",
        "backends (an unexecuted backend is never qualified):",
    ]
    for name, b in ledger["backends"].items():
        extra = f" ({b['reason']})" if b["reason"] else ""
        lines.append(
            f"  {name}: {b['status']}: passed={b['tests_passed']} failed={b['tests_failed']}"
            f" skipped={b['tests_skipped']}{extra}"
        )
    if ledger["skips"]:
        lines += ["", "skips:"]
        for s in ledger["skips"]:
            tag = s["category"] + (f"/{s['kind']}" if s.get("kind") else "")
            lines.append(f"  [{tag}] {s['nodeid']}: {s['reason']}")
    if ledger["violations"]:
        lines += ["", "VIOLATIONS (the gate fails):"]
        for v in ledger["violations"]:
            lines.append(f"  {v['code']}: {v['nodeid']}: {v['message']}")
    lines.append("=" * 78)
    return "\n".join(lines)


def write_ledger(ledger: dict[str, Any], directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    js = directory / "test-gate-ledger.json"
    tx = directory / "test-gate-ledger.txt"
    js.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tx.write_text(render_text(ledger) + "\n", encoding="utf-8")
    return js, tx
