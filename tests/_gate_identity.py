"""Stable identities for the test gate: node-id helpers, body hashes and the checked-in inventory.

Pure helpers (no pytest import) shared by ``tests/_gate_plugin.py`` (the run) and ``scripts/gate_inventory.py``
(the reviewed generator). See ``docs/TEST_GATES.md``.

The inventory ``tests/_gate_inventory.json`` lists, per mandatory module, every test id (parametrised ids
included) and a hash of each test FUNCTION's normalised source. A run is compared with it by identity, not by
count: a deleted, renamed, added or deselected mandatory test is a difference, and so is a changed body.
"""

from __future__ import annotations

import fnmatch
import hashlib
import inspect
import json
import textwrap
from pathlib import Path
from typing import Any

INVENTORY_SCHEMA = "regaudit-test-gate-inventory/1"
DEFAULT_INVENTORY = Path(__file__).with_name("_gate_inventory.json")


def split_nodeid(nodeid: str) -> tuple[str, str]:
    """``tests/a.py::Cls::test_x[p]`` -> (``tests/a.py``, ``Cls::test_x[p]``)."""
    module, _, rest = nodeid.partition("::")
    return module, rest


def function_key(rest: str) -> str:
    """The test id without its parametrisation: ``Cls::test_x[p]`` -> ``Cls::test_x``."""
    head, sep, _ = rest.partition("[")
    return head if sep else rest


def normalise_source(source: str) -> str:
    """Dedent, drop trailing blanks and blank lines. Comments are kept (changing one needs a reviewed update)."""
    lines = [ln.rstrip() for ln in textwrap.dedent(source).splitlines()]
    return "\n".join(ln for ln in lines if ln.strip())


def source_hash(func: Any) -> str:
    """SHA-256 of the normalised source of ``func`` (decorators included), or ``"unavailable"``.

    It hashes the function's own text only. It does not see a fixture, a helper, a module constant, a
    parametrisation table or the code under test.
    """
    try:
        text = inspect.getsource(inspect.unwrap(func))
    except (OSError, TypeError):
        return "unavailable"
    return hashlib.sha256(normalise_source(text).encode("utf-8")).hexdigest()


_cache: dict[int, str] = {}


def cached_source_hash(func: Any) -> str:
    key = id(func)
    if key not in _cache:
        _cache[key] = source_hash(func)
    return _cache[key]


def glob_match(nodeid: str, pattern: str) -> bool:
    """fnmatch with only ``*`` and ``?`` special: ``[`` and ``]`` are literal (parametrised ids use them)."""
    return fnmatch.fnmatchcase(nodeid, pattern.replace("[", "[[]"))


def patterns_of(rule: dict[str, Any]) -> list[str]:
    raw = rule.get("nodeid", "*")
    return [raw] if isinstance(raw, str) else list(raw)


def rule_names_nodeid(rule: dict[str, Any], nodeid: str) -> bool:
    return any(glob_match(nodeid, p) for p in patterns_of(rule))


def rule_is_scoped(rule: dict[str, Any]) -> bool:
    """A rule is scoped when it lists patterns and none of them is a bare ``*``."""
    pats = patterns_of(rule)
    return bool(pats) and all(p.strip() not in ("", "*", "**") for p in pats)


def load_inventory(path: Path | None = None) -> dict[str, Any]:
    p = path or DEFAULT_INVENTORY
    data = json.loads(p.read_text(encoding="utf-8"))
    if data.get("schema") != INVENTORY_SCHEMA:
        raise ValueError(f"{p}: unknown inventory schema {data.get('schema')!r}")
    return data  # type: ignore[no-any-return]


def dump_inventory(inv: dict[str, Any]) -> str:
    return json.dumps(inv, indent=1, sort_keys=True) + "\n"


def build_inventory(
    items: list[tuple[str, Any]],
    manifest: Any,
    all_modules: list[str],
) -> dict[str, Any]:
    """Build the inventory from collected ``(nodeid, function)`` pairs and the reviewed manifest.

    ``manifest.SECURITY_GATE_MODULES`` / ``TENSEAL_REQUIRED_MODULES`` say which modules are mandatory and
    ``manifest.SCOPES`` says which of them each named scope requires.
    """
    tiers: dict[str, str] = {m: "security" for m in manifest.SECURITY_GATE_MODULES}
    tiers.update({m: "tenseal" for m in manifest.TENSEAL_REQUIRED_MODULES})
    modules: dict[str, dict[str, Any]] = {}
    for nodeid, func in items:
        module, rest = split_nodeid(nodeid)
        if module not in tiers:
            continue
        entry = modules.setdefault(module, {"tier": tiers[module], "ids": [], "functions": {}})
        entry["ids"].append(rest)
        entry["functions"][function_key(rest)] = source_hash(func)
    for entry in modules.values():
        entry["ids"].sort()
    scopes: dict[str, Any] = {}
    for name, meta in manifest.SCOPES.items():
        excluded = set(meta.get("exclude_modules", {}))
        mods = sorted(m for m in tiers if m not in excluded)
        scope: dict[str, Any] = {
            "description": meta["description"],
            "full_suite": bool(meta.get("full_suite")),
            "modules": mods,
        }
        if meta.get("full_suite"):
            scope["all_modules"] = sorted(all_modules)
        scopes[name] = scope
    return {"schema": INVENTORY_SCHEMA, "modules": dict(sorted(modules.items())), "scopes": scopes}


def diff_inventory(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Human-readable differences, empty when equal. Both directions are reported."""
    out: list[str] = []
    om, nm = old.get("modules", {}), new.get("modules", {})
    for m in sorted(set(om) | set(nm)):
        if m not in nm:
            out.append(f"module in the inventory but not collected: {m}")
            continue
        if m not in om:
            out.append(f"module collected but not in the inventory: {m}")
            continue
        if om[m]["tier"] != nm[m]["tier"]:
            out.append(f"{m}: tier {om[m]['tier']} -> {nm[m]['tier']}")
        oi, ni = set(om[m]["ids"]), set(nm[m]["ids"])
        out += [f"{m}::{i}: in the inventory, not collected" for i in sorted(oi - ni)]
        out += [f"{m}::{i}: collected, not in the inventory" for i in sorted(ni - oi)]
        for fk in sorted(set(om[m]["functions"]) & set(nm[m]["functions"])):
            if om[m]["functions"][fk] != nm[m]["functions"][fk]:
                out.append(f"{m}::{fk}: body changed")
    if old.get("scopes") != new.get("scopes"):
        for s in sorted(set(old.get("scopes", {})) | set(new.get("scopes", {}))):
            if old.get("scopes", {}).get(s) != new.get("scopes", {}).get(s):
                out.append(f"scope {s!r}: definition or module list differs")
    return out
