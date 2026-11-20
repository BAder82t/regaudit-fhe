#!/usr/bin/env python3
"""Generate or check the mandatory-test inventory behind the test gate (tests/_gate_inventory.json).

    python scripts/gate_inventory.py --check    # exit 1 if collection and the inventory differ, either direction
    python scripts/gate_inventory.py --write    # regenerate; review the diff in the same commit as the test change

The inventory lists, per mandatory module (tests/_gate_manifest.py), every collected test id, parametrised ids
included, and a hash of each test function's normalised source; and, per named scope, which modules it requires.
The gate (tests/_gate_plugin.py) compares every run with it by identity. See docs/TEST_GATES.md.

It collects the WHOLE suite, so it needs the optional packages installed (tenseal, fastapi, httpx, yaml,
hypothesis): with one missing, modules would collect nothing and the inventory would silently shrink. It refuses
to run then.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
NEEDED = ("tenseal", "fastapi", "httpx", "yaml", "hypothesis", "uvicorn")


def _load_manifest(path: Path | None) -> Any:
    if path is None:
        sys.path.insert(0, str(REPO))
        from tests import _gate_manifest

        return _gate_manifest
    spec = importlib.util.spec_from_file_location("_gate_inventory_manifest", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def collect(root: Path, paths: list[str]) -> tuple[list[tuple[str, Any]], list[str], list[str]]:
    """Collect without running. Returns (nodeid, function) pairs, the module ids seen, the modules that errored."""
    import pytest

    items: list[tuple[str, Any]] = []
    modules: list[str] = []
    errors: list[str] = []

    class Collector:
        def pytest_collectreport(self, report: Any) -> None:
            if str(report.nodeid).endswith(".py"):
                modules.append(report.nodeid)
                if report.outcome == "failed":
                    errors.append(report.nodeid)

        def pytest_collection_finish(self, session: Any) -> None:
            for it in session.items:
                items.append((it.nodeid, getattr(it, "obj", None)))

    cwd = os.getcwd()
    os.chdir(root)
    try:
        rc = pytest.main(
            ["--collect-only", "-q", "-p", "no:cacheprovider", "-W", "ignore", *paths],
            plugins=[Collector()],
        )
    finally:
        os.chdir(cwd)
    if rc not in (0, 5):
        errors.append(f"pytest collection exited {int(rc)}")
    return items, modules, errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="regenerate the inventory file")
    mode.add_argument("--check", action="store_true", help="fail if collection and the file differ")
    ap.add_argument(
        "--root", type=Path, default=REPO, help="project root (default: this repository)"
    )
    ap.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="manifest module (default: tests/_gate_manifest.py)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="inventory file (default: tests/_gate_inventory.json)",
    )
    ap.add_argument(
        "--no-env-check", action="store_true", help="skip the optional-package check (tests only)"
    )
    ap.add_argument("paths", nargs="*", default=["tests"], help="what to collect (default: tests)")
    args = ap.parse_args(argv)

    sys.path.insert(0, str(args.root))
    sys.path.insert(0, str(REPO))
    from tests import _gate_identity as ident

    if not args.no_env_check:
        missing = [m for m in NEEDED if importlib.util.find_spec(m) is None]
        if missing:
            print(
                f"gate_inventory: cannot run, these packages are not installed: {', '.join(missing)}. "
                "Install '.[dev,server,fhe]'; collecting without them would shrink the inventory.",
                file=sys.stderr,
            )
            return 2

    manifest = _load_manifest(args.manifest)
    out = args.out or ident.DEFAULT_INVENTORY
    items, modules, errors = collect(args.root.resolve(), args.paths)
    if errors:
        print("gate_inventory: collection errors: " + ", ".join(errors), file=sys.stderr)
        return 2
    new = ident.build_inventory(items, manifest, modules)
    declared = set(manifest.SECURITY_GATE_MODULES) | set(manifest.TENSEAL_REQUIRED_MODULES)
    absent = sorted(declared - set(new["modules"]))
    if absent:
        print(
            "gate_inventory: mandatory modules that collected no test: " + ", ".join(absent),
            file=sys.stderr,
        )
        return 2

    if args.write:
        out.write_text(ident.dump_inventory(new), encoding="utf-8")
        n = sum(len(m["ids"]) for m in new["modules"].values())
        print(f"wrote {out} ({len(new['modules'])} modules, {n} test ids)")
        return 0

    try:
        old = ident.load_inventory(out)
    except (OSError, ValueError) as exc:
        print(f"gate_inventory: cannot read {out}: {exc}", file=sys.stderr)
        return 1
    diffs = ident.diff_inventory(old, new)
    if diffs:
        print(
            "gate_inventory: the inventory is out of date. Run --write and review the diff:",
            file=sys.stderr,
        )
        for d in diffs[:200]:
            print("  " + d, file=sys.stderr)
        if len(diffs) > 200:
            print(f"  ... and {len(diffs) - 200} more", file=sys.stderr)
        return 1
    print(json.dumps({"inventory": "up to date", "modules": len(new["modules"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
