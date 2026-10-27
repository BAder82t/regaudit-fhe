#!/usr/bin/env python3
"""Test the declared minimum versions of the server extra.

``pyproject.toml`` declares ``fastapi>=X`` and ``pydantic>=Y`` in the ``server`` extra. The ordinary CI jobs install the
newest versions the resolver offers, so nothing would notice if the code stopped working at the declared minimums.

    server_floors.py constraints [PYPROJECT]   print a pip constraints file pinning the floors exactly
    server_floors.py check [PYPROJECT]         fail unless the INSTALLED fastapi and pydantic are exactly the floors
                                               and pydantic-core is the version that pydantic itself requires

The floors are read from ``pyproject.toml`` every time, so an intentional floor increase moves the test with it.
Standard library only (it runs on Python 3.10, which has no ``tomllib``).
"""

from __future__ import annotations

import re
import sys
from importlib import metadata
from pathlib import Path

PACKAGES = ("fastapi", "pydantic")
DEFAULT_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _version(name: str) -> str:
    return metadata.version(name)


def server_floors(pyproject: Path = DEFAULT_PYPROJECT) -> dict[str, str]:
    """Return {package: minimum version} for the packages in PACKAGES, from the ``server`` extra."""
    text = pyproject.read_text(encoding="utf-8")
    block = re.search(r"^server\s*=\s*\[(.*?)^\]", text, re.MULTILINE | re.DOTALL)
    if not block:
        raise SystemExit("FAIL: no 'server = [...]' extra in pyproject.toml")
    floors: dict[str, str] = {}
    for line in block.group(1).splitlines():
        match = re.match(
            r'\s*"([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*>=\s*([0-9][0-9A-Za-z.]*)\s*"', line
        )
        if match and match.group(1).lower() in PACKAGES:
            floors[match.group(1).lower()] = match.group(2)
    missing = [p for p in PACKAGES if p not in floors]
    if missing:
        raise SystemExit(f"FAIL: no '>=' minimum for {missing} in the server extra")
    return floors


def constraints(pyproject: Path = DEFAULT_PYPROJECT) -> str:
    return "".join(
        f"{name}=={version}\n" for name, version in sorted(server_floors(pyproject).items())
    )


def pydantic_core_requirement() -> str:
    """The exact pydantic-core version that the installed pydantic requires."""
    for req in metadata.requires("pydantic") or []:
        match = re.match(r"pydantic[-_]core\s*==\s*([0-9][0-9A-Za-z.]*)\s*(?:;|$)", req)
        if match and "extra ==" not in req:
            return match.group(1)
    raise SystemExit("FAIL: the installed pydantic does not pin pydantic-core with ==")


def check(pyproject: Path = DEFAULT_PYPROJECT) -> list[str]:
    """Return the problems; the empty list means the installed versions ARE the floors."""
    problems = []
    wanted = dict(server_floors(pyproject))
    for name, version in wanted.items():
        try:
            got = _version(name)
        except metadata.PackageNotFoundError:
            problems.append(f"{name} is not installed")
            continue
        if got != version:
            problems.append(f"{name}: installed {got}, declared minimum {version}")
    try:
        core_have, core_want = _version("pydantic-core"), pydantic_core_requirement()
        if core_have != core_want:
            problems.append(f"pydantic-core: installed {core_have}, pydantic requires {core_want}")
    except metadata.PackageNotFoundError:
        problems.append("pydantic-core is not installed")
    return problems


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("constraints", "check") or len(argv) > 2:
        print(__doc__, file=sys.stderr)
        return 2
    path = Path(argv[1]) if len(argv) == 2 else DEFAULT_PYPROJECT
    if argv[0] == "constraints":
        sys.stdout.write(constraints(path))
        return 0
    problems = check(path)
    if problems:
        print(
            "SERVER FLOOR CHECK FAILED", *(f"  - {p}" for p in problems), sep="\n", file=sys.stderr
        )
        return 1
    versions = {n: _version(n) for n in (*PACKAGES, "pydantic-core", "starlette")}
    print("server floors installed:", ", ".join(f"{n} {v}" for n, v in versions.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
