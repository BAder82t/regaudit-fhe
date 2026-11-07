"""Fail when a Portal test was skipped for a reason that is not on the reviewed list, or when too few tests ran.

Usage: check_skips.py JUNIT.xml ALLOWED_SKIPS.txt MINIMUM_TESTS.txt

ALLOWED_SKIPS.txt holds one regular expression per line (blank lines and lines starting with # are ignored). Every
skipped test's reason has to match one of them. MINIMUM_TESTS.txt holds one integer: the number of tests that must have
run and passed, so that a collection error or a deleted test file cannot make the job look healthy.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def lines(path: Path) -> list[str]:
    return [
        ln.strip()
        for ln in path.read_text().splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]


def check(junit: Path, allowed: list[str], minimum: int) -> list[str]:
    problems: list[str] = []
    patterns = [re.compile(p) for p in allowed]
    tests = skipped = failed = 0
    for case in ET.parse(junit).getroot().iter("testcase"):  # noqa: S314 - the job's own pytest output, not outside data
        tests += 1
        if case.find("failure") is not None or case.find("error") is not None:
            failed += 1
        skip = case.find("skipped")
        if skip is not None:
            skipped += 1
            reason = skip.get("message") or (skip.text or "")
            if not any(p.search(reason) for p in patterns):
                problems.append(
                    f"unexpected skip: {case.get('classname')}::{case.get('name')}: {reason!r}"
                )
    passed = tests - skipped - failed
    if failed:
        problems.append(f"{failed} test(s) failed or errored")
    if passed < minimum:
        problems.append(f"only {passed} tests passed; at least {minimum} are required")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__)
        return 2
    junit, allowed, minimum = (Path(a) for a in argv[1:])
    problems = check(junit, lines(allowed), int(lines(minimum)[0]))
    for problem in problems:
        print(problem)
    print("portal test check:", "FAILED" if problems else "ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
