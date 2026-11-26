#!/usr/bin/env python3
"""Say whether the ci.yml ``openfhe`` job has to run for a set of changed files.

Reads one repository-relative path per line on stdin and prints ``true`` or ``false``. The job takes about 13 minutes
and executes the OpenFHE backend, so a pull request that cannot affect it (documentation, the portal, the examples,
other workflows) skips it. The rule errs towards running: anything under ``src/``, the OpenFHE tests, the gate
machinery its scope runs under, the pinned wheel, ``pyproject.toml`` and ``ci.yml`` itself count, and no input at all
means "run" because a change set that could not be read must not be taken as a change set with nothing in it.

The workflow does not use this for a push to ``master``, a manual run or any event other than a pull request: those
always run the job.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable

# A changed path that starts with one of these can change what the job runs or what it finds.
RELEVANT_PREFIXES = (
    "src/",  # the engine, including the OpenFHE backend and the primitives and oracles it is compared with
    "tests/_gate",  # the gate machinery, its manifest (the openfhe scope) and its inventory
)

# A changed path that is exactly one of these can too.
RELEVANT_FILES = frozenset(
    {
        "tests/test_openfhe_backend.py",  # the tests the job exists to run
        "scripts/openfhe-requirements.lock",  # the pinned wheel
        "scripts/gate_inventory.py",  # builds the inventory the scope is held to
        "scripts/openfhe_lane_needed.py",  # this rule
        "tests/test_openfhe_lane_paths.py",  # its tests
        "pyproject.toml",  # extras, Python versions, test configuration
        ".github/workflows/ci.yml",  # the job itself
    }
)


def lane_needed(paths: Iterable[str]) -> bool:
    """True if any path is relevant, or if there are no paths at all."""
    seen = [p.strip() for p in paths if p.strip()]
    if not seen:
        return True
    return any(p in RELEVANT_FILES or p.startswith(RELEVANT_PREFIXES) for p in seen)


def main() -> int:
    print("true" if lane_needed(sys.stdin.read().splitlines()) else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
