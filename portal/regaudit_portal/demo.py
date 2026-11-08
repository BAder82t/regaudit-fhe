"""A demonstration folder: the portal's bundled demonstration trust list, a configuration and sample reports.

Nothing here is real evidence and nothing here signs anything. The trust list and the signed reports are copies of the
files bundled with the portal (made once by ``tools/make_demo_samples.py`` with throwaway keys that were then
discarded), so the trust list holds the bundled demonstration key, which the portal recognises by its pinned
fingerprint. The configuration says ``"trust_mode": "demonstration"``. With that setting the portal checks files
against the list only as a demonstration and labels every result that way; without it, or with ``"customer"``, the
configuration is refused. The bundled key can never be customer trust.

The signed reports were made on a fixed date, 2026-10-01, so the configuration allows a long maximum age, 3650 days, the
longest a configuration may give. That is accepted only because this is a demonstration, and the setup page says so.
The profile stays confidential and the replay mode check, so nothing else is relaxed. The reports then verify until
2036-09-28.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import json
import os
from importlib import resources
from pathlib import Path

VERIFIER = "demo-verifier"  # the audience the bundled reports were signed for
MAX_AGE_DAYS = 3650  # the bundled reports were signed on 2026-10-01; see the module's note
MAX_REPORT_BYTES = 1 << 20
TRUST_LIST = "demo-trust-list.json"

# Each file the folder gets, and the bundled file it is a copy of. The bundled reports are copied byte for byte.
COPIED = (
    ("1-trusted.json", "trusted.json"),
    ("2-untrusted-signer.json", "untrusted-signer.json"),
    ("3-changed-after-signing.json", "modified.json"),
    ("6-declares-encrypted-backend.json", "declares-encrypted-backend.json"),
)
NOT_A_REPORT = "4-not-a-report.json"
TOO_LARGE = "5-too-large.json"


def _bundled(*parts: str) -> bytes:
    return resources.files(__package__).joinpath("samples", *parts).read_bytes()


def create(directory: str | Path) -> Path:
    root = Path(directory).absolute()
    reports = root / "sample-reports"
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    reports.mkdir(mode=0o700)
    config = {
        "trust_store": "trust-store.json",
        "profile": "confidential",
        "verifier_id": VERIFIER,
        "max_age_days": MAX_AGE_DAYS,
        "replay_mode": "check",
        "replay_db": "replay.db",
        "trust_mode": "demonstration",
    }
    for name, data in (
        ("trust-store.json", _bundled(TRUST_LIST)),
        ("portal-config.json", (json.dumps(config, indent=2) + "\n").encode()),
    ):
        fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    for name, bundled in COPIED:
        (reports / name).write_bytes(_bundled("reports", bundled))
    (reports / NOT_A_REPORT).write_text('{"hello": "this is not a signed report"}\n')
    (reports / TOO_LARGE).write_text(" " * (MAX_REPORT_BYTES + 1))
    return root
