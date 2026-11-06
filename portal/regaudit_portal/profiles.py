"""What each trust profile does in this portal, in plain words, as the published regaudit-fhe 0.2.1 engine applies it.

Every sentence here describes what ``regaudit_fhe.verification`` in 0.2.1 does with the settings this portal always uses: a
trust list, a maximum report age, a replay file kept on disk, a verifier id, the provenance check, no timestamp
verifier and no trust history. ``tests/test_profiles.py`` checks each sentence against the engine itself, so a sentence
that stops being true fails a test instead of misleading an administrator.

Only the three fixed profiles exist. There is no free-form policy. Standard library only.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from typing import Any

PROFILE_NAMES = ("confidential", "high-assurance", "development")
REPLAY_MODES = ("check", "record")

COMMON = (
    "In every profile, a report is accepted only if it is signed by a key in your trust list, names the issuer the "
    "trust list gives for that key, and has not changed since it was signed. A report older than your maximum report "
    "age, or dated more than five minutes in the future, is refused. A key marked retired or compromised is refused, "
    "because published 0.2.1 has no authenticated record of when a key changed status."
)

_PROFILES: dict[str, dict[str, Any]] = {
    "confidential": {
        "title": "Confidential",
        "summary": "For reports you will rely on.",
        "does": (
            "A report that names its intended recipients is refused unless your verifier id is one of them. A report "
            "that names no recipient is not refused for that reason.",
            "A report is refused if the replay file cannot be read or written.",
            "A report in the older v1 format is refused, because it has no run identifier to check for repeats.",
            "The engine requires a trust list, a maximum report age and a replay file kept on disk. This portal "
            "always provides them.",
        ),
        "does_not": (),
    },
    "high-assurance": {
        "title": "High-assurance",
        "summary": "Like confidential, and every report must be addressed to your verifier id.",
        "does": (
            "Everything the confidential profile does.",
            "A report is refused unless it names your verifier id among its intended recipients. A report that names "
            "no recipient at all is refused too.",
            "Every report in the older v1 format is refused.",
        ),
        "does_not": (
            "In published 0.2.1 it does not authenticate the trust list, does not share the replay record with other "
            "computers and does not ask for a verified timestamp. The name does not add those.",
        ),
    },
    "development": {
        "title": "Development",
        "summary": "For trying things out. Do not rely on its results.",
        "does": (
            "Every result on this portal then says not to rely on it.",
            "A report is not refused when the replay file cannot be read or written. The result only notes it.",
            "A report in the older v1 format is not refused for lacking a run identifier.",
            "A report that names its intended recipients must still name your verifier id. A report that names none "
            "is not refused for that reason.",
            "It is the only profile that allows the engine's development options. This portal does not offer them.",
        ),
        "does_not": (),
    },
}

_REPLAY = {
    "check": (
        "Check: a report already recorded in the replay file is refused, but nothing new is recorded, so checking the "
        "same report twice gives the same answer. Each result says it was not recorded as used."
    ),
    "record": (
        "Record: each accepted report is recorded in the replay file, and a second check of the same report is "
        "refused as a repeat. Repeats are detected only against this portal's own replay file."
    ),
}

MAX_AGE = (
    "The oldest report you accept, in days, from 1 to 3650. Older reports are refused. Do not raise it later while you "
    "keep the same replay file."
)
VERIFIER_ID = (
    "The name your organisation is known by to report issuers. A report that names its intended recipients must "
    "include it."
)


def explain(profile: str) -> dict[str, Any]:
    """The plain-language description of one profile. ``KeyError`` for anything that is not one of the three."""
    found = _PROFILES[profile]
    return {
        "name": profile,
        "title": found["title"],
        "summary": found["summary"],
        "does": list(found["does"]),
        "does_not": list(found["does_not"]),
    }


def replay_text(mode: str) -> str:
    return _REPLAY[mode]


def guide() -> dict[str, Any]:
    """Everything the setup pages show about choosing a policy. Fixed text: nothing here depends on a request."""
    return {
        "common": COMMON,
        "profiles": [explain(name) for name in PROFILE_NAMES],
        "replay_modes": [{"name": mode, "text": _REPLAY[mode]} for mode in REPLAY_MODES],
        "max_age": MAX_AGE,
        "verifier_id": VERIFIER_ID,
    }
