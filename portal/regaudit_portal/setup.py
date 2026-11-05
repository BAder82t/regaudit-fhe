"""What the read-only setup page shows: how ready this portal is, and where the administrator's files belong.

This only looks. It creates no folder, no file, no trust list and no setting, it enrols no key and approves nothing, and
it never reads, accepts or shows a signing key. It has no way to write: nothing here opens a file for writing, makes a
folder, renames, deletes or changes permissions, and the replay file is not even opened. Places are shown relative to
the home folder (``~/...``) and never as full paths.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import (
    ConfigProblem,
    Settings,
    approved_entries,
    check_replay_location,
    read_settings,
    read_trust_store,
)
from .engine import Identity
from .paths import CONFIG_NAME, default_config_folder, default_config_path, display_path, hide_paths

HOST = "127.0.0.1"


def _row(row_id: str, title: str, state: str, detail: str) -> dict[str, Any]:
    return {"id": row_id, "title": title, "state": state, "ok": state == "ok", "detail": detail}


def _replay_text(mode: str) -> str:
    if mode == "record":
        return "Mode: record. A second check of the same report is refused as a repeat."
    return "Mode: check. Looking at a report twice gives the same answer, and each result says it was not recorded as used."


def readiness(
    config_path: Path | None, *, port: int, identity: Identity, own_state: str, own_message: str
) -> dict[str, Any]:
    """Look at the configuration, the trust list and the replay setting without changing anything."""
    location = config_path if config_path is not None else default_config_path()
    settings: Settings | None = None
    found: ConfigProblem | None = None
    try:
        settings = read_settings(location)
    except ConfigProblem as exc:
        found = exc
    places = [location, location.parent]
    if settings is not None:
        places += [settings.store_path, settings.replay_path]

    def say(text: str) -> str:
        return hide_paths(text, *places)

    unsafe: list[str] = []
    checked_files = (
        settings is not None
    )  # the configuration file and its folder passed the check of who can change them

    if settings is not None:
        configuration = _row(
            "configuration",
            "Configuration found and valid",
            "ok",
            f"Found at {display_path(location)} and valid.",
        )
    elif found is not None and found.kind == "missing":
        where = display_path(location)
        extra = (
            " The portal is in welcome mode: the samples work and your own reports are not set up."
            if config_path is None
            else ""
        )
        configuration = _row(
            "configuration",
            "Configuration found and valid",
            "missing",
            f"No configuration file was found at {where}.{extra}",
        )
    elif found is not None and found.kind == "unsafe":
        unsafe.append(say(str(found)))
        configuration = _row(
            "configuration",
            "Configuration found and valid",
            "problem",
            f"Found, but not read: {say(str(found))}",
        )
    else:
        checked_files = True  # an invalid file was read, so its ownership and its folder's passed
        configuration = _row(
            "configuration", "Configuration found and valid", "problem", say(str(found))
        )

    if settings is None:
        trust = _row(
            "trust_list",
            "Trust list found and valid",
            "not_checked",
            "Not checked until the configuration is found and valid.",
        )
        replay = _row(
            "replay",
            "Replay setting",
            "not_checked",
            "Not checked until the configuration is found and valid.",
        )
    else:
        try:
            store = read_trust_store(settings)
            trust = _row(
                "trust_list",
                "Trust list found and valid",
                "ok",
                f"{approved_entries(len(store.keys)).capitalize()} in {display_path(settings.store_path)}.",
            )
        except ConfigProblem as exc:
            if exc.kind == "unsafe":
                unsafe.append(say(str(exc)))
                trust = _row(
                    "trust_list",
                    "Trust list found and valid",
                    "problem",
                    f"Found, but not read: {say(str(exc))}",
                )
            else:
                state = "missing" if exc.kind == "missing" else "problem"
                trust = _row("trust_list", "Trust list found and valid", state, say(str(exc)))
        problem = check_replay_location(settings)
        text = _replay_text(settings.replay_mode)
        if problem is not None:
            unsafe.append(say(str(problem)))
            replay = _row("replay", "Replay setting", "problem", f"{text} {say(str(problem))}")
        else:
            replay = _row("replay", "Replay setting", "ok", text)

    if unsafe:
        files = _row(
            "file_check", "File ownership and permission check", "problem", " ".join(unsafe)
        )
    elif checked_files:
        files = _row(
            "file_check",
            "File ownership and permission check",
            "ok",
            "The files read so far, and the folders holding them, belong to this account and cannot be changed by group or others.",
        )
    else:
        files = _row(
            "file_check",
            "File ownership and permission check",
            "not_checked",
            "Not checked: there is no configuration to check yet.",
        )

    engine = _row(
        "engine",
        "Verification engine",
        "ok" if identity.ok and identity.engine else "problem",
        identity.engine["summary"]
        if identity.ok and identity.engine
        else "The verification engine does not pass its check.",
    )
    network = _row(
        "network",
        "Port and loopback-only",
        "ok",
        f"Listening on {HOST}, port {port}. Only this computer can reach it.",
    )
    return {
        "read_only": True,
        "location_for_this_computer": display_path(default_config_folder()) + "/",
        "config_file_name": CONFIG_NAME,
        "configuration_in_use": display_path(location),
        "own_reports": {"ready": own_state == "ready", "state": own_state, "message": own_message},
        "rows": [engine, configuration, trust, replay, files, network],
    }
