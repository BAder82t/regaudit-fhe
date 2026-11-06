"""What the read-only setup page shows: how ready this portal is, and where the administrator's files belong.

This only looks. It creates no folder, no file, no trust list and no setting, it enrols no key and approves nothing, and
it never reads, accepts or shows a signing key. It has no way to write: nothing here opens a file for writing, makes a
folder, renames, deletes or changes permissions, and the replay file is not even opened. Places are shown relative to
the home folder (``~/...``) and never as full paths.

For each requirement that is missing or fails, a row says what is missing, why it matters and the one next step. A
configuration that says ``"trust_mode": "demonstration"``, or a trust list that holds one of the portal's bundled
demonstration keys (by fingerprint), is labelled a demonstration and is never counted as trust being set up. The page
also shows which trust mode the running portal is in.

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
    trust_mode_of,
)
from .engine import Identity
from .paths import (
    CONFIG_NAME,
    bundled_command,
    default_config_folder,
    default_config_path,
    display_path,
    hide_paths,
    shell_path,
)
from .profiles import explain, guide

HOST = "127.0.0.1"


def _row(
    row_id: str,
    title: str,
    state: str,
    detail: str,
    why: str | None = None,
    next_step: str | None = None,
) -> dict[str, Any]:
    """One line of the status. ``why`` and ``next_step`` are given for every requirement that is missing or fails."""
    return {
        "id": row_id,
        "title": title,
        "state": state,
        "ok": state == "ok",
        "detail": detail,
        "why": why,
        "next_step": next_step,
    }


_PREPARE = (
    "Prepare a setup plan on the Prepare a setup plan page, then apply it outside the browser: with Administrator "
    "setup in the application's menu, or with admin-apply in Terminal."
)
_FIX_ACCESS = (
    "Make the folder and the file belong to this account, and remove write access for group and others, for example "
    "with Get Info in Finder. Then restart the portal."
)
_WHY = {
    "configuration_missing": (
        "Without a configuration the portal cannot check your own reports. Only the made-up samples work."
    ),
    "configuration_invalid": (
        "The portal gives no verdict for your own reports until its configuration can be read and is complete."
    ),
    "unsafe": (
        "If another account can change these files, it can change which keys you trust, so the portal does not use "
        "them."
    ),
    "trust_missing": "The portal accepts a report only from a key in the trust list, so without it nothing is accepted.",
    "trust_invalid": "The portal gives no verdict for your own reports until the trust list can be read.",
    "demonstration": (
        "A demonstration key is not a real issuer. It signed only made-up sample reports, so trusting it says "
        "nothing about any real report."
    ),
    "development": "The development profile relaxes checks, and every result says not to rely on it.",
    "replay": (
        "Without a usable replay file the portal cannot tell a repeated report, so it does not check your own reports."
    ),
    "engine": "Only the published regaudit-fhe 0.2.1 may give verdicts, so nothing is checked until it passes.",
}
_STATE_NEXT = {
    "configuration_invalid": (
        "Run the check-config command below to see the exact reason, and correct the file. A setup plan cannot "
        "replace an existing configuration."
    ),
    "trust_missing": (
        "Make the trust list with the trust add command below, using the file name the configuration gives, or "
        "restore it from a copy."
    ),
    "trust_invalid": "Run the check-config command below to see the exact reason, and correct the trust list.",
    "demonstration": (
        "Move this configuration and its trust list out of the folder, then prepare and apply a setup plan with "
        "your issuers' real keys."
    ),
    "development": (
        "To have the replay and format checks enforced, change the profile in the configuration to confidential or high-assurance "
        "and restart the portal."
    ),
    "engine": "Reinstall the published regaudit-fhe 0.2.1, as the portal's terminal output says.",
}


_TRUST_INTRO = (
    "Run this once for each issuer key, in the folder above, with the same Python environment the portal is installed in. "
    "It refuses a key whose fingerprint does not match the one you received."
)
_APPLICATION_INTRO = (
    "This portal is running from the application, which does not install these commands on your computer under their "
    "usual names. Each one is run by the full path of its program inside the application, as shown here. For now they "
    "are run in Terminal, in the folder above. Run the command below once for each issuer key. It refuses a key whose "
    "fingerprint does not match the one you received."
)


def commands() -> dict[str, Any]:
    """How to type the commands on this computer: by plain name in a normal install, by full path in the application.

    The only places this can show are the two wrapper programs, and only when they are there. It looks and creates nothing.
    """
    trust = bundled_command("regaudit-fhe")
    check = bundled_command("regaudit-portal")
    program = shell_path(trust) if trust is not None else "regaudit-fhe"
    portal = shell_path(check) if check is not None else "regaudit-portal"
    inside = trust is not None or check is not None
    return {
        "in_application": inside,
        "intro": _APPLICATION_INTRO if inside else _TRUST_INTRO,
        "trust_add": (
            f'{program} trust add --store trust-store.json --key-id KEY_ID --issuer "ISSUER NAME" \\\n'
            "  --public-key issuer.pub --fingerprint FINGERPRINT"
        ),
        "check_config": portal + " check-config",
        "admin_describe": f"{portal} admin-describe setup-plan.json",
        "admin_apply": (
            f"{portal} admin-apply setup-plan.json \\\n  --expect-fingerprint KEY_ID=FINGERPRINT_FROM_THE_ISSUER"
        ),
    }


def _replay_text(mode: str) -> str:
    if mode == "record":
        return "Mode: record. A second check of the same report is refused as a repeat."
    return "Mode: check. Looking at a report twice gives the same answer, and each result says it was not recorded as used."


_CONFIGURATION = "Configuration found and valid"
_POLICY = "Trust policy (profile)"
_TRUST = "Trust list found and valid"
_REPLAY = "Replay setting"
_FILES = "File ownership and permission check"
_AFTER_CONFIGURATION = "Not checked until the configuration is found and valid."


def readiness(
    config_path: Path | None,
    *,
    port: int,
    identity: Identity,
    own_state: str,
    own_message: str,
    mode: dict[str, Any] | None = None,
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
    demonstration = False

    if settings is not None:
        configuration = _row(
            "configuration", _CONFIGURATION, "ok", f"Found at {display_path(location)} and valid."
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
            _CONFIGURATION,
            "missing",
            f"No configuration file was found at {where}.{extra}",
            _WHY["configuration_missing"],
            _PREPARE,
        )
    elif found is not None and found.kind == "unsafe":
        unsafe.append(say(str(found)))
        configuration = _row(
            "configuration",
            _CONFIGURATION,
            "problem",
            f"Found, but not read: {say(str(found))}",
            _WHY["unsafe"],
            _FIX_ACCESS,
        )
    else:
        checked_files = True  # an invalid file was read, so its ownership and its folder's passed
        configuration = _row(
            "configuration",
            _CONFIGURATION,
            "problem",
            say(str(found)),
            _WHY["configuration_invalid"],
            _STATE_NEXT["configuration_invalid"],
        )

    if settings is None:
        policy = _row("trust_policy", _POLICY, "not_checked", _AFTER_CONFIGURATION)
        trust = _row("trust_list", _TRUST, "not_checked", _AFTER_CONFIGURATION)
        replay = _row("replay", _REPLAY, "not_checked", _AFTER_CONFIGURATION)
    else:
        meaning = explain(settings.profile)
        days = settings.max_age_days
        described = (
            f"Profile {settings.profile}: {meaning['summary']} Maximum report age {days} "
            f"day{'' if days == 1 else 's'}."
        )
        if settings.profile == "development":
            policy = _row(
                "trust_policy",
                _POLICY,
                "problem",
                described,
                _WHY["development"],
                _STATE_NEXT["development"],
            )
        else:
            policy = _row("trust_policy", _POLICY, "ok", described)
        try:
            store = read_trust_store(settings)
            kind, reason = trust_mode_of(settings, store)
            demonstration = kind == "demonstration"
            if demonstration:
                trust = _row(
                    "trust_list",
                    _TRUST,
                    "demonstration",
                    f"This is demonstration trust, because {reason}. It does not count as trust being set up. The "
                    "portal checks files against it only as a demonstration, and every result says so.",
                    _WHY["demonstration"],
                    _STATE_NEXT["demonstration"],
                )
            else:
                trust = _row(
                    "trust_list",
                    _TRUST,
                    "ok",
                    f"{approved_entries(len(store.keys)).capitalize()} in {display_path(settings.store_path)}.",
                )
        except ConfigProblem as exc:
            if exc.kind == "unsafe":
                unsafe.append(say(str(exc)))
                trust = _row(
                    "trust_list",
                    _TRUST,
                    "problem",
                    f"Found, but not read: {say(str(exc))}",
                    _WHY["unsafe"],
                    _FIX_ACCESS,
                )
            elif exc.kind == "missing":
                trust = _row(
                    "trust_list",
                    _TRUST,
                    "missing",
                    say(str(exc)),
                    _WHY["trust_missing"],
                    _STATE_NEXT["trust_missing"],
                )
            else:
                trust = _row(
                    "trust_list",
                    _TRUST,
                    "problem",
                    say(str(exc)),
                    _WHY["trust_invalid"],
                    _STATE_NEXT["trust_invalid"],
                )
        problem = check_replay_location(settings)
        text = _replay_text(settings.replay_mode)
        if problem is not None:
            unsafe.append(say(str(problem)))
            replay = _row(
                "replay",
                _REPLAY,
                "problem",
                f"{text} {say(str(problem))}",
                _WHY["replay"],
                _FIX_ACCESS,
            )
        else:
            replay = _row("replay", _REPLAY, "ok", text)

    if unsafe:
        files = _row("file_check", _FILES, "problem", " ".join(unsafe), _WHY["unsafe"], _FIX_ACCESS)
    elif checked_files:
        files = _row(
            "file_check",
            _FILES,
            "ok",
            "The files read so far, and the folders holding them, belong to this account and cannot be changed by group or others.",
        )
    else:
        files = _row(
            "file_check",
            _FILES,
            "not_checked",
            "Not checked: there is no configuration to check yet.",
        )

    engine_ok = bool(identity.ok and identity.engine)
    engine = _row(
        "engine",
        "Verification engine",
        "ok" if engine_ok else "problem",
        identity.engine["summary"]
        if engine_ok and identity.engine
        else "The verification engine does not pass its check.",
        None if engine_ok else _WHY["engine"],
        None if engine_ok else _STATE_NEXT["engine"],
    )
    network = _row(
        "network",
        "Port and loopback-only",
        "ok",
        f"Listening on {HOST}, port {port}. Only this computer can reach it.",
    )
    rows = [engine, configuration, policy, trust, replay, files, network]
    required = ("engine", "configuration", "trust_list", "replay", "file_check")
    return {
        "read_only": True,
        # The mode the running portal is in, from the configuration it was started with.
        **(mode or {"trust_mode": "none"}),
        "location_for_this_computer": display_path(default_config_folder()) + "/",
        "config_file_name": CONFIG_NAME,
        "configuration_in_use": display_path(location),
        "own_reports": {"ready": own_state == "ready", "state": own_state, "message": own_message},
        # Trust counts as set up only when every requirement passes and the trust list is not a demonstration.
        "trust_configured": all(row["ok"] for row in rows if row["id"] in required),
        "demonstration_trust_list": demonstration,
        "rows": rows,
        "commands": commands(),
        "guide": guide(),
    }
