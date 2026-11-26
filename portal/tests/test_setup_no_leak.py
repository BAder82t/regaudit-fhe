"""What ``GET /api/setup`` may and may not say when the administrator's own files are broken or hostile.

The status page shows the text of a configuration problem so the administrator can fix it. CodeQL reports that flow as
``py/stack-trace-exposure`` (alert 187). It is not a stack trace, and these tests are the evidence that holds it to that:

* no traceback, and no Python source line, is ever in the response;
* no full path: a place under the home folder is shown as ``~/...``, anywhere else as ``(outside your home folder)/name``;
* no file VALUE is echoed: not the bytes of a file that is not valid, not a value in a configuration member, not the
  text of a key, not the contents of a replay file;
* the only file CONTENT that can appear is an identifier the administrator wrote themselves: the name of an unknown
  configuration member, or a key id. That is pinned in its own test, so widening it is a decision and not an accident.

The endpoint is GET only, answers on 127.0.0.1 only, refuses a foreign Host or Origin, and has no sign-in
(portal/SECURITY.md). Anything that can reach the port can read this text, so it must stay free of anything that is not an
identifier the administrator already chose.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path

import pytest
from helpers import client_for, fake_home, install_configuration
from regaudit_portal.paths import default_config_folder

CANARY = "LEAK-CANARY-7f3a91c2d4e85b60"
STORE = "trust-store.json"
CONFIG = "portal-config.json"


def _write(path: Path, content: bytes | str) -> None:
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    os.chmod(path, 0o600)


def _config(folder: Path) -> dict:
    return json.loads((folder / CONFIG).read_text())


def _store(folder: Path) -> dict:
    return json.loads((folder / STORE).read_text())


# ----------------------------------------------------------------------------- hostile files whose VALUES must not appear


def _config_not_utf8(folder: Path) -> None:
    _write(folder / CONFIG, b"\xff\xfe" + CANARY.encode())


def _config_duplicate_key(folder: Path) -> None:
    _write(folder / CONFIG, f'{{"profile": "confidential", "profile": "{CANARY}"}}')


def _config_bad_profile_value(folder: Path) -> None:
    _write(folder / CONFIG, json.dumps({**_config(folder), "profile": CANARY}))


def _config_wrong_type_value(folder: Path) -> None:
    _write(folder / CONFIG, json.dumps({**_config(folder), "max_age_days": CANARY}))


def _config_bad_replay_mode_value(folder: Path) -> None:
    _write(folder / CONFIG, json.dumps({**_config(folder), "replay_mode": CANARY}))


def _config_bad_trust_mode_value(folder: Path) -> None:
    _write(folder / CONFIG, json.dumps({**_config(folder), "trust_mode": CANARY}))


def _store_not_json(folder: Path) -> None:
    _write(folder / STORE, "not json " + CANARY)


def _store_not_utf8(folder: Path) -> None:
    _write(folder / STORE, b"\xff\xfe\xfd" + CANARY.encode())


def _store_pem_value(folder: Path) -> None:
    store = _store(folder)
    key_id = next(iter(store["entries"]))
    store["entries"][key_id]["public_key_pem"] = CANARY
    _write(folder / STORE, json.dumps(store))


def _store_status_value(folder: Path) -> None:
    store = _store(folder)
    key_id = next(iter(store["entries"]))
    store["entries"][key_id]["status"] = CANARY
    _write(folder / STORE, json.dumps(store))


def _store_legacy_value(folder: Path) -> None:
    key_id = next(iter(_store(folder)["entries"]))
    _write(folder / STORE, json.dumps({"keys": {key_id: CANARY}}))


def _store_not_an_object(folder: Path) -> None:
    _write(folder / STORE, json.dumps([CANARY]))


def _replay_not_sqlite(folder: Path) -> None:
    _write(folder / "replay.db", b"SQLite format 3\x00" + CANARY.encode())


def _replay_text_file(folder: Path) -> None:
    _write(folder / "replay.db", CANARY)


VALUE_SCENARIOS = {
    "config-not-utf8": _config_not_utf8,
    "config-duplicate-key": _config_duplicate_key,
    "config-bad-profile-value": _config_bad_profile_value,
    "config-wrong-type-value": _config_wrong_type_value,
    "config-bad-replay-mode-value": _config_bad_replay_mode_value,
    "config-bad-trust-mode-value": _config_bad_trust_mode_value,
    "store-not-json": _store_not_json,
    "store-not-utf8": _store_not_utf8,
    "store-pem-value": _store_pem_value,
    "store-status-value": _store_status_value,
    "store-legacy-value": _store_legacy_value,
    "store-not-an-object": _store_not_an_object,
    "replay-not-sqlite": _replay_not_sqlite,
    "replay-text-file": _replay_text_file,
}


NOT_OPENED = {"replay-not-sqlite", "replay-text-file"}


def states(body: dict) -> dict[str, str]:
    return {row["id"]: row["state"] for row in body["rows"]}


# ----------------------------------------------------------------------------- where the files live


@pytest.fixture(params=["in-home", "outside-home"])
def place(request, tmp_path, monkeypatch, demo):
    """A configuration folder under the (fake) home folder, or one elsewhere. Returns (folder, config file path)."""
    home = fake_home(tmp_path, monkeypatch)
    folder = (
        default_config_folder() if request.param == "in-home" else tmp_path / "elsewhere" / "setup"
    )
    config = install_configuration(demo, folder)
    assert home in default_config_folder().parents or request.param == "outside-home"
    return folder, config


def _body(config: Path) -> dict:
    response = client_for(config).get("/api/setup")
    assert response.status_code == 200
    return response.json()


def _details(body: dict) -> list[str]:
    return [
        str(row.get(k))
        for row in body["rows"]
        for k in ("detail", "why", "next_step")
        if row.get(k)
    ]


# ----------------------------------------------------------------------------- the three promises


@pytest.mark.parametrize("name", sorted(VALUE_SCENARIOS))
def test_a_hostile_file_never_puts_its_values_into_the_response(place, tmp_path, name):
    folder, config = place
    VALUE_SCENARIOS[name](folder)
    body = _body(config)
    blob = json.dumps(body)
    assert CANARY not in blob, f"{name}: a value from a file was echoed"
    if name in NOT_OPENED:
        # The status page does not open the replay file (setup.py: "the replay file is not even opened"), so a broken
        # one is not noticed here and its contents cannot reach the response. If that changes, this scenario must be
        # rethought on purpose: the page would then be reading a file whose contents it must not repeat.
        assert states(body)["replay"] == "ok"
    else:
        assert any(row["state"] != "ok" for row in body["rows"]), (
            f"{name}: the broken file was not noticed"
        )


@pytest.mark.parametrize("name", sorted(VALUE_SCENARIOS))
def test_no_response_holds_a_traceback_or_a_full_path(place, tmp_path, name):
    folder, config = place
    VALUE_SCENARIOS[name](folder)
    blob = json.dumps(_body(config))
    assert "Traceback" not in blob and 'File "' not in blob
    assert not re.search(r"\bline \d+, in \w+", blob), "a traceback line"
    assert not re.search(r"\.py\b", blob), "a Python source file name"
    assert str(tmp_path) not in blob, "a full path from the test's folder"
    assert str(folder) not in blob and str(config) not in blob
    assert str(Path.home()) not in blob, "the real home folder"


def test_a_place_is_shown_as_home_relative_or_by_its_name_only(place, tmp_path):
    folder, config = place
    _store_not_json(folder)
    texts = " ".join(_details(_body(config)))
    inside = str(folder).startswith(str(Path.home()))
    assert ("~/" in texts) if inside else ("(outside your home folder)/" in texts)
    assert str(folder.parent) not in texts


# ----------------------------------------------------------------------------- the identifiers that ARE shown, on purpose


def test_the_name_of_an_unknown_configuration_member_is_shown_as_the_identifier_it_is(place):
    folder, config = place
    _write(config, json.dumps({**_config(folder), CANARY: "a value that must stay out"}))
    blob = json.dumps(_body(config))
    assert CANARY in blob  # the administrator needs the name to find the line
    assert "a value that must stay out" not in blob


def test_a_key_id_is_shown_as_the_identifier_it_is_and_its_key_text_is_not(place):
    folder, config = place
    store = _store(folder)
    entry = next(iter(store["entries"].values()))
    store["entries"] = {
        CANARY: {**entry, "public_key_pem": "-----BEGIN PUBLIC KEY-----\nNOT-A-KEY\n"}
    }
    _write(folder / STORE, json.dumps(store))
    blob = json.dumps(_body(config))
    assert CANARY in blob  # the administrator needs the id to find the entry
    assert "NOT-A-KEY" not in blob and "BEGIN PUBLIC KEY" not in blob


def test_the_replay_file_s_table_names_are_what_may_be_shown_and_nothing_stored_in_them(place):
    folder, config = place
    with sqlite3.connect(folder / "replay.db") as db:
        db.execute("CREATE TABLE foreign_table (x TEXT)")
        db.execute("INSERT INTO foreign_table VALUES (?)", (CANARY,))
    os.chmod(folder / "replay.db", 0o600)
    assert CANARY not in json.dumps(_body(config))


def test_the_issuers_list_shows_names_bounded_and_with_invisible_characters_made_visible(place):
    """The list of trusted issuers is the page's purpose, so an issuer name is shown. It is capped and made safe first."""
    folder, config = place
    store = _store(folder)
    key_id = next(iter(store["entries"]))
    store["entries"][key_id]["issuer"] = "Northwind \u202e" + CANARY * 40
    _write(folder / STORE, json.dumps(store))
    body = _body(config)
    shown = json.dumps(body["issuers"])
    assert CANARY in shown  # the name the administrator chose
    assert "(shortened)" in shown and CANARY * 40 not in shown  # but not all 1160 characters of it
    assert "\\u{202E}" in shown, (
        "a right-to-left override must be shown as a visible escape, never applied"
    )
    assert "\u202e" not in shown.lower().replace("\\u{202e}", "")
