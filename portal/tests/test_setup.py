"""The administrator setup page only reads. It says what is set up, never changes anything, and shows places as ~/..."""

from __future__ import annotations

import ast
import builtins
import json
import os
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest
import regaudit_portal.engine as engine_module
from helpers import client_for, fake_home, install_configuration, snapshot
from regaudit_portal.config import ConfigProblem, load_portal
from regaudit_portal.paths import default_config_folder, default_config_path, display_path

PORTAL = Path(__file__).parents[1]
STATIC = PORTAL / "regaudit_portal" / "static"
REFUSED_STATUS = {"ready": False, "state": "unavailable"}
GOOD = {
    "engine": "ok",
    "configuration": "ok",
    "trust_list": "ok",
    "replay": "ok",
    "file_check": "ok",
    "network": "ok",
}


def _crashes(_folder):
    raise RuntimeError("the hash could not be computed")


def states(body: dict) -> dict[str, str]:
    return {row["id"]: row["state"] for row in body["rows"]}


# ----------------------------------------------------------------------------- one place to make each situation


def _installed(demo, **_):
    return install_configuration(demo, default_config_folder())


def _absent(demo, **_):
    return None


def _empty_folder(demo, **_):
    default_config_folder().mkdir(parents=True)
    os.chmod(default_config_folder(), 0o700)
    return None


def _edit(path: Path, text: str) -> None:
    path.write_text(text)
    os.chmod(path, 0o600)


def _bad_json(demo, **_):
    config = install_configuration(demo, default_config_folder())
    _edit(config, "{")
    return None


def _unknown_member(demo, **_):
    config = install_configuration(demo, default_config_folder())
    data = json.loads(config.read_text())
    _edit(config, json.dumps({**data, "surprise": True}))
    return None


def _no_trust_list(demo, **_):
    install_configuration(demo, default_config_folder())
    (default_config_folder() / "trust-store.json").unlink()
    return None


def _bad_trust_list(demo, **_):
    install_configuration(demo, default_config_folder())
    _edit(default_config_folder() / "trust-store.json", "{")
    return None


def _legacy_trust_list(demo, **_):
    install_configuration(demo, default_config_folder())
    store = json.loads((demo / "trust-store.json").read_text())
    key_id, entry = next(iter(store["entries"].items()))
    _edit(
        default_config_folder() / "trust-store.json",
        json.dumps({"keys": {key_id: entry["public_key_pem"]}}),
    )
    return None


def _unsafe_folder(demo, **_):
    install_configuration(demo, default_config_folder(), mode=0o777)
    return None


def _unsafe_config_file(demo, **_):
    config = install_configuration(demo, default_config_folder())
    os.chmod(config, 0o666)  # noqa: S103 - the point of the test
    return None


def _unsafe_trust_list(demo, **_):
    install_configuration(demo, default_config_folder())
    os.chmod(default_config_folder() / "trust-store.json", 0o666)  # noqa: S103 - the point of the test
    return None


def _unsafe_replay_file(demo, **_):
    install_configuration(demo, default_config_folder())
    replay = default_config_folder() / "replay.db"
    replay.write_bytes(b"")
    os.chmod(replay, 0o666)  # noqa: S103 - the point of the test
    return None


def _given_outside_home(demo, **_):
    return demo / "portal-config.json"


def _given_and_missing(demo, tmp_path):
    return tmp_path / "nowhere" / "portal-config.json"


SCENARIOS = {
    "good": (_installed, GOOD),
    "absent": (_absent, {**GOOD, "configuration": "missing", "trust_list": "not_checked", "replay": "not_checked", "file_check": "not_checked"}),
    "empty-folder": (_empty_folder, {**GOOD, "configuration": "missing", "trust_list": "not_checked", "replay": "not_checked", "file_check": "not_checked"}),
    "bad-json": (_bad_json, {**GOOD, "configuration": "problem", "trust_list": "not_checked", "replay": "not_checked"}),
    "unknown-member": (_unknown_member, {**GOOD, "configuration": "problem", "trust_list": "not_checked", "replay": "not_checked"}),
    "no-trust-list": (_no_trust_list, {**GOOD, "trust_list": "missing"}),
    "bad-trust-list": (_bad_trust_list, {**GOOD, "trust_list": "problem"}),
    "legacy-trust-list": (_legacy_trust_list, {**GOOD, "trust_list": "problem"}),
    "unsafe-folder": (_unsafe_folder, {**GOOD, "configuration": "problem", "trust_list": "not_checked", "replay": "not_checked", "file_check": "problem"}),
    "unsafe-config-file": (_unsafe_config_file, {**GOOD, "configuration": "problem", "trust_list": "not_checked", "replay": "not_checked", "file_check": "problem"}),
    "unsafe-trust-list": (_unsafe_trust_list, {**GOOD, "trust_list": "problem", "file_check": "problem"}),
    "unsafe-replay-file": (_unsafe_replay_file, {**GOOD, "replay": "problem", "file_check": "problem"}),
    "given-outside-home": (_given_outside_home, GOOD),
    "given-and-missing": (_given_and_missing, {**GOOD, "configuration": "missing", "trust_list": "not_checked", "replay": "not_checked", "file_check": "not_checked"}),
}  # fmt: skip


@pytest.fixture(params=sorted(SCENARIOS))
def scenario(request, tmp_path, monkeypatch, demo):
    home = fake_home(tmp_path, monkeypatch)
    build, expected = SCENARIOS[request.param]
    given = build(demo, tmp_path=tmp_path)
    return request.param, given, expected, home, client_for(given)


# ----------------------------------------------------------------------------- what it reports


def test_each_row_reports_its_own_state_correctly(scenario):
    name, _, expected, _, client = scenario
    body = client.get("/api/setup").json()
    assert states(body) == expected, name
    assert [row["id"] for row in body["rows"]] == [
        "engine",
        "configuration",
        "trust_list",
        "replay",
        "file_check",
        "network",
    ]
    assert body["read_only"] is True and all(row["detail"] for row in body["rows"])


def test_the_report_agrees_with_what_loading_the_configuration_decides(scenario):
    name, given, _, _, client = scenario
    body = client.get("/api/setup").json()
    checks = [
        row["ok"]
        for row in body["rows"]
        if row["id"] in ("configuration", "trust_list", "replay", "file_check")
    ]
    try:
        load_portal(given if given is not None else default_config_path())
        loads = True
    except ConfigProblem:
        loads = False
    assert all(checks) is loads is body["own_reports"]["ready"], name
    assert client.get("/api/status").json()["ready"] is loads


def test_the_port_and_loopback_row_tells_the_port_and_that_only_this_computer_can_reach_it(
    scenario,
):
    body = scenario[4].get("/api/setup").json()
    row = next(row for row in body["rows"] if row["id"] == "network")
    assert row["detail"] == "Listening on 127.0.0.1, port 8765. Only this computer can reach it."


def test_the_engine_row_says_the_engine_passes(client):
    row = next(r for r in client.get("/api/setup").json()["rows"] if r["id"] == "engine")
    assert row["ok"] and "regaudit-fhe 0.2.1" in row["detail"]


def test_the_state_of_your_own_reports_is_said_in_plain_words(tmp_path, monkeypatch, demo):
    fake_home(tmp_path, monkeypatch)
    welcome = client_for(None).get("/api/setup").json()["own_reports"]
    assert welcome["state"] == "not_set_up" and welcome["ready"] is False
    assert (
        welcome["message"]
        == "Verification of your own reports is not set up yet. An administrator has to set up trust first."
    )
    ready = (
        client_for(install_configuration(demo, default_config_folder()))
        .get("/api/setup")
        .json()["own_reports"]
    )
    assert ready["state"] == "ready" and ready["ready"] is True


def test_the_location_for_this_computer_is_the_standard_one(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    body = client_for(None).get("/api/setup").json()
    assert body["location_for_this_computer"] == display_path(default_config_folder()) + "/"
    assert body["location_for_this_computer"].startswith("~/")
    expected = (
        "~/Library/Application Support/Evidence Verification Portal/"
        if sys.platform == "darwin"
        else "~/.config/evidence-verification-portal/"
    )
    assert body["location_for_this_computer"] == expected
    assert body["config_file_name"] == "portal-config.json"


# ----------------------------------------------------------------------------- places are shown as ~/... and only here


def test_places_on_this_page_are_relative_to_the_home_folder_and_never_full_paths(
    scenario, tmp_path
):
    name, given, _, home, client = scenario
    text = client.get("/api/setup").text
    assert str(tmp_path) not in text and str(home) not in text, name
    assert "/private/" not in text and "/var/folders" not in text
    if given is None:
        assert "~/" in text
    else:
        assert "(outside your home folder)/portal-config.json" in text or "nowhere" not in text


def test_a_configuration_given_from_outside_the_home_folder_is_shown_by_its_file_name_only(
    tmp_path, monkeypatch, demo
):
    fake_home(tmp_path, monkeypatch)
    body = client_for(demo / "portal-config.json").get("/api/setup").json()
    assert body["configuration_in_use"] == "(outside your home folder)/portal-config.json"
    assert str(demo) not in json.dumps(body)


def test_places_are_not_shown_on_the_verification_pages_or_in_their_refusals(
    tmp_path, monkeypatch, demo
):
    home = fake_home(tmp_path, monkeypatch)
    install_configuration(
        demo, default_config_folder(), mode=0o777
    )  # unusable, so there is something to refuse about
    client = client_for(default_config_path())
    seen = [
        client.get("/").text,
        client.get("/api/status").text,
        client.post(
            "/api/verify", content=b"{}", headers={"content-type": "application/json"}
        ).text,
        client.post("/api/samples/trusted/verify").text,
    ]
    for text in seen:
        for place in (str(tmp_path), str(home), "~/", "Library", ".config", "Application Support"):
            assert place not in text, place


def test_display_path_shows_home_places_as_tilde_and_others_by_name_only(tmp_path, monkeypatch):
    home = fake_home(tmp_path, monkeypatch)
    assert display_path(home) == "~"
    assert display_path(home / "a" / "b.json") == "~/a/b.json"
    assert display_path(tmp_path / "elsewhere" / "b.json") == "(outside your home folder)/b.json"


# ----------------------------------------------------------------------------- it changes nothing


def test_looking_at_the_setup_page_changes_nothing_on_disk(scenario, tmp_path):
    name, _, _, _, client = scenario
    before = snapshot(tmp_path)
    for path in ("/setup", "/api/setup", "/security"):
        assert client.get(path).status_code == 200
        assert client.head(path).status_code == 200
    assert snapshot(tmp_path) == before, name


def test_it_does_not_create_the_replay_file_that_is_missing(tmp_path, monkeypatch, demo):
    fake_home(tmp_path, monkeypatch)
    client = client_for(install_configuration(demo, default_config_folder()))
    replay = default_config_folder() / "replay.db"
    replay.unlink()  # the portal made it when it started
    for _ in range(3):
        client.get("/api/setup")
    assert not replay.exists()


def test_it_does_not_create_the_per_user_folder_or_anything_in_it(tmp_path, monkeypatch):
    home = fake_home(tmp_path, monkeypatch)
    before = snapshot(home)
    welcome = client_for(None)
    for path in ("/", "/setup", "/api/setup", "/api/status"):
        welcome.get(path)
    assert snapshot(home) == before and list(home.iterdir()) == []


def _forbid_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every way of changing the disk raise, so a page that is served without raising cannot have used one."""

    def refuse(name: str):
        def refused(*_args, **_kwargs):
            raise AssertionError(f"{name} was called")

        return refused

    real_open, real_os_open = builtins.open, os.open

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in str(mode) for flag in "wax+"):
            raise AssertionError(f"open({file!r}, {mode!r}) was called")
        return real_open(file, mode, *args, **kwargs)

    def guarded_os_open(path, flags, *args, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError(f"os.open({path!r}) for writing was called")
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(os, "open", guarded_os_open)
    for name in (
        "mkdir",
        "makedirs",
        "remove",
        "unlink",
        "rename",
        "replace",
        "rmdir",
        "chmod",
        "symlink",
        "link",
        "truncate",
        "utime",
        "chown",
    ):
        monkeypatch.setattr(os, name, refuse(f"os.{name}"))
    for name in ("copy", "copy2", "copyfile", "move", "rmtree", "copytree"):
        monkeypatch.setattr(shutil, name, refuse(f"shutil.{name}"))
    for name in (
        "write_text",
        "write_bytes",
        "touch",
        "mkdir",
        "unlink",
        "rename",
        "replace",
        "rmdir",
        "chmod",
        "symlink_to",
    ):
        monkeypatch.setattr(Path, name, refuse(f"Path.{name}"))
    monkeypatch.setattr(sqlite3, "connect", refuse("sqlite3.connect"))


def test_no_way_of_writing_is_reached_while_the_setup_page_is_served(scenario, monkeypatch):
    name, _, _, _, client = scenario
    _forbid_writes(monkeypatch)
    for path in ("/setup", "/api/setup"):
        assert client.get(path).status_code == 200, (name, path)
        assert client.head(path).status_code == 200


def test_the_guard_against_writing_is_real(tmp_path, monkeypatch, demo):
    """Loading a configuration does create the replay file. With writing forbidden, that fails: so the guard works."""
    fake_home(tmp_path, monkeypatch)
    config = install_configuration(demo, default_config_folder())
    _forbid_writes(monkeypatch)
    with pytest.raises(AssertionError):
        load_portal(config)


def _called_names(source: str, only_in: set[str] | None = None) -> set[str]:
    names: set[str] = set()

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack: list[str] = []

        def visit_FunctionDef(self, node):
            for (
                decorator
            ) in node.decorator_list:  # a decorator runs in the scope around the function
                self.visit(decorator)
            self.stack.append(node.name)
            for statement in node.body:
                self.visit(statement)
            self.stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            if only_in is None or (self.stack and self.stack[-1] in only_in):
                target = node.func
                parts = []
                while isinstance(target, ast.Attribute):
                    parts.append(target.attr)
                    target = target.value
                if isinstance(target, ast.Name):
                    parts.append(target.id)
                names.add(".".join(reversed(parts)))
            self.generic_visit(node)

    Visitor().visit(ast.parse(source))
    return names


def test_the_code_behind_the_setup_page_has_no_call_that_could_write():
    forbidden_calls = {
        "open", "os.open", "os.mkdir", "os.makedirs", "os.remove", "os.unlink", "os.rename", "os.replace", "os.rmdir",
        "os.chmod", "os.symlink", "os.link", "SqliteReplayCache", "_create_replay_file", "load_portal", "load_samples",
    }  # fmt: skip
    forbidden_endings = (
        "write_text", "write_bytes", "touch", "mkdir", "unlink", "rename", "rmdir", "chmod", "symlink_to", "write",
        "writelines", "truncate",
    )  # fmt: skip
    for name in ("setup.py", "paths.py"):
        source = (PORTAL / "regaudit_portal" / name).read_text()
        called = _called_names(source)
        assert not called & forbidden_calls, (name, called & forbidden_calls)
        assert not [
            c
            for c in called
            if c.startswith(("shutil.", "sqlite3.", "tempfile.")) or c.endswith(forbidden_endings)
        ], name
        tree = ast.parse(source)
        imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        assert not imported & {"shutil", "sqlite3", "tempfile"}, name
    reads = (PORTAL / "regaudit_portal" / "config.py").read_text()
    assert (
        "read_settings" in reads
        and "read_trust_store" in reads
        and "check_replay_location" in reads
    )


def test_the_two_setup_routes_only_look():
    source = (PORTAL / "regaudit_portal" / "app.py").read_text()
    called = _called_names(source, {"setup_page", "setup_status"})
    assert called == {
        "FileResponse",
        "check_engine",
        "watch.seen",
        "_unavailable_status",
        "readiness",
        "_own_message",
    }, called


@pytest.mark.parametrize("path", ["/setup", "/api/setup"])
@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_the_setup_routes_accept_nothing_but_looking(client, path, method):
    response = client.request(method.upper(), path, content=b'{"key": "anything"}')
    assert response.status_code == 405


# ----------------------------------------------------------------------------- no signing key, ever


def test_the_setup_page_has_no_form_and_sends_nothing():
    html = (STATIC / "setup.html").read_text()
    script = (STATIC / "setup.js").read_text()
    for element in (
        "<form",
        "<input",
        "<textarea",
        "<select",
        "<button",
        'type="file"',
        "contenteditable",
    ):
        assert element not in html, element
    assert 'fetch("/api/setup")' in script and script.count("fetch(") == 1
    for write in ("method:", "POST", "PUT", "FormData", "body:", "localStorage", "innerHTML"):
        assert write not in script, write


def test_the_setup_answer_never_carries_key_material_or_the_trust_lists_contents(
    tmp_path, monkeypatch, demo
):
    fake_home(tmp_path, monkeypatch)
    config = install_configuration(demo, default_config_folder())
    text = client_for(config).get("/api/setup").text
    store = json.loads((demo / "trust-store.json").read_text())
    key_id, entry = next(iter(store["entries"].items()))
    for secret in (
        "PUBLIC KEY",
        "PRIVATE KEY",
        entry["public_key_pem"].strip().splitlines()[1],
        key_id,
        "Example Synthetic Issuer",
    ):
        assert secret not in text, secret


# ----------------------------------------------------------------------------- what the page tells an administrator


def test_the_setup_page_explains_what_to_prepare_where_it_goes_and_the_existing_commands():
    html = (STATIC / "setup.html").read_text()
    for said in (
        "This page only reads",
        "It does not create or change anything: no trust list, no key, no setting, no approval",
        "never asks for a signing key and never shows one",
        "What an administrator has to prepare",
        "another route than the report itself",
        "A report cannot vouch for its own key",
        "Where the files go",
        "one folder that only your account can change",
        "must not be writable by group or others",
        "Restart the portal after any change",
        "regaudit-fhe trust add --store trust-store.json --key-id KEY_ID",
        "--public-key issuer.pub --fingerprint FINGERPRINT",
        "regaudit-portal check-config",
        "For now, making the trust list needs these commands",
        "Creating it in the browser would be a separate change",
        "Read the full limitation",
    ):
        assert said in html, said
    assert "Library" not in html and "~/" not in html, (
        "the places come from the portal, not from the page"
    )


def test_the_setup_page_is_linked_from_the_start_and_from_the_not_set_up_note():
    html = (STATIC / "index.html").read_text()
    main = html[html.index("<main") : html.index("</main>")]
    assert 'id="choose-setup" href="/setup"' in main
    assert (
        main.count('href="/setup"') == 2
    )  # the start, and the note that your own reports are not set up


def test_when_the_engine_stops_passing_the_setup_answer_is_the_unavailable_one(client, monkeypatch):
    assert client.get("/api/setup").json()["own_reports"]["ready"] is True
    monkeypatch.setattr(engine_module, "files_digest", _crashes)
    assert client.get("/api/setup").json() == REFUSED_STATUS
