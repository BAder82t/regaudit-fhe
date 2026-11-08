"""On macOS the configuration folder is inside ~/Library, which Finder hides. Every recovery message that sends you
there says how to open it in Finder, with the exact folder. Anywhere else nothing is added."""

import json
import os
import sys
from pathlib import Path

import pytest
from helpers import (
    client_for,
    fake_home,
    fingerprint_of,
    install_configuration,
    make_synthetic_portal,
    prepare_plan,
)
from regaudit_portal.paths import default_config_folder, finder_steps

FINDER = (
    " Finder hides that folder. To open it, click Finder in the Dock, choose Go > Go to Folder… in the menu "
    "bar at the top of the screen, type ~/Library/Application Support/Evidence Verification Portal and press Return."
)


@pytest.fixture
def mac_home(tmp_path, monkeypatch):
    """An account on macOS, whatever this computer is, with ~/Library/Application Support as a real account has it."""
    monkeypatch.setattr(sys, "platform", "darwin")
    home = fake_home(tmp_path, monkeypatch)
    parent = default_config_folder().parent
    parent.mkdir(parents=True)
    for place in (home, home / "Library", parent):
        os.chmod(place, 0o755)  # noqa: S103 - what a real home folder has
    return home


def test_the_steps_name_the_exact_folder_only_when_finder_hides_it(mac_home, monkeypatch):
    standard = default_config_folder()
    assert standard == mac_home / "Library" / "Application Support" / "Evidence Verification Portal"
    assert finder_steps(standard) == FINDER
    assert finder_steps(mac_home / "Documents" / "portal") == ""  # Finder shows it
    assert finder_steps(Path("/opt/portal")) == ""
    assert str(mac_home) not in finder_steps(standard)  # shown as ~/..., never by its full path
    monkeypatch.setattr(sys, "platform", "linux")
    assert finder_steps(standard) == ""


def _rows(config: Path) -> tuple[str, dict]:
    answer = client_for(config).get("/api/setup")
    return answer.text, {row["id"]: row for row in answer.json()["rows"]}


def test_the_setup_page_says_how_to_reach_the_folder_for_a_missing_trust_list(mac_home, demo):
    config = install_configuration(demo, default_config_folder())
    (default_config_folder() / "trust-store.json").unlink()
    text, rows = _rows(config)
    assert rows["trust_list"]["state"] == "missing"
    assert rows["trust_list"]["next_step"].endswith(FINDER)
    assert str(mac_home) not in text


def test_the_setup_page_says_how_to_reach_the_folder_for_an_invalid_configuration(mac_home, demo):
    config = install_configuration(demo, default_config_folder())
    config.write_text("{}")
    text, rows = _rows(config)
    assert rows["configuration"]["state"] == "problem"
    assert rows["configuration"]["next_step"].endswith(FINDER)
    assert str(mac_home) not in text


def test_the_setup_page_says_how_to_reach_the_folder_for_a_legacy_configuration(mac_home, demo):
    config = install_configuration(demo, default_config_folder())
    settings = json.loads(config.read_text())
    del settings["trust_mode"]
    config.write_text(json.dumps(settings))
    _text, rows = _rows(config)
    assert rows["trust_mode"]["state"] == "warning"
    assert rows["trust_mode"]["next_step"].endswith(FINDER)


def test_a_configuration_outside_library_gets_no_finder_steps(mac_home, demo):
    config = install_configuration(demo, mac_home / "Documents" / "portal")
    (config.parent / "trust-store.json").unlink()
    _text, rows = _rows(config)
    assert rows["trust_list"]["state"] == "missing"
    assert "Go to Folder" not in rows["trust_list"]["next_step"]


def test_admin_apply_says_how_to_reach_the_folder_it_will_not_replace(
    mac_home, demo, tmp_path, run, northwind
):
    install_configuration(demo, default_config_folder())
    plan = tmp_path / "setup-plan.json"
    plan.write_text(prepare_plan([northwind]))
    expect = f"{northwind.key_id}={fingerprint_of(northwind)}"
    code, _, err = run("admin-apply", plan, "--expect-fingerprint", expect)
    assert code == 2 and "There is already a configuration" in err
    assert FINDER.strip() in " ".join(err.split())


def test_admin_apply_says_how_to_reach_a_demonstration_folder_it_will_not_add_to(
    mac_home, tmp_path, run, northwind
):
    demonstration = make_synthetic_portal(tmp_path / "demo", trust_mode="demonstration")
    install_configuration(demonstration, default_config_folder())
    plan = tmp_path / "setup-plan.json"
    plan.write_text(prepare_plan([northwind], mode="add-issuers"))
    expect = f"{northwind.key_id}={fingerprint_of(northwind)}"
    code, _, err = run("admin-apply", plan, "--expect-fingerprint", expect)
    assert code == 2 and "Move it and the trust list away" in err
    assert FINDER.strip() in " ".join(err.split())
