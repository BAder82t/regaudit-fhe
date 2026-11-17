"""A configuration that exists but is refused or not valid is not the same as having none, and the portal never says
"No trust is set up" for it. It says a configuration was found and needs attention, and that the samples still work."""

from __future__ import annotations

import json
import os

import regaudit_portal.app as app_module
from helpers import client_for, fake_home, install_configuration
from regaudit_portal.demo import create
from regaudit_portal.paths import default_config_folder

LABEL = "DEMONSTRATION — NOT CUSTOMER-TRUSTED"


def _both(client) -> tuple[dict, dict]:
    return client.get("/api/status").json(), client.get("/api/setup").json()


def _says_refused(status: dict, setup: dict) -> None:
    for body in (status, setup):
        assert body["trust_mode"] == "none"
        assert body["trust_mode_text"] == app_module._REFUSED_TRUST_MODE
        assert "No trust is set up" not in body["trust_mode_text"]
        assert (
            "A configuration was found, but it was refused or is not valid"
            in body["trust_mode_text"]
        )
        assert LABEL in body["trust_mode_text"]


def test_an_invalid_configuration_is_said_to_be_found_and_refused(tmp_path, monkeypatch, demo):
    fake_home(tmp_path, monkeypatch)
    config = install_configuration(demo, default_config_folder())
    config.write_text("{")
    os.chmod(config, 0o600)
    client = client_for(config)
    status, setup = _both(client)
    _says_refused(status, setup)
    assert status["state"] == "needs_attention" and status["message"] == app_module._NOT_READY
    assert "only the bundled samples can be checked" in status["message"]
    assert "No report can be checked" not in status["message"]
    assert client.post("/api/samples/trusted/verify").status_code == 200  # as the message says


def test_a_configuration_refused_for_the_demonstration_key_is_said_to_be_found_and_refused(
    tmp_path, monkeypatch
):
    fake_home(tmp_path, monkeypatch)
    demo = create(tmp_path / "demo")
    config = demo / "portal-config.json"
    settings = json.loads(config.read_text())
    settings["trust_mode"] = "customer"
    config.write_text(json.dumps(settings))
    status, setup = _both(client_for(config))
    _says_refused(status, setup)
    assert status["message"] == app_module._DEMONSTRATION_KEY_REFUSED


def test_with_no_configuration_the_portal_still_says_no_trust_is_set_up(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    status, setup = _both(client_for(None))
    for body in (status, setup):
        assert body["trust_mode_text"] == app_module._NO_TRUST_MODE
        assert body["trust_mode_text"].startswith("Trust mode: none. No trust is set up")
