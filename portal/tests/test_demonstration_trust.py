"""A demonstration trust list in the configuration is kept apart from trust set up by an administrator.

The portal never reports it as ready, and every result it gives, on the page and in the saved file, is labelled a
demonstration, with demonstration wording. The engine and its verdicts are unchanged: only the portal's labels differ.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import JSON_HEADERS, client_for, make_synthetic_portal, post
from regaudit_portal.__main__ import started_message
from regaudit_portal.config import ConfigProblem, load_portal, read_settings
from regaudit_portal.demo import create
from regaudit_portal.explain import DEMONSTRATION_TRUST_NOTICE

PORTAL = Path(__file__).resolve().parents[1]
SAMPLES = PORTAL / "regaudit_portal" / "samples"
ADMINISTRATOR_WORDS = (
    "an issuer your administrator approved",
    "configured trust rules",
    "your administrator",
)


def _edit(config: Path, **change) -> Path:
    data = json.loads(config.read_text())
    data.update(change)
    config.write_text(json.dumps(data))
    os.chmod(config, 0o600)
    return config


# ----------------------------------------------------------------------------- what a reviewer saw


def test_a_demo_setup_configuration_is_never_ready_and_every_result_is_a_labelled_demonstration(
    tmp_path,
):
    """demo-setup, then serve --config with it, then the demonstration-signed report checked as your own."""
    demo = create(tmp_path / "demo")
    client = client_for(demo / "portal-config.json")
    assert client.app.state.ready is False and client.app.state.mode == "demonstration"
    status = client.get("/api/status").json()
    assert status["ready"] is False and status["state"] == "demonstration"
    assert (
        status["demonstration_checks"] is True and "demonstration trust list" in status["message"]
    )
    assert "approved issuer" not in json.dumps(status) and "policy_id" not in status

    body = post(client, demo, "1-trusted.json").json()
    assert body["verification"]["trust_status"] == "TRUSTED"  # the engine's own verdict, unchanged
    assert body["synthetic_demonstration"] is True
    assert body["demonstration"]["notice"] == DEMONSTRATION_TRUST_NOTICE
    assert "not trust set up by an administrator" in body["demonstration"]["trust_list"]
    explanation = body["explanation"]
    assert explanation["warnings"][0] == {
        "code": "DEMONSTRATION_ONLY",
        "message": DEMONSTRATION_TRUST_NOTICE,
    }
    assert "the demonstration trust list" in explanation["verdict"]
    shown = json.dumps({k: v for k, v in explanation.items() if k != "display"})
    for words in ADMINISTRATOR_WORDS:
        assert words not in shown, words


@pytest.mark.parametrize("name", ["2-untrusted-signer.json", "4-changed-after-signing.json"])
def test_refused_reports_under_a_demonstration_trust_list_are_labelled_too(tmp_path, name):
    demo = create(tmp_path / "demo")
    body = post(client_for(demo / "portal-config.json"), demo, name).json()
    assert (
        body["verification"]["trust_status"] == "INVALID"
        and body["synthetic_demonstration"] is True
    )
    assert body["demonstration"]["notice"] == DEMONSTRATION_TRUST_NOTICE


def test_the_saved_result_is_named_and_marked_a_demonstration_by_the_page():
    """The page saves the answer as it came, and names the file by its marker."""
    script = (PORTAL / "regaudit_portal" / "static" / "app.js").read_text()
    assert (
        'const kind = lastSaved.body.synthetic_demonstration === true ? "demonstration-result-" : "verification-result-";'
        in script
    )
    assert (
        "const saved = Object.assign({ report_file_name: lastSaved.name }, lastSaved.body);"
        in script
    )
    assert 'show("upload-demo-note", demonstrationOnly);' in script
    assert (
        '<p id="upload-demo-note" class="demo-banner" hidden></p>'
        in (PORTAL / "regaudit_portal" / "static" / "index.html").read_text()
    )


def test_an_administrators_own_configuration_is_unchanged(client, demo):
    status = client.get("/api/status").json()
    assert status["ready"] is True and status["state"] == "ready"
    body = post(client, demo, "1-trusted.json").json()
    assert body["synthetic_demonstration"] is False and "demonstration" not in body
    assert "an issuer your administrator approved" in body["explanation"]["means"]


# ----------------------------------------------------------------------------- how a demonstration is recognised


def test_demo_setup_writes_an_explicit_marker_that_the_portal_reads(tmp_path):
    demo = create(tmp_path / "demo")
    assert json.loads((demo / "portal-config.json").read_text())["demonstration"] is True
    assert read_settings(demo / "portal-config.json").demonstration is True
    assert load_portal(demo / "portal-config.json").demonstration is True


def test_the_marker_alone_makes_any_trust_list_a_demonstration(tmp_path):
    root = make_synthetic_portal(tmp_path / "own")
    assert load_portal(root / "portal-config.json").demonstration is False
    _edit(root / "portal-config.json", demonstration=True)
    assert load_portal(root / "portal-config.json").demonstration is True


def test_without_the_marker_a_demo_setup_trust_list_is_still_caught_by_its_names(tmp_path):
    demo = create(tmp_path / "demo")
    data = json.loads((demo / "portal-config.json").read_text())
    data.pop("demonstration")
    (demo / "portal-config.json").write_text(json.dumps(data))
    assert load_portal(demo / "portal-config.json").demonstration is True
    assert (
        client_for(demo / "portal-config.json").get("/api/status").json()["state"]
        == "demonstration"
    )


def test_a_marker_set_to_false_cannot_switch_the_detection_off(tmp_path):
    demo = create(tmp_path / "demo")
    _edit(demo / "portal-config.json", demonstration=False)
    assert load_portal(demo / "portal-config.json").demonstration is True


@pytest.mark.parametrize("value", ["yes", 1, None, "true"])
def test_the_marker_must_be_true_or_false(tmp_path, value):
    root = make_synthetic_portal(tmp_path / "own")
    _edit(root / "portal-config.json", demonstration=value)
    with pytest.raises(ConfigProblem, match="demonstration must be true or false"):
        load_portal(root / "portal-config.json")


def test_a_bundled_demonstration_key_in_an_unmarked_configuration_is_caught_by_its_fingerprint(
    tmp_path,
):
    """Copied into an administrator's own trust list, under another name and key id."""
    root = make_synthetic_portal(tmp_path / "own")
    store_path = root / "trust-store.json"
    store = json.loads(store_path.read_text())
    pem = json.loads((SAMPLES / "demo-trust-list.json").read_text())["entries"][
        "demo-only-synthetic-key"
    ]["public_key_pem"]
    store["entries"]["acme-1"] = {"issuer": "Acme Ltd", "public_key_pem": pem, "status": "active"}
    store_path.write_text(json.dumps(store))
    assert load_portal(root / "portal-config.json").demonstration is True
    body = (
        client_for(root / "portal-config.json")
        .post(
            "/api/verify",
            content=(SAMPLES / "reports" / "trusted.json").read_bytes(),
            headers=JSON_HEADERS,
        )
        .json()
    )
    assert body["synthetic_demonstration"] is True


def test_renaming_a_demo_setup_key_to_escape_the_label_makes_it_verify_nothing(tmp_path):
    """Its reports name the old issuer and key id inside the signature, and its private key was thrown away."""
    demo = create(tmp_path / "demo")
    config = _edit(demo / "portal-config.json", demonstration=False)
    data = json.loads(config.read_text())
    data.pop("demonstration")
    config.write_text(json.dumps(data))
    store_path = demo / "trust-store.json"
    store = json.loads(store_path.read_text())
    entry = store["entries"].pop("synthetic-issuer-key")
    entry["issuer"] = "Acme Ltd"
    store["entries"]["acme-1"] = entry
    store_path.write_text(json.dumps(store))
    assert load_portal(config).demonstration is False  # the label is gone ...
    client = client_for(config)
    for name in ("1-trusted.json", "7-declares-encrypted-backend.json"):
        body = post(client, demo, name).json()
        assert (
            body["verification"]["trust_status"] == "INVALID"
        )  # ... and so is anything it could vouch for


# ----------------------------------------------------------------------------- the terminal and the setup page


def test_check_config_refuses_a_demonstration_for_your_own_reports(tmp_path):
    demo = create(tmp_path / "demo")
    done = subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-m", "regaudit_portal", "check-config", "--config", str(demo / "portal-config.json")],
        env={**os.environ, "PYTHONPATH": str(PORTAL)}, capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert done.returncode == 3 and done.stdout == ""
    assert done.stderr.startswith(
        "not usable for your own reports: the trust list is a demonstration"
    )


def test_the_terminal_and_the_launcher_line_say_demonstration():
    said = started_message("demonstration", 8765)
    assert "The trust list is a demonstration" in said and "only as a demonstration" in said


def test_the_setup_page_says_what_the_portal_does_with_a_demonstration_trust_list(tmp_path):
    demo = create(tmp_path / "demo")
    body = client_for(demo / "portal-config.json").get("/api/setup").json()
    row = next(r for r in body["rows"] if r["id"] == "trust_list")
    assert row["state"] == "demonstration" and "only as a demonstration" in row["detail"]
    assert body["own_reports"]["ready"] is False and body["own_reports"]["state"] == "demonstration"
    assert (
        "demonstration trust list" in body["own_reports"]["message"]
        and body["trust_configured"] is False
    )
