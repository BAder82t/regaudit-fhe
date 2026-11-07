"""Demonstration trust is kept apart from customer trust, and every demonstration result says so in exactly one way.

The mode comes from the configuration the portal was started with: ``"trust_mode": "demonstration"`` (demo-setup writes
it). A trust list that holds one of the bundled demonstration keys, recognised by exact fingerprint, is refused without
that setting (see test_demonstration_key.py). No name or key id decides it. The engine and its verdicts are unchanged:
only the portal's labels and readiness differ.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import JSON_HEADERS, client_for, make_synthetic_portal, post, signed_report
from regaudit_portal.__main__ import started_message
from regaudit_portal.config import ConfigProblem, load_portal, read_settings
from regaudit_portal.demo import create
from regaudit_portal.explain import DEMONSTRATION_LABEL, DEMONSTRATION_TRUST_NOTICE


PORTAL = Path(__file__).resolve().parents[1]
STATIC = PORTAL / "regaudit_portal" / "static"
SAMPLES = PORTAL / "regaudit_portal" / "samples"
LABEL = "DEMONSTRATION — NOT CUSTOMER-TRUSTED"
ADMINISTRATOR_WORDS = (
    "an issuer your administrator approved",
    "configured trust rules",
    "your administrator",
)


def _edit(config: Path, **change) -> Path:
    data = json.loads(config.read_text())
    for key, value in change.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    config.write_text(json.dumps(data))
    os.chmod(config, 0o600)
    return config


# ----------------------------------------------------------------------------- the one label, exactly


def test_the_label_is_exactly_the_agreed_text():
    assert DEMONSTRATION_LABEL == LABEL


def test_every_demonstration_result_carries_the_label_in_its_members_and_its_notice_block(tmp_path):
    demo = create(tmp_path / "demo")
    client = client_for(demo / "portal-config.json")
    for body in (
        post(client, demo, "1-trusted.json").json(),  # a file checked against demonstration trust
        post(client, demo, "2-untrusted-signer.json").json(),
        client.post("/api/samples/trusted/verify").json(),  # a bundled sample
    ):
        assert body["demonstration_label"] == LABEL
        assert body["demonstration"]["label"] == LABEL
        assert body["synthetic_demonstration"] is True and body["trust_mode"] == "demonstration"


def test_a_sample_checked_in_a_customer_portal_is_labelled_too(client):
    body = client.post("/api/samples/trusted/verify").json()
    assert body["demonstration_label"] == LABEL and body["demonstration"]["label"] == LABEL


def test_the_verdict_and_reason_codes_are_the_engines_own_and_shown_next_to_the_label(tmp_path):
    demo = create(tmp_path / "demo")
    client = client_for(demo / "portal-config.json")
    good = post(client, demo, "1-trusted.json").json()
    assert (
        good["verification"]["trust_status"] == "TRUSTED"
        and good["verification"]["accepted"] is True
    )
    bad = post(client, demo, "3-changed-after-signing.json").json()
    assert bad["verification"]["trust_status"] == "INVALID"
    assert "HASH_MISMATCH" in bad["verification"]["blocking_reasons"]
    assert [r["code"] for r in bad["explanation"]["reasons"]] == [
        *bad["verification"]["blocking_reasons"],
        *[
            c
            for c in bad["verification"]["reasons"]
            if c not in bad["verification"]["blocking_reasons"]
        ],
    ]
    script = (STATIC / "app.js").read_text()
    html = (STATIC / "index.html").read_text()
    assert (
        '<p id="verdict" class="verdict"></p>\n      <p id="demo-label" class="demo-label" hidden></p>'
        in html
    )
    assert "verdict.textContent = v.trust_status;" in script
    assert '$("demo-label").textContent = demonstration ? body.demonstration_label : "";' in script


def test_the_banner_shows_the_label_from_the_portal_and_the_style_adds_no_other_wording():
    script = (STATIC / "app.js").read_text()
    assert "label.textContent = body.demonstration.label;" in script
    assert (
        'banner.append(label, document.createElement("br"), body.demonstration.notice);' in script
    )
    css = (STATIC / "app.css").read_text()
    assert "DEMONSTRATION" not in css and 'content: "DEMONSTRATION' not in css


def test_the_saved_file_carries_the_label_inside_it_and_not_only_in_its_name(tmp_path):
    """The page saves the result as it came, so the label members are inside the file."""
    demo = create(tmp_path / "demo")
    body = post(client_for(demo / "portal-config.json"), demo, "1-trusted.json").json()
    saved = {"report_file_name": "1-trusted.json", **body}  # what the page's download writes
    text = json.dumps(saved, indent=2)
    assert (
        json.loads(text)["demonstration_label"] == LABEL
        and LABEL in json.loads(text)["demonstration"]["label"]
    )
    script = (STATIC / "app.js").read_text()
    assert (
        "const saved = Object.assign({ report_file_name: lastSaved.name }, lastSaved.body);"
        in script
    )
    assert (
        'const kind = lastSaved.body.synthetic_demonstration === true ? "demonstration-result-" : "verification-result-";'
        in script
    )


def test_the_status_and_the_setup_page_show_the_label_in_demonstration_mode(tmp_path):
    demo = create(tmp_path / "demo")
    client = client_for(demo / "portal-config.json")
    for body in (client.get("/api/status").json(), client.get("/api/setup").json()):
        assert body["trust_mode"] == "demonstration" and body["demonstration_label"] == LABEL
        assert LABEL in body["trust_mode_text"]


# ----------------------------------------------------------------------------- what a reviewer saw


def test_a_demo_setup_configuration_is_never_ready_and_every_result_is_a_labelled_demonstration(
    tmp_path,
):
    demo = create(tmp_path / "demo")
    client = client_for(demo / "portal-config.json")
    assert client.app.state.ready is False and client.app.state.mode == "demonstration"
    status = client.get("/api/status").json()
    assert status["ready"] is False and status["state"] == "demonstration"
    assert "approved issuer" not in json.dumps(status) and "policy_id" not in status
    body = post(client, demo, "1-trusted.json").json()
    assert body["demonstration"]["notice"] == DEMONSTRATION_TRUST_NOTICE
    explanation = body["explanation"]
    assert explanation["warnings"][0] == {
        "code": "DEMONSTRATION_ONLY",
        "message": DEMONSTRATION_TRUST_NOTICE,
    }
    shown = json.dumps({k: v for k, v in explanation.items() if k != "display"})
    for words in ADMINISTRATOR_WORDS:
        assert words not in shown, words


def test_an_administrators_own_configuration_is_customer_trust_and_never_labelled(client, demo):
    status = client.get("/api/status").json()
    assert (
        status["ready"] is True
        and status["trust_mode"] == "customer"
        and "demonstration_label" not in status
    )
    body = post(client, demo, "1-trusted.json").json()
    assert body["synthetic_demonstration"] is False and body["trust_mode"] == "customer"
    assert (
        "demonstration" not in body
        and "demonstration_label" not in body
        and LABEL not in json.dumps(body)
    )


@pytest.mark.parametrize(
    "issuer, key_id",
    [
        ("Demo Analytics Ltd", "demo-2026"),
        ("Synthetic Data Works", "synthetic-issuer-key"),
        ("DEMO-ONLY synthetic issuer", "demo-only-synthetic-key"),
    ],
)
def test_a_legitimate_issuer_whose_name_or_key_id_says_demo_or_synthetic_is_never_labelled(
    tmp_path, issuer, key_id
):
    from helpers import make_portal

    config, signer = make_portal(tmp_path / "own", issuer=issuer, key_id=key_id)
    assert load_portal(config).trust_mode == "customer"
    client = client_for(config)
    assert client.get("/api/status").json()["trust_mode"] == "customer"
    body = client.post("/api/verify", content=signed_report(signer), headers=JSON_HEADERS).json()
    assert body["verification"]["trust_status"] == "TRUSTED"
    assert body["synthetic_demonstration"] is False and "demonstration_label" not in body


# ----------------------------------------------------------------------------- how the mode is decided


def test_demo_setup_writes_the_explicit_mode_that_the_portal_reads(tmp_path):
    demo = create(tmp_path / "demo")
    assert json.loads((demo / "portal-config.json").read_text())["trust_mode"] == "demonstration"
    assert read_settings(demo / "portal-config.json").trust_mode == "demonstration"
    portal = load_portal(demo / "portal-config.json")
    assert portal.trust_mode == "demonstration" and "trust_mode" in portal.trust_mode_reason


def test_the_mode_setting_alone_makes_any_trust_list_a_demonstration(tmp_path):
    root = make_synthetic_portal(tmp_path / "own")
    assert load_portal(root / "portal-config.json").trust_mode == "customer"
    _edit(root / "portal-config.json", trust_mode="demonstration")
    assert load_portal(root / "portal-config.json").trust_mode == "demonstration"


@pytest.mark.parametrize("setting", [None, "customer"])
def test_a_bundled_demonstration_key_without_the_demonstration_setting_is_refused_not_labelled(
    tmp_path, setting
):
    """A missing or "customer" setting cannot switch the fingerprint rule off: the configuration is refused."""
    root = create(tmp_path / "demo")
    _edit(root / "portal-config.json", trust_mode=setting)
    with pytest.raises(ConfigProblem, match="bundled demonstration key") as caught:
        load_portal(root / "portal-config.json")
    assert caught.value.kind == "demonstration_key"
    client = client_for(root / "portal-config.json")
    response = post(client, root, "1-trusted.json")
    assert response.status_code == 503 and "verification" not in response.json()
    assert LABEL not in json.dumps(response.json())


@pytest.mark.parametrize("value", ["yes", 1, True, "Demonstration", "demo", ""])
def test_the_mode_setting_is_customer_or_demonstration_and_nothing_else(tmp_path, value):
    root = make_synthetic_portal(tmp_path / "own")
    _edit(root / "portal-config.json", trust_mode=value)
    with pytest.raises(ConfigProblem, match="trust_mode must be"):
        load_portal(root / "portal-config.json")


def test_an_old_demo_folder_copied_without_its_setting_cannot_be_recognised(tmp_path):
    """The known limit, now only for folders made by the earlier demo-setup: their keys were made fresh and no name
    rule exists, so a copy of such a trust list under a configuration without the setting is customer trust, and its
    own sample reports verify as customer TRUSTED. The setting is the only control for those keys. The current
    demo-setup installs the bundled key instead, which is refused without the setting."""
    old = make_synthetic_portal(tmp_path / "old", trust_mode="demonstration")
    assert load_portal(old / "portal-config.json").trust_mode == "demonstration"
    _edit(old / "portal-config.json", trust_mode=None)
    portal = load_portal(old / "portal-config.json")
    assert portal.trust_mode == "customer"
    body = post(client_for(old / "portal-config.json"), old, "1-trusted.json").json()
    assert (
        body["verification"]["trust_status"] == "TRUSTED"
        and body["synthetic_demonstration"] is False
    )


# ----------------------------------------------------------------------------- the mode is chosen only by configuration


def test_the_mode_follows_the_configuration_given_at_start_and_nothing_a_request_sends(
    tmp_path, monkeypatch
):
    demo = create(tmp_path / "demo")
    own = make_synthetic_portal(tmp_path / "own")
    demonstration_client = client_for(demo / "portal-config.json")
    customer_client = client_for(own / "portal-config.json")
    attempts = [
        ("GET", "/api/status?trust_mode=customer", {}),
        ("GET", "/api/status", {"X-Trust-Mode": "customer"}),
        ("POST", "/api/status", {}),
        ("POST", "/api/mode", {}),
        ("PUT", "/api/setup", {}),
    ]
    for client, expected in (
        (demonstration_client, "demonstration"),
        (customer_client, "customer"),
    ):
        for method, path, headers in attempts:
            client.request(method, path, headers=headers, content=b'{"trust_mode": "customer"}')
        post(client, demo, "1-trusted.json")  # a report cannot change it either
        assert client.get("/api/status").json()["trust_mode"] == expected
    route_text = " ".join(route.path for route in demonstration_client.app.routes)
    assert "mode" not in route_text


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


def test_the_terminal_says_demonstration_and_the_pages_show_the_mode():
    said = started_message("demonstration", 8765)
    assert "The trust list is a demonstration" in said and "only as a demonstration" in said
    for page, script in (("index.html", "app.js"), ("setup.html", "setup.js")):
        assert (
            '<p id="trust-mode" class="statement" role="status"></p>' in (STATIC / page).read_text()
        )
        assert (
            '$("trust-mode").textContent = body.trust_mode_text || "";'
            in (STATIC / script).read_text()
        )


def test_the_setup_page_says_why_it_is_demonstration_trust(tmp_path):
    demo = create(tmp_path / "demo")
    body = client_for(demo / "portal-config.json").get("/api/setup").json()
    row = next(r for r in body["rows"] if r["id"] == "trust_list")
    assert row["state"] == "demonstration" and '"trust_mode": "demonstration"' in row["detail"]
    assert "only as a demonstration" in row["detail"]
    assert body["own_reports"]["ready"] is False and body["trust_configured"] is False


def test_welcome_mode_says_no_trust_is_set_up(tmp_path, monkeypatch):
    from helpers import fake_home

    fake_home(tmp_path, monkeypatch)
    status = client_for(None).get("/api/status").json()
    assert status["trust_mode"] == "none" and LABEL in status["trust_mode_text"]


def test_the_setup_page_state_for_a_demonstration_trust_row_is_the_label_itself():
    script = (STATIC / "setup.js").read_text()
    assert f'demonstration: "{LABEL}"' in script
    assert "Demonstration only" not in script
