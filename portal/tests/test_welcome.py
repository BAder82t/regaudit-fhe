"""The welcome flow: serve without a configuration, the standard per-user location, and what a launcher can rely on."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest
import regaudit_portal.app as portal_app
import regaudit_portal.engine as engine_module
from helpers import client_for, fake_home, install_configuration, post, snapshot
from regaudit_portal.__main__ import _bind_loopback, listening_line
from regaudit_portal.paths import default_config_folder, default_config_path
from test_fallback import STATUS, Running, _damaged_copy, ask

PORTAL = Path(__file__).parents[1]
STATIC = PORTAL / "regaudit_portal" / "static"
LISTENING = re.compile(r"^portal-listening url=http://127\.0\.0\.1:(\d+)/ mode=([a-z-]+)$")
NOT_SET_UP = "Verification of your own reports is not set up yet. An administrator has to set up trust first."
NEEDS_ATTENTION = (
    "This portal cannot check reports right now, because its setup needs attention. Contact your administrator. "
    "No report can be checked until then."
)


def _crashes(_folder):
    raise RuntimeError("the hash could not be computed")


def mode_of(running: Running) -> str:
    lines = [LISTENING.match(line) for line in running.lines]
    found = [m for m in lines if m]
    assert len(found) == 1, running.lines
    assert int(found[0].group(1)) == running.port
    return found[0].group(2)


def call(running: Running, method: str, path: str, **kwargs):
    status, headers, body = ask(running.port, method, path, **kwargs)
    return status, json.loads(body) if body and headers.get("content-type", "").startswith(
        "application/json"
    ) else body


def upload(running: Running, raw: bytes):
    return call(
        running, "POST", "/api/verify", body=raw, headers={"Content-Type": "application/json"}
    )


# ----------------------------------------------------------------------------- where the configuration is looked for


def test_the_standard_location_is_per_user_and_depends_on_the_system(tmp_path, monkeypatch):
    home = fake_home(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "platform", "darwin")
    mac = (
        home
        / "Library"
        / "Application Support"
        / "Evidence Verification Portal"
        / "portal-config.json"
    )
    assert default_config_path() == mac and default_config_folder() == mac.parent
    monkeypatch.setattr(sys, "platform", "linux")
    assert (
        default_config_path()
        == home / ".config" / "evidence-verification-portal" / "portal-config.json"
    )


def test_looking_for_the_standard_location_creates_nothing(tmp_path, monkeypatch):
    home = fake_home(tmp_path, monkeypatch)
    before = snapshot(home)
    default_config_path()
    default_config_folder()
    assert snapshot(home) == before


def test_a_launcher_line_says_where_the_portal_is_and_in_which_mode():
    assert (
        listening_line(54321, "welcome")
        == "portal-listening url=http://127.0.0.1:54321/ mode=welcome"
    )
    for mode in ("ready", "welcome", "needs-attention", "unavailable"):
        match = LISTENING.match(listening_line(8765, mode))
        assert match and match.group(2) == mode


def test_the_portal_listens_on_this_computer_only_and_port_zero_takes_a_free_port():
    sock = _bind_loopback(0)
    try:
        host, port = sock.getsockname()
        assert host == "127.0.0.1" and port > 0
        other = _bind_loopback(0)
        assert other.getsockname()[1] != port
        other.close()
        with pytest.raises(OSError):
            _bind_loopback(port)  # taken
    finally:
        sock.close()


# ----------------------------------------------------------------------------- welcome mode, as a launcher would start it


def test_with_no_configuration_the_portal_starts_in_welcome_mode_and_creates_nothing(
    tmp_path, monkeypatch
):
    home = fake_home(tmp_path, monkeypatch)
    before = snapshot(home)
    with Running(tmp_path, ["serve"], env={"HOME": str(home)}) as running:
        assert mode_of(running) == "welcome"
        human = next(line for line in running.lines if line.startswith("open http"))
        assert (
            human.startswith(f"open http://127.0.0.1:{running.port} in a browser.")
            and "samples work" in human
        )
        status, body = call(running, "GET", "/api/status")
        assert status == 200 and body["ready"] is False and body["state"] == "not_set_up"
        assert body["message"] == NOT_SET_UP and len(body["samples"]) == 5
        refused = upload(
            running,
            (PORTAL / "regaudit_portal" / "samples" / "reports" / "trusted.json").read_bytes(),
        )
        assert (
            refused[0] == 503
            and refused[1]["error"] == "not_set_up"
            and "verification" not in refused[1]
        )
        sample = call(running, "POST", "/api/samples/trusted/verify")
        assert sample[0] == 200 and sample[1]["verification"]["trust_status"] == "TRUSTED"
        assert sample[1]["synthetic_demonstration"] is True
        assert call(running, "GET", "/api/setup")[0] == 200
    assert snapshot(home) == before and list(home.iterdir()) == []


def test_an_empty_standard_folder_is_welcome_mode_too_and_stays_empty(tmp_path, monkeypatch):
    home = fake_home(tmp_path, monkeypatch)
    default_config_folder().mkdir(parents=True)
    os.chmod(default_config_folder(), 0o700)
    before = snapshot(home)
    with Running(tmp_path, ["serve"], env={"HOME": str(home)}) as running:
        assert mode_of(running) == "welcome"
    assert snapshot(home) == before


def test_a_configuration_in_the_standard_place_is_used_exactly_as_it_would_be_with_config(
    tmp_path, monkeypatch, demo
):
    home = fake_home(tmp_path, monkeypatch)
    install_configuration(demo, default_config_folder())
    raw = (demo / "sample-reports" / "1-trusted.json").read_bytes()
    with Running(tmp_path, ["serve"], env={"HOME": str(home)}) as running:
        assert mode_of(running) == "ready"
        body = call(running, "GET", "/api/status")[1]
        assert body["ready"] is True and body["state"] == "ready" and "message" not in body
        verdict = upload(running, raw)
        assert verdict[0] == 200 and verdict[1]["verification"]["trust_status"] == "TRUSTED"
        assert verdict[1]["synthetic_demonstration"] is False
        assert (
            call(running, "POST", "/api/samples/trusted/verify")[1]["synthetic_demonstration"]
            is True
        )


def test_a_standard_configuration_that_cannot_be_used_refuses_your_own_reports_and_keeps_the_samples(
    tmp_path, monkeypatch, demo
):
    home = fake_home(tmp_path, monkeypatch)
    config = install_configuration(demo, default_config_folder())
    config.write_text("{")
    os.chmod(config, 0o600)
    with Running(tmp_path, ["serve"], env={"HOME": str(home)}) as running:
        assert mode_of(running) == "needs-attention"
        body = call(running, "GET", "/api/status")[1]
        assert (
            body["ready"] is False
            and body["state"] == "needs_attention"
            and body["message"] == NEEDS_ATTENTION
        )
        refused = upload(running, (demo / "sample-reports" / "1-trusted.json").read_bytes())
        assert (
            refused[0] == 503
            and refused[1]["error"] == "not_ready"
            and "verification" not in refused[1]
        )
        assert refused[1]["message"] == NEEDS_ATTENTION
        assert call(running, "POST", "/api/samples/trusted/verify")[0] == 200
        setup = call(running, "GET", "/api/setup")[1]
        assert {r["id"]: r["state"] for r in setup["rows"]}["configuration"] == "problem"
        assert str(home) not in json.dumps(setup)


def test_a_standard_folder_others_can_change_is_refused_like_any_other(tmp_path, monkeypatch, demo):
    home = fake_home(tmp_path, monkeypatch)
    install_configuration(demo, default_config_folder(), mode=0o777)
    with Running(tmp_path, ["serve"], env={"HOME": str(home)}) as running:
        assert mode_of(running) == "needs-attention"
        assert upload(running, b"{}")[0] == 503
        rows = {r["id"]: r["state"] for r in call(running, "GET", "/api/setup")[1]["rows"]}
        assert rows["file_check"] == "problem"


def test_config_still_overrides_the_standard_location(tmp_path, monkeypatch, demo):
    home = fake_home(tmp_path, monkeypatch)
    broken = install_configuration(demo, default_config_folder())
    broken.write_text("{")
    os.chmod(broken, 0o600)
    with Running(
        tmp_path, ["serve", "--config", str(demo / "portal-config.json")], env={"HOME": str(home)}
    ) as running:
        assert mode_of(running) == "ready"
        assert call(running, "GET", "/api/status")[1]["ready"] is True


def test_port_zero_picks_a_free_port_and_the_launcher_line_gives_the_real_one(
    tmp_path, monkeypatch
):
    home = fake_home(tmp_path, monkeypatch)
    with Running(tmp_path, ["serve"], env={"HOME": str(home)}, port=0) as running:
        assert running.port > 0 and mode_of(running) == "welcome"
        assert any(
            line.startswith(f"open http://127.0.0.1:{running.port} in a browser.")
            for line in running.lines
        )
        assert (
            call(running, "GET", "/api/status")[0] == 200
        )  # the host check was set up for the real port


def test_the_portal_is_not_reachable_from_another_address_of_this_computer(tmp_path, monkeypatch):
    home = fake_home(tmp_path, monkeypatch)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(
            ("192.0.2.1", 9)
        )  # a documentation address: nothing is sent, it only picks the outgoing interface
        outgoing = probe.getsockname()[0]
    with Running(tmp_path, ["serve"], env={"HOME": str(home)}) as running:
        assert call(running, "GET", "/api/status")[0] == 200
        if not outgoing.startswith("127."):
            with (
                pytest.raises(OSError),
                socket.create_connection((outgoing, running.port), timeout=5),
            ):
                pass


def test_check_config_without_config_uses_the_standard_location_and_says_when_there_is_none(
    tmp_path, monkeypatch, demo
):
    home = fake_home(tmp_path, monkeypatch)
    env = dict(os.environ, HOME=str(home), PYTHONPATH=str(PORTAL))
    run = lambda: subprocess.run(  # noqa: E731
        [sys.executable, "-m", "regaudit_portal", "check-config"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
        cwd=tmp_path,
    )
    absent = run()
    assert (
        absent.returncode == 3
        and "there is no configuration at ~/" in absent.stderr
        and str(home) not in absent.stderr
    )
    assert snapshot(home) == snapshot(home) and list(home.iterdir()) == []
    install_configuration(demo, default_config_folder())
    present = run()
    assert present.returncode == 0 and present.stdout.startswith("usable: ")


# ----------------------------------------------------------------------------- the same app in process


def test_welcome_mode_in_process_states_what_is_and_is_not_available(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    client = client_for(None)
    assert client.app.state.mode == "welcome" and client.app.state.ready is False
    body = client.get("/api/status").json()
    assert (
        body["state"] == "not_set_up" and body["message"] == NOT_SET_UP and body["ready"] is False
    )
    assert body["samples"][0]["id"] == "trusted"


def test_a_configuration_that_cannot_be_used_is_needs_attention_in_process(
    tmp_path, monkeypatch, demo
):
    fake_home(tmp_path, monkeypatch)
    (demo / "trust-store.json").unlink()
    client = client_for(demo / "portal-config.json")
    assert client.app.state.mode == "needs-attention"
    assert client.get("/api/status").json()["state"] == "needs_attention"
    assert client.post("/api/samples/trusted/verify").status_code == 200


def test_with_the_engine_refused_welcome_mode_gives_no_sample_verdict_either(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    client = client_for(None)
    assert client.post("/api/samples/trusted/verify").status_code == 200
    monkeypatch.setattr(engine_module, "files_digest", _crashes)
    assert client.get("/api/status").json() == {"ready": False, "state": "unavailable"}
    refused = client.post("/api/samples/trusted/verify")
    assert (
        refused.status_code == 503
        and refused.json()["state"] == "unavailable"
        and "verification" not in refused.json()
    )


def test_the_samples_stop_if_the_engine_changes_while_one_is_being_checked(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    real = portal_app.verify

    def verify_then_break(*args, **kwargs):
        result = real(*args, **kwargs)
        monkeypatch.setattr(engine_module, "files_digest", _crashes)
        return result

    monkeypatch.setattr(portal_app, "verify", verify_then_break)
    refused = client_for(None).post("/api/samples/trusted/verify")
    assert refused.status_code == 503 and "verification" not in refused.json()


# ----------------------------------------------------------------------------- the strict engine rule holds in both modes


@pytest.mark.parametrize("configured", [False, True], ids=["welcome-mode", "configured"])
def test_a_refused_engine_gives_only_the_unavailable_page_whatever_the_mode(
    tmp_path, monkeypatch, demo, configured
):
    home = fake_home(tmp_path, monkeypatch)
    _damaged_copy(tmp_path, "modified")
    args = ["serve", "--config", str(demo / "portal-config.json")] if configured else ["serve"]
    with Running(tmp_path, args, path_first=tmp_path, env={"HOME": str(home)}) as running:
        assert mode_of(running) == "unavailable"
        status, _, page = ask(running.port, "GET", "/")
        assert status == 200 and b"Verification unavailable" in page
        for choice in (b"Try a sample report", b"Verify your own report", b"Administrator setup"):
            assert choice not in page
        assert ask(running.port, "GET", "/api/status")[2] == STATUS
        sample = ask(running.port, "POST", "/api/samples/trusted/verify")
        assert sample[0] == 503 and json.loads(sample[2]) == {
            "error": "unavailable",
            "state": "unavailable",
        }
        assert ask(running.port, "POST", "/api/verify", body=b"{}")[0] == 503
        for path in ("/setup", "/api/setup", "/static/setup.js"):
            assert ask(running.port, "GET", path)[0] == 404, path
        everything = page + sample[2] + ask(running.port, "GET", "/api/status")[2]
        for place in (str(tmp_path).encode(), str(home).encode(), b"~/", b"Library", b".config"):
            assert place not in everything, place


# ----------------------------------------------------------------------------- the page offers only what can work


def test_the_start_page_offers_three_choices_and_the_third_is_the_setup_page():
    html = (STATIC / "index.html").read_text()
    welcome = html[
        html.index('<section id="welcome"') : html.index(
            "</section>", html.index('<section id="welcome"')
        )
    ]
    assert welcome.count('class="choice"') == 3
    for label in ("Try a sample report", "Verify your own report", "Administrator setup"):
        assert f"<strong>{label}</strong>" in welcome
    assert (
        'id="choose-samples"' in welcome
        and 'id="choose-own"' in welcome
        and 'id="choose-setup" href="/setup"' in welcome
    )
    assert "<form" not in html and "<input" in html and html.count('type="file"') == 1


def test_the_page_does_not_offer_an_upload_that_cannot_work():
    script = (STATIC / "app.js").read_text()
    assert 'const view = name === "own" ? (ownReady ? "upload" : "not-ready") : name;' in script
    assert "ownReady = body.ready === true;" in script
    html = (STATIC / "index.html").read_text()
    assert (
        '<section id="upload" class="panel" hidden>' in html
        and '<section id="not-ready" class="panel notice" hidden>' in html
    )
    assert (
        '<p><a href="/setup">Administrator setup</a></p>'
        in html[html.index('<section id="not-ready"') :]
    )
    assert 'show("upload", true)' not in script, (
        "the upload is shown only through the one place that checks it can work"
    )


def test_a_sample_is_chosen_from_a_list_and_nothing_is_sent_with_the_request():
    script = (STATIC / "app.js").read_text()
    check = script[
        script.index("async function checkSample") : script.index("function listSamples")
    ]
    assert (
        'fetch("/api/samples/" + encodeURIComponent(sample.id) + "/verify", { method: "POST" })'
        in check
    )
    assert "headers:" not in check and "FormData" not in check and "arrayBuffer" not in check
    assert "chosen" not in check, "no file the person picked is involved"
    assert "listSamples(body.samples || [])" in script
    html = (STATIC / "index.html").read_text()
    samples = html[
        html.index('<section id="samples"') : html.index(
            "</section>", html.index('<section id="samples"')
        )
    ]
    assert "<input" not in samples and 'type="file"' not in samples
    assert "synthetic demonstration reports" in samples and "pick one from the list" in samples


def test_the_welcome_page_still_carries_both_permanent_warnings(client):
    page = client.get("/").text
    assert (
        "Signature verification does not verify that any FHE (encrypted) computation was executed."
        in page
    )
    assert page.count("Read the full limitation") == 2
    assert "http://" not in page and "https://" not in page


def test_an_uploaded_file_and_a_sample_never_share_an_endpoint(client, demo):
    assert post(client, demo, "1-trusted.json").status_code == 200
    assert (
        client.post(
            "/api/samples/trusted/verify",
            content=(demo / "sample-reports" / "1-trusted.json").read_bytes(),
        ).json()["report_sha256"]
        != post(client, demo, "1-trusted.json").json()["report_sha256"]
    )
