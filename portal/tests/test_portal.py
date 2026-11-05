"""The acceptance list: each kind of upload, each kind of broken configuration, and that nothing softens a verdict."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import (
    JSON_HEADERS,
    backend_verdict,
    client_for,
    make_portal,
    not_ready,
    post,
    post_bytes,
    rewrite,
    signed_report,
)
from regaudit_portal.__main__ import portal_command, started_message
from regaudit_portal.app import MAX_REPORT_BYTES
from regaudit_portal.config import ConfigProblem, approved_entries, load_portal
from regaudit_portal.demo import create
from regaudit_portal.explain import _REASONS, describe

PORTAL_FOLDER = Path(__file__).parents[1]


def cli_verdict(demo: Path, name: str) -> dict:
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            sys.executable, "-m", "regaudit_fhe.cli", "verify", "-i", f"sample-reports/{name}",
            "--trusted-keys", "trust-store.json", "--profile", "confidential", "--max-age-seconds", str(30 * 86400),
            "--replay-mode", "check", "--replay-db", "cli-replay.db", "--verifier-id", "demo-verifier",
        ],
        cwd=demo, capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    return json.loads(out.stdout)


# ----------------------------------------------------------------------------- the five sample uploads


def test_a_trusted_report_is_trusted_and_still_carries_its_limits(client, demo):
    response = post(client, demo, "1-trusted.json")
    assert response.status_code == 200
    body = response.json()
    assert body["verification"]["trust_status"] == "TRUSTED"
    assert body["verification"]["accepted"] is True
    assert body["explanation"]["verdict"] == (
        "Signature and configured trust rules verified. This is not a regulatory certification and not proof of "
        "encrypted computation."
    )
    codes = {w["code"] for w in body["explanation"]["warnings"]}
    assert "REPLAY_NOT_RECORDED" in codes and "TIME_NOT_INDEPENDENT" in codes
    assert (
        "not a regulatory certification" in body["not_a_claim"]
        and "not proof of encrypted computation" in body["not_a_claim"]
    )


@pytest.mark.parametrize(
    "name",
    [
        "2-untrusted-signer.json",
        "3-valid-signature-wrong-issuer.json",
        "4-changed-after-signing.json",
    ],
)
def test_a_rejected_report_is_never_told_it_would_pass_again(client, demo, name):
    body = post(client, demo, name).json()
    text = json.dumps(body["explanation"])
    assert "would pass here again" not in text and "No durable local record" not in text
    assert "Do not rely on this report" in body["explanation"]["verdict"]
    assert body["explanation"]["reasons"], "the reason is still listed"


def test_a_refused_repeat_is_not_told_it_would_pass_again(demo):
    client = client_for(rewrite(demo, replay_mode="record"))
    post(client, demo, "1-trusted.json")
    body = post(client, demo, "1-trusted.json").json()
    assert body["verification"]["trust_status"] == "INVALID"
    assert "would pass here again" not in json.dumps(body["explanation"])
    assert "already been recorded" in body["explanation"]["verdict"]


def test_a_trusted_result_says_what_it_does_not_mean(client, demo):
    means = post(client, demo, "1-trusted.json").json()["explanation"]["means"]
    assert "does not mean the report's findings are correct" in means


def test_a_signer_nobody_enrolled_is_invalid_and_the_signature_is_called_unchecked_not_failed(
    client, demo
):
    """With a trust store, the verifier does not check a signature against a key it doesn't hold."""
    body = post(client, demo, "2-untrusted-signer.json").json()
    v = body["verification"]
    assert v["trust_status"] == "INVALID" and v["accepted"] is False
    assert v["integrity_valid"] is False and v["issuer_trusted"] is False
    assert (
        "ISSUER_UNKNOWN" in v["blocking_reasons"]
        and "SIGNATURE_INVALID" not in v["blocking_reasons"]
    )
    assert body["explanation"]["signature"].startswith("Not checked")
    assert "ISSUER_NOT_ASSURED" in {w["code"] for w in body["explanation"]["warnings"]}
    assert any(
        r["code"] == "ISSUER_UNKNOWN" and r["blocking"] for r in body["explanation"]["reasons"]
    )


def test_a_valid_signature_with_the_wrong_issuer_is_invalid_and_told_apart(client, demo):
    body = post(client, demo, "3-valid-signature-wrong-issuer.json").json()
    v = body["verification"]
    assert v["trust_status"] == "INVALID" and v["accepted"] is False
    assert v["integrity_valid"] is True and v["issuer_trusted"] is False
    assert "ISSUER_MISMATCH" in v["blocking_reasons"]
    assert body["explanation"]["signature"].startswith("Passed")
    assert body["explanation"]["issuer"].startswith("Failed")
    assert body["explanation"]["verdict"].startswith(
        "Not accepted. The report names a different issuer"
    )


def test_a_report_changed_after_signing_is_invalid_with_its_reason(client, demo):
    body = post(client, demo, "4-changed-after-signing.json").json()
    v = body["verification"]
    assert (
        v["trust_status"] == "INVALID" and v["accepted"] is False and v["integrity_valid"] is False
    )
    assert v["blocking_reasons"]
    assert body["explanation"]["signature"].startswith("Failed")
    assert body["explanation"]["issuer"].startswith("Not confirmed")
    assert body["explanation"]["means"] is None
    assert "verified" not in body["explanation"]["verdict"]


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not json",
        b"{",
        b"[]",
        b"null",
        b'{"hello": "x"}',
        b'{"a": 1, "a": 2}',
        b"\xff\xfe",
        b"[" * 5000,
    ],
    ids=[
        "empty",
        "text",
        "cut",
        "array",
        "null",
        "not-a-report",
        "duplicate-key",
        "not-utf8",
        "deep",
    ],
)
def test_a_malformed_upload_gets_no_verdict_and_echoes_nothing(client, content):
    response = client.post("/api/verify", content=content, headers=JSON_HEADERS)
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "not_a_report" and "verification" not in body
    assert "Traceback" not in response.text and "hello" not in response.text


def test_the_sample_that_is_not_a_report_gets_no_verdict(client, demo):
    assert post(client, demo, "5-not-a-report.json").status_code == 422


def test_a_large_upload_is_refused_by_its_declared_size(client, demo):
    response = post(client, demo, "6-too-large.json")
    assert response.status_code == 413 and "verification" not in response.json()


def test_a_large_upload_without_a_declared_size_is_refused(client):
    def chunks():
        for _ in range(3):
            yield b" " * MAX_REPORT_BYTES

    response = client.post("/api/verify", content=chunks(), headers=JSON_HEADERS)
    assert response.status_code == 413


def test_a_bad_declared_size_is_refused(client):
    response = client.post(
        "/api/verify", content=b"{}", headers={**JSON_HEADERS, "content-length": "-1"}
    )
    assert response.status_code in (400, 413)


# ----------------------------------------------------------------------------- the verdict is exactly the backend's


@pytest.mark.parametrize(
    "name",
    [
        "1-trusted.json",
        "2-untrusted-signer.json",
        "3-valid-signature-wrong-issuer.json",
        "4-changed-after-signing.json",
        "7-declares-encrypted-backend.json",
    ],
)
def test_the_result_is_exactly_what_the_verifier_returned(client, demo, name):
    shown = post(client, demo, name).json()["verification"]
    direct = backend_verdict(demo, name)
    assert shown == direct
    assert shown["trust_status"] == cli_verdict(demo, name)["trust_status"]


@pytest.mark.parametrize("status", ["TRUSTED", "SELF_SIGNED_ONLY", "INVALID", "SOMETHING_NEW"])
def test_only_trusted_is_ever_described_as_verified(status):
    result = {
        "trust_status": status, "blocking_reasons": [], "reasons": [], "consumption": "NOT_CHECKED",
        "replay_durable": None, "issuer_trusted": False, "chronology": "NONE", "trust_history": "UNPROVEN",
        "integrity_valid": True,
    }  # fmt: skip
    verdict = describe(result, "confidential")["verdict"]
    assert ("verified" in verdict) is (status == "TRUSTED")
    assert (
        status == "TRUSTED"
        or "not accepted" in verdict.lower()
        or "not one this portal knows" in verdict
    )


def _codes_the_verifier_can_emit() -> set[str]:
    """Every string handed to the verifier's ``block`` or ``note``, found in its source.

    A call is either ``block("X")`` or ``(note if development else block)("X")``.
    """
    import ast
    import inspect

    import regaudit_fhe.verification as module

    def is_emitter(func: ast.expr) -> bool:
        if isinstance(func, ast.Name):
            return func.id in ("block", "note")
        return isinstance(func, ast.IfExp) and is_emitter(func.body) and is_emitter(func.orelse)

    return {
        node.args[0].value
        for node in ast.walk(ast.parse(inspect.getsource(module)))
        if isinstance(node, ast.Call)
        and is_emitter(node.func)
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }


def test_every_reason_code_the_verifier_can_emit_has_plain_words():
    codes = _codes_the_verifier_can_emit()
    assert (
        len(codes) >= 30 and "LEGACY_V1_FORMAT" in codes
    )  # a code with a digit in it was once missed
    assert codes - set(_REASONS) == set()
    assert set(_REASONS) - codes == set(), "a line for a code the verifier no longer emits"
    assert all(len(words) > 20 for words in _REASONS.values())


def test_the_older_report_format_is_explained_without_changing_its_meaning():
    words = _REASONS["LEGACY_V1_FORMAT"]
    assert "older v1 format" in words and "issuer key, deployment or run" in words
    assert "accepted" not in words and "trusted" not in words


def test_a_code_with_no_words_is_still_shown():
    result = {
        "trust_status": "INVALID", "blocking_reasons": ["BRAND_NEW"], "reasons": ["BRAND_NEW", "OTHER"],
        "consumption": "NOT_CHECKED", "replay_durable": None, "issuer_trusted": False, "chronology": "NONE",
        "trust_history": "UNPROVEN", "integrity_valid": False,
    }  # fmt: skip
    reasons = describe(result, "confidential")["reasons"]
    assert [(r["code"], r["blocking"]) for r in reasons] == [("BRAND_NEW", True), ("OTHER", False)]


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"consumption": "CHECKED_NOT_CONSUMED"}, "REPLAY_NOT_RECORDED"),
        ({"replay_durable": False}, "REPLAY_NOT_DURABLE"),
        ({"replay_durable": None}, "REPLAY_NOT_DURABLE"),
        ({"issuer_trusted": False}, "ISSUER_NOT_ASSURED"),
        ({"chronology": "SIGNER_ASSERTED"}, "TIME_NOT_INDEPENDENT"),
        ({"trust_history": "UNPROVEN"}, "TRUST_LIST_FRESHNESS_UNPROVEN"),
    ],
)
def test_each_limit_produces_its_warning_even_when_trusted(change, code):
    clean = {
        "trust_status": "TRUSTED", "blocking_reasons": [], "reasons": [], "consumption": "RECORDED_LOCAL",
        "replay_durable": True, "issuer_trusted": True, "chronology": "AUTHENTICATED", "trust_history": "FRESH",
        "integrity_valid": True, "key_status": "active",
    }  # fmt: skip
    assert {w["code"] for w in describe(clean, "confidential")["warnings"]} == {"REPLAY_LOCAL_ONLY"}
    assert code in {w["code"] for w in describe({**clean, **change}, "confidential")["warnings"]}


# ----------------------------------------------------------------------------- administrator's configuration


def test_a_missing_configuration_gives_no_verdicts(demo):
    not_ready(demo / "absent.json", demo)


def test_a_missing_trust_store_gives_no_verdicts(demo):
    (demo / "trust-store.json").unlink()
    not_ready(demo / "portal-config.json", demo)


@pytest.mark.parametrize(
    "content",
    ["{", "[]", '{"entries": {}}', '{"keys": {}}', '{"nonsense": 1}'],
    ids=["cut", "array", "no-entries", "no-keys", "other"],
)
def test_an_invalid_trust_store_gives_no_verdicts(demo, content):
    (demo / "trust-store.json").write_text(content)
    not_ready(demo / "portal-config.json", demo)


def test_a_store_that_states_no_issuer_gives_no_verdicts(demo):
    store = json.loads((demo / "trust-store.json").read_text())
    key_id, entry = next(iter(store["entries"].items()))
    (demo / "trust-store.json").write_text(json.dumps({"keys": {key_id: entry["public_key_pem"]}}))
    not_ready(demo / "portal-config.json", demo)


@pytest.mark.parametrize(
    "change",
    [
        {"profile": "made-up"},
        {"profile": 1},
        {"max_age_days": 0},
        {"max_age_days": "30"},
        {"verifier_id": ""},
        {"replay_mode": "off"},
        {"surprise": True},
        {"allow_self_signed": True},
    ],
    ids=lambda c: next(iter(c)) + "-" + str(next(iter(c.values()))),
)
def test_an_invalid_policy_gives_no_verdicts(demo, change):
    not_ready(rewrite(demo, **change), demo)


@pytest.mark.parametrize("name", ["portal-config.json", "trust-store.json"])
@pytest.mark.parametrize("mode", [0o666, 0o660, 0o620], ids=oct)
def test_an_administrator_file_others_can_change_gives_no_verdicts(demo, name, mode):
    os.chmod(demo / name, mode)
    not_ready(demo / "portal-config.json", demo)
    assert stat.S_IMODE((demo / name).stat().st_mode) == mode


def test_a_directory_others_can_change_gives_no_verdicts(demo):
    os.chmod(demo, 0o777)  # noqa: S103 - the point of the test
    not_ready(demo / "portal-config.json", demo)


def test_a_symlinked_trust_store_gives_no_verdicts(demo):
    (demo / "real.json").write_bytes((demo / "trust-store.json").read_bytes())
    (demo / "trust-store.json").unlink()
    (demo / "trust-store.json").symlink_to(demo / "real.json")
    not_ready(demo / "portal-config.json", demo)


def test_a_replay_file_others_can_change_gives_no_verdicts(demo):
    load_portal(demo / "portal-config.json")
    os.chmod(demo / "replay.db", 0o666)  # noqa: S103 - the point of the test
    not_ready(demo / "portal-config.json", demo)


def test_a_new_replay_file_is_private(demo):
    load_portal(demo / "portal-config.json")
    assert stat.S_IMODE((demo / "replay.db").stat().st_mode) == 0o600


def test_a_read_only_store_works(demo):
    os.chmod(demo / "trust-store.json", 0o444)
    assert load_portal(demo / "portal-config.json").approved_count == 1


def test_the_command_line_check_says_why(demo):
    os.chmod(demo / "trust-store.json", 0o666)  # noqa: S103 - the point of the test
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1]))
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_portal", "check-config", "--config", str(demo / "portal-config.json")],
        capture_output=True, text=True, timeout=60, check=False, env=env,
    )  # fmt: skip
    assert out.returncode == 3 and "can be changed by group or others" in out.stderr


# ----------------------------------------------------------------------------- what the browser can reach


def test_the_browser_has_no_way_to_change_the_configuration(client, demo):
    before = (demo / "trust-store.json").read_bytes(), (demo / "portal-config.json").read_bytes()
    routes = {route.path for route in client.app.routes}
    assert routes == {
        "/",
        "/static/{name}",
        "/security",
        "/setup",
        "/api/setup",
        "/api/status",
        "/api/verify",
        "/api/samples/{sample_id}/verify",
    }
    for method, path in (
        ("post", "/api/status"),
        ("put", "/api/verify"),
        ("delete", "/api/verify"),
        ("post", "/"),
    ):
        assert getattr(client, method)(path).status_code == 405
    assert client.get("/docs").status_code == 404 and client.get("/openapi.json").status_code == 404
    assert before == (
        (demo / "trust-store.json").read_bytes(),
        (demo / "portal-config.json").read_bytes(),
    )


def test_status_does_not_reveal_paths_or_key_material(client, demo):
    text = client.get("/api/status").text
    assert str(demo) not in text and "PUBLIC KEY" not in text and "trust-store.json" not in text


def test_a_not_ready_page_does_not_reveal_why(demo):
    (demo / "trust-store.json").unlink()
    text = client_for(demo / "portal-config.json").get("/api/status").text
    assert str(demo) not in text and "trust-store.json" not in text


def test_uploads_are_not_kept(client, demo):
    before = {p for p in demo.rglob("*")}
    report = (demo / "sample-reports" / "1-trusted.json").read_bytes()
    assert client.post("/api/verify", content=report, headers=JSON_HEADERS).status_code == 200
    new = {p.name for p in demo.rglob("*")} - {p.name for p in before}
    assert new <= {"replay.db-journal"}
    assert report not in (demo / "replay.db").read_bytes()


def test_a_page_on_another_site_cannot_post(client, demo):
    report = (demo / "sample-reports" / "1-trusted.json").read_bytes()
    response = client.post(
        "/api/verify", content=report, headers={**JSON_HEADERS, "origin": "https://evil.example"}
    )
    assert response.status_code == 403


def test_a_form_post_is_refused(client, demo):
    report = (demo / "sample-reports" / "1-trusted.json").read_bytes()
    for kind in (
        "text/plain",
        "multipart/form-data; boundary=x",
        "application/x-www-form-urlencoded",
    ):
        assert (
            client.post("/api/verify", content=report, headers={"content-type": kind}).status_code
            == 415
        )


@pytest.mark.parametrize(
    "host", ["evil.example", "evil.example:8765", "127.0.0.1:9999", "0.0.0.0:8765"]
)
def test_a_name_rebound_to_this_address_is_refused(client, host):
    assert client.get("/api/status", headers={"host": host}).status_code == 403


def test_the_page_carries_a_strict_content_policy(client):
    headers = client.get("/").headers
    assert "default-src 'none'" in headers["content-security-policy"]
    assert "unsafe" not in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff" and headers["cache-control"] == "no-store"


def test_only_the_two_static_files_can_be_read(client):
    for name in ("app.js", "app.css"):
        assert client.get(f"/static/{name}").status_code == 200
    for name in ("index.html", "..%2Fconfig.py", "%2e%2e%2fapp.py"):
        assert client.get(f"/static/{name}").status_code == 404


def test_the_page_uses_no_outside_resources_and_no_html_injection():
    static = Path(__file__).parents[1] / "regaudit_portal" / "static"
    text = "".join((static / n).read_text() for n in ("index.html", "app.js", "app.css"))
    assert "http://" not in text and "https://" not in text
    assert "innerHTML" not in text and "eval(" not in text


def test_too_many_checks_are_refused(demo, monkeypatch):
    import regaudit_portal.app as module

    monkeypatch.setattr(module, "MAX_REQUESTS_PER_MINUTE", 2)
    client = client_for(demo / "portal-config.json")
    report = (demo / "sample-reports" / "1-trusted.json").read_bytes()
    codes = [
        client.post("/api/verify", content=report, headers=JSON_HEADERS).status_code
        for _ in range(4)
    ]
    assert codes[:2] == [200, 200] and codes[2:] == [429, 429]


def test_no_verdict_messages_say_to_treat_it_as_not_accepted(client, demo):
    for name in ("5-not-a-report.json", "6-too-large.json"):
        assert "treat it as not accepted" in post(client, demo, name).json()["message"]


def test_a_failure_inside_the_verifier_gives_no_verdict(demo, monkeypatch):
    import regaudit_portal.app as module

    def boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(module, "verify", boom)
    client = client_for(demo / "portal-config.json")
    report = (demo / "sample-reports" / "1-trusted.json").read_bytes()
    response = client.post("/api/verify", content=report, headers=JSON_HEADERS)
    assert (
        response.status_code == 503
        and "verification" not in response.json()
        and "boom" not in response.text
    )


def test_a_replay_store_that_breaks_is_invalid_not_trusted(demo):
    client = client_for(demo / "portal-config.json")
    (demo / "replay.db").write_bytes(b"not a database, longer than a header " * 10)
    body = post(client, demo, "1-trusted.json").json()
    assert body["verification"]["trust_status"] == "INVALID"
    assert "REPLAY_STATE_UNAVAILABLE" in body["verification"]["blocking_reasons"]


# ----------------------------------------------------------------------------- policy choices the administrator can make


def test_record_mode_refuses_a_repeat_and_says_why(demo):
    client = client_for(rewrite(demo, replay_mode="record"))
    first = post(client, demo, "1-trusted.json").json()
    assert first["verification"]["trust_status"] == "TRUSTED"
    assert "REPLAY_NOT_RECORDED" not in {w["code"] for w in first["explanation"]["warnings"]}
    second = post(client, demo, "1-trusted.json").json()
    assert second["verification"]["trust_status"] == "INVALID"
    assert "REPLAY_DETECTED" in second["verification"]["blocking_reasons"]


def test_the_development_profile_says_so_on_every_result(demo):
    client = client_for(rewrite(demo, profile="development"))
    body = post(client, demo, "1-trusted.json").json()
    assert "DEVELOPMENT_PROFILE" in {w["code"] for w in body["explanation"]["warnings"]}


def test_a_trust_store_is_always_present_so_the_self_signed_path_is_not_reached(demo):
    """SELF_SIGNED_ONLY needs a verifier with no trust material, and this portal refuses to run without any."""
    client = client_for(rewrite(demo, profile="development", allow_self_signed=True))
    body = post(client, demo, "2-untrusted-signer.json").json()
    assert (
        body["verification"]["trust_status"] == "INVALID"
        and body["verification"]["accepted"] is False
    )


def test_the_demo_directory_is_private_and_holds_no_private_key(demo):
    assert stat.S_IMODE(demo.stat().st_mode) == 0o700
    for path in demo.rglob("*"):
        if path.is_file():
            assert b"PRIVATE KEY" not in path.read_bytes()


def test_demo_setup_will_not_overwrite(demo):
    with pytest.raises(FileExistsError):
        create(demo)


# ----------------------------------------------------------------------------- what verifier_id does


def _check(tmp_path: Path, name: str, *, profile: str, audience) -> dict:
    config, signer = make_portal(tmp_path / name, profile=profile)
    return post_bytes(client_for(config), signed_report(signer, audience=audience)).json()[
        "verification"
    ]


def test_verifier_id_is_checked_only_against_reports_that_name_an_audience(tmp_path):
    named_other = _check(tmp_path, "a", profile="confidential", audience=("someone-else",))
    assert (
        named_other["trust_status"] == "INVALID"
        and "AUDIENCE_MISMATCH" in named_other["blocking_reasons"]
    )
    named_this = _check(
        tmp_path, "b", profile="confidential", audience=("someone-else", "demo-verifier")
    )
    assert named_this["trust_status"] == "TRUSTED"
    none_named = _check(tmp_path, "c", profile="confidential", audience=None)
    assert (
        none_named["trust_status"] == "TRUSTED" and "AUDIENCE_MISMATCH" not in none_named["reasons"]
    )


def test_the_high_assurance_profile_also_refuses_a_report_that_names_no_audience(tmp_path):
    refused = _check(tmp_path, "d", profile="high-assurance", audience=None)
    assert (
        refused["trust_status"] == "INVALID" and "AUDIENCE_MISMATCH" in refused["blocking_reasons"]
    )


# ----------------------------------------------------------------------------- small wording and start-up behaviour


def test_the_entry_count_is_singular_for_one(demo):
    assert approved_entries(1) == "1 approved issuer entry"
    assert approved_entries(0) == "0 approved issuer entries"
    assert approved_entries(2) == "2 approved issuer entries"
    status = client_for(demo / "portal-config.json").get("/api/status").json()
    assert status["policy_text"] == f"Policy {status['policy_id']}, 1 approved issuer entry."
    env = dict(os.environ, PYTHONPATH=str(PORTAL_FOLDER))
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_portal", "check-config", "--config", str(demo / "portal-config.json")],
        capture_output=True, text=True, timeout=60, check=False, env=env,
    )  # fmt: skip
    assert out.returncode == 0 and "1 approved issuer entry," in out.stdout


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"max_age_days": "30"}, "max_age_days must be a whole number"),
        ({"max_age_days": 1.5}, "max_age_days must be a whole number"),
        ({"profile": 1}, "profile must be text"),
        ({"verifier_id": 5}, "verifier_id must be text"),
        ({"allow_self_signed": "yes"}, "allow_self_signed must be true or false"),
    ],
)
def test_a_wrongly_typed_setting_is_named_in_plain_words(demo, change, message):
    rewrite(demo, **change)
    with pytest.raises(ConfigProblem) as raised:
        load_portal(demo / "portal-config.json")
    assert str(raised.value) == message and " a int" not in str(raised.value)


@pytest.mark.parametrize("path", ["/", "/static/app.js", "/static/app.css", "/api/status"])
def test_head_answers_like_get_without_a_body(client, path):
    got, head = client.get(path), client.head(path)
    assert head.status_code == 200 and head.content == b"" and got.content != b""
    for name in (
        "content-type",
        "content-security-policy",
        "cache-control",
        "x-content-type-options",
    ):
        assert head.headers[name] == got.headers[name]


def test_head_does_not_open_the_verify_route_or_anything_else(client):
    assert client.head("/api/verify").status_code == 405
    assert client.head("/static/index.html").status_code == 404


def test_the_started_message_always_says_where_to_open_the_page_and_says_what_works(tmp_path):
    ready = started_message("ready", 8765)
    assert ready == "open http://127.0.0.1:8765 in a browser. Press Ctrl-C to stop."
    welcome = started_message("welcome", 8765)
    assert welcome.startswith("open http://127.0.0.1:8765 in a browser.")
    assert "samples work" in welcome and "not set up yet" in welcome
    attention = started_message("needs-attention", 8765)
    assert attention.startswith("open http://127.0.0.1:8765 in a browser.")
    assert "samples work" in attention and "check-config" in attention


def test_the_app_knows_whether_it_is_ready(demo):
    assert client_for(demo / "portal-config.json").app.state.ready is True
    assert client_for(demo / "absent.json").app.state.ready is False


def test_serve_does_not_say_to_open_the_page_when_it_cannot_bind_its_port(demo):
    env = dict(os.environ, PYTHONPATH=str(PORTAL_FOLDER))
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        port = taken.getsockname()[1]
        out = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-m", "regaudit_portal", "serve", "--config", str(demo / "portal-config.json"), "--port", str(port)],
            capture_output=True, text=True, timeout=60, check=False, env=env,
        )  # fmt: skip
    assert out.returncode != 0
    assert "open http" not in out.stdout and "open http" not in out.stderr


def test_the_command_to_start_the_portal_is_written_to_work_when_typed(tmp_path, monkeypatch):
    assert portal_command("/x/.venv/bin/regaudit-portal", "/py") == "/x/.venv/bin/regaudit-portal"
    started_with_dash_m = portal_command("/p/regaudit_portal/__main__.py", "/my env/bin/python")
    assert started_with_dash_m == "'/my env/bin/python' -m regaudit_portal"
    assert portal_command("/odd dir/regaudit-portal", "/py") == "'/odd dir/regaudit-portal'"
    monkeypatch.chdir(tmp_path)
    assert portal_command(".venv/bin/regaudit-portal", "/py") == os.path.join(
        os.getcwd(), ".venv/bin/regaudit-portal"
    )
    monkeypatch.setattr(shutil, "which", lambda _name: "/found/bin/regaudit-portal")
    assert portal_command("regaudit-portal", "/py") == "/found/bin/regaudit-portal"


def test_the_next_command_that_demo_setup_prints_works_exactly_as_typed(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(PORTAL_FOLDER))
    elsewhere = tmp_path / "somewhere else"
    elsewhere.mkdir()
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_portal", "demo-setup", str(tmp_path / "my demo")],
        capture_output=True, text=True, timeout=60, check=False, env=env, cwd=elsewhere,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    line = next(line for line in out.stdout.splitlines() if line.startswith("next: "))
    typed = shlex.split(line.removeprefix("next: "))  # what a shell would make of the printed line
    assert (
        typed[-3] == "serve"
        and typed[-2] == "--config"
        and typed[-1] == str(tmp_path / "my demo" / "portal-config.json")
    )
    assert typed[:3] == [sys.executable, "-m", "regaudit_portal"]
    typed[-3] = (
        "check-config"  # the same program and the same arguments, but one that ends by itself
    )
    checked = subprocess.run(  # noqa: S603 - the argv is the printed command
        typed, capture_output=True, text=True, timeout=60, check=False, env=env, cwd=elsewhere
    )
    assert checked.returncode == 0 and checked.stdout.startswith("usable: "), checked.stderr
