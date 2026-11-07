"""The one route that prepares a setup plan: same guards as the other POST routes, stateless, and it keeps nothing."""

from __future__ import annotations

import builtins
import gc
import importlib
import json
import logging
import os
import secrets
from collections import deque
from pathlib import Path

import pytest
import regaudit_portal.engine as engine_module
from helpers import (
    JSON_HEADERS,
    client_for,
    fake_home,
    fingerprint_of,
    issuer_signer,
    plan_request,
    snapshot,
)
from regaudit_portal import config as config_module
from regaudit_portal import demonstration
from test_setup import _forbid_writes

ROUTE = "/api/setup/plan"


@pytest.fixture
def welcome(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    return client_for(None)


def _body(name: str = "Northwind Ltd", key_id: str = "northwind-2026", **options) -> bytes:
    return json.dumps(plan_request([issuer_signer(name, key_id)], **options)).encode()


# ----------------------------------------------------------------------------- it answers in every mode


def test_it_prepares_a_plan_in_welcome_mode_ready_mode_and_needs_attention_mode(
    tmp_path, monkeypatch, demo
):
    fake_home(tmp_path, monkeypatch)
    os.chmod(demo / "trust-store.json", 0o666)  # noqa: S103 - a configuration that needs attention
    attention = client_for(demo / "portal-config.json")
    os.chmod(demo / "trust-store.json", 0o600)
    for client in (client_for(None), client_for(demo / "portal-config.json"), attention):
        response = client.post(ROUTE, content=_body(), headers=JSON_HEADERS)
        assert response.status_code == 200 and response.json()["ok"] is True


def test_the_answer_carries_the_strict_headers(welcome):
    headers = welcome.post(ROUTE, content=_body(), headers=JSON_HEADERS).headers
    assert "default-src 'none'" in headers["content-security-policy"]
    assert headers["cache-control"] == "no-store" and headers["x-content-type-options"] == "nosniff"


# ----------------------------------------------------------------------------- the same guards as the other POST routes


@pytest.mark.parametrize(
    "host", ["evil.example", "evil.example:8765", "127.0.0.1:9999", "0.0.0.0:8765", "[::1]:8765"]
)
def test_a_name_rebound_to_this_address_is_refused_exactly_as_for_verify(welcome, host):
    for route in (ROUTE, "/api/verify"):
        assert (
            welcome.post(route, content=_body(), headers={**JSON_HEADERS, "host": host}).status_code
            == 403
        )


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "null",
        "http://127.0.0.1:9999",
        "https://127.0.0.1:8765",
        "http://localhost.evil:8765",
        "",
    ],
)
def test_a_page_on_another_site_cannot_post_exactly_as_for_verify(welcome, origin):
    for route in (ROUTE, "/api/verify"):
        response = welcome.post(route, content=_body(), headers={**JSON_HEADERS, "origin": origin})
        assert response.status_code == 403, (route, origin)
        assert response.json()["error"] == "bad_origin"


@pytest.mark.parametrize("origin", ["http://127.0.0.1:8765", "http://localhost:8765"])
def test_the_portals_own_page_can_post(welcome, origin):
    host = origin.removeprefix("http://")
    response = welcome.post(
        ROUTE, content=_body(), headers={**JSON_HEADERS, "origin": origin, "host": host}
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "kind",
    [
        "text/plain",
        "multipart/form-data; boundary=x",
        "application/x-www-form-urlencoded",
        "application/json-patch+json",
        "application/jsonx",
        "",
    ],
)
def test_a_form_or_anything_but_json_is_refused(welcome, kind):
    headers = {"content-type": kind} if kind else {}
    assert welcome.post(ROUTE, content=_body(), headers=headers).status_code == 415


def test_json_with_a_charset_is_accepted(welcome):
    response = welcome.post(
        ROUTE, content=_body(), headers={"content-type": "application/json; charset=utf-8"}
    )
    assert response.status_code == 200


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH"])
def test_the_route_accepts_only_post_and_the_page_only_looking(welcome, method):
    assert welcome.request(method, ROUTE, content=_body()).status_code == 405
    if method != "GET":
        assert welcome.request(method, "/setup/plan", content=_body()).status_code == 405
    assert welcome.post("/setup/plan", content=_body(), headers=JSON_HEADERS).status_code == 405


def test_a_declared_size_over_the_limit_is_refused_unread(welcome):
    for length in (str(64 * 1024 + 1), "999999999999", "abc", "-1"):
        response = welcome.post(
            ROUTE, content=b"{}", headers={**JSON_HEADERS, "content-length": length}
        )
        assert response.status_code == 413, length


def test_a_streamed_body_over_the_limit_is_refused(welcome):
    def chunks():
        for _ in range(20):
            yield b" " * 8192

    assert welcome.post(ROUTE, content=chunks(), headers=JSON_HEADERS).status_code == 413


def test_a_body_that_does_not_arrive_in_time_is_refused(welcome, monkeypatch):
    monkeypatch.setattr(importlib.import_module("regaudit_portal.app"), "BODY_TIMEOUT_S", 0.0)
    client = client_for(None)
    assert client.post(ROUTE, content=_body(), headers=JSON_HEADERS).status_code == 408


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[" * 20000 + b"]" * 20000,
        b'{"a":' * 5000 + b"1" + b"}" * 5000,
        b"\xef\xbb\xbf{}",
        b"\xc3\x28",
    ],
)
def test_malformed_or_deeply_nested_json_is_refused_without_a_crash(welcome, raw):
    response = welcome.post(ROUTE, content=raw, headers=JSON_HEADERS)
    assert response.status_code in (413, 422) and response.json()["error"] in (
        "not_json",
        "too_large",
    )


def test_too_many_requests_are_refused(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    monkeypatch.setattr(
        importlib.import_module("regaudit_portal.app"), "MAX_REQUESTS_PER_MINUTE", 2
    )
    client = client_for(None)
    codes = [
        client.post(ROUTE, content=_body(), headers=JSON_HEADERS).status_code for _ in range(4)
    ]
    assert codes == [200, 200, 429, 429]


# ----------------------------------------------------------------------------- the engine


def test_with_the_engine_refused_at_start_no_plan_is_prepared(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    monkeypatch.setattr(engine_module, "RELEASE_FILES_SHA256", "0" * 64)
    response = client_for(None).post(ROUTE, content=_body(), headers=JSON_HEADERS)
    assert response.status_code == 503 and response.json()["state"] == "unavailable"


def test_when_the_engine_stops_passing_no_plan_is_prepared(welcome, monkeypatch):
    def crashes(_folder):
        raise RuntimeError("the hash could not be computed")

    monkeypatch.setattr(engine_module, "files_digest", crashes)
    response = welcome.post(ROUTE, content=_body(), headers=JSON_HEADERS)
    assert response.status_code == 503 and "plan_text" not in response.text


# ----------------------------------------------------------------------------- refusals say why and repeat nothing


def test_a_private_key_is_refused_and_appears_in_no_answer_and_no_log(welcome, caplog):
    from cryptography.hazmat.primitives import serialization

    signer = issuer_signer()
    secret = signer.private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    request = plan_request([signer])
    request["issuers"][0]["public_key"] = secret
    caplog.set_level(logging.DEBUG)
    response = welcome.post(ROUTE, content=json.dumps(request).encode(), headers=JSON_HEADERS)
    assert response.status_code == 422 and response.json()["error"] == "secret_key_material"
    body_line = secret.strip().splitlines()[1]
    assert body_line not in response.text and "PRIVATE KEY" not in response.text
    assert all(body_line not in record.getMessage() for record in caplog.records)


def _fingerprint_forms(signer) -> list[str]:
    """The computed fingerprint as the page could show it: lower case, upper case, and in pairs with colons."""
    fp = fingerprint_of(signer)
    return [fp, fp.upper(), ":".join(fp[i : i + 2] for i in range(0, 64, 2))]


def test_a_wrong_fingerprint_says_only_that_it_does_not_match(welcome):
    """The page must not offer the value the administrator is supposed to check with the issuer."""
    signer = issuer_signer()
    typed = "ab" * 32
    request = plan_request([signer], fingerprints=[typed])
    response = welcome.post(ROUTE, content=json.dumps(request).encode(), headers=JSON_HEADERS)
    assert response.status_code == 422 and response.json()["error"] == "fingerprint_mismatch"
    assert response.json()["issuers"] == [
        {"number": 1, "issuer": signer.issuer, "key_id": signer.key_id, "matches": False}
    ]
    for shown in (*_fingerprint_forms(signer), typed):
        assert shown not in response.text, shown
    assert "plan_text" not in response.text and "writes" not in response.json()


def test_two_issuers_with_one_wrong_fingerprint_make_no_plan_and_show_no_fingerprint(welcome):
    right, wrong = issuer_signer("Northwind Ltd", "northwind-2026"), issuer_signer("Acme Ltd", "acme-1")
    request = plan_request([right, wrong], fingerprints=[fingerprint_of(right), "cd" * 32])
    response = welcome.post(ROUTE, content=json.dumps(request).encode(), headers=JSON_HEADERS)
    body = response.json()
    assert response.status_code == 422 and body["error"] == "fingerprint_mismatch"
    assert [row["matches"] for row in body["issuers"]] == [True, False]
    assert all(set(row) == {"number", "issuer", "key_id", "matches"} for row in body["issuers"])
    for signer in (right, wrong):
        for shown in _fingerprint_forms(signer):
            assert shown not in response.text, shown
    assert "plan_text" not in body and "writes" not in body


def test_a_good_plan_answer_carries_no_fingerprint_either(welcome):
    signer = issuer_signer()
    response = welcome.post(ROUTE, content=json.dumps(plan_request([signer])).encode(), headers=JSON_HEADERS)
    assert response.status_code == 200 and response.json()["issuers"][0]["matches"] is True
    for shown in _fingerprint_forms(signer):
        assert shown not in response.text, shown


def test_guard_off_the_earlier_answer_would_have_shown_the_computed_fingerprint(welcome, monkeypatch):
    """The control: with the answer built the earlier way, the computed fingerprint is in the mismatch response, so
    the checks above would catch it."""
    from regaudit_portal import plan as plan_module

    def earlier(number, issuer, typed):
        return {
            "number": number,
            "issuer": issuer.issuer,
            "key_id": issuer.key_id,
            "computed_fingerprint": issuer.fingerprint,
            "matches": plan_module.fingerprints_match(typed, issuer.fingerprint),
        }

    monkeypatch.setattr(plan_module, "_check_row", earlier)
    signer = issuer_signer()
    request = plan_request([signer], fingerprints=["ab" * 32])
    response = welcome.post(ROUTE, content=json.dumps(request).encode(), headers=JSON_HEADERS)
    assert response.status_code == 422 and fingerprint_of(signer) in response.text


def test_the_page_has_no_place_for_a_computed_fingerprint():
    static = Path(__file__).parents[1] / "regaudit_portal" / "static"
    script, html = (static / "plan.js").read_text(), (static / "plan.html").read_text()
    assert "computed_fingerprint" not in script and "Computed from the key" not in html
    assert "<th>The fingerprint you typed matches the key</th>" in html
    assert "The portal does not show the fingerprint of the key: check it with the issuer." in html
    assert "subtle" not in script and "digest(" not in script  # the page never works one out either


def test_names_with_escape_sequences_never_reach_the_log(welcome, caplog):
    caplog.set_level(logging.DEBUG)
    response = welcome.post(
        ROUTE, content=_body(name="\x1b[2J\x1b]0;owned\x07Evil"), headers=JSON_HEADERS
    )
    assert response.status_code == 422
    assert "\x1b" not in response.text
    assert not [r for r in caplog.records if "\x1b" in r.getMessage() or "Evil" in r.getMessage()]


# ----------------------------------------------------------------------------- stateless: it writes, reads and keeps nothing


def test_preparing_a_plan_changes_nothing_on_disk(tmp_path, monkeypatch, demo):
    fake_home(tmp_path, monkeypatch)
    client = client_for(demo / "portal-config.json")
    before = snapshot(tmp_path)
    for body in (_body(), _body(mode="add-issuers"), b"not json"):
        client.post(ROUTE, content=body, headers=JSON_HEADERS)
    assert snapshot(tmp_path) == before


def test_no_way_of_writing_is_reached_while_a_plan_is_prepared(welcome, monkeypatch):
    welcome.post(
        ROUTE, content=_body(), headers=JSON_HEADERS
    )  # anything loaded once is loaded before the guard
    _forbid_writes(monkeypatch)
    for body in (
        _body(),
        _body(mode="add-issuers"),
        _body(name="DEMO-ONLY synthetic issuer"),
        b"{",
    ):
        assert welcome.post(ROUTE, content=body, headers=JSON_HEADERS).status_code in (200, 422)


def test_preparing_a_plan_opens_no_file_at_all_and_never_looks_at_the_configuration(
    tmp_path, monkeypatch, demo
):
    fake_home(tmp_path, monkeypatch)
    client = client_for(demo / "portal-config.json")
    client.post(ROUTE, content=_body(), headers=JSON_HEADERS)
    demonstration.fingerprints()

    def refused(*_args, **_kwargs):
        raise AssertionError("a file was opened or the configuration was read")

    for module, name in ((config_module, "read_settings"), (config_module, "read_trust_store")):
        monkeypatch.setattr(module, name, refused)
    monkeypatch.setattr(
        engine_module, "check_engine", lambda *_: engine_module.Identity(True, "OK", "", {})
    )
    app_module = importlib.import_module("regaudit_portal.app")
    monkeypatch.setattr(
        app_module, "check_engine", lambda *_: engine_module.Identity(True, "OK", "", {})
    )
    monkeypatch.setattr(builtins, "open", refused)
    monkeypatch.setattr(os, "open", refused)
    response = client.post(ROUTE, content=_body(), headers=JSON_HEADERS)
    assert response.status_code == 200, response.text


def _kept(*markers: str) -> list[str]:
    """The kinds of every live container that holds a string or bytes with one of these markers in it."""
    gc.collect()

    def holds(value) -> bool:
        if isinstance(value, str):
            return any(m in value for m in markers)
        if isinstance(value, (bytes, bytearray)):
            return any(m.encode() in value for m in markers)
        return False

    found = []
    for obj in gc.get_objects():
        try:
            if isinstance(obj, dict):
                items = [*obj.keys(), *obj.values()]
            elif isinstance(obj, (list, tuple, set, frozenset, deque)):
                items = list(obj)
            else:
                continue
        except Exception:  # noqa: S112 - an object that cannot be listed holds nothing we sent
            continue
        if any(holds(item) for item in items):
            found.append(type(obj).__name__)
    return found


def _prepare_once(client, marker: str, key_id: str) -> int:
    response = client.post(ROUTE, content=_body(name=marker, key_id=key_id), headers=JSON_HEADERS)
    assert marker in response.text
    return response.status_code


def test_nothing_about_a_prepared_plan_is_kept_by_the_portal_afterwards(welcome):
    marker, key_id = "Marker" + secrets.token_hex(8), "kid-" + secrets.token_hex(6)
    assert _prepare_once(welcome, marker, key_id) == 200
    assert _kept(marker, key_id) == []
    state = vars(welcome.app.state).get("_state", {})
    assert set(state) == {"ready", "mode"}


def test_the_check_for_anything_kept_would_notice_a_plan_that_was_kept(welcome, monkeypatch):
    plan_module = importlib.import_module("regaudit_portal.plan")
    app_module = importlib.import_module("regaudit_portal.app")
    stash: list[bytes] = []
    real = plan_module.prepared

    def keeping(raw: bytes):
        stash.append(raw)
        return real(raw)

    monkeypatch.setattr(app_module, "prepared", keeping)
    client = client_for(None)
    marker, key_id = "Marker" + secrets.token_hex(8), "kid-" + secrets.token_hex(6)
    assert _prepare_once(client, marker, key_id) == 200
    assert "list" in _kept(marker, key_id)
