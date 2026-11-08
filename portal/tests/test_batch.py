"""Checking several report files in one request: each file is checked exactly as a single upload is, within fixed limits,
and nothing about one file can affect another."""

from __future__ import annotations

import base64
import json
import sys
import threading
import time
import types
import uuid
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest
import regaudit_portal.app as app_module
import regaudit_portal.batch as batch_module
from helpers import (
    JSON_HEADERS,
    client_for,
    make_portal,
    make_synthetic_portal,
    signed_report,
)
from regaudit_portal.config import load_portal
from regaudit_portal.explain import DEMONSTRATION_LABEL

import regaudit_fhe as rf
from regaudit_fhe.report_v2 import envelope_v2, parse_envelope_strict
from regaudit_fhe.verification import verify

MB = 1 << 20


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def body_of(files: list[tuple[object, bytes | str]]) -> bytes:
    return json.dumps(
        {
            "files": [
                {"name": n, "content_b64": c if isinstance(c, str) else b64(c)} for n, c in files
            ]
        }
    ).encode()


def send(client, files, **kw):
    return client.post("/api/verify-batch", content=body_of(files), headers=JSON_HEADERS, **kw)


def single(client, raw: bytes):
    response = client.post("/api/verify", content=raw, headers=JSON_HEADERS)
    return response.status_code, response.json()


def dated(signer, issued_at, parameter_set=None) -> bytes:
    report = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    env = envelope_v2(
        "drift",
        report,
        signer=signer,
        deployment_id="synthetic-test",
        audience=["demo-verifier"],
        parameter_set=parameter_set,
        issued_at=issued_at,
        audit_run_id=str(uuid.uuid4()),
    )
    return json.dumps(env.to_dict()).encode()


@pytest.fixture
def portal(tmp_path):
    config, signer = make_portal(tmp_path / "p")
    return config, signer, client_for(config)


def crafted(signer) -> dict[str, bytes]:
    """Reports that make the engine say different things, each made fresh."""
    stranger = rf.Signer.generate(issuer="Northwind Test Issuer", key_id="k-other")
    renamed = rf.Signer("Another Issuer", signer.key_id, signer.private_key, signer.public_key)
    tampered = json.loads(signed_report(signer))
    tampered["deployment_id"] = "changed-after-signing"
    now = datetime.now(timezone.utc)
    return {
        "trusted.json": signed_report(signer),
        "tampered.json": json.dumps(tampered).encode(),
        "unknown-issuer.json": signed_report(stranger),
        "wrong-issuer.json": signed_report(renamed),
        "over-age.json": dated(signer, now - timedelta(days=45)),
        "future.json": dated(signer, now + timedelta(days=2)),
        "not-a-report.json": b'{"hello": "this is not a signed report"}',
    }


def strip(result: dict) -> dict:
    return {k: v for k, v in result.items() if k != "checked_at"}


# ----------------------------------------------------------------------------- parity with the single path


def test_each_file_of_a_batch_is_the_single_result_and_the_engines_own(portal):
    config, signer, client = portal
    reports = crafted(signer)
    response = send(client, list(reports.items()))
    assert response.status_code == 200
    body = response.json()
    assert [f["name"] for f in body["files"]] == list(reports)
    policy = load_portal(config).policy
    for entry, (name, raw) in zip(body["files"], reports.items(), strict=True):
        status, alone = single(client, raw)
        if status == 200:
            assert entry["ok"] is True
            assert strip(entry["result"]) == strip(alone), name  # every member, statuses included
            direct = verify(parse_envelope_strict(json.loads(raw)), policy).to_dict()
            assert entry["result"]["verification"] == direct, name
            assert entry["result"]["statuses"] == alone["statuses"]
            assert entry["result"]["trust_mode"] == "customer"
        else:
            assert entry["ok"] is False and entry["error"] == alone, name
        assert entry["report_sha256"] and entry["size_bytes"] == len(raw)


def test_parity_for_the_seven_sample_files_of_a_configuration(tmp_path):
    demo = make_synthetic_portal(tmp_path / "demo")
    client = client_for(demo / "portal-config.json")
    reports = [(p.name, p.read_bytes()) for p in sorted((demo / "sample-reports").iterdir())]
    assert len(reports) == 7
    body = send(client, reports).json()
    for entry, (name, raw) in zip(body["files"], reports, strict=True):
        status, alone = single(client, raw)
        if status == 200:
            assert strip(entry["result"]) == strip(alone), name
        else:
            assert entry["error"] == alone, name
    assert [f["ok"] for f in body["files"]] == [True, True, True, True, False, False, True]
    assert body["files"][5]["error"]["error"] == "too_large"
    assert body["files"][4]["error"]["error"] == "not_a_report"


def test_a_demonstration_configuration_labels_every_file_and_the_batch(tmp_path):
    demo = make_synthetic_portal(tmp_path / "d", trust_mode="demonstration")
    client = client_for(demo / "portal-config.json")
    reports = [(p.name, p.read_bytes()) for p in sorted((demo / "sample-reports").iterdir())][:4]
    body = send(client, reports).json()
    assert (
        body["trust_mode"] == "demonstration" and body["demonstration_label"] == DEMONSTRATION_LABEL
    )
    for entry in body["files"]:
        result = entry["result"]
        assert result["trust_mode"] == "demonstration"
        assert result["demonstration_label"] == DEMONSTRATION_LABEL
        assert result["statuses"]["demonstration_label"] == DEMONSTRATION_LABEL
        assert result["verification"]["trust_status"] in ("TRUSTED", "INVALID")


def test_a_customer_configuration_never_labels_a_batch_a_demonstration(portal):
    _, signer, client = portal
    body = send(client, [("a.json", signed_report(signer))]).json()
    assert body["trust_mode"] == "customer" and "demonstration_label" not in body
    assert body["files"][0]["result"]["trust_mode"] == "customer"
    assert "demonstration_label" not in body["files"][0]["result"]["statuses"]


def test_the_bundled_demonstration_samples_are_not_customer_trusted_in_a_customer_batch(portal):
    from regaudit_portal.samples import load_samples

    _, _, client = portal
    samples = load_samples()
    files = [(s.id, samples.read(s)) for s in samples.items]
    body = send(client, files).json()
    for entry in body["files"]:
        assert entry["ok"] and entry["result"]["verification"]["trust_status"] == "INVALID"
        assert entry["result"]["trust_mode"] == "customer"


# ----------------------------------------------------------------------------- identity, order, names


def test_results_come_back_in_request_order_with_ids_and_the_summary_counts_them(portal):
    _, signer, client = portal
    reports = crafted(signer)
    names = list(reports)[::-1]
    body = send(client, [(n, reports[n]) for n in names]).json()
    assert [f["id"] for f in body["files"]] == [f"file-{i + 1}" for i in range(len(names))]
    assert [f["index"] for f in body["files"]] == list(range(len(names)))
    assert [f["name"] for f in body["files"]] == names
    summary = body["summary"]
    assert summary["total"] == 7
    assert summary["trusted"] == 1 and summary["refused"] == 1
    assert (
        summary["trusted"] + summary["not_accepted"] + summary["refused"] + summary["not_run"] == 7
    )
    assert uuid.UUID(body["batch_id"]) and body["schema"] == batch_module.SCHEMA
    assert body["complete"] is True


HOSTILE_NAMES = [
    "evil‮name.json",
    "zero​width⁠.json",
    "<img src=x onerror=alert(1)>.json",
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "a" * 5000,
    "nul\x00byte.json",
    "line\nbreak .json",
    "퟿private.json",
]


def test_file_names_are_untrusted_text_shown_neutralised_capped_and_never_a_path(
    portal, tmp_path, monkeypatch
):
    _, signer, client = portal
    monkeypatch.chdir(tmp_path)
    before = sorted(p.name for p in tmp_path.iterdir())
    raw = signed_report(signer)
    body = send(client, [(n, raw) for n in HOSTILE_NAMES]).json()
    shown = [f["name"] for f in body["files"]]
    for _name, text in zip(HOSTILE_NAMES, shown, strict=True):
        assert "‮" not in text and "​" not in text and "\x00" not in text and "\n" not in text
        assert (
            len(text)
            <= batch_module.MAX_NAME_SHOWN + len(" (shortened)") + 6 * batch_module.MAX_NAME_SHOWN
        )
    assert shown[0].startswith("evil\\u{202E}name")
    assert (
        body["files"][5]["name_shortened"] is True and body["files"][0]["name_shortened"] is False
    )
    assert all(f["ok"] for f in body["files"])  # a strange name does not change a verdict
    assert (
        sorted(p.name for p in tmp_path.iterdir()) == before
    )  # no file by any of those names exists


@pytest.mark.parametrize("name", [None, 5, "", ["x"], {"a": 1}])
def test_a_missing_or_non_text_name_is_shown_as_no_name(portal, name):
    _, signer, client = portal
    body = json.dumps(
        {"files": [{"name": name, "content_b64": b64(signed_report(signer))}]}
    ).encode()
    response = client.post("/api/verify-batch", content=body, headers=JSON_HEADERS)
    assert response.status_code == 200 and response.json()["files"][0]["name"] == "(no name)"


def test_a_file_with_no_name_member_is_accepted_too(portal):
    _, signer, client = portal
    body = json.dumps({"files": [{"content_b64": b64(signed_report(signer))}]}).encode()
    assert client.post("/api/verify-batch", content=body, headers=JSON_HEADERS).json()["files"][0][
        "ok"
    ]


# ----------------------------------------------------------------------------- partial completion


def test_a_bad_file_never_stops_the_others(portal):
    _, signer, client = portal
    good = signed_report(signer)
    nested = b'{"a":' * 40 + b"1" + b"}" * 40
    files = [
        ("one.json", good),
        ("not-base64", "!!! not base64 !!!"),
        ("huge.json", b"x" * (MB + 1)),
        ("two.json", good),
        ("utf8.json", b'{"a": "\xff\xfe"}'),
        ("null.json", b'{"a": "\x00"}'),
        ("dup.json", b'{"a": 1, "a": 2}'),
        ("deep.json", nested),
        ("empty.json", b""),
        ("array.json", b"[1,2,3]"),
        ("three.json", good),
    ]
    body = send(client, files).json()
    ok = [f["ok"] for f in body["files"]]
    assert ok == [True, False, False, True, False, False, False, False, False, False, True]
    codes = {f["name"]: f["error"]["error"] for f in body["files"] if not f["ok"]}
    assert codes["not-base64"] == "not_a_report" and codes["huge.json"] == "too_large"
    assert {
        codes[n]
        for n in ("utf8.json", "null.json", "dup.json", "deep.json", "empty.json", "array.json")
    } == {"not_a_report"}
    for f in body["files"]:
        if not f["ok"]:
            assert f["error"]["message"] in (
                app_module._NOT_A_REPORT,
                app_module._TOO_LARGE,
            )  # the existing wording
    assert body["summary"]["trusted"] == 3 and body["summary"]["refused"] == 8


def test_a_file_far_over_the_limit_is_refused_before_it_is_decoded(portal, monkeypatch):
    _, signer, client = portal
    decoded = []
    real = batch_module.base64.b64decode
    monkeypatch.setattr(
        batch_module.base64, "b64decode", lambda s, **k: decoded.append(len(s)) or real(s, **k)
    )
    huge = "A" * (batch_module.MAX_REPORT_BASE64 + 4)
    body = send(client, [("huge", huge), ("ok", signed_report(signer))]).json()
    assert body["files"][0]["error"]["error"] == "too_large" and body["files"][1]["ok"]
    assert len(huge) not in decoded


def test_many_tiny_files_and_identical_files_are_each_checked(portal):
    _, signer, client = portal
    tiny = [(f"t{i}.json", b"{}") for i in range(batch_module.MAX_FILES)]
    body = send(client, tiny).json()
    assert body["summary"]["refused"] == batch_module.MAX_FILES
    raw = signed_report(signer)
    body = send(client, [(f"same-{i}.json", raw) for i in range(batch_module.MAX_FILES)]).json()
    assert {f["result"]["verification"]["trust_status"] for f in body["files"]} == {"TRUSTED"}
    assert (
        len({json.dumps(strip(f["result"])["verification"], sort_keys=True) for f in body["files"]})
        == 1
    )
    assert len({f["report_sha256"] for f in body["files"]}) == 1


def test_one_huge_file_among_small_ones_costs_the_small_ones_nothing(portal):
    _, signer, client = portal
    raw = signed_report(signer)
    files = [("a", raw), ("huge", b"x" * (MB + 1)), ("b", raw)]
    body = send(client, files).json()
    assert [f["ok"] for f in body["files"]] == [True, False, True]
    alone = single(client, raw)[1]
    assert strip(body["files"][2]["result"]) == strip(alone)


# ----------------------------------------------------------------------------- the whole request is refused

BAD_BODIES = [
    b"not json",
    b"[]",
    b'{"files": []}',
    b'{"files": "x"}',
    b'{"files": [1]}',
    b'{"files": [{"name": "a"}]}',
    b'{"files": [{"name": "a", "content_b64": "", "extra": 1}]}',
    b'{"files": [], "extra": 1}',
    b'{"files": [{"content_b64": "", "content_b64": "e30="}]}',  # duplicate keys
    b'{"files": [{"name": "\xff", "content_b64": ""}]}',  # invalid UTF-8
    b'{"files": [{"name": "\\ud800", "content_b64": ""}]}',  # a lone surrogate
    b"\xef\xbb\xbf" + b'{"files": [{"content_b64": ""}]}',
    b'{"files":' * 5000 + b"[]" + b"}" * 5000,  # far too deep
    b'{"files": [{"content_b64": NaN}]}',
]


@pytest.mark.parametrize("raw", BAD_BODIES)
def test_a_request_that_is_not_a_list_of_files_is_refused_whole(portal, raw):
    _, _, client = portal
    response = client.post("/api/verify-batch", content=raw, headers=JSON_HEADERS)
    assert response.status_code == 422 and response.json()["error"] == "not_a_batch"
    assert response.json()["message"] == batch_module.NOT_A_BATCH and "files" not in response.json()


def test_a_batch_over_the_file_count_is_refused_before_anything_is_checked(portal, monkeypatch):
    _, signer, client = portal
    calls = []
    monkeypatch.setattr(app_module, "_verify_between_checks", lambda *a: calls.append(1))
    raw = signed_report(signer)
    response = send(client, [(f"{i}", raw) for i in range(batch_module.MAX_FILES + 1)])
    assert response.status_code == 413 and response.json()["error"] == "too_many_files"
    assert calls == []
    assert send(client, [(f"{i}", raw) for i in range(batch_module.MAX_FILES)]).status_code == 200


def test_a_request_over_the_size_limit_is_refused_by_length_and_while_streaming(
    portal, monkeypatch
):
    _, _, client = portal
    big = b'{"files": [{"content_b64": "' + b"A" * (batch_module.MAX_BODY_BYTES) + b'"}]}'
    response = client.post("/api/verify-batch", content=big, headers=JSON_HEADERS)
    assert response.status_code == 413 and response.json()["error"] == "too_large"

    def chunks():
        for _ in range(batch_module.MAX_BODY_BYTES // 65536 + 2):
            yield b"A" * 65536

    response = client.post("/api/verify-batch", content=chunks(), headers=JSON_HEADERS)
    assert response.status_code == 413  # no Content-Length to go by: cut off while streaming


def test_eleven_full_size_files_do_not_fit_and_the_limit_is_stated(portal):
    _, _, client = portal
    files = [(f"f{i}", b"x" * MB) for i in range(11)]
    response = send(client, files)
    assert response.status_code == 413 and "MB limit" in response.json()["message"]


def test_the_wrong_content_type_and_methods_are_refused(portal):
    _, _, client = portal
    assert (
        client.post(
            "/api/verify-batch", content=b"{}", headers={"content-type": "text/plain"}
        ).status_code
        == 415
    )
    assert client.post("/api/verify-batch", content=b"{}").status_code == 415
    assert client.get("/api/verify-batch").status_code == 405
    assert client.put("/api/verify-batch").status_code == 405


# ----------------------------------------------------------------------------- the same protections


def test_host_and_origin_and_headers_are_the_same_as_for_a_single_upload(portal):
    _, signer, client = portal
    body = body_of([("a", signed_report(signer))])
    bad_host = client.post(
        "/api/verify-batch", content=body, headers={**JSON_HEADERS, "host": "evil.example"}
    )
    assert bad_host.status_code == 403 and bad_host.json()["error"] == "bad_host"
    bad_origin = client.post(
        "/api/verify-batch", content=body, headers={**JSON_HEADERS, "origin": "http://evil.example"}
    )
    assert bad_origin.status_code == 403 and bad_origin.json()["error"] == "bad_origin"
    ok = client.post("/api/verify-batch", content=body, headers=JSON_HEADERS)
    alone = client.post("/api/verify", content=signed_report(signer), headers=JSON_HEADERS)
    for name in (
        "content-security-policy",
        "x-content-type-options",
        "cache-control",
        "referrer-policy",
    ):
        assert ok.headers[name] == alone.headers[name]
    assert ok.headers["cache-control"] == "no-store"


def test_a_portal_that_is_not_set_up_gives_no_batch_verdicts(tmp_path):
    client = client_for(None)
    response = client.post(
        "/api/verify-batch", content=body_of([("a", b"{}")]), headers=JSON_HEADERS
    )
    assert response.status_code == 503 and response.json()["error"] == "not_set_up"
    assert "files" not in response.json()


def test_a_batch_is_refused_whole_when_the_engine_fails_its_check(portal, monkeypatch):
    _, signer, client = portal
    monkeypatch.setattr(
        app_module,
        "check_engine",
        lambda *a: types.SimpleNamespace(ok=False, reason="X", detail="", engine=None),
    )
    response = send(client, [("a", signed_report(signer))])
    assert response.status_code == 503 and response.json()["error"] == "unavailable"


def test_the_engine_is_checked_before_and_after_every_report_of_a_batch(portal, monkeypatch):
    _, signer, client = portal
    calls = []
    real = app_module.check_engine
    monkeypatch.setattr(app_module, "check_engine", lambda *a: calls.append(1) or real(*a))
    n = 5
    send(client, [(f"{i}", signed_report(signer)) for i in range(n)])
    assert (
        len(calls) == 1 + 2 * n
    )  # once before the upload is read, then twice around each verification


def test_an_engine_that_fails_in_the_middle_stops_the_rest_and_no_verdict_is_given_for_it(
    portal, monkeypatch
):
    _, signer, client = portal
    real = app_module.check_engine
    state = {"n": 0}

    def flaky(*a):
        state["n"] += 1
        return (
            real(*a)
            if state["n"] <= 1 + 2 * 2 + 1
            else types.SimpleNamespace(ok=False, reason="X", detail="", engine=None)
        )

    monkeypatch.setattr(app_module, "check_engine", flaky)
    body = send(client, [(f"{i}", signed_report(signer)) for i in range(5)]).json()
    kinds = [f["ok"] or f["error"]["error"] for f in body["files"]]
    assert kinds == [True, True, "unavailable", "not_run", "not_run"]
    assert body["complete"] is False and body["summary"]["not_run"] == 2
    assert (
        "result" not in body["files"][2]
        and body["files"][3]["error"]["message"] == batch_module.NOT_RUN_ENGINE
    )
    # the next batch is a fresh start
    monkeypatch.setattr(app_module, "check_engine", real)
    assert send(client, [("a", signed_report(signer))]).json()["complete"] is True


# ----------------------------------------------------------------------------- the rate limit


@pytest.fixture
def clock(monkeypatch):
    now = {"t": 970.0}
    monkeypatch.setattr(app_module, "time", types.SimpleNamespace(monotonic=lambda: now["t"]))
    return now


def test_a_batch_costs_one_check_per_file_in_the_same_budget_as_single_uploads(
    portal, clock, monkeypatch
):
    _, signer, client = portal
    monkeypatch.setattr(app_module, "MAX_REQUESTS_PER_MINUTE", 120)
    client = client_for(portal[0])
    raw = signed_report(signer)
    first = send(client, [(f"{i}", raw) for i in range(20)]).json()
    assert first["rate"]["limit"] == 120 and first["rate"]["remaining"] == 100
    assert single(client, raw)[0] == 200
    second = send(client, [(f"{i}", raw) for i in range(20)]).json()
    assert second["rate"]["remaining"] == 79
    assert 1 <= second["rate"]["resets_in_seconds"] <= 60


def test_a_batch_that_does_not_fit_in_what_is_left_is_refused_whole_with_retry_after(
    portal, clock, monkeypatch
):
    config, signer, _ = portal
    monkeypatch.setattr(app_module, "MAX_REQUESTS_PER_MINUTE", 30)
    client = client_for(config)
    calls = []
    real = app_module._verify_between_checks
    monkeypatch.setattr(
        app_module, "_verify_between_checks", lambda *a: calls.append(1) or real(*a)
    )
    raw = signed_report(signer)
    assert send(client, [(f"{i}", raw) for i in range(20)]).status_code == 200  # 20 of 30 used
    calls.clear()
    clock["t"] = 990.5  # part-way through the minute: 30 seconds left
    refused = send(client, [(f"{i}", raw) for i in range(20)])
    assert (
        refused.status_code == 429 and calls == []
    )  # nothing was verified, not even the first file
    info = refused.json()
    assert info["error"] == "too_many" and info["rate"]["batch_size"] == 20
    assert (
        info["retry_after_seconds"]
        == int(refused.headers["retry-after"])
        == info["rate"]["resets_in_seconds"]
    )
    assert refused.headers["retry-after"] == "30"
    assert info["rate"]["remaining"] == 9  # the refusal cost one check, as any refused request does
    # A smaller batch that fits is still served, and one past the budget is refused deterministically.
    assert send(client, [(f"{i}", raw) for i in range(9)]).status_code == 200
    assert send(client, [("x", raw)]).status_code == 429
    clock["t"] = 1030.0  # the next minute: the budget is whole again
    assert send(client, [(f"{i}", raw) for i in range(20)]).status_code == 200


def test_the_rate_limit_is_not_raised_for_a_batch(portal, clock, monkeypatch):
    config, signer, _ = portal
    client = client_for(config)
    assert app_module.MAX_REQUESTS_PER_MINUTE == 120 and batch_module.MAX_FILES <= 120 // 4
    raw = signed_report(signer)
    statuses = [send(client, [(f"{i}", raw) for i in range(20)]).status_code for _ in range(8)]
    # 6 x 20 = 120 is the whole minute's budget, and the seventh batch is refused.
    assert statuses == [200] * 6 + [429] * 2


def test_a_single_check_is_refused_when_a_batch_used_the_budget(portal, clock, monkeypatch):
    config, signer, _ = portal
    monkeypatch.setattr(app_module, "MAX_REQUESTS_PER_MINUTE", 20)
    client = client_for(config)
    raw = signed_report(signer)
    assert send(client, [(f"{i}", raw) for i in range(20)]).status_code == 200
    assert client.post("/api/verify", content=raw, headers=JSON_HEADERS).status_code == 429
    assert client.post("/api/samples/trusted/verify").status_code == 429


# ----------------------------------------------------------------------------- concurrency


def test_batches_in_progress_are_capped_and_the_refusal_says_when_to_retry(portal, monkeypatch):
    _config, signer, client = portal
    monkeypatch.setattr(batch_module, "MAX_CONCURRENT_BATCHES", 0)
    response = send(client, [("a", signed_report(signer))])
    assert response.status_code == 429 and response.json()["error"] == "busy"
    assert response.headers["retry-after"] == "2"


def test_at_most_the_configured_number_of_batches_and_verifications_run_at_once(
    portal, monkeypatch
):
    _config, signer, client = portal
    real = app_module._verify_between_checks
    lock = threading.Lock()
    live = {"now": 0, "max": 0}

    def slow(*args):
        with lock:
            live["now"] += 1
            live["max"] = max(live["max"], live["now"])
        try:
            time.sleep(0.05)
            return real(*args)
        finally:
            with lock:
                live["now"] -= 1

    monkeypatch.setattr(app_module, "_verify_between_checks", slow)
    raw = signed_report(signer)
    results = []

    def go():
        results.append(send(client, [(f"{i}", raw) for i in range(6)]).status_code)

    threads = [threading.Thread(target=go) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert set(results) <= {200, 429}
    assert 200 in results
    assert (
        live["max"] <= batch_module.MAX_CONCURRENT_BATCHES
    )  # each batch checks its files one at a time
    assert live["max"] <= app_module.MAX_CONCURRENT


# ----------------------------------------------------------------------------- record mode


@pytest.fixture
def recording(tmp_path):
    config, signer = make_portal(tmp_path / "r")
    settings = json.loads(config.read_text())
    settings["replay_mode"] = "record"
    config.write_text(json.dumps(settings))
    return config, signer, client_for(config)


def recorded_rows(config) -> int:
    import sqlite3

    db = config.parent / "replay.db"
    with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
        tables = [r[0] for r in conn.execute("select name from sqlite_master where type='table'")]
        return sum(conn.execute(f"select count(*) from {t}").fetchone()[0] for t in tables)  # noqa: S608


def test_record_mode_records_each_accepted_file_once_and_lists_exactly_which(recording):
    config, signer, client = recording
    one, two = signed_report(signer), signed_report(signer)
    body = send(client, [("a", one), ("b", two), ("again", one), ("bad", b"{}")]).json()
    kinds = [f["ok"] and f["result"]["statuses"]["replay"]["state"] for f in body["files"]]
    assert kinds == ["recorded", "recorded", "repeat_detected", False]
    assert body["replay_mode"] == "record"
    assert body["summary"]["recorded_in_replay_file"] == ["file-1", "file-2"]
    assert recorded_rows(config) == 2
    # the same files again, by one at a time: every one is a repeat, as the batch said
    assert single(client, one)[1]["statuses"]["replay"]["state"] == "repeat_detected"


def test_check_mode_records_nothing_so_a_batch_can_be_repeated(portal):
    _config, signer, client = portal
    raw = signed_report(signer)
    first = send(client, [("a", raw), ("b", raw)]).json()
    second = send(client, [("a", raw), ("b", raw)]).json()
    for body in (first, second):
        assert [f["result"]["statuses"]["replay"]["state"] for f in body["files"]] == [
            "checked_not_seen"
        ] * 2
        assert body["summary"]["recorded_in_replay_file"] == []


def test_a_refused_batch_records_nothing(recording, monkeypatch):
    config, signer, client = recording
    monkeypatch.setattr(app_module, "MAX_REQUESTS_PER_MINUTE", 3)
    client = client_for(config)
    raw = signed_report(signer)
    assert send(client, [(f"{i}", signed_report(signer)) for i in range(10)]).status_code == 429
    assert send(client, [("a", raw)] * 1 + [("b", b"{}")] * 25).status_code in (413, 429)
    assert not (config.parent / "replay.db").stat().st_size or recorded_rows(config) == 0


# ----------------------------------------------------------------------------- nothing is written or kept


def test_a_batch_writes_no_file_and_creates_no_temporary_file_in_check_mode(portal):
    config, signer, client = portal
    send(client, [("warm", signed_report(signer))])  # the engine and the framework are loaded
    raw = signed_report(signer)
    files = [(f"f{i}", raw) for i in range(10)] + [("junk", b"{}")]
    events: list[tuple] = []
    armed = threading.Event()

    def hook(event, args):
        if not armed.is_set():
            return
        if event == "open":
            path, mode, flags = args
            writing = isinstance(mode, str) and any(c in mode for c in "wax+")
            if isinstance(flags, int) and flags & (0o1 | 0o2 | 0o100 | 0o1000 | 0o2000):
                writing = True
            if writing:
                events.append((event, str(path), mode, flags))
        elif event in (
            "tempfile.mkstemp",
            "tempfile.mkdtemp",
            "os.mkdir",
            "os.rename",
            "shutil.copyfile",
        ):
            events.append((event, *map(str, args)))

    sys.addaudithook(hook)
    armed.set()
    try:
        # The control: the hook does see a file opened for writing, so an empty list below means something.
        with open(config.parent / "control.txt", "w") as control:
            control.write("x")
        assert [e[1] for e in events] == [str(config.parent / "control.txt")]
        events.clear()
        response = send(client, files)
    finally:
        armed.clear()
    assert response.status_code == 200 and response.json()["summary"]["trusted"] == 10
    assert events == []


def test_nothing_of_a_batch_is_kept_after_the_response(portal):
    config, signer, client = portal
    before = {p: p.stat().st_mtime_ns for p in config.parent.rglob("*") if p.is_file()}
    marker = "needle-" + uuid.uuid4().hex
    send(client, [(marker, signed_report(signer))])
    assert before == {p: p.stat().st_mtime_ns for p in config.parent.rglob("*") if p.is_file()}
    # and a second batch cannot see the first: ids restart, and the batch id is new
    first = send(client, [("a", signed_report(signer))]).json()
    second = send(client, [("b", signed_report(signer))]).json()
    assert first["batch_id"] != second["batch_id"] and second["files"][0]["id"] == "file-1"
    assert marker not in json.dumps(second)


def test_the_status_says_what_the_batch_limits_are(portal):
    _, _, client = portal
    limits = client.get("/api/status").json()["batch"]
    assert limits == batch_module.limits()
    assert limits["max_files"] == 20 and limits["max_file_bytes"] == MB
