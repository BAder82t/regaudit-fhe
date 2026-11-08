"""The bundled demonstration: made-up reports checked against a demonstration trust list, and nothing else."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest
import regaudit_portal.app as portal_app
from helpers import client_for, post, post_bytes
from regaudit_portal.explain import DEMONSTRATION_NOTICE
from test_sample_data import (
    DEMO_KEY_ID,
    EXPECTED,
    SAMPLE_IDS,
    SAMPLES,
    _bundled,
    engine_verdict,
)

PACKAGE = Path(__file__).parents[1] / "regaudit_portal"


def check_sample(client, sample_id: str):
    return client.post(f"/api/samples/{sample_id}/verify")


@pytest.fixture
def welcome(tmp_path):
    return client_for(None)


# ----------------------------------------------------------------------------- the list and the verdicts


def test_the_samples_are_listed_in_order_with_a_plain_title_and_description(client):
    listing = client.get("/api/status").json()["samples"]
    assert [item["id"] for item in listing] == list(SAMPLE_IDS)
    for item in listing:
        assert set(item) == {"id", "title", "description"}
        assert len(item["title"]) > 10 and len(item["description"]) > 40


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_each_samples_verdict_is_exactly_what_the_engine_returns_for_that_file(client, sample_id):
    body = check_sample(client, sample_id).json()
    direct = engine_verdict(sample_id)
    assert body["verification"] == direct
    status, blocking = EXPECTED[sample_id]
    assert direct["trust_status"] == status and direct["blocking_reasons"] == blocking
    assert body["verification"]["accepted"] is (status == "TRUSTED")


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_a_sample_works_with_no_trust_set_up_at_all(welcome, sample_id):
    response = check_sample(welcome, sample_id)
    assert response.status_code == 200
    assert response.json()["verification"] == engine_verdict(sample_id)


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_a_samples_result_names_the_file_it_checked(client, sample_id):
    body = check_sample(client, sample_id).json()
    assert (
        body["report_sha256"]
        == hashlib.sha256(_bundled("reports", f"{sample_id}.json")).hexdigest()
    )


# ----------------------------------------------------------------------------- every sample result says what it is


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_every_sample_result_and_export_is_labelled_a_synthetic_demonstration(client, sample_id):
    body = check_sample(client, sample_id).json()
    assert body["synthetic_demonstration"] is True
    assert body["demonstration"]["notice"] == DEMONSTRATION_NOTICE
    assert DEMONSTRATION_NOTICE == (
        "This is a synthetic demonstration. The report was made with made-up data and checked against a "
        "demonstration trust list. It says nothing about any real report or issuer."
    )
    assert body["demonstration"]["sample"]["id"] == sample_id
    assert body["demonstration"]["issuer"] == "DEMO-ONLY synthetic issuer"
    assert "demonstration trust list" in body["demonstration"]["trust_list"]
    assert body["explanation"]["warnings"][0] == {
        "code": "DEMONSTRATION_ONLY",
        "message": DEMONSTRATION_NOTICE,
    }
    # the saved file is this whole response with the file name added, so it carries the label too
    saved = {"report_file_name": f"sample-{sample_id}", **body}
    assert json.loads(json.dumps(saved))["synthetic_demonstration"] is True


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_a_sample_result_speaks_of_the_demonstration_not_of_an_administrator(client, sample_id):
    body = check_sample(client, sample_id).json()
    text = json.dumps(body["explanation"])
    assert "administrator" not in text and "your organization" not in text
    assert "demonstration" in text


def test_an_uploaded_report_result_says_it_is_not_a_demonstration(client, demo):
    body = post(client, demo, "1-trusted.json").json()
    assert body["synthetic_demonstration"] is False and "demonstration" not in body
    assert body["explanation"]["warnings"][0]["code"] != "DEMONSTRATION_ONLY"
    assert "your administrator" in body["explanation"]["means"]


def test_the_page_labels_a_sample_result_and_names_its_saved_file_a_demonstration():
    script = (PACKAGE / "static" / "app.js").read_text()
    html = (PACKAGE / "static" / "index.html").read_text()
    assert 'id="demo-banner"' in html[html.index('<section id="result"') :]
    assert (
        "body.synthetic_demonstration === true" in script and "body.demonstration.notice" in script
    )
    assert 'show("demo-banner", demonstration);' in script
    assert '"demonstration-result-"' in script
    download = script[
        script.index("async function download()") : script.index("async function start()")
    ]
    assert "Object.assign({ report_file_name: lastSaved.name }, lastSaved.body)" in download


# ----------------------------------------------------------------------------- the demonstration policy is for samples only


def _policy_keys(monkeypatch) -> list[set[str]]:
    """The trust-list keys of the policy each call to the engine's verify was given."""
    seen: list[set[str]] = []
    real = portal_app.verify

    def spy(env, policy):
        seen.append(set(policy.trust_store.keys))
        return real(env, policy)

    monkeypatch.setattr(portal_app, "verify", spy)
    return seen


def test_the_demonstration_policy_checks_a_sample_and_the_administrators_policy_checks_an_upload(
    client, demo, monkeypatch
):
    seen = _policy_keys(monkeypatch)
    check_sample(client, "trusted")
    post(client, demo, "1-trusted.json")
    assert seen == [{DEMO_KEY_ID}, {"synthetic-issuer-key"}]


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_a_sample_report_uploaded_as_your_own_is_checked_against_the_administrators_policy_and_not_accepted(
    client, monkeypatch, sample_id
):
    seen = _policy_keys(monkeypatch)
    raw = (SAMPLES / "reports" / f"{sample_id}.json").read_bytes()
    body = post_bytes(client, raw).json()
    assert seen == [{"synthetic-issuer-key"}], (
        "the administrator's policy, never the demonstration's"
    )
    assert (
        body["verification"]["trust_status"] == "INVALID"
        and body["verification"]["accepted"] is False
    )
    assert "ISSUER_UNKNOWN" in body["verification"]["blocking_reasons"]
    assert body["synthetic_demonstration"] is False


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_a_sample_report_uploaded_with_no_trust_set_up_is_refused_with_no_verdict(
    welcome, monkeypatch, sample_id
):
    seen = _policy_keys(monkeypatch)
    raw = (SAMPLES / "reports" / f"{sample_id}.json").read_bytes()
    response = post_bytes(welcome, raw)
    assert response.status_code == 503 and seen == []
    body = response.json()
    assert (
        body["error"] == "not_set_up" and "verification" not in body and "explanation" not in body
    )
    assert body["message"] == (
        "Verification of your own reports is not set up yet. An administrator has to set up trust first."
    )


def test_only_the_sample_route_ever_touches_the_demonstration_policy():
    users: dict[str, set[str]] = {}

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack: list[str] = []

        def visit_FunctionDef(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Attribute(self, node):
            if node.attr == "policy" and isinstance(node.value, ast.Name):
                users.setdefault(node.value.id, set()).add(
                    self.stack[-1] if self.stack else "(module)"
                )
            self.generic_visit(node)

    Visitor().visit(ast.parse((PACKAGE / "app.py").read_text()))
    assert users["samples"] == {"check_sample"}, users
    assert users["portal"] <= {"check", "_status_body"}, users
    source = (PACKAGE / "app.py").read_text()
    assert "demonstration_policy" not in source and "load_samples()" in source


# ----------------------------------------------------------------------------- the sample route


@pytest.mark.parametrize(
    "sample_id",
    [
        "nothing",
        "TRUSTED",
        "trusted.json",
        "reports%2Ftrusted",
        "..%2F..%2Fetc%2Fpasswd",
        "%2e%2e",
        "trusted%00",
        "a" * 300,
    ],
)
def test_an_id_that_is_not_in_the_list_is_refused_and_never_used_as_a_file_name(client, sample_id):
    response = client.post(f"/api/samples/{sample_id}/verify")
    assert response.status_code in (404, 405)
    assert "verification" not in response.text


def test_the_sample_route_takes_post_only_and_reads_no_body(client, monkeypatch):
    assert client.get("/api/samples/trusted/verify").status_code == 405
    assert client.put("/api/samples/trusted/verify").status_code == 405
    monkeypatch.setattr(
        portal_app, "_read_limited", lambda *_a, **_k: pytest.fail("a body was read")
    )
    response = client.post("/api/samples/trusted/verify", content=b"x" * (3 << 20))
    assert (
        response.status_code == 200 and response.json()["verification"]["trust_status"] == "TRUSTED"
    )


def test_a_sample_check_counts_against_the_same_rate_limit(client, monkeypatch):
    monkeypatch.setattr(portal_app, "MAX_REQUESTS_PER_MINUTE", 2)
    client = client_for(None)
    codes = [check_sample(client, "trusted").status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429]


def test_the_sample_route_keeps_the_host_and_origin_refusals(client):
    assert (
        client.post("/api/samples/trusted/verify", headers={"host": "evil.example"}).status_code
        == 403
    )
    assert (
        client.post(
            "/api/samples/trusted/verify", headers={"origin": "https://evil.example"}
        ).status_code
        == 403
    )
