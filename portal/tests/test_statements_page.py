"""The page shows the five separate statements without turning any of them into a conclusion the verifier did not reach.

The page's own ``statementRows`` and ``renderStatements`` are run here, in Node, from the shipped ``app.js``, so the tests
see what the page does and not only what its text says. They are skipped where Node is not installed. The consistency test
reads the states the Python side can emit from ``statuses.py`` and checks that each has fixed wording on the page.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from helpers import client_for, fake_home

PORTAL = Path(__file__).parents[1]
SCRIPT = PORTAL / "regaudit_portal" / "static" / "app.js"
INDEX = PORTAL / "regaudit_portal" / "static" / "index.html"
STATUSES = PORTAL / "regaudit_portal" / "statuses.py"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="Node is not installed")

HARNESS = r"""
const fs = require("fs");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const source = input.source;
const from = source.indexOf("const STATEMENTS = [");
const to = source.indexOf("function render(body, fileName)");
if (from < 0 || to < from) throw new Error("the statement code was not found");
const made = [];
const elements = {};
const shown = {};
const makeNode = (tag) => ({
  tag, children: [], dataset: {}, className: "", textContent: "",
  append(...kids) { this.children.push(...kids); },
  replaceChildren(...kids) { this.children = kids; },
});
const $ = (id) => elements[id] || (elements[id] = makeNode("#" + id));
const show = (id, visible) => { shown[id] = visible; };
const document = { createElement: (tag) => { const n = makeNode(tag); made.push(n); return n; } };
const code = source.slice(from, to) + "\nreturn { STATEMENTS, statementRows, renderStatements };";
const api = new Function("$", "show", "document", code)($, show, document);
const out = { rows: api.statementRows(input.statuses), table: api.STATEMENTS.map(([k, l, w]) => [k, l, w]) };
api.renderStatements(input.statuses);
const flat = (n) => (n.textContent || "") + (n.children || []).map(flat).join("");
out.shown = shown;
out.items = $("statements").children.map((li) => ({ state: li.dataset.state, key: li.dataset.statement, text: flat(li) }));
process.stdout.write(JSON.stringify(out));
"""


def run_page(statuses) -> dict:
    assert NODE is not None
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [NODE, "-e", HARNESS],
        input=json.dumps({"source": SCRIPT.read_text(), "statuses": statuses}),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def entry(state: str, text: str = "words", limit: str | None = "limit words") -> dict:
    return {"state": state, "text": text, "limit": limit, "derived_from": [], "details": {}}


FIVE = ("signature", "issuer_trust", "freshness", "replay", "encryption_claims")


@needs_node
def test_the_five_statements_are_shown_in_a_fixed_order_with_the_portals_own_words():
    statuses = {
        "signature": entry("passed", "sig text", "sig limit"),
        "issuer_trust": entry("not_listed", "issuer text", "issuer limit"),
        "freshness": entry("within_limit", "age text", None),
        "replay": entry("checked_not_seen", "replay text", "replay limit"),
        "encryption_claims": entry("declared_by_signer", "enc text", "enc limit"),
    }
    out = run_page(
        dict(reversed(list(statuses.items())))
    )  # the order of the members must not decide the order shown
    assert [r["key"] for r in out["rows"]] == list(FIVE)
    assert out["shown"] == {"statements-box": True}
    flat = [i["text"] for i in out["items"]]
    for needle, line in zip(
        ("sig text", "issuer text", "age text", "replay text", "enc text"), flat, strict=True
    ):
        assert needle in line
    assert (
        "age limit" not in " ".join(flat) and "sig limit" in flat[0]
    )  # a missing limit is not invented


@needs_node
def test_every_state_the_python_side_can_return_has_fixed_wording_on_the_page():
    """If statuses.py gains a state the page lacks, the page would show it as 'not interpreted'. This test fails first."""
    source = STATUSES.read_text()
    emitted = set(re.findall(r'state = "([a-z_]+)"', source)) | set(
        re.findall(r'"[A-Z_]+": "([a-z_]+)"', source)
    )
    emitted |= {"not_stated"}  # the .get() default of the encryption statement
    table = {k: set(w) for k, _l, w in run_page({})["table"]}
    on_page = set().union(*table.values())
    assert emitted <= on_page, sorted(emitted - on_page)
    states_per = {
        "signature": {"passed", "failed", "not_checked"},
        "issuer_trust": {"listed", "listed_with_limit", "not_listed"},
        "freshness": {"within_limit", "too_old", "from_future", "not_checked"},
        "replay": {
            "repeat_detected",
            "state_unavailable",
            "recorded",
            "checked_not_seen",
            "not_checked",
        },
        "encryption_claims": {"plaintext_stated", "declared_by_signer", "not_stated"},
    }
    assert table == states_per


@needs_node
def test_no_wording_on_the_page_turns_a_statement_into_a_trust_conclusion():
    forbidden = re.compile(
        r"\b(trusted|verified|authentic|genuine|secure|safe|certified|compliant|approved|proves?|guarantee[sd]?)\b",
        re.IGNORECASE,
    )
    words = [w for _k, _l, ws in run_page({})["table"] for w in ws.values()]
    labels = [label for _k, label, _ws in run_page({})["table"]]
    bad = [w for w in words + labels if forbidden.search(w)]
    # "not verified" is the one phrase that denies a claim; everything else must be free of these words.
    assert [w for w in bad if "not verified" not in w] == []


@needs_node
def test_a_state_the_page_does_not_know_is_shown_as_sent_and_marked_not_interpreted():
    out = run_page(
        {"signature": entry("quantum_valid"), **{k: entry("not_checked") for k in FIVE[1:]}}
    )
    first = out["rows"][0]
    assert first["known"] is False
    assert first["stateText"] == "quantum_valid (not interpreted by this page)"
    assert "valid" not in first["stateText"].replace("quantum_valid", "")


@needs_node
@pytest.mark.parametrize(
    "statuses",
    [
        None,
        {},
        [],
        "text",
        5,
        {"signature": None},
        {"signature": "x"},
        {"unrelated": entry("passed")},
    ],
)
def test_missing_or_odd_statuses_show_nothing_and_do_not_throw(statuses):
    out = run_page(statuses)
    assert out["rows"] == [] and out["shown"] == {"statements-box": False} and out["items"] == []


@needs_node
def test_report_text_is_shown_as_text_never_as_markup():
    hostile = "<img src=x onerror=alert(1)>‮<script>1</script>"
    out = run_page(
        {
            "signature": entry("passed", hostile, hostile),
            **{k: entry("not_checked") for k in FIVE[1:]},
        }
    )
    assert (
        hostile in out["items"][0]["text"]
    )  # present as plain text in a textContent, which the page never parses
    page = SCRIPT.read_text()
    section = page[page.index("function renderStatements") : page.index("function render(body")]
    assert (
        "innerHTML" not in section
        and "insertAdjacentHTML" not in section
        and "outerHTML" not in section
    )


def test_the_page_has_the_container_and_does_not_replace_the_verdict_markup():
    html = INDEX.read_text()
    assert 'id="statements-box"' in html and 'id="statements"' in html
    for kept in (
        'id="verdict"',
        'id="verdict-meaning"',
        'id="fhe-notice"',
        'id="reasons-box"',
        'id="raw"',
    ):
        assert kept in html, kept
    assert (
        "Signature verification does not verify that any FHE (encrypted) computation was executed."
        in html
    )


@needs_node
def test_the_statements_the_portal_really_returns_are_all_understood_by_the_page(
    tmp_path, monkeypatch, demo
):
    """End to end over the real engine: every sample's statuses are rendered with known wording and the same verdict."""
    fake_home(tmp_path, monkeypatch)
    client = client_for(demo / "portal-config.json")
    samples = client.get("/api/status").json()["samples"]
    assert samples
    for sample in samples:
        body = client.post(f"/api/samples/{sample['id']}/verify").json()
        assert body["statuses"]["verdict"] == body["verification"]["trust_status"]
        out = run_page(body["statuses"])
        assert [r["key"] for r in out["rows"]] == list(FIVE), sample["id"]
        assert all(r["known"] for r in out["rows"]), (
            sample["id"],
            [r["state"] for r in out["rows"] if not r["known"]],
        )
