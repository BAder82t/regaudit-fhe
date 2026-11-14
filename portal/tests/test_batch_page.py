"""The batch part of the page: planning against the limits, the request it builds, the rows it shows, and the check that a
batch result is consistent before it is shown or saved.

The page's own pure functions are run in Node from the shipped ``app.js``, so the tests see what the page does. They are
skipped where Node is not installed. Three things are shown:

* the request the page builds is exactly what the portal's own reader accepts, and the page refuses over-limit batches
  before sending anything, with the same limits the portal enforces;
* the rows show the verifier's verdict for each file unchanged, and nothing for a file the portal could not check;
* ``validateBatch`` accepts what the portal really returns for real reports and refuses every tampered variant, and each
  file of a real batch has the same verdict as the same bytes sent alone.
"""

from __future__ import annotations

import base64
import copy
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import regaudit_portal.batch as batch_module
from helpers import JSON_HEADERS, client_for, make_portal, signed_report

import regaudit_fhe as rf

PORTAL = Path(__file__).parents[1]
SCRIPT = PORTAL / "regaudit_portal" / "static" / "app.js"
INDEX = PORTAL / "regaudit_portal" / "static" / "index.html"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="Node is not installed")

HARNESS = r"""
const fs = require("fs");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const source = input.source;
const cut = (a, b) => { const i = source.indexOf(a), j = source.indexOf(b); if (i < 0 || j < i) throw new Error("missing " + a); return source.slice(i, j); };
const parts = cut("const STATEMENTS = [", "function render(body, fileName)") + "\n" +
  cut("const BATCH_SCHEMA", "function renderBatch(answer)");
const api = new Function(parts + "\nreturn { planBatch, batchRequestBody, batchRows, validateBatch, batchLimits, BATCH_FALLBACK };")();
const out = {};
for (const [name, args] of Object.entries(input.calls)) {
  try {
    if (name === "request") {
      out[name] = api.batchRequestBody(args[0].map((e) => ({ name: e.name, bytes: Uint8Array.from(Buffer.from(e.b64, "base64")) })));
    } else {
      out[name] = api[args[0]](...args.slice(1));
    }
  } catch (e) { out[name] = { threw: String(e) }; }
}
process.stdout.write(JSON.stringify(out));
"""


def page(**calls) -> dict:
    assert NODE is not None
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [NODE, "-e", HARNESS],
        input=json.dumps({"source": SCRIPT.read_text(), "calls": calls}),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


LIMITS = {"max_files": 20, "max_file_bytes": 1 << 20, "max_total_bytes": 8 << 20}


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


@pytest.fixture
def portal(tmp_path):
    config, signer = make_portal(tmp_path / "p")
    return config, signer, client_for(config)


def real_batch(
    client, signer, extra: dict[str, bytes] | None = None
) -> tuple[dict, dict[str, bytes]]:
    stranger = rf.Signer.generate(issuer="Northwind Test Issuer", key_id="k-other")
    tampered = json.loads(signed_report(signer))
    tampered["deployment_id"] = "changed-after-signing"
    files = {
        "trusted.json": signed_report(signer),
        "unknown-issuer.json": signed_report(stranger),
        "tampered.json": json.dumps(tampered).encode(),
        "not-a-report.json": b'{"hello": "x"}',
        "garbage.json": b"\xff\xfe not json",
        **(extra or {}),
    }
    body = {"files": [{"name": n, "content_b64": b64(c)} for n, c in files.items()]}
    response = client.post(
        "/api/verify-batch", content=json.dumps(body).encode(), headers=JSON_HEADERS
    )
    assert response.status_code == 200, response.text
    return response.json(), files


# --- the limits the page plans against are the portal's own ------------------------------------------------------------


@needs_node
def test_the_page_falls_back_to_the_portals_own_limits_and_uses_the_ones_it_is_told():
    out = page(
        fallback=["batchLimits", None],
        told=[
            "batchLimits",
            {"batch": {"max_files": 3, "max_file_bytes": 10, "max_total_bytes": 20}},
        ],
        odd=[
            "batchLimits",
            {"batch": {"max_files": -1, "max_file_bytes": "x", "max_total_bytes": 1.5}},
        ],
    )
    assert out["fallback"] == {
        "max_files": batch_module.MAX_FILES,
        "max_file_bytes": batch_module.MAX_REPORT_BYTES,
        "max_total_bytes": batch_module.MAX_TOTAL_REPORT_BYTES,
    }
    assert out["told"] == {"max_files": 3, "max_file_bytes": 10, "max_total_bytes": 20}
    assert out["odd"] == out["fallback"]  # a nonsense limit is never trusted


@needs_node
def test_a_batch_over_any_limit_is_refused_before_anything_is_sent_and_at_the_boundary_it_is_not():
    f = lambda n, size: [{"name": f"f{i}", "size": size} for i in range(n)]  # noqa: E731
    mb = 1 << 20
    out = page(
        none=["planBatch", [], LIMITS],
        one=["planBatch", f(1, 10), LIMITS],
        twenty=["planBatch", f(20, 10), LIMITS],
        twentyone=["planBatch", f(21, 10), LIMITS],
        one_at_limit=["planBatch", f(1, mb), LIMITS],
        one_over=["planBatch", f(1, mb + 1), LIMITS],
        eight_total=["planBatch", f(8, mb), LIMITS],
        nine_total=["planBatch", f(9, mb), LIMITS],
        big_and_small=[
            "planBatch",
            [{"name": "a", "size": mb + 1}, {"name": "b", "size": 1}],
            LIMITS,
        ],
    )
    ok = {n: out[n]["ok"] for n in out}
    assert ok == {
        "none": False,
        "one": True,
        "twenty": True,
        "twentyone": False,
        "one_at_limit": True,
        "one_over": False,
        "eight_total": True,
        "nine_total": False,
        "big_and_small": False,  # one over-limit file refuses the batch whole, as the portal does
    }
    for refused in ("none", "twentyone", "one_over", "nine_total", "big_and_small"):
        assert "Nothing was verified" in out[refused]["message"] or refused == "none"
    assert str(batch_module.MAX_FILES) in out["twentyone"]["message"]


# --- the request the page builds is what the portal's reader accepts --------------------------------------------------


@needs_node
def test_the_request_the_page_builds_is_exactly_what_the_portals_reader_accepts():
    files = [
        {"name": "a.json", "b64": b64(b'{"x": 1}')},
        {
            "name": "b é.json",
            "b64": b64(bytes(range(256)) * 300),
        },  # binary, past the page's 32 KiB chunk size
    ]
    out = page(request=[files])
    built = out["request"]
    assert isinstance(built, str)
    items = batch_module.read_items(built.encode())
    assert [i.name for i in items] == ["a.json", "b é.json"]
    assert [batch_module.decode(i) for i in items] == [base64.b64decode(f["b64"]) for f in files]
    assert set(json.loads(built)) == {"files"}  # nothing else is sent: no path, no extra member


# --- the rows show the verifier's words, unchanged ------------------------------------------------------------------


@needs_node
def test_each_row_shows_the_verifiers_verdict_for_that_file_and_a_refused_file_has_no_verdict(
    portal,
):
    _config, signer, client = portal
    answer, files = real_batch(client, signer)
    rows = page(rows=["batchRows", answer])["rows"]
    assert [r["name"] for r in rows] == list(files)
    by_name = {r["name"]: r for r in rows}
    for name, entry in zip(files, answer["files"], strict=True):
        row = by_name[name]
        if entry["ok"]:
            assert row["verdict"] == entry["result"]["verification"]["trust_status"]  # unchanged
            assert [s["key"] for s in row["statements"]] == [
                "signature", "issuer_trust", "freshness", "replay", "encryption_claims",
            ]  # fmt: skip
        else:
            assert row["verdict"] is None and row["statements"] == [] and row["message"]
    assert by_name["trusted.json"]["verdict"] == "TRUSTED"
    assert by_name["unknown-issuer.json"]["verdict"] != "TRUSTED"
    assert by_name["garbage.json"]["verdict"] is None


# --- the export is checked for consistency before it is shown or saved --------------------------------------------


@needs_node
def test_a_real_batch_answer_passes_the_consistency_check(portal):
    _config, signer, client = portal
    answer, _files = real_batch(client, signer)
    assert page(v=["validateBatch", answer])["v"] == []


def _tamper_cases(answer: dict) -> dict[str, dict]:
    ok_index = next(i for i, f in enumerate(answer["files"]) if f["ok"])
    bad_index = next(i for i, f in enumerate(answer["files"]) if not f["ok"])
    cases: dict[str, dict] = {}

    def case(name, edit):
        copy_ = copy.deepcopy(answer)
        edit(copy_)
        cases[name] = copy_

    case(
        "verdict_word_changed",
        lambda a: a["files"][ok_index]["result"]["verification"].update(trust_status="PROVEN"),
    )
    case(
        "statements_name_another_verdict",
        lambda a: a["files"][ok_index]["result"]["statuses"].update(
            verdict="TRUSTED"
            if a["files"][ok_index]["result"]["verification"]["trust_status"] != "TRUSTED"
            else "INVALID"
        ),
    )
    case("total_wrong", lambda a: a["summary"].update(total=a["summary"]["total"] + 1))
    case("trusted_count_wrong", lambda a: a["summary"].update(trusted=a["summary"]["trusted"] + 1))
    case("refused_count_wrong", lambda a: a["summary"].update(refused=0))
    case("files_reordered", lambda a: a["files"].reverse())
    case("file_dropped", lambda a: a["files"].pop())
    case("id_changed", lambda a: a["files"][0].update(id="file-9"))
    case(
        "result_and_error",
        lambda a: a["files"][ok_index].update(error={"error": "x", "message": "y"}),
    )
    case(
        "error_with_result",
        lambda a: a["files"][bad_index].update(
            result=copy.deepcopy(a["files"][ok_index]["result"])
        ),
    )
    case("digest_removed", lambda a: a["files"][ok_index].update(report_sha256=None))
    case("wrong_schema", lambda a: a.update(schema="something-else"))
    case("no_summary", lambda a: a.pop("summary"))
    case(
        "complete_but_not_run",
        lambda a: (
            a["files"][bad_index].update(error={"error": "not_run", "message": "m"}),
            a.update(complete=True),
        ),
    )
    return cases


@needs_node
def test_every_tampered_variant_of_a_batch_answer_is_refused(portal):
    _config, signer, client = portal
    answer, _files = real_batch(client, signer)
    cases = _tamper_cases(answer)
    assert len(cases) >= 12
    results = page(**{name: ["validateBatch", variant] for name, variant in cases.items()})
    unflagged = [name for name, problems in results.items() if problems == []]
    assert unflagged == [], f"these tampered answers passed the check: {unflagged}"


@needs_node
@pytest.mark.parametrize(
    "junk",
    [
        None,
        [],
        "text",
        5,
        {},
        {"schema": "regaudit-portal-batch/1"},
        {"schema": "x", "files": [], "summary": {}},
    ],
)
def test_a_value_that_is_not_a_batch_answer_is_refused_without_throwing(junk):
    problems = page(v=["validateBatch", junk])["v"]
    assert isinstance(problems, list) and problems, problems


# --- each file of a batch has the verdict the same bytes get alone, and the page's check agrees --------------------------


def test_each_file_of_a_real_batch_has_the_single_files_verdict_and_statements(portal):
    _config, signer, client = portal
    answer, files = real_batch(client, signer)
    for entry, (name, raw) in zip(answer["files"], files.items(), strict=True):
        alone = client.post("/api/verify", content=raw, headers=JSON_HEADERS)
        if entry["ok"]:
            assert alone.status_code == 200, name
            single = alone.json()
            assert entry["result"]["verification"] == single["verification"], name
            assert entry["result"]["statuses"] == single["statuses"], name
            assert entry["result"]["explanation"] == single["explanation"], name
            assert entry["report_sha256"] == single["report_sha256"], name
        else:
            assert alone.status_code != 200, name


# --- the page itself ------------------------------------------------------------------------------------------------------


def test_the_batch_markup_exists_and_the_batch_code_never_builds_markup_from_report_text():
    html = INDEX.read_text()
    for needed in (
        "batch-files",
        "batch-verify",
        "batch-cancel",
        "batch-result",
        "batch-summary",
        "batch-rows",
        "batch-download",
    ):
        assert f'id="{needed}"' in html, needed
    assert "multiple" in html
    script = SCRIPT.read_text()
    section = script[
        script.index("// ---- Several reports at once") : script.index("async function start()")
    ]
    for forbidden in ("innerHTML", "insertAdjacentHTML", "outerHTML", "document.write", "eval("):
        assert forbidden not in section, forbidden
    assert re.search(r"fetch\(\"/api/verify-batch\"", section)
    assert (
        "localStorage" not in section
        and "sessionStorage" not in section
        and "indexedDB" not in section
    )
    assert "AbortController" in section  # cancellation is wired


def test_the_page_never_names_a_file_in_a_url_or_a_path():
    script = SCRIPT.read_text()
    section = script[
        script.index("// ---- Several reports at once") : script.index("async function start()")
    ]
    # The only request is a POST to one fixed path with the bytes in the body.
    assert re.findall(r"fetch\(([^,)]+)", section) == [
        '"/api/status"',
        '"/api/verify-batch"',
        '"/api/status"',
    ]
