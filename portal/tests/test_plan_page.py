"""The plan page, run as the page runs it: what it shows about fingerprints, and that pasted keys do not stay in it.

The page's own script is run here in Node against a small stand-in for the browser's document, with the portal's real
answers, so the tests see what the page does and not only what its text says. They are skipped where Node is not
installed. The checks of the script's text below them always run.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from helpers import JSON_HEADERS, PLAN_VERIFIER, client_for, fake_home, fingerprint_of, issuer_signer, plan_request

PORTAL = Path(__file__).parents[1]
STATIC = PORTAL / "regaudit_portal" / "static"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="Node is not installed")

HARNESS = r"""
const fs = require("fs");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
class El {
  constructor(tag) {
    this.tagName = tag.toUpperCase(); this.children = []; this.parent = null; this.dataset = {}; this.attributes = {};
    this.listeners = {}; this.hidden = false; this.value = ""; this.own = ""; this.checked = false; this.disabled = false;
    this.id = ""; this.name = "";
  }
  get textContent() { return this.own + this.children.map((c) => (typeof c === "string" ? c : c.textContent)).join(""); }
  set textContent(v) { this.own = String(v); this.children = []; }
  append(...items) { for (const i of items) { if (typeof i !== "string") i.parent = this; this.children.push(i); } }
  replaceChildren(...items) { this.children = []; this.own = ""; this.append(...items); }
  remove() { if (this.parent) { this.parent.children = this.parent.children.filter((c) => c !== this); this.parent = null; } }
  setAttribute(k, v) { this.attributes[k] = v; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  click() { if (this.tagName === "A") log.downloads.push({ name: this.download, text: lastBlob }); (this.listeners.click || []).forEach((fn) => fn()); }
  *walk() { for (const c of this.children) if (typeof c !== "string") { yield c; yield* c.walk(); } }
  querySelectorAll(sel) { return [...this.walk()].filter((e) => matches(e, sel)); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}
function matches(e, sel) {
  let m = sel.match(/^\[data-member(?:="([^"]+)")?\]$/);
  if (m) return "member" in e.dataset && (m[1] === undefined || e.dataset.member === m[1]);
  m = sel.match(/^input\[name="([^"]+)"\](:checked)?$/);
  if (m) return e.tagName === "INPUT" && e.name === m[1] && (!m[2] || e.checked);
  return e.tagName === sel.toUpperCase();
}
const log = { sent: [], downloads: [], steps: [] };
let lastBlob = null;
const byId = {};
const roots = [];
const document = {
  getElementById(id) { if (!byId[id]) { const e = new El("div"); e.id = id; byId[id] = e; roots.push(e); } return byId[id]; },
  createElement(tag) { return new El(tag); },
  querySelectorAll(sel) { const out = []; for (const r of roots) { if (matches(r, sel)) out.push(r); out.push(...r.querySelectorAll(sel)); } return out; },
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; },
  body: new El("body"),
};
for (const [value, checked] of [["first-setup", true], ["add-issuers", false]]) {
  const radio = new El("input"); radio.name = "mode"; radio.value = value; radio.checked = checked; roots.push(radio);
}
document.getElementById("max-age").value = "30";
const responses = input.responses.slice();
const fetch = async (path, options) => {
  if (path === "/api/setup") return { json: async () => input.setup };
  if (path !== "/api/setup/plan") throw new Error("unexpected request " + path);
  log.sent.push(JSON.parse(options.body));
  const answer = responses.shift();
  return { json: async () => answer };
};
class FakeBlob { constructor(parts) { lastBlob = parts.join(""); } }
const FakeURL = { createObjectURL: () => "blob:test", revokeObjectURL: () => {} };
const run = new Function("document", "fetch", "Blob", "URL", input.source + "\nreturn { check, save, prepared: () => prepared };");
const page = run(document, fetch, FakeBlob, FakeURL);
const $ = (id) => document.getElementById(id);
const everything = () => {
  const texts = [];
  for (const root of [...roots, document.body]) for (const e of [root, ...root.walk()]) texts.push(e.value || "", e.own || "");
  return texts.join("\n");
};
function fill(values) {
  for (const [member, value] of Object.entries(values.issuer)) $("issuers").querySelector('[data-member="' + member + '"]').value = value;
  $("verifier-id").value = values.verifier_id;
  for (const radio of document.querySelectorAll('input[name="profile"]')) radio.checked = radio.value === "confidential";
}
function snapshot(name) {
  const boxes = {};
  for (const control of $("issuers").querySelectorAll("[data-member]")) boxes[control.dataset.member] = control.value;
  const rows = $("fingerprints").querySelectorAll("tr").map((tr) => tr.querySelectorAll("td").map((td) => td.textContent));
  const prepared = page.prepared();
  log.steps.push({
    name, boxes, verifier_id: $("verifier-id").value, rows, message: $("message").textContent, saved: $("saved").textContent,
    prepared: prepared === null ? null : Object.keys(prepared).sort(), writes: $("writes").textContent,
    save_hidden: $("save").hidden, everything: everything(),
  });
}
(async () => {
  await new Promise((r) => setTimeout(r, 0));
  for (const step of input.steps) {
    if (step.fill) fill(step.fill);
    if (step.action === "check") await page.check();
    if (step.action === "save") page.save();
    snapshot(step.name);
  }
  process.stdout.write(JSON.stringify(log));
})().catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""


@pytest.fixture
def welcome(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    return client_for(None)


def _run_page(setup: dict, responses: list[dict], steps: list[dict]) -> dict:
    assert NODE is not None
    given = {"source": (STATIC / "plan.js").read_text(), "setup": setup, "responses": responses, "steps": steps}
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [NODE, "-e", HARNESS], input=json.dumps(given), capture_output=True, text=True, timeout=60, check=False
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _answer(client, signer, fingerprint: str) -> dict:
    request = plan_request([signer], fingerprints=[fingerprint])
    return client.post("/api/setup/plan", content=json.dumps(request).encode(), headers=JSON_HEADERS).json()


def _form(signer, fingerprint: str, public_key: str | None = None, issuer: str | None = None) -> dict:
    return {
        "issuer": {
            "issuer": issuer if issuer is not None else signer.issuer,
            "key_id": signer.key_id,
            "public_key": public_key if public_key is not None else signer.public_key_pem(),
            "fingerprint": fingerprint,
        },
        "verifier_id": PLAN_VERIFIER,
    }


def _key_line(pem: str) -> str:
    return pem.strip().splitlines()[1]


@needs_node
def test_a_mismatch_shows_only_that_it_does_not_match_and_the_pasted_key_is_cleared(welcome):
    signer = issuer_signer()
    typed = "ab" * 32
    done = _run_page(
        welcome.get("/api/setup").json(),
        [_answer(welcome, signer, typed)],
        [{"name": "checked", "fill": _form(signer, typed), "action": "check"}],
    )
    assert done["sent"][0]["issuers"][0]["public_key"] == signer.public_key_pem()  # it was used for the check
    step = done["steps"][0]
    assert step["rows"] == [[f"1. {signer.issuer} (key id {signer.key_id})", "No: it does not match this key"]]
    assert step["boxes"]["public_key"] == "" and step["prepared"] is None
    assert step["message"].endswith("The public keys you pasted were cleared from the page.")
    assert _key_line(signer.public_key_pem()) not in step["everything"]
    assert fingerprint_of(signer) not in step["everything"]


@needs_node
def test_a_private_key_is_never_sent_and_is_cleared_with_the_public_keys(welcome):
    signer = issuer_signer()
    private = (
        Ed25519PrivateKey.generate()
        .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        .decode()
    )
    for form in (
        _form(signer, fingerprint_of(signer), public_key=private),  # in the key box
        _form(signer, fingerprint_of(signer), issuer=private),  # in another box
    ):
        done = _run_page(welcome.get("/api/setup").json(), [], [{"name": "refused", "fill": form, "action": "check"}])
        step = done["steps"][0]
        assert done["sent"] == [] and step["message"].startswith("Something you entered looks like a private")
        assert step["boxes"]["public_key"] == "" and step["boxes"]["issuer"] in ("", signer.issuer)
        assert _key_line(private) not in step["everything"]


@needs_node
def test_a_good_plan_keeps_only_what_saving_needs_and_nothing_once_saved(welcome):
    signer = issuer_signer()
    answer = _answer(welcome, signer, fingerprint_of(signer))
    done = _run_page(
        welcome.get("/api/setup").json(),
        [answer],
        [
            {"name": "checked", "fill": _form(signer, fingerprint_of(signer)), "action": "check"},
            {"name": "saved", "action": "save"},
        ],
    )
    checked, saved = done["steps"]
    assert checked["boxes"]["public_key"] == "" and checked["prepared"] == ["file_name", "plan_text"]
    assert checked["rows"] == [[f"1. {signer.issuer} (key id {signer.key_id})", "Yes"]]
    # Only the administrator's own typing holds the fingerprint: nothing the portal answered shows it.
    for shown in (checked["writes"], checked["message"], json.dumps(checked["rows"])):
        assert fingerprint_of(signer) not in shown
    assert done["downloads"] == [{"name": answer["file_name"], "text": answer["plan_text"]}]
    assert saved["prepared"] is None and saved["writes"] == "" and saved["save_hidden"] is True
    assert saved["saved"].endswith("The plan was cleared from this page.")
    assert _key_line(signer.public_key_pem()) not in saved["everything"]


@needs_node
def test_guard_off_without_clearing_the_pasted_key_stays_in_the_page(welcome):
    """The control: with the clearing switched off, the key is still in its box after the check."""
    signer = issuer_signer()
    typed = "ab" * 32
    source = (STATIC / "plan.js").read_text().replace(
        "  clearKeyMaterial(); // from here", "  // switched off for the control // from here"
    )
    assert "clearKeyMaterial();" not in source.split("function clearKeyMaterial")[1].split("async function check")[1]
    given = {
        "source": source,
        "setup": welcome.get("/api/setup").json(),
        "responses": [_answer(welcome, signer, typed)],
        "steps": [{"name": "checked", "fill": _form(signer, typed), "action": "check"}],
    }
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [NODE, "-e", HARNESS], input=json.dumps(given), capture_output=True, text=True, timeout=60, check=False
    )
    assert done.returncode == 0, done.stderr
    step = json.loads(done.stdout)["steps"][0]
    assert step["boxes"]["public_key"] == signer.public_key_pem()


# ----------------------------------------------------------------------------- the script's text, always checked


def test_the_script_clears_the_keys_on_every_outcome_of_a_check_and_keeps_only_the_plan_to_save():
    script = (STATIC / "plan.js").read_text()
    check = script.split("async function check() {")[1].split("\nfunction save() {")[0]
    assert check.index("clearKeyMaterial();") < check.index("if (secret)") < check.index("await fetch(")
    assert "prepared = { plan_text: body.plan_text, file_name: body.file_name };" in check
    assert "prepared = body" not in script
    save = script.split("function save() {")[1].split("\nfunction showMode()")[0]
    assert save.index("prepared = null;") < save.index("link.click();")
    assert 'control.dataset.member === "public_key" || SECRET.test(control.value)' in script
