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
from helpers import (
    JSON_HEADERS,
    PLAN_VERIFIER,
    client_for,
    fake_home,
    fingerprint_of,
    issuer_signer,
    plan_request,
)

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
  removeAttribute(k) { delete this.attributes[k]; }
  focus() { log.focus = describe(this); }
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
const log = { sent: [], downloads: [], steps: [], focus: null };
// A box as a person would name it: "issuer 1, public_key", or the id or name of a box outside the issuers.
function describe(e) {
  const sets = document.getElementById("issuers").querySelectorAll("fieldset");
  const index = sets.findIndex((set) => set.querySelectorAll("[data-member]").includes(e));
  return index >= 0 ? "issuer " + (index + 1) + ", " + e.dataset.member : e.name || e.id;
}
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
  const profile = values.profile === undefined ? "confidential" : values.profile;
  for (const radio of document.querySelectorAll('input[name="profile"]')) radio.checked = radio.value === profile;
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
    problems: $("problems").hidden ? [] : $("problems").children.map((li) => li.textContent), focus: log.focus,
    choices: document.querySelectorAll("input").filter((r) => r.name === "profile" || r.name === "replay").map((r) => {
      const all = roots.flatMap((x) => [x, ...x.walk()]);
      const find = (id) => all.find((e) => e.id === id && id);
      return { group: r.name, value: r.value, label: r.parent.textContent,
        name: (find(r.attributes["aria-labelledby"]) || {}).textContent || null,
        description: (find(r.attributes["aria-describedby"]) || {}).textContent || null };
    }),
    invalid: [...$("issuers").querySelectorAll("[data-member]"), $("verifier-id"), $("max-age"),
      ...document.querySelectorAll('input[name="profile"]')].filter((e) => e.attributes["aria-invalid"] === "true").map(describe),
  });
  log.focus = null;
}
(async () => {
  await new Promise((r) => setTimeout(r, 0));
  for (const step of input.steps) {
    if (step.fill) fill(step.fill);
    if (step.max_age !== undefined) $("max-age").value = step.max_age;
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
    given = {
        "source": (STATIC / "plan.js").read_text(),
        "setup": setup,
        "responses": responses,
        "steps": steps,
    }
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [NODE, "-e", HARNESS],
        input=json.dumps(given),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _answer(client, signer, fingerprint: str) -> dict:
    request = plan_request([signer], fingerprints=[fingerprint])
    return client.post(
        "/api/setup/plan", content=json.dumps(request).encode(), headers=JSON_HEADERS
    ).json()


def _form(
    signer, fingerprint: str, public_key: str | None = None, issuer: str | None = None
) -> dict:
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
    assert (
        done["sent"][0]["issuers"][0]["public_key"] == signer.public_key_pem()
    )  # it was used for the check
    step = done["steps"][0]
    assert step["rows"] == [
        [f"1. {signer.issuer} (key id {signer.key_id})", "No: it does not match this key"]
    ]
    assert step["boxes"]["public_key"] == "" and step["prepared"] is None
    assert step["message"].endswith(
        "The public key box was emptied, as after every check: paste the public key again, then type the fingerprint "
        "the issuer gave you and press Check the plan."
    )
    assert step["focus"] == "issuer 1, public_key"  # the emptied box, to paste the key again
    assert step["invalid"] == ["issuer 1, public_key", "issuer 1, fingerprint"]
    assert _key_line(signer.public_key_pem()) not in step["everything"]
    assert fingerprint_of(signer) not in step["everything"]


@needs_node
def test_a_private_key_is_never_sent_and_is_cleared_with_the_public_keys(welcome):
    signer = issuer_signer()
    private = (
        Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    for form in (
        _form(signer, fingerprint_of(signer), public_key=private),  # in the key box
        _form(signer, fingerprint_of(signer), issuer=private),  # in another box
    ):
        done = _run_page(
            welcome.get("/api/setup").json(),
            [],
            [{"name": "refused", "fill": form, "action": "check"}],
        )
        step = done["steps"][0]
        assert done["sent"] == [] and step["message"].startswith(
            "Something you entered looks like a private"
        )
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
    assert checked["boxes"]["public_key"] == "" and checked["prepared"] == [
        "file_name",
        "plan_text",
    ]
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
    source = (
        (STATIC / "plan.js")
        .read_text()
        .replace(
            "  clearKeyMaterial(); // from here", "  // switched off for the control // from here"
        )
    )
    assert (
        "clearKeyMaterial();"
        not in source.split("function clearKeyMaterial")[1].split("async function check")[1]
    )
    given = {
        "source": source,
        "setup": welcome.get("/api/setup").json(),
        "responses": [_answer(welcome, signer, typed)],
        "steps": [{"name": "checked", "fill": _form(signer, typed), "action": "check"}],
    }
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [NODE, "-e", HARNESS],
        input=json.dumps(given),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    step = json.loads(done.stdout)["steps"][0]
    assert step["boxes"]["public_key"] == signer.public_key_pem()


@needs_node
def test_an_empty_form_lists_everything_missing_sends_nothing_and_says_nothing_about_keys(welcome):
    done = _run_page(welcome.get("/api/setup").json(), [], [{"name": "empty", "action": "check"}])
    step = done["steps"][0]
    assert done["sent"] == []
    assert (
        step["message"]
        == "Nothing was sent. Correct what is listed below, then press Check the plan again."
    )
    assert step["problems"] == [
        "Choose a profile.",
        "Type your verifier id.",
        "Issuer 1: type the issuer's name.",
        "Issuer 1: type the key id.",
        "Issuer 1: paste the issuer's public key.",
        "Issuer 1: type the fingerprint the issuer gave you.",
    ]
    assert step["focus"] == "profile"  # the first box that needs attention
    assert "issuer 1, fingerprint" in step["invalid"] and "verifier-id" in step["invalid"]
    assert "cleared" not in step["message"] and "configuration" not in step["message"]


@needs_node
def test_a_missing_fingerprint_is_listed_and_the_pasted_key_must_be_pasted_again(welcome):
    signer = issuer_signer()
    done = _run_page(
        welcome.get("/api/setup").json(),
        [],
        [{"name": "no fingerprint", "fill": _form(signer, ""), "action": "check"}],
    )
    step = done["steps"][0]
    assert done["sent"] == []
    assert step["problems"] == ["Issuer 1: type the fingerprint the issuer gave you."]
    assert step["message"].endswith(
        "The public keys you pasted were cleared from the page, as after every check: paste them again."
    )
    assert step["boxes"]["public_key"] == "" and step["focus"] == "issuer 1, fingerprint"


@needs_node
def test_a_problem_the_portal_finds_is_said_in_plain_words_at_its_box(welcome):
    bundled = json.loads((STATIC.parent / "samples" / "demo-trust-list.json").read_text())
    pem = bundled["entries"]["demo-only-synthetic-key"]["public_key_pem"]
    typed = "220618ae027e2cf3c634778f5f4708fc1ea53006973d379ef0d799d936e30df8"
    request = plan_request([issuer_signer()], fingerprints=[typed])
    request["issuers"][0]["public_key"] = pem
    answer = welcome.post(
        "/api/setup/plan", content=json.dumps(request).encode(), headers=JSON_HEADERS
    ).json()
    assert answer["where"] == "issuer 1, public key"
    done = _run_page(
        welcome.get("/api/setup").json(),
        [answer],
        [
            {
                "name": "demo key",
                "fill": _form(issuer_signer(), typed, public_key=pem),
                "action": "check",
            }
        ],
    )
    step = done["steps"][0]
    assert step["message"].startswith(
        "Issuer 1, public key: This is one of the portal's demonstration keys"
    )
    assert step["focus"] == "issuer 1, public_key" and step["boxes"]["public_key"] == ""
    assert "paste them again" in step["message"]


@needs_node
def test_a_configuration_problem_has_no_technical_prefix_and_focuses_its_box(welcome):
    signer = issuer_signer()
    request = plan_request([signer], verifier_id=" spaced")
    answer = welcome.post(
        "/api/setup/plan", content=json.dumps(request).encode(), headers=JSON_HEADERS
    ).json()
    assert answer["where"] == "configuration"
    form = _form(signer, fingerprint_of(signer))
    form["verifier_id"] = " spaced"
    done = _run_page(
        welcome.get("/api/setup").json(),
        [answer],
        [{"name": "spaced", "fill": form, "action": "check"}],
    )
    step = done["steps"][0]
    assert step["message"].startswith(answer["message"])
    assert "configuration:" not in step["message"]
    assert step["focus"] == "verifier-id" and step["invalid"] == ["verifier-id"]


@needs_node
def test_each_profile_has_a_short_accessible_name_and_a_separate_description(welcome):
    setup = welcome.get("/api/setup").json()
    done = _run_page(setup, [], [{"name": "shown"}])
    choices = done["steps"][0]["choices"]
    profiles = [c for c in choices if c["group"] == "profile"]
    assert [c["value"] for c in profiles] == [p["name"] for p in setup["guide"]["profiles"]]
    for shown, profile in zip(profiles, setup["guide"]["profiles"], strict=True):
        lines = [profile["summary"], *profile["does"], *profile["does_not"]]
        assert shown["name"] == profile["title"] + "."  # short: the title alone
        assert shown["description"] == "".join(" " + line for line in lines)
        # The layout and the text a person reads are as before: the title, then what it means, in one label.
        assert shown["label"] == " " + profile["title"] + "." + shown["description"]
    # The replay modes have no title of their own, so their whole text stays their name.
    assert all(
        c["name"] is None and c["description"] is None for c in choices if c["group"] == "replay"
    )


@needs_node
def test_a_maximum_age_out_of_range_is_not_called_missing(welcome):
    """The lead says to correct what is listed, which fits a wrong value as well as a missing one."""
    signer = issuer_signer()
    form = _form(signer, fingerprint_of(signer))
    done = _run_page(
        welcome.get("/api/setup").json(),
        [],
        [{"name": "age", "fill": form, "action": "check", "max_age": "0"}],
    )
    step = done["steps"][0]
    assert done["sent"] == []
    assert step["problems"] == [
        "Type the maximum report age as a whole number of days, from 1 to 3650."
    ]
    assert step["message"].startswith("Nothing was sent. Correct what is listed below")
    assert "missing" not in step["message"] and step["focus"] == "max-age"


# ----------------------------------------------------------------------------- the script's text, always checked


def test_the_script_clears_the_keys_on_every_outcome_of_a_check_and_keeps_only_the_plan_to_save():
    script = (STATIC / "plan.js").read_text()
    check = script.split("async function check() {")[1].split("\nfunction save() {")[0]
    assert (
        check.index("clearKeyMaterial();")
        < check.index("if (secret)")
        < check.index("await fetch(")
    )
    assert "prepared = { plan_text: body.plan_text, file_name: body.file_name };" in check
    assert "prepared = body" not in script
    save = script.split("function save() {")[1].split("\nfunction showMode()")[0]
    assert save.index("prepared = null;") < save.index("link.click();")
    assert 'control.dataset.member === "public_key" || SECRET.test(control.value)' in script


def test_the_script_never_puts_the_technical_place_in_front_of_a_message():
    script = (STATIC / "plan.js").read_text()
    assert 'body.where + ": "' not in script
    assert (
        "Nothing was sent. Correct what is listed below, then press Check the plan again." in script
    )
    assert "paste the public key again" in script
