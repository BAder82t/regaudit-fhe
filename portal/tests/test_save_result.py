"""Saving a result: a checked sample can always be saved while the engine passes, your own report needs the policy.

The page's own ``download`` function is run here, in Node, against what the portal really answers, so the tests see what
the page does and not only what its text says. They are skipped where Node is not installed. The text of the condition
is checked separately and always.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import regaudit_portal.engine as engine_module
from helpers import client_for, fake_home, post
from regaudit_portal.explain import DEMONSTRATION_NOTICE, FHE_NOTICE

PORTAL = Path(__file__).parents[1]
SCRIPT = PORTAL / "regaudit_portal" / "static" / "app.js"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="Node is not installed")

# Runs the page's savePermitted and download functions with stand-ins for the page around them, and prints what happened.
HARNESS = r"""
const fs = require("fs");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const source = input.source;
const from = source.indexOf("function savePermitted(");
const to = source.indexOf("async function start()");
if (from < 0 || to < from) throw new Error("the functions were not found");
const log = { file: null, contents: null, unavailable: false, failed: null, shown: {}, status_fetches: 0 };
const elements = {};
const $ = (id) => elements[id] || (elements[id] = { textContent: "", hidden: true });
const show = (id, visible) => { log.shown[id] = visible; $(id).hidden = !visible; };
const unavailable = () => { log.unavailable = true; };
const fail = (message) => { log.failed = message; };
const fetch = async (path) => {
  if (path !== "/api/status") throw new Error("unexpected request " + path);
  log.status_fetches += 1;
  return { json: async () => input.status };
};
const document = {
  createElement: () => ({
    click() { log.file = this.download; },
  }),
};
class FakeBlob { constructor(parts) { log.contents = parts.join(""); } }
const FakeURL = { createObjectURL: () => "blob:test", revokeObjectURL: () => {} };
const body = "let lastSaved = input.saved;\n" + source.slice(from, to) + "\nreturn download();";
const run = new Function("input", "$", "show", "unavailable", "fail", "fetch", "document", "Blob", "URL", body);
run(input, $, show, unavailable, fail, fetch, document, FakeBlob, FakeURL).then(() => {
  log.saved_text = $("saved").textContent;
  process.stdout.write(JSON.stringify(log));
});
"""


def press_download(status: dict, result: dict, name: str) -> dict:
    """What the page does when "Download result" is pressed, given what the portal says now and the result on screen."""
    assert NODE is not None
    given = {
        "source": SCRIPT.read_text(),
        "status": status,
        "saved": {"body": result, "name": name},
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


def welcome(tmp_path, monkeypatch, demo):
    fake_home(tmp_path, monkeypatch)
    return client_for(None)


def needs_attention(tmp_path, monkeypatch, demo):
    fake_home(tmp_path, monkeypatch)
    (demo / "trust-store.json").unlink()
    return client_for(demo / "portal-config.json")


def ready(tmp_path, monkeypatch, demo):
    fake_home(tmp_path, monkeypatch)
    return client_for(demo / "portal-config.json")


MODES = {"welcome": welcome, "needs-attention": needs_attention, "ready": ready}


def a_sample(client, sample_id: str = "trusted") -> dict:
    response = client.post(f"/api/samples/{sample_id}/verify")
    assert response.status_code == 200
    return response.json()


def saved_file(done: dict) -> dict:
    assert done["failed"] is None and done["unavailable"] is False, done
    assert done["contents"] is not None, "nothing was saved"
    return json.loads(done["contents"])


# ----------------------------------------------------------------------------- a sample can be saved without a policy


@needs_node
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("sample_id", ["trusted", "modified"])
def test_a_checked_sample_can_be_saved_in_every_mode(tmp_path, monkeypatch, demo, mode, sample_id):
    client = MODES[mode](tmp_path, monkeypatch, demo)
    result = a_sample(client, sample_id)
    status = client.get("/api/status").json()
    done = press_download(status, result, "sample-" + sample_id)
    assert done["status_fetches"] == 1, "the engine is checked again when the result is saved"
    assert done["file"].startswith("demonstration-result-sample-" + sample_id + "-")
    assert done["file"].endswith(result["report_sha256"][:12] + ".json")
    assert done["shown"]["saved"] is True and done["saved_text"].endswith(done["file"])
    saved_file(done)


@needs_node
@pytest.mark.parametrize("mode", ["welcome", "needs-attention"])
def test_a_saved_sample_is_labelled_a_synthetic_demonstration_with_the_notices(
    tmp_path, monkeypatch, demo, mode
):
    client = MODES[mode](tmp_path, monkeypatch, demo)
    result = a_sample(client)
    saved = saved_file(press_download(client.get("/api/status").json(), result, "sample-trusted"))
    assert saved["synthetic_demonstration"] is True
    assert saved["demonstration"]["notice"] == DEMONSTRATION_NOTICE
    assert saved["demonstration"]["sample"]["id"] == "trusted"
    assert saved["demonstration"]["issuer"] and saved["demonstration"]["trust_list"]
    assert saved["fhe_notice"] == FHE_NOTICE
    assert saved["encryption_declarations"]["encryption_verified"] is False
    assert saved["engine"]["summary"] and saved["engine"]["security_limitation"]
    assert saved["engine"]["security_limitation_short"]
    assert saved["report_file_name"] == "sample-trusted"
    assert saved["verification"] == result["verification"]  # the verifier's answer, unchanged


# ----------------------------------------------------------------------------- the engine must still pass when saving


@needs_node
@pytest.mark.parametrize("mode", MODES)
def test_saving_is_refused_when_the_engine_has_stopped_passing(tmp_path, monkeypatch, demo, mode):
    client = MODES[mode](tmp_path, monkeypatch, demo)
    result = a_sample(client)

    def crashes(_folder):
        raise RuntimeError("the hash could not be computed")

    monkeypatch.setattr(engine_module, "files_digest", crashes)
    status = client.get("/api/status").json()
    assert status == {"ready": False, "state": "unavailable"}
    done = press_download(status, result, "sample-trusted")
    assert done["file"] is None and done["contents"] is None
    assert done["unavailable"] is True and done["shown"].get("saved") is not True


@needs_node
def test_saving_is_refused_for_a_status_that_does_not_name_an_engine(tmp_path, monkeypatch, demo):
    result = a_sample(welcome(tmp_path, monkeypatch, demo))
    for status in ({}, {"ready": True}, {"ready": False, "state": "not_set_up"}):
        done = press_download(status, result, "sample-trusted")
        assert done["file"] is None and done["contents"] is None, status


# ----------------------------------------------------------------------------- your own report still needs the policy


@needs_node
@pytest.mark.parametrize("mode", ["welcome", "needs-attention"])
def test_a_result_for_your_own_report_cannot_be_saved_without_a_loaded_policy(
    tmp_path, monkeypatch, demo, mode
):
    fake_home(tmp_path, monkeypatch)
    own = post(client_for(demo / "portal-config.json"), demo, "1-trusted.json").json()
    assert own["synthetic_demonstration"] is False
    if mode == "welcome":
        client = client_for(None)
    else:
        (demo / "trust-store.json").unlink()
        client = client_for(demo / "portal-config.json")
    status = client.get("/api/status").json()
    assert status["ready"] is False and status["engine"]
    done = press_download(status, own, "report.json")
    assert done["file"] is None and done["contents"] is None
    assert done["unavailable"] is False and "cannot save a result right now" in done["failed"]
    assert done["shown"].get("saved") is not True


@needs_node
def test_your_own_result_is_saved_as_a_verification_result_when_the_policy_is_loaded(
    tmp_path, monkeypatch, demo
):
    client = ready(tmp_path, monkeypatch, demo)
    own = post(client, demo, "1-trusted.json").json()
    done = press_download(client.get("/api/status").json(), own, "report.json")
    assert done["file"].startswith("verification-result-report-")
    saved = saved_file(done)
    assert saved["synthetic_demonstration"] is False and "demonstration" not in saved
    assert saved["report_file_name"] == "report.json"


# ----------------------------------------------------------------------------- the text of the condition, always checked


def _save_check() -> str:
    script = SCRIPT.read_text()
    return script[
        script.index("function savePermitted(") : script.index("async function download()")
    ]


def test_the_condition_for_saving_names_the_engine_the_demonstration_and_the_policy():
    check = _save_check()
    assert 'status.state === "unavailable" || !status.engine' in check
    assert "result.synthetic_demonstration === true || status.ready === true" in check


def test_download_asks_the_portal_again_and_uses_that_condition():
    script = SCRIPT.read_text()
    saving = script[
        script.index("async function download()") : script.index("async function start()")
    ]
    assert 'fetch("/api/status")' in saving
    assert "savePermitted(status, lastSaved.body)" in saving
    assert "status.ready" not in saving, "the policy is only asked for through savePermitted"
