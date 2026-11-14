"""In customer mode the setup page lists the enrolled issuers, read-only: each name, key id and status, as the trust list
file states them in plain text. It never shows a public key or a fingerprint, and it lists nothing for demonstration
trust or for a trust list that cannot be used."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from helpers import client_for, fake_home, install_configuration, make_synthetic_portal

STATIC = Path(__file__).parents[1] / "regaudit_portal" / "static"
NODE = shutil.which("node")


def _setup(config: Path) -> dict:
    return client_for(config).get("/api/setup").json()


def test_customer_trust_lists_each_issuer_name_key_id_and_status(tmp_path, monkeypatch, demo):
    fake_home(tmp_path, monkeypatch)
    body = _setup(install_configuration(demo, tmp_path / "admin"))
    assert body["trust_mode"] == "customer"
    assert [set(item) for item in body["issuers"]] == [{"issuer", "key_id", "status"}]
    store = json.loads((demo / "trust-store.json").read_text())
    key_id, entry = next(iter(store["entries"].items()))
    assert body["issuers"] == [{"issuer": entry["issuer"], "key_id": key_id, "status": "active"}]


def test_a_legacy_customer_configuration_lists_its_issuers_too(tmp_path, monkeypatch, demo):
    fake_home(tmp_path, monkeypatch)
    config = install_configuration(demo, tmp_path / "admin")
    settings = json.loads(config.read_text())
    del settings["trust_mode"]
    config.write_text(json.dumps(settings))
    body = _setup(config)
    assert body["warnings"] and [i["issuer"] for i in body["issuers"]] == ["Northwind Test Issuer"]


def test_demonstration_trust_lists_no_issuers(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    demonstration = make_synthetic_portal(tmp_path / "demo", trust_mode="demonstration")
    body = _setup(demonstration / "portal-config.json")
    assert body["demonstration_trust_list"] is True and body["issuers"] == []


def test_no_configuration_and_a_broken_trust_list_list_no_issuers(tmp_path, monkeypatch, demo):
    fake_home(tmp_path, monkeypatch)
    assert _setup(None)["issuers"] == []
    config = install_configuration(demo, tmp_path / "admin")
    (config.parent / "trust-store.json").write_text("{}")
    os.chmod(config.parent / "trust-store.json", 0o600)
    assert _setup(config)["issuers"] == []


def test_a_name_with_invisible_characters_is_shown_with_them_made_visible(
    tmp_path, monkeypatch, demo
):
    fake_home(tmp_path, monkeypatch)
    config = install_configuration(demo, tmp_path / "admin")
    store_path = config.parent / "trust-store.json"
    store = json.loads(store_path.read_text())
    key_id = next(iter(store["entries"]))
    store["entries"][key_id]["issuer"] = "Example‮Issuer"
    store_path.write_text(json.dumps(store))
    os.chmod(store_path, 0o600)
    assert _setup(config)["issuers"][0]["issuer"] == "Example\\u{202E}Issuer"


def test_the_list_is_hidden_until_there_is_something_to_list_and_says_why_no_fingerprint():
    html = (STATIC / "setup.html").read_text()
    assert '<section id="enrolled" class="panel" hidden>' in html
    panel = html[
        html.index('<section id="enrolled"') : html.index(
            "</section>", html.index('<section id="enrolled"')
        )
    ]
    assert "No fingerprint is shown here, on purpose." in panel
    assert "This page only reads the list." in panel
    # A compromised or retired key is listed too, so the list does not say every issuer in it is accepted.
    assert (
        "The issuers named in the trust list, with the status the list gives each. Only active keys are accepted."
        in panel
    )
    assert "whose reports this portal accepts" not in panel
    assert (
        '<th scope="col">Issuer</th><th scope="col">Key id</th><th scope="col">Status</th>' in panel
    )


HARNESS = r"""
const fs = require("fs");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const elements = {};
const make = () => ({ textContent: "", children: [], hidden: false, dataset: {},
  replaceChildren() { this.children = []; }, append(...items) { this.children.push(...items); } });
const element = (id) => elements[id] || (elements[id] = make());
const document = { getElementById: element, createElement: () => make() };
const fetch = async () => ({ json: async () => input.answer });
new Function("document", "fetch", input.source)(document, fetch);
setTimeout(() => {
  const rows = element("enrolled-rows").children.map((tr) => tr.children.map((td) => td.textContent));
  process.stdout.write(JSON.stringify({ hidden: element("enrolled").hidden, rows }));
}, 50);
"""


@pytest.mark.skipif(NODE is None, reason="Node is not installed")
@pytest.mark.parametrize("customer", [True, False])
def test_the_page_shows_the_issuers_the_portal_answers_with(tmp_path, monkeypatch, demo, customer):
    fake_home(tmp_path, monkeypatch)
    if customer:
        config = install_configuration(demo, tmp_path / "admin")
    else:
        config = (
            make_synthetic_portal(tmp_path / "demo2", trust_mode="demonstration")
            / "portal-config.json"
        )
    answer = _setup(config)
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [NODE, "-e", HARNESS],
        input=json.dumps({"source": (STATIC / "setup.js").read_text(), "answer": answer}),
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    shown = json.loads(done.stdout)
    assert shown["hidden"] is not customer
    assert shown["rows"] == [[i["issuer"], i["key_id"], i["status"]] for i in answer["issuers"]]
    assert bool(shown["rows"]) is customer
