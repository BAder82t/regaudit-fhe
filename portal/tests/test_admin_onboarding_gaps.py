"""Behaviours of the administrator setup that other test files pin only in part.

The page tests run the real page script in Node against the portal's real answers (skipped where Node is missing). The
controller tests run the real ``admin-describe`` and ``admin-apply``.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
from helpers import (
    JSON_HEADERS,
    client_for,
    fake_home,
    fingerprint_of,
    issuer_signer,
    plan_request,
    prepare_plan,
    snapshot,
)
from test_admin import _expect, _first_setup, _plan_file
from test_plan_page import HARNESS, NODE, STATIC, _form, needs_node

SWIFT = Path(__file__).resolve().parents[1] / "installer" / "macos" / "launcher" / "main.swift"

# The harness has no way to pick the mode radio; this adds a step member "mode" and nothing else.
_HARNESS = HARNESS.replace(
    "    if (step.fill) fill(step.fill);",
    "    if (step.mode) for (const r of document.querySelectorAll('input[name=\"mode\"]')) r.checked = r.value === step.mode;\n"
    "    if (step.fill) fill(step.fill);",
)
assert _HARNESS != HARNESS


def _page(setup: dict, responses: list[dict], steps: list[dict]) -> dict:
    given = {
        "source": (STATIC / "plan.js").read_text(),
        "setup": setup,
        "responses": responses,
        "steps": steps,
    }
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [NODE, "-e", _HARNESS],
        input=json.dumps(given),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@pytest.fixture
def welcome(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    return client_for(None)


# ----------------------------------------------------------------------------- the page


@needs_node
def test_the_page_shows_the_weak_profile_notice_before_anything_else_of_the_plan(welcome):
    signer = issuer_signer()
    request = plan_request([signer], profile="development", max_age_days=3650, replay_mode="check")
    answer = welcome.post(
        "/api/setup/plan", content=json.dumps(request).encode(), headers=JSON_HEADERS
    ).json()
    assert answer["ok"] is True
    form = {**_form(signer, fingerprint_of(signer)), "profile": "development"}
    done = _page(
        welcome.get("/api/setup").json(), [answer], [{"name": "c", "fill": form, "action": "check"}]
    )
    assert done["sent"][0]["configuration"]["profile"] == "development"
    shown = done["steps"][0]["everything"]
    notice = shown.index("Notice: the profile is development.")
    assert notice < shown.index("Verifier id:") < shown.index("Issuers to enrol")
    assert "Do not rely on its results" in shown
    step = done["steps"][0]
    for portal_said in (step["writes"], step["message"], json.dumps(step["rows"])):
        assert (
            fingerprint_of(signer) not in portal_said
        )  # only the administrator's own typing holds it


@needs_node
@pytest.mark.parametrize("where", ["fingerprint", "verifier_id"])
def test_a_private_key_pasted_into_the_fingerprint_or_verifier_box_is_not_sent_and_is_cleared(
    welcome, where
):
    signer = issuer_signer()
    secret = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIabc\n-----END PRIVATE KEY-----"  # noqa: S105 - a made-up private-key look-alike
    form = _form(signer, fingerprint_of(signer))
    if where == "fingerprint":
        form["issuer"]["fingerprint"] = secret
    else:
        form["verifier_id"] = secret
    done = _page(
        welcome.get("/api/setup").json(), [], [{"name": "r", "fill": form, "action": "check"}]
    )
    step = done["steps"][0]
    assert done["sent"] == [] and step["message"].startswith(
        "Something you entered looks like a private"
    )
    assert step["boxes"]["fingerprint" if where == "fingerprint" else "public_key"] == ""
    assert step["verifier_id"] == ("" if where == "verifier_id" else form["verifier_id"])
    assert "MC4CAQAw" not in step["everything"]


@needs_node
def test_the_add_issuers_page_sends_no_configuration_and_keeps_no_pasted_key(welcome):
    signer = issuer_signer()
    request = plan_request([signer], mode="add-issuers")
    answer = welcome.post(
        "/api/setup/plan", content=json.dumps(request).encode(), headers=JSON_HEADERS
    ).json()
    assert answer["ok"] is True
    form = _form(signer, fingerprint_of(signer))
    done = _page(
        welcome.get("/api/setup").json(),
        [answer],
        [{"name": "c", "mode": "add-issuers", "fill": form, "action": "check"}],
    )
    sent = done["sent"][0]
    assert sent["mode"] == "add-issuers" and "configuration" not in sent
    step = done["steps"][0]
    assert step["prepared"] == ["file_name", "plan_text"] and step["boxes"]["public_key"] == ""
    assert "Verifier id" not in step["everything"]


# ----------------------------------------------------------------------------- the controller


def _damage(folder: Path, name: str, text: str) -> None:
    (folder / name).write_text(text)
    os.chmod(folder / name, 0o600)


@pytest.mark.parametrize("which", ["portal-config.json", "trust-store.json"])
def test_adding_issuers_to_a_damaged_configuration_or_trust_list_is_refused_and_changes_nothing(
    home, tmp_path, run, northwind, which
):
    folder = _first_setup(tmp_path, run, northwind)
    _damage(folder, which, "{")
    before = snapshot(folder)
    later = issuer_signer("Later Ltd", "later-1")
    plan = _plan_file(tmp_path, prepare_plan([later], mode="add-issuers"), "add.json")
    word = "configuration" if which == "portal-config.json" else "trust list"
    for command, extra in (("admin-apply", _expect(later)), ("admin-describe", [])):
        code, out, err = run(command, plan, *extra)
        assert code == 2 and f"The existing {word} cannot be used" in err + out, (command, out, err)
        if command == "admin-apply":
            assert "Enrolled" not in out
    assert snapshot(folder) == before


def test_adding_issuers_never_echoes_a_fingerprint_and_keeps_every_file_private(
    home, tmp_path, run, northwind
):
    folder = _first_setup(tmp_path, run, northwind)
    later = issuer_signer("Later Ltd", "later-1")
    plan = _plan_file(tmp_path, prepare_plan([later], mode="add-issuers"), "add.json")
    code, out, err = run("admin-describe", "--json", plan)
    assert code == 0, err
    code2, out2, err2 = run("admin-describe", plan)
    assert code2 == 0, err2
    code3, out3, err3 = run("admin-apply", plan, *_expect(later))
    assert code3 == 0, err3
    wrong = "0" * 63 + "1"
    other = issuer_signer("Third Ltd", "third-1")
    plan_b = _plan_file(tmp_path, prepare_plan([other], mode="add-issuers"), "b.json")
    code4, out4, err4 = run(
        "admin-apply", plan_b, "--expect-fingerprint", f"{other.key_id}={wrong}"
    )
    assert code4 != 0
    for text in (out, out2, out3, err3, out4, err4):
        for signer in (northwind, later, other):
            assert fingerprint_of(signer) not in text and fingerprint_of(signer).upper() not in text
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    for name in ("portal-config.json", "trust-store.json"):
        info = (folder / name).stat()
        assert (
            stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
        )
    assert sorted(p.name for p in folder.iterdir()) == ["portal-config.json", "trust-store.json"]


# ----------------------------------------------------------------------------- the launcher


def test_the_launcher_applies_only_after_describe_and_an_explicit_apply_and_never_after_a_refusal():
    code = "\n".join(
        line for line in SWIFT.read_text().splitlines() if not line.strip().startswith("//")
    )
    admin = code[code.index("@objc func administratorSetup()") : code.index("func restartPortal()")]
    assert admin.count('"admin-apply"') == 1 and admin.count('"admin-describe"') == 1
    assert (
        admin.index('"admin-describe"')
        < admin.index("present(alert)")
        < admin.index('"admin-apply"')
    )
    assert admin.index('alert.addButton(withTitle: "Apply")') < admin.index(
        'alert.addButton(withTitle: "Cancel")'
    )
    assert (
        "let answer = present(alert)" in admin
    )  # the alert is shown through the helper that brings it to the front
    assert "guard answer == .alertFirstButtonReturn else { adminBusy = false; return }" in admin
    # A plan Python will not describe as applicable returns before the alert is built.
    refused = admin.index("This setup plan cannot be applied here.")
    assert refused < admin.index("NSAlert()") and "return inform(" in admin[refused - 60 : refused]
    assert 'body["ok"] as? Bool == true' in admin and "!issuers.isEmpty" in admin
