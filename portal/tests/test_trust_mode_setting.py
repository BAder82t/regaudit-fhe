"""The ``trust_mode`` setting, row by row: explicit customer, explicit demonstration, a legacy configuration without it,
a new configuration, the bundled demonstration key without it, and every malformed value.

A legacy configuration (no ``trust_mode``, no bundled key) is still customer trust and verifies exactly as before, with
one warning, word for word, from check-config (on standard error, exit status 0), on the setup page and in /api/setup.
Nothing rewrites a configuration or a trust list. Requiring the setting is a later release's change.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import (
    JSON_HEADERS,
    client_for,
    fingerprint_of,
    make_synthetic_portal,
    plan_request,
    post,
    post_bytes,
    prepare_plan,
    snapshot,
)
from regaudit_portal import admin
from regaudit_portal import config as config_module
from regaudit_portal import setup as readiness_module
from regaudit_portal.config import (
    LEGACY_TRUST_MODE_WARNING,
    ConfigProblem,
    load_portal,
    read_settings,
    read_trust_store,
)
from regaudit_portal.demo import create
from regaudit_portal.paths import default_config_folder
from regaudit_portal.plan import read_plan
from test_admin import _expect, _first_setup, _plan_file
from test_admin import home  # noqa: F401 - a fixture
from test_admin import northwind  # noqa: F401 - a fixture
from test_admin import run  # noqa: F401 - a fixture

PORTAL = Path(__file__).resolve().parents[1]
SAMPLES = PORTAL / "regaudit_portal" / "samples"
WARNING = (
    "This configuration does not specify `trust_mode`. It is currently treated as a legacy customer configuration. "
    "Explicitly set `trust_mode: customer` after reviewing the trusted keys. A future release will require this "
    "setting."
)
LABEL = "DEMONSTRATION — NOT CUSTOMER-TRUSTED"
BUNDLED_PEM = json.loads((SAMPLES / "demo-trust-list.json").read_text())["entries"]["demo-only-synthetic-key"][
    "public_key_pem"
]


def _set(root: Path, **change) -> Path:
    path = root / "portal-config.json"
    data = json.loads(path.read_text())
    for key, value in change.items():
        if value is _ABSENT:
            data.pop(key, None)
        else:
            data[key] = value
    path.write_text(json.dumps(data))
    os.chmod(path, 0o600)
    return path


_ABSENT = object()


def _check_config(config: Path) -> subprocess.CompletedProcess:
    """The real command, so that standard error is exactly what a person sees."""
    return subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-m", "regaudit_portal", "check-config", "--config", str(config)],
        env={**os.environ, "PYTHONPATH": str(PORTAL)}, capture_output=True, text=True, timeout=60, check=False,
        stdin=subprocess.DEVNULL,
    )  # fmt: skip


def _row(body: dict, row_id: str) -> dict | None:
    return next((r for r in body["rows"] if r["id"] == row_id), None)


def test_the_warning_is_word_for_word():
    assert LEGACY_TRUST_MODE_WARNING == WARNING


# ----------------------------------------------------------------------------- explicit customer


def test_explicit_customer_is_customer_trust_with_no_warning(tmp_path):
    root = make_synthetic_portal(tmp_path / "own")  # "trust_mode": "customer"
    assert json.loads((root / "portal-config.json").read_text())["trust_mode"] == "customer"
    portal = load_portal(root / "portal-config.json")
    assert portal.trust_mode == "customer" and portal.warnings == ()
    done = _check_config(root / "portal-config.json")
    assert done.returncode == 0 and done.stderr == ""
    assert done.stdout.startswith("usable: profile confidential, 1 approved issuer entry, replay mode check\n")
    client = client_for(root / "portal-config.json")
    setup = client.get("/api/setup").json()
    assert _row(setup, "trust_mode") is None and setup["warnings"] == [] and setup["trust_configured"] is True
    body = post(client, root, "1-trusted.json").json()
    assert body["verification"]["trust_status"] == "TRUSTED" and body["trust_mode"] == "customer"


# ----------------------------------------------------------------------------- explicit demonstration


@pytest.mark.parametrize("made_by", ["demo-setup", "an earlier demo-setup"])
def test_explicit_demonstration_is_labelled_and_never_gets_the_legacy_warning(tmp_path, made_by):
    root = (
        create(tmp_path / "demo")
        if made_by == "demo-setup"
        else make_synthetic_portal(tmp_path / "old", trust_mode="demonstration")
    )
    portal = load_portal(root / "portal-config.json")
    assert portal.trust_mode == "demonstration" and portal.warnings == ()
    done = _check_config(root / "portal-config.json")
    assert done.returncode == 3 and WARNING not in done.stderr
    assert done.stderr.startswith("not usable for your own reports: the trust list is a demonstration")
    client = client_for(root / "portal-config.json")
    setup = client.get("/api/setup").json()
    assert _row(setup, "trust_mode") is None and setup["warnings"] == []
    assert post(client, root, "1-trusted.json").json()["demonstration_label"] == LABEL


# ----------------------------------------------------------------------------- missing, on a usable customer configuration


@pytest.fixture
def legacy(tmp_path) -> Path:
    return make_synthetic_portal(tmp_path / "legacy", trust_mode=None)


def test_a_legacy_configuration_is_customer_trust_with_the_warning_in_check_config(legacy):
    assert "trust_mode" not in json.loads((legacy / "portal-config.json").read_text())
    portal = load_portal(legacy / "portal-config.json")
    assert portal.trust_mode == "customer" and portal.warnings == (WARNING,)
    done = _check_config(legacy / "portal-config.json")
    assert done.returncode == 0  # a warning, not a failure
    assert done.stderr == WARNING + "\n"  # on standard error, alone, word for word
    assert done.stdout.startswith("usable: profile confidential, 1 approved issuer entry, replay mode check\n")
    assert WARNING not in done.stdout


def test_a_legacy_configuration_shows_the_warning_on_the_setup_page_and_in_its_api(legacy):
    client = client_for(legacy / "portal-config.json")
    setup = client.get("/api/setup").json()
    assert setup["warnings"] == [WARNING]
    row = _row(setup, "trust_mode")
    assert row == {
        "id": "trust_mode",
        "title": "Trust mode setting",
        "state": "warning",
        "ok": False,
        "detail": WARNING,
        "why": readiness_module._WHY["legacy_trust_mode"],
        "next_step": readiness_module._STATE_NEXT["legacy_trust_mode"],
    }
    assert '"trust_mode": "customer"' in row["next_step"] and "restart the portal" in row["next_step"]
    ids = [r["id"] for r in setup["rows"]]
    assert ids.index("trust_mode") == ids.index("trust_list") + 1
    # Usable as it is: trust counts as set up, and your own reports can be checked.
    assert setup["trust_configured"] is True and setup["own_reports"]["ready"] is True
    status = client.get("/api/status").json()
    assert status["ready"] is True and status["trust_mode"] == "customer"
    script = (PORTAL / "regaudit_portal" / "static" / "setup.js").read_text()
    assert '  warning: "Warning",' in script
    assert 'dd strong[data-state="warning"]' in (PORTAL / "regaudit_portal" / "static" / "app.css").read_text()


def test_the_portal_log_carries_the_warning_when_it_starts(legacy, caplog):
    caplog.set_level("WARNING", logger="regaudit_portal.config")
    client_for(legacy / "portal-config.json")
    assert [r.getMessage() for r in caplog.records if r.name == "regaudit_portal.config"] == [WARNING]


def _verdicts(config: Path, root: Path) -> list[dict]:
    client = client_for(config)
    found = []
    for name in sorted(p.name for p in (root / "sample-reports").iterdir() if p.name != "6-too-large.json"):
        response = post(client, root, name)
        body = response.json()
        found.append({"file": name, "status": response.status_code, **{k: body.get(k) for k in ("verification", "error")}})
    for name in ("trusted.json", "modified.json", "untrusted-signer.json"):
        body = post_bytes(client, (SAMPLES / "reports" / name).read_bytes()).json()
        found.append({"file": name, "verification": body.get("verification")})
    found.append({"sample": client.post("/api/samples/trusted/verify").json()["verification"]})
    return found


def test_a_legacy_configuration_verifies_exactly_as_the_same_one_with_customer_written_out(legacy, tmp_path):
    explicit = tmp_path / "explicit"
    shutil.copytree(legacy, explicit)
    _set(explicit, trust_mode="customer")
    before = _verdicts(legacy / "portal-config.json", legacy)
    after = _verdicts(explicit / "portal-config.json", legacy)
    assert before == after  # the verifier's whole result, every field, for every file
    statuses = [item["verification"]["trust_status"] for item in before if item.get("verification")]
    assert "TRUSTED" in statuses and "INVALID" in statuses


def test_nothing_rewrites_a_legacy_configuration_or_its_trust_list(legacy, run):  # noqa: F811
    kept = {name: snapshot(legacy)[name] for name in ("portal-config.json", "trust-store.json")}
    load_portal(legacy / "portal-config.json")
    assert run("check-config", "--config", legacy / "portal-config.json")[0] == 0
    client = client_for(legacy / "portal-config.json")
    client.get("/api/status"), client.get("/api/setup"), post(client, legacy, "1-trusted.json")
    assert {name: snapshot(legacy)[name] for name in kept} == kept
    assert "trust_mode" not in json.loads((legacy / "portal-config.json").read_text())


def test_guard_off_without_the_legacy_check_no_warning_is_given_and_the_tests_above_would_fail(
    legacy, monkeypatch, caplog
):
    monkeypatch.setattr(config_module, "legacy_warnings", lambda _settings, _mode: ())
    monkeypatch.setattr(readiness_module, "legacy_warnings", lambda _settings, _mode: ())
    assert load_portal(legacy / "portal-config.json").warnings == ()
    setup = client_for(legacy / "portal-config.json").get("/api/setup").json()
    assert setup["warnings"] == [] and _row(setup, "trust_mode") is None


# ----------------------------------------------------------------------------- missing, on a new administrator configuration


def _json_examples(text: str) -> list[dict]:
    found = []
    for block in re.findall(r"\{\n(?:  .*\n)+\}", text):
        if '"trust_store"' in block:
            found.append(json.loads(block))
    return found


def test_every_configuration_this_code_base_writes_or_shows_says_its_trust_mode(tmp_path):
    """admin-apply writes the plan's configuration text; demo-setup writes its own; the README and the setup page
    show the example an administrator copies by hand. There is no other way here to make a configuration."""
    plan = read_plan(prepare_plan([admin_signer()]).encode())
    assert json.loads(plan.configuration_text())["trust_mode"] == "customer"
    assert json.loads((create(tmp_path / "demo") / "portal-config.json").read_text())["trust_mode"] == "demonstration"
    examples = [
        *_json_examples((PORTAL / "README.md").read_text()),
        *_json_examples((PORTAL / "regaudit_portal" / "static" / "setup.html").read_text()),
    ]
    assert len(examples) == 2 and all(example["trust_mode"] == "customer" for example in examples)


def admin_signer():
    from helpers import issuer_signer

    return issuer_signer("Northwind Ltd", "northwind-2026")


def _drop_the_setting(monkeypatch) -> None:
    real = admin.Plan.configuration_text

    def without(self):
        text = real(self)
        if text is None:
            return None
        data = json.loads(text)
        data.pop("trust_mode")
        return json.dumps(data, indent=2) + "\n"

    monkeypatch.setattr(admin.Plan, "configuration_text", without)


def test_admin_apply_never_writes_a_configuration_without_the_setting(home, tmp_path, run, northwind, monkeypatch):  # noqa: F811
    code, out, err = run("admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind))
    assert code == 0
    assert json.loads((default_config_folder() / "portal-config.json").read_text())["trust_mode"] == "customer"
    shutil.rmtree(default_config_folder())
    _drop_the_setting(monkeypatch)  # as if the plan's text came out without it
    code, out, err = run("admin-apply", _plan_file(tmp_path, prepare_plan([northwind]), "again.json"), *_expect(northwind))
    assert code == 2 and "The new configuration does not say what the plan says" in err
    assert not default_config_folder().exists()


def test_guard_off_the_earlier_check_would_have_written_a_legacy_configuration(home, tmp_path, run, northwind, monkeypatch):  # noqa: F811
    """The control: comparing only what the portal makes of the file (customer, also for a missing setting), as the
    check did before, lets a configuration without the setting through."""
    def earlier(staging_path, plan):
        settings = read_settings(staging_path / "portal-config.json")
        store = read_trust_store(settings)
        found = (
            settings.profile,
            settings.verifier_id,
            settings.max_age_days,
            settings.replay_mode,
            settings.allow_self_signed,
            config_module.trust_mode_of(settings, store)[0],
        )
        if found != (plan.profile, plan.verifier_id, plan.max_age_days, plan.replay_mode, False, "customer"):
            raise admin.Refused("The new configuration does not say what the plan says.")

    _drop_the_setting(monkeypatch)
    monkeypatch.setattr(admin, "_check_staged_first_setup", earlier)
    code, _, err = run("admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind))
    assert code == 0, err
    assert "trust_mode" not in json.loads((default_config_folder() / "portal-config.json").read_text())


def test_adding_issuers_to_a_legacy_configuration_warns_and_rewrites_nothing_but_the_trust_list(
    home, tmp_path, run, northwind  # noqa: F811
):
    folder = _first_setup(tmp_path, run, northwind)
    config = folder / "portal-config.json"
    data = json.loads(config.read_text())
    data.pop("trust_mode")
    config.write_text(json.dumps(data, indent=2) + "\n")
    os.chmod(config, 0o600)
    kept = config.read_bytes()
    from helpers import issuer_signer

    later = issuer_signer("Later Ltd", "later-1")
    plan = _plan_file(tmp_path, prepare_plan([later], mode="add-issuers"), "add.json")
    code, out, _ = run("admin-describe", plan)
    assert code == 0 and WARNING in out.splitlines()
    code, out, _ = run("admin-apply", plan, *_expect(later))
    assert code == 0 and WARNING in out.splitlines() and config.read_bytes() == kept
    # With the setting written out, neither says it.
    data["trust_mode"] = "customer"
    config.write_text(json.dumps(data, indent=2) + "\n")
    third = issuer_signer("Third Ltd", "third-1")
    plan = _plan_file(tmp_path, prepare_plan([third], mode="add-issuers"), "add3.json")
    assert WARNING not in run("admin-describe", plan)[1]
    assert WARNING not in run("admin-apply", plan, *_expect(third))[1]


# ----------------------------------------------------------------------------- the bundled key without the setting


def _bundled_spellings() -> dict[str, str]:
    body = "".join(BUNDLED_PEM.strip().splitlines()[1:-1])
    head, tail = "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"
    der = base64.b64decode(body)
    return {
        "as bundled": BUNDLED_PEM,
        "wrapped at 20": f"{head}\n{body[:20]}\n{body[20:]}\n{tail}\n",
        "CRLF": BUNDLED_PEM.replace("\n", "\r\n"),
        "no final newline": BUNDLED_PEM.rstrip("\n"),
        "blank line after": BUNDLED_PEM + "\n",
        "re-encoded": f"{head}\n{base64.b64encode(der).decode()}\n{tail}\n",
    }


@pytest.mark.parametrize("spelling", sorted(_bundled_spellings()))
@pytest.mark.parametrize("setting", [_ABSENT, "customer"])
def test_the_bundled_key_in_any_spelling_without_demonstration_is_never_customer_trust(tmp_path, spelling, setting):
    root = make_synthetic_portal(tmp_path / "own")
    (root / "trust-store.json").write_text(
        json.dumps({"entries": {"acme-1": {"issuer": "Acme Ltd", "public_key_pem": _bundled_spellings()[spelling], "status": "active"}}})
    )
    config = _set(root, trust_mode=setting)
    with pytest.raises(ConfigProblem) as caught:
        load_portal(config)
    assert caught.value.kind in ("demonstration_key", "invalid"), caught.value  # refused, either way
    response = post_bytes(client_for(config), (SAMPLES / "reports" / "trusted.json").read_bytes())
    assert response.status_code == 503 and "verification" not in response.json()


MALFORMED = [
    (None, "trust_mode must be text"),
    (0, "trust_mode must be text"),
    (1, "trust_mode must be text"),
    (1.5, "trust_mode must be text"),
    (True, "trust_mode must be text"),
    (False, "trust_mode must be text"),
    ([], "trust_mode must be text"),
    (["customer"], "trust_mode must be text"),
    ({}, "trust_mode must be text"),
    ({"mode": "customer"}, "trust_mode must be text"),
    ("", "trust_mode must be 'customer' or 'demonstration'"),
    ("CUSTOMER", "trust_mode must be 'customer' or 'demonstration'"),
    ("Customer", "trust_mode must be 'customer' or 'demonstration'"),
    ("DEMONSTRATION", "trust_mode must be 'customer' or 'demonstration'"),
    (" customer", "trust_mode must be 'customer' or 'demonstration'"),
    ("customer ", "trust_mode must be 'customer' or 'demonstration'"),
    ("customer\n", "trust_mode must be 'customer' or 'demonstration'"),
    ("custоmer", "trust_mode must be 'customer' or 'demonstration'"),  # a Cyrillic o
    ("legacy", "trust_mode must be 'customer' or 'demonstration'"),
    ("none", "trust_mode must be 'customer' or 'demonstration'"),
]


@pytest.mark.parametrize("bundled", [False, True])
@pytest.mark.parametrize("value, message", MALFORMED, ids=[repr(v) for v, _ in MALFORMED])
def test_every_malformed_trust_mode_is_refused_whatever_the_trust_list_holds(tmp_path, run, bundled, value, message):  # noqa: F811
    root = make_synthetic_portal(tmp_path / "own")
    if bundled:
        entries = json.loads((root / "trust-store.json").read_text())["entries"]
        entries["acme-1"] = {"issuer": "Acme Ltd", "public_key_pem": BUNDLED_PEM, "status": "active"}
        (root / "trust-store.json").write_text(json.dumps({"entries": entries}))
    config = _set(root, trust_mode=value)
    with pytest.raises(ConfigProblem, match=re.escape(message)) as caught:
        load_portal(config)
    assert caught.value.kind == "invalid"
    code, out, err = run("check-config", "--config", config)
    assert code == 3 and out == "" and err == f"not usable: {message}\n"
    client = client_for(config)
    assert client.get("/api/status").json()["state"] == "needs_attention"
    response = post(client, root, "1-trusted.json")
    assert response.status_code == 503 and "verification" not in response.json()


def test_guard_off_without_the_value_check_a_malformed_mode_would_be_read_as_legacy_customer(tmp_path, monkeypatch):
    """The control: if the setting were read without its check, "CUSTOMER" would quietly become a legacy customer
    configuration."""
    root = make_synthetic_portal(tmp_path / "own")
    config = _set(root, trust_mode="CUSTOMER")
    monkeypatch.setattr(config_module, "TRUST_MODES", ("customer", "demonstration", "CUSTOMER"))
    portal = load_portal(config)
    assert portal.trust_mode == "customer"


# ----------------------------------------------------------------------------- the maximum age in customer mode


def test_a_plan_must_state_its_maximum_age_and_the_page_suggests_30(tmp_path):
    from helpers import issuer_signer

    request = plan_request([issuer_signer()])
    del request["configuration"]["max_age_days"]
    client = client_for(None)
    response = client.post("/api/setup/plan", content=json.dumps(request).encode(), headers=JSON_HEADERS)
    assert response.status_code == 422
    html = (PORTAL / "regaudit_portal" / "static" / "plan.html").read_text()
    assert 'id="max-age" type="number" min="1" max="3650" step="1" value="30"' in html


def test_a_long_age_in_a_customer_plan_is_flagged_written_as_given_and_never_called_a_demonstration(
    home, tmp_path, run, northwind  # noqa: F811
):
    plan = _plan_file(tmp_path, prepare_plan([northwind], max_age_days=3650))
    code, out, _ = run("admin-describe", plan)
    assert code == 0 and "Notice: the maximum report age is 3650 days." in out
    assert run("admin-apply", plan, *_expect(northwind))[0] == 0
    written = json.loads((default_config_folder() / "portal-config.json").read_text())
    assert written["max_age_days"] == 3650 and written["trust_mode"] == "customer"
    setup = client_for(default_config_folder() / "portal-config.json").get("/api/setup").json()
    assert "only because this is a demonstration" not in json.dumps(setup)
    assert fingerprint_of(northwind) not in out


def test_a_plan_with_the_suggested_age_writes_30():
    plan = read_plan(prepare_plan([admin_signer()]).encode())
    assert json.loads(plan.configuration_text())["max_age_days"] == 30


# ----------------------------------------------------------------------------- what the documents say


def test_the_documents_give_the_warning_word_for_word_the_way_on_and_that_enforcement_is_later():
    readme = (PORTAL / "README.md").read_text()
    security = (PORTAL / "SECURITY.md").read_text()
    for text in (readme, security):
        assert f"```\n{WARNING}\n```" in text
        assert "Nothing rewrites" in text and "status 0" in text
        assert "A later release will" in text
    for step in (
        "1. Review every key in the trust list with its issuer",
        '2. Add `"trust_mode": "customer"` to the configuration file.',
        "3. Restart the portal. `check-config` then prints no warning.",
        "That is a change for that release. This one still accepts it, with the warning.",
        "`check-config` prints the warning on standard error and still exits with status 0",
        "`/api/setup` lists it under `warnings`",
    ):
        assert step in readme, step
