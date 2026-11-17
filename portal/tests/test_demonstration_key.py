"""The bundled demonstration key is a demonstration only when the configuration says so, and is otherwise refused.

The key is recognised by its pinned fingerprint and by nothing else: no file name, issuer name, key id or label. A
trust list that holds it is allowed only with ``"trust_mode": "demonstration"``, and every result is then labelled.
With ``"customer"``, or with no setting, the configuration is refused: check-config exits non-zero, the portal shows a
plain reason and gives no verdict for an uploaded report. A changed key is a different key: it is ordinary customer
trust and verifies only reports signed by its own private key, never the bundled samples. The verifier's verdicts and
reason codes are never changed.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from helpers import (
    client_for,
    make_synthetic_portal,
    post,
    post_bytes,
    signed_report,
)
from regaudit_portal import app as app_module
from regaudit_portal import config as config_module
from regaudit_portal import demo as demo_module
from regaudit_portal.config import (
    BUNDLED_KEY_AS_CUSTOMER,
    BUNDLED_KEY_WITHOUT_MODE,
    ConfigProblem,
    load_portal,
)
from regaudit_portal.demo import create

import regaudit_fhe as rf
from regaudit_fhe._keys import spki_fingerprint

PORTAL = Path(__file__).resolve().parents[1]
SAMPLES = PORTAL / "regaudit_portal" / "samples"
LABEL = "DEMONSTRATION — NOT CUSTOMER-TRUSTED"
BUNDLED_PEM = json.loads((SAMPLES / "demo-trust-list.json").read_text())["entries"][
    "demo-only-synthetic-key"
]["public_key_pem"]
BUNDLED_FINGERPRINT = "220618ae027e2cf3c634778f5f4708fc1ea53006973d379ef0d799d936e30df8"


def _config(root: Path, **change) -> Path:
    path = root / "portal-config.json"
    data = json.loads(path.read_text())
    for key, value in change.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    path.write_text(json.dumps(data))
    os.chmod(path, 0o600)
    return path


def _store(root: Path, entries: dict) -> None:
    path = root / "trust-store.json"
    path.write_text(json.dumps({"entries": entries}))
    os.chmod(path, 0o600)


def _bundled_list_copied(root: Path, setting: str | None) -> Path:
    """The bundled trust list copied byte for byte into an ordinary folder, under a configuration of its own."""
    root.mkdir(mode=0o700)
    (root / "trust-store.json").write_bytes((SAMPLES / "demo-trust-list.json").read_bytes())
    os.chmod(root / "trust-store.json", 0o600)
    config = {
        "trust_store": "trust-store.json",
        "profile": "confidential",
        "verifier_id": "demo-verifier",
        "max_age_days": 3650,
        "replay_mode": "check",
    }
    if setting is not None:
        config["trust_mode"] = setting
    (root / "portal-config.json").write_text(json.dumps(config))
    os.chmod(root / "portal-config.json", 0o600)
    return root / "portal-config.json"


def _check_config(config: Path) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-m", "regaudit_portal", "check-config", "--config", str(config)],
        env={**os.environ, "PYTHONPATH": str(PORTAL)}, capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip


def _bundled_sample(name: str) -> bytes:
    return (SAMPLES / "reports" / name).read_bytes()


def _assert_refused(config: Path, expected: str) -> None:
    """Refused everywhere: the loader, check-config, the status, the setup page and an upload."""
    with pytest.raises(ConfigProblem) as caught:
        load_portal(config)
    assert caught.value.kind == "demonstration_key" and str(caught.value) == expected
    done = _check_config(config)
    assert done.returncode == 3 and done.stdout == ""
    assert done.stderr == f"not usable: {expected}\n"
    client = client_for(config)
    assert client.app.state.ready is False and client.app.state.mode == "needs-attention"
    status = client.get("/api/status").json()
    assert status["ready"] is False and status["state"] == "needs_attention"
    assert status["message"] == app_module._DEMONSTRATION_KEY_REFUSED
    assert str(config.parent) not in json.dumps(status) and "trust-store.json" not in json.dumps(
        status
    )
    assert status["trust_mode"] == "none" and "policy_id" not in status
    for report in (_bundled_sample("trusted.json"), _bundled_sample("modified.json")):
        response = post_bytes(client, report)
        body = response.json()
        assert response.status_code == 503 and body["error"] == "not_ready"
        assert (
            body["message"] == app_module._DEMONSTRATION_KEY_REFUSED and "verification" not in body
        )
    setup = client.get("/api/setup").json()
    row = next(r for r in setup["rows"] if r["id"] == "trust_list")
    assert row["state"] == "problem" and row["detail"] == expected
    assert (
        "never be customer trust" in row["why"]
        and '"trust_mode": "demonstration"' in row["next_step"]
    )
    assert setup["own_reports"]["ready"] is False and setup["trust_configured"] is False
    # The bundled samples still work, each one labelled, as in every other state.
    sample = client.post("/api/samples/trusted/verify").json()
    assert (
        sample["verification"]["trust_status"] == "TRUSTED"
        and sample["demonstration_label"] == LABEL
    )


# ----------------------------------------------------------------------------- what demo-setup makes


def test_demo_setup_installs_the_bundled_key_and_copies_the_bundled_reports_byte_for_byte(tmp_path):
    root = create(tmp_path / "demo")
    assert (root / "trust-store.json").read_bytes() == (
        SAMPLES / "demo-trust-list.json"
    ).read_bytes()
    entries = json.loads((root / "trust-store.json").read_text())["entries"]
    assert [spki_fingerprint(e["public_key_pem"]) for e in entries.values()] == [
        BUNDLED_FINGERPRINT
    ]
    for name, bundled in demo_module.COPIED:
        assert (root / "sample-reports" / name).read_bytes() == _bundled_sample(bundled)
    assert sorted(p.name for p in (root / "sample-reports").iterdir()) == [
        "1-trusted.json",
        "2-untrusted-signer.json",
        "3-changed-after-signing.json",
        "4-not-a-report.json",
        "5-too-large.json",
        "6-declares-encrypted-backend.json",
    ]
    assert json.loads((root / "portal-config.json").read_text()) == {
        "trust_store": "trust-store.json",
        "profile": "confidential",
        "verifier_id": "demo-verifier",
        "max_age_days": 3650,
        "replay_mode": "check",
        "replay_db": "replay.db",
        "trust_mode": "demonstration",
    }
    for path in root.rglob("*"):
        assert b"PRIVATE KEY" not in (path.read_bytes() if path.is_file() else b"")
    for name in ("trust-store.json", "portal-config.json"):
        assert (root / name).stat().st_mode & 0o777 == 0o600


def test_the_demo_setup_samples_give_the_verifiers_own_verdicts_each_one_labelled(tmp_path):
    root = create(tmp_path / "demo")
    client = client_for(root / "portal-config.json")
    assert client.app.state.mode == "demonstration" and client.app.state.ready is False
    expected = {
        "1-trusted.json": ("TRUSTED", []),
        "2-untrusted-signer.json": ("INVALID", ["ISSUER_UNKNOWN"]),
        "3-changed-after-signing.json": ("INVALID", ["HASH_MISMATCH", "SIGNATURE_INVALID"]),
        "6-declares-encrypted-backend.json": ("TRUSTED", []),
    }
    for name, (status, blocking) in expected.items():
        body = post(client, root, name).json()
        assert body["verification"]["trust_status"] == status, name
        assert body["verification"]["blocking_reasons"] == blocking, name
        assert body["demonstration_label"] == LABEL and body["trust_mode"] == "demonstration"
    assert post(client, root, "4-not-a-report.json").status_code == 422
    assert post(client, root, "5-too-large.json").status_code == 413


def test_the_long_age_is_labelled_on_the_setup_page_only_for_a_demonstration(tmp_path):
    root = create(tmp_path / "demo")
    row = next(
        r
        for r in client_for(root / "portal-config.json").get("/api/setup").json()["rows"]
        if r["id"] == "trust_policy"
    )
    assert "Maximum report age 3650 days." in row["detail"]
    assert "accepted here only because this is a demonstration" in row["detail"]
    own = make_synthetic_portal(tmp_path / "own")
    _config(own, max_age_days=3650)
    row = next(
        r
        for r in client_for(own / "portal-config.json").get("/api/setup").json()["rows"]
        if r["id"] == "trust_policy"
    )
    assert "only because this is a demonstration" not in row["detail"]


# ----------------------------------------------------------------------------- the bundled key without the setting


@pytest.mark.parametrize(
    "setting, expected",
    [("customer", BUNDLED_KEY_AS_CUSTOMER), (None, BUNDLED_KEY_WITHOUT_MODE)],
)
def test_demo_setup_output_without_its_demonstration_setting_is_refused(
    tmp_path, setting, expected
):
    root = create(tmp_path / "demo")
    _assert_refused(_config(root, trust_mode=setting), expected)


@pytest.mark.parametrize(
    "setting, expected",
    [("customer", BUNDLED_KEY_AS_CUSTOMER), (None, BUNDLED_KEY_WITHOUT_MODE)],
)
def test_the_bundled_list_copied_into_another_folder_without_the_marker_is_refused(
    tmp_path, setting, expected
):
    _assert_refused(_bundled_list_copied(tmp_path / "copy", setting), expected)


@pytest.mark.parametrize("setting", ["customer", None])
@pytest.mark.parametrize(
    "key_id, issuer, status",
    [
        ("acme-1", "Acme Ltd", "active"),
        ("northwind-2026", "Northwind Ltd", "active"),
        ("x", "Real Bank plc", "active"),
    ],
)
def test_renaming_the_bundled_key_or_its_issuer_never_makes_it_customer_trust(
    tmp_path, setting, key_id, issuer, status
):
    root = make_synthetic_portal(tmp_path / "own")
    entries = json.loads((root / "trust-store.json").read_text())["entries"]
    entries[key_id] = {"issuer": issuer, "public_key_pem": BUNDLED_PEM, "status": status}
    _store(root, entries)
    expected = BUNDLED_KEY_AS_CUSTOMER if setting else BUNDLED_KEY_WITHOUT_MODE
    _assert_refused(_config(root, trust_mode=setting), expected)


def test_the_bundled_key_written_another_way_is_still_recognised(tmp_path):
    """The same key in a differently wrapped PEM is the same key: the fingerprint is of the key, not of the text."""
    der = base64.b64decode("".join(BUNDLED_PEM.strip().splitlines()[1:-1]))
    body = base64.b64encode(der).decode()
    rewrapped = (
        "-----BEGIN PUBLIC KEY-----\n"
        + body[:20]
        + "\n"
        + body[20:]
        + "\n-----END PUBLIC KEY-----\n"
    )
    assert rewrapped != BUNDLED_PEM and spki_fingerprint(rewrapped) == BUNDLED_FINGERPRINT
    root = make_synthetic_portal(tmp_path / "own")
    _store(root, {"other": {"issuer": "Other", "public_key_pem": rewrapped, "status": "active"}})
    with pytest.raises(ConfigProblem, match="bundled demonstration key"):
        load_portal(root / "portal-config.json")


def test_a_list_with_the_bundled_key_and_a_real_key_is_a_demonstration_only_with_the_setting(
    tmp_path,
):
    root = make_synthetic_portal(tmp_path / "own")
    entries = json.loads((root / "trust-store.json").read_text())["entries"]
    entries["acme-1"] = {"issuer": "Acme Ltd", "public_key_pem": BUNDLED_PEM, "status": "active"}
    _store(root, entries)
    _assert_refused(root / "portal-config.json", BUNDLED_KEY_AS_CUSTOMER)
    _assert_refused(_config(root, trust_mode=None), BUNDLED_KEY_WITHOUT_MODE)
    _config(root, trust_mode="demonstration")
    portal = load_portal(root / "portal-config.json")
    assert (
        portal.trust_mode == "demonstration"
        and "bundled demonstration key" in portal.trust_mode_reason
    )
    client = client_for(root / "portal-config.json")
    own = post(client, root, "1-trusted.json").json()  # signed by the real key in the same list
    assert own["verification"]["trust_status"] == "TRUSTED" and own["demonstration_label"] == LABEL


def test_guard_off_without_the_fingerprint_check_the_copied_list_would_be_customer_trusted(
    tmp_path, monkeypatch
):
    """The control: with the fingerprint check switched off, the copied list loads as customer trust and the bundled
    sample is accepted for your own reports, unlabelled. It is the fingerprint check that refuses it."""
    config = _bundled_list_copied(tmp_path / "copy", None)
    monkeypatch.setattr(config_module, "is_demonstration_entry", lambda _pem: False)
    portal = load_portal(config)
    assert portal.trust_mode == "customer"
    body = post_bytes(client_for(config), _bundled_sample("trusted.json")).json()
    assert (
        body["verification"]["trust_status"] == "TRUSTED"
        and body["synthetic_demonstration"] is False
    )
    assert "demonstration_label" not in body


# ----------------------------------------------------------------------------- a changed key is a different key


def _changed_key() -> str:
    """The bundled key with one bit of the key itself changed: a different, valid public key."""
    der = bytearray(base64.b64decode("".join(BUNDLED_PEM.strip().splitlines()[1:-1])))
    for index in range(len(der) - 32, len(der)):
        for bit in range(8):
            changed = bytearray(der)
            changed[index] ^= 1 << bit
            try:
                key = Ed25519PublicKey.from_public_bytes(bytes(changed[-32:]))
            except ValueError:
                continue
            return key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
    raise AssertionError("no changed key could be loaded")


@pytest.mark.parametrize("setting", [None, "customer"])
def test_a_changed_demonstration_key_is_an_ordinary_key_that_never_accepts_the_bundled_samples(
    tmp_path, setting
):
    """It is treated as what it is, an ordinary key in customer trust. It cannot be promoted: the bundled samples,
    signed by the real demonstration key, are INVALID against it, under the same key id and issuer name."""
    pem = _changed_key()
    assert spki_fingerprint(pem) != BUNDLED_FINGERPRINT
    root = make_synthetic_portal(tmp_path / "own")
    _store(
        root,
        {
            "demo-only-synthetic-key": {
                "issuer": "DEMO-ONLY synthetic issuer",
                "public_key_pem": pem,
                "status": "active",
            }
        },
    )
    config = _config(root, trust_mode=setting)
    portal = load_portal(config)
    assert portal.trust_mode == "customer"
    client = client_for(config)
    for name in ("trusted.json", "plaintext-backend.json", "declares-encrypted-backend.json"):
        body = post_bytes(client, _bundled_sample(name)).json()
        assert body["verification"]["trust_status"] == "INVALID", name
        assert (
            body["verification"]["accepted"] is False and body["synthetic_demonstration"] is False
        )


def test_a_different_key_under_the_demonstration_names_verifies_only_its_own_reports(tmp_path):
    """A key someone made and enrolled under the bundled key's id and issuer name is customer trust for reports it
    signed, and nothing more: it never accepts the bundled samples."""
    signer = rf.Signer.generate(
        issuer="DEMO-ONLY synthetic issuer", key_id="demo-only-synthetic-key"
    )
    root = make_synthetic_portal(tmp_path / "own")
    _store(
        root,
        {
            "demo-only-synthetic-key": {
                "issuer": "DEMO-ONLY synthetic issuer",
                "public_key_pem": signer.public_key_pem(),
                "status": "active",
            }
        },
    )
    client = client_for(root / "portal-config.json")
    own = post_bytes(client, signed_report(signer)).json()
    assert own["verification"]["trust_status"] == "TRUSTED" and own["trust_mode"] == "customer"
    sample = post_bytes(client, _bundled_sample("trusted.json")).json()
    assert (
        sample["verification"]["trust_status"] == "INVALID"
        and sample["verification"]["accepted"] is False
    )


# ----------------------------------------------------------------------------- folders made by the earlier demo-setup


def test_an_old_demo_folder_with_fresh_keys_and_the_marker_keeps_working_as_a_demonstration(
    tmp_path,
):
    root = make_synthetic_portal(tmp_path / "old", trust_mode="demonstration")
    client = client_for(root / "portal-config.json")
    assert client.app.state.mode == "demonstration"
    body = post(client, root, "1-trusted.json").json()
    assert (
        body["verification"]["trust_status"] == "TRUSTED" and body["demonstration_label"] == LABEL
    )


def test_an_old_demo_folder_without_the_marker_is_the_known_limit(tmp_path):
    """Its keys were made fresh and nothing can recognise them, so without the setting it is customer trust. This is
    only for folders made by the earlier demo-setup: the current one installs the bundled key, which is refused."""
    root = make_synthetic_portal(tmp_path / "old", trust_mode=None)
    assert load_portal(root / "portal-config.json").trust_mode == "customer"


def test_the_page_reason_names_no_file_and_no_setting():
    """The page gets a plain reason. File names and the exact setting go to the administrator's terminal."""
    reason = app_module._DEMONSTRATION_KEY_REFUSED
    assert "/" not in reason and ".json" not in reason and "trust_mode" not in reason
