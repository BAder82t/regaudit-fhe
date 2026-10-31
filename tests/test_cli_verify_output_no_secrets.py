"""`verify` prints verdict metadata only: no key material or free-form report content.

Synthetic keys and sentinel strings only. Pins the stdout field inventory and checks that
neither stream carries the private key (PEM body, DER base64, or hex) on any verdict path.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

DRIFT = {"p": [0.2, 0.3, 0.5], "q": [0.25, 0.25, 0.5]}

SENTINEL = "SENTINEL-7f3c9a-not-a-secret"

STDOUT_FIELDS = {
    "trust_status", "accepted", "valid", "integrity_valid", "issuer_trusted", "key_status",
    "chronology", "signed_not_after", "timestamp_status", "reasons", "blocking_reasons",
    "policy_id", "format", "replay_scope", "replay_durable", "consumption", "trust_history",
    "trust_store_as_of", "issuer", "key_id", "primitive", "issued_at", "regulations",
    "parameter_set_hash", "deployment_id", "audit_run_id", "trusted_issuer", "reason",
}  # fmt: skip


def cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=cwd,
        check=False,
    )


@pytest.fixture
def work(tmp_path: Path) -> Path:
    (tmp_path / "in.json").write_text(json.dumps(DRIFT))
    return tmp_path


def _keygen(work: Path, name: str = "k", key_id: str = "acme-2026") -> dict:
    proc = cli(
        "keygen", "--key-id", key_id, "--issuer", "acme",
        "--private-key", f"{name}.pem", "--public-key", f"{name}.pub", cwd=work,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _sign(work: Path):
    return cli(
        "audit", "drift", "-i", "in.json", "-o", "report.json",
        "--signing-key", "k.pem", "--key-id", "acme-2026", "--issuer", "acme", "--deployment-id", "prod-1", cwd=work,
    )  # fmt: skip


def _trust_add(work: Path, info: dict, name: str = "k", store: str = "store.json"):
    return cli(
        "trust", "add", "--store", store, "--key-id", info["key_id"], "--issuer", "acme",
        "--public-key", f"{name}.pub", "--fingerprint", info["fingerprint_sha256"], cwd=work,
    )  # fmt: skip


def _verify(work: Path, *extra: str, report: str = "report.json"):
    return cli("verify", "-i", report, *extra, cwd=work)


def _private_markers(path: Path) -> list[str]:
    pem = path.read_text()
    body = "".join(pem.strip().splitlines()[1:-1])
    der = base64.b64decode(body)
    return ["PRIVATE KEY", body, der.hex(), base64.b64encode(der[-32:]).decode()]


def _assert_clean(proc, markers: list[str]) -> None:
    for stream in (proc.stdout, proc.stderr):
        for marker in markers:
            assert marker not in stream


def _scalar_or_str_list(value) -> bool:
    return (
        value is None
        or isinstance(value, bool | str)
        or (isinstance(value, list) and all(isinstance(v, str) for v in value))
    )


@pytest.fixture
def signed(work: Path):
    info = _keygen(work)
    assert _sign(work).returncode == 0
    assert _trust_add(work, info).returncode == 0
    return info, _private_markers(work / "k.pem")


def test_stdout_is_an_allowlisted_scalar_inventory_on_every_verdict_path(work, signed):
    _info, markers = signed
    report = json.loads((work / "report.json").read_text())

    tampered = dict(report, result={"x": 1})
    (work / "tampered.json").write_text(json.dumps(tampered))
    other = _keygen(work, name="o", key_id="other-1")
    assert _trust_add(work, other, name="o", store="other.json").returncode == 0
    store = "store.json"

    runs = [
        _verify(work, "--trusted-keys", store),  # TRUSTED
        _verify(work, "--trusted-keys", store, report="tampered.json"),  # INVALID
        _verify(work, "--trusted-keys", "other.json"),  # untrusted issuer
        _verify(work, "--allow-self-signed"),  # SELF_SIGNED_ONLY
    ]
    assert [r.returncode for r in runs] == [0, 1, 1, 1]
    for proc in runs:
        payload = json.loads(proc.stdout)
        assert set(payload) <= STDOUT_FIELDS
        assert all(_scalar_or_str_list(v) for v in payload.values())
        assert isinstance(payload["issuer_trusted"], bool)
        assert isinstance(payload["trusted_issuer"], bool)
        _assert_clean(proc, markers)


def test_free_form_report_content_is_not_echoed(work, signed):
    _, markers = signed
    report = json.loads((work / "report.json").read_text())
    report["result"] = {"note": SENTINEL}
    (work / "r2.json").write_text(json.dumps(report))  # signature no longer matches
    proc = _verify(work, "--trusted-keys", "store.json", report="r2.json")
    assert proc.returncode == 1
    assert SENTINEL not in proc.stdout + proc.stderr
    _assert_clean(proc, markers)


def test_malformed_and_unusable_inputs_do_not_leak_the_private_key(work, signed):
    _, markers = signed
    (work / "bad.json").write_text("{" + SENTINEL)
    store = "store.json"
    (work / "badstore.json").write_text("{" + SENTINEL)
    runs = [
        _verify(work, "--trusted-keys", store, report="bad.json"),
        _verify(work, "--trusted-keys", "badstore.json"),
        _verify(work, "--trusted-keys", store, report="missing.json"),
        _verify(work),  # no trust material
        _verify(work, "--trusted-keys", store, report="k.pem"),  # private key given as the report
        _verify(work, "--trusted-keys", "k.pem"),  # private key given as the trust store
    ]
    assert [r.returncode for r in runs] == [2, 3, 2, 2, 2, 3]
    for proc in runs:
        assert proc.stdout == ""
        _assert_clean(proc, markers)
        assert not re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY", proc.stdout + proc.stderr)
