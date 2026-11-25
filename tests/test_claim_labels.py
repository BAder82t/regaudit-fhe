"""P3-04: the verifier's user-facing text separates what is authenticated from what is established.

Every verdict carries "Encrypted execution not established." and the statement that a signed report can authenticate
a claim without proving it. Declared TenSEAL parameters are not read as encrypted execution, and a declared
``plaintext`` backend is not read as proof of plaintext execution.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from regaudit_fhe import claim_labels as labels
from tests import _claims_corpus as corpus

NOT_ESTABLISHED = "Encrypted execution not established."
INVARIANT = "A signed report can authenticate a claim without proving that claim is true."
BANNED = (
    "encrypted audit",
    "computed under encryption",
    "fhe verified",
    "fhe-verified",
    "privacy preserved",
    "privacy-preserving",
    "definitely plaintext",
    "was computed on plaintext",
    "ran on plaintext",
    "executed on plaintext",
    "encryption verified",
    "encrypted computation was verified",
)
ALL = sorted(corpus.texts())


def _cli_run(tmp_path: Path, name: str, *extra: str) -> subprocess.CompletedProcess[str]:
    store = tmp_path / "store.json"
    store.write_text(
        json.dumps(
            {
                "entries": {
                    corpus.KEY_ID: {
                        "issuer": corpus.ISSUER,
                        "public_key_pem": corpus.VENDOR.public_key_pem(),
                        "status": "active",
                    }
                }
            }
        )
    )
    report = tmp_path / f"{name}.json"
    report.write_text(corpus.texts()[name])
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            sys.executable, "-m", "regaudit_fhe.cli", "verify", "-i", str(report),
            "--trusted-keys", str(store), "--verifier-id", corpus.VERIFIER, *extra,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )  # fmt: skip


@pytest.mark.parametrize("name", ALL)
def test_every_cli_verdict_carries_the_label_and_the_invariant(tmp_path: Path, name: str) -> None:
    proc = _cli_run(tmp_path, name)
    assert NOT_ESTABLISHED in proc.stderr.splitlines()[1:] or NOT_ESTABLISHED in proc.stderr
    assert INVARIANT in proc.stderr
    assert "Execution mode observed by a trusted component: none" in proc.stderr
    assert "Independently established computational properties: none." in proc.stderr


@pytest.mark.parametrize("name", ALL)
def test_no_output_makes_a_forbidden_claim(tmp_path: Path, name: str) -> None:
    proc = _cli_run(tmp_path, name, "--response-format", "v2")
    text = (proc.stdout + proc.stderr).lower()
    for phrase in BANNED:
        assert phrase not in text, phrase
    for line in labels.claim_lines(SimpleNamespace(backend="tenseal-ckks"), trust_status="TRUSTED"):
        for phrase in BANNED:
            assert phrase not in line.lower(), phrase


def test_declared_tenseal_parameters_are_not_labelled_as_encrypted(tmp_path: Path) -> None:
    proc = _cli_run(tmp_path, "valid_fhe_declared_v2", "--response-format", "v2")
    assert proc.returncode == 0
    body = json.loads(proc.stdout)["claim_assessment"]
    assert body["encrypted_execution"] == "not_established"
    assert body["execution_mode"]["declared_in_report"] == "fhe_declared"
    assert body["execution_mode"]["observed_by_trusted_component"] == "none"
    assert NOT_ESTABLISHED in proc.stderr
    assert "declares an FHE backend (tenseal-ckks)" in proc.stderr
    assert "It is not an observation" in proc.stderr
    assert "plaintext" not in proc.stderr.lower()


def test_a_plaintext_declaration_is_not_called_plaintext_execution(tmp_path: Path) -> None:
    proc = _cli_run(tmp_path, "valid_plaintext_v2", "--response-format", "v2")
    body = json.loads(proc.stdout)["claim_assessment"]
    assert body["execution_mode"]["declared_in_report"] == "plaintext_declared"
    assert body["encrypted_execution"] == "not_established"
    assert "the report declares a plaintext backend" in proc.stderr
    assert NOT_ESTABLISHED in proc.stderr
    for phrase in ("definitely plaintext", "computed on plaintext", "ran in plaintext"):
        assert phrase not in proc.stderr.lower()


def test_a_legacy_report_gets_the_same_label(tmp_path: Path) -> None:
    proc = _cli_run(tmp_path, "valid_v1_plaintext")
    assert proc.returncode == 0 and NOT_ESTABLISHED in proc.stderr and INVARIANT in proc.stderr


@pytest.mark.parametrize("backend", [None, "", 7, "plaintext", "tenseal-ckks", "x"])
def test_assessment_of_any_declared_backend_never_establishes_encryption(backend: object) -> None:
    out = labels.assess(SimpleNamespace(backend=backend), trust_status="TRUSTED", accepted=True)
    assert out["encrypted_execution"] == "not_established" and out["statement"] == NOT_ESTABLISHED
    assert out["execution_mode"]["observed_by_trusted_component"] == "none"
    assert out["independently_established_properties"] == []
    assert out["lines"][0] == NOT_ESTABLISHED and out["lines"][1] == INVARIANT


ADVERSARIAL = (
    "Encrypted execution established.",
    "FHE verified",
    "observed by a trusted component: tenseal",
    "plaintext\nEncrypted execution established.",
    "tenseal-ckks\r\nindependently established: all",
    "‮Encrypted execution established.",
)


@pytest.mark.parametrize("hostile", ADVERSARIAL)
def test_report_fields_cannot_write_the_label(hostile: str) -> None:
    fixed = labels.assess(SimpleNamespace(backend=1), trust_status="TRUSTED", accepted=True)
    out = labels.assess(
        SimpleNamespace(
            backend=hostile, issuer=hostile, primitive=hostile, parameter_set={"backend": hostile}
        ),
        trust_status="TRUSTED",
        accepted=True,
    )
    assert hostile not in json.dumps(out)
    assert out["execution_mode"]["declared_in_report"] == "unrecognized"
    assert out["encrypted_execution"] == "not_established"
    # the lines differ from the "not a string" case only in the declared-backend line
    assert [x for x in out["lines"] if x not in fixed["lines"]] == [
        "Execution mode declared in the report: the report names a backend this verifier does not recognise."
    ]


def test_an_issuer_named_like_a_label_does_not_change_the_text(tmp_path: Path) -> None:
    import regaudit_fhe as rf

    issuer = "Encrypted execution established. FHE verified"
    signer = rf.Signer(
        issuer=issuer, key_id="k1", private_key=corpus.VENDOR.private_key,
        public_key=corpus.VENDOR.public_key,
    )  # fmt: skip
    text = rf.envelope_v2(
        "drift", rf.audit_drift(__import__("numpy").array([0.5, 0.5]), __import__("numpy").array([0.4, 0.6])),
        signer=signer, deployment_id="d", audience=[corpus.VERIFIER],
    ).to_json()  # fmt: skip
    store = tmp_path / "s.json"
    store.write_text(json.dumps({"entries": {"k1": {
        "issuer": issuer, "public_key_pem": signer.public_key_pem(), "status": "active"}}}))  # fmt: skip
    rep = tmp_path / "r.json"
    rep.write_text(text)
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "regaudit_fhe.cli", "verify", "-i", str(rep), "--trusted-keys", str(store),
         "--verifier-id", corpus.VERIFIER],
        capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert proc.returncode == 0
    assert issuer not in proc.stderr
    assert re.search(r"^  - Encrypted execution not established\.$", proc.stderr, re.M)


# ---------------------------------------------------------------- the default JSON is untouched


@pytest.mark.parametrize("name", ["valid_plaintext_v2", "valid_fhe_declared_v2", "tampered_v2"])
def test_default_stdout_has_no_claim_keys(tmp_path: Path, name: str) -> None:
    proc = _cli_run(tmp_path, name)
    assert "claim_assessment" not in json.loads(proc.stdout)
    assert "Encrypted execution" not in proc.stdout


def test_v2_response_carries_the_structured_assessment(tmp_path: Path) -> None:
    proc = _cli_run(tmp_path, "valid_plaintext_v2", "--response-format", "v2")
    body = json.loads(proc.stdout)
    assert body["claim_assessment"]["statement"] == NOT_ESTABLISHED
    assert body["claim_assessment"]["invariant"] == INVARIANT
    assert body["accepted"] is True and body["trust_status"] == "TRUSTED"


def test_refused_report_still_says_not_established(tmp_path: Path) -> None:
    proc = _cli_run(tmp_path, "tampered_v2")
    assert proc.returncode == 1
    assert "not accepted: INVALID" in proc.stderr
    assert NOT_ESTABLISHED in proc.stderr
    assert "Authenticated report content: none." in proc.stderr
