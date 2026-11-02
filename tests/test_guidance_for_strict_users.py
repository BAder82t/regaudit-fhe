"""A strict profile refuses what ``trust migrate`` writes, so no message may send a strict user there."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.verification import PolicyError, VerificationPolicy

SIGNER = rf.Signer.generate(issuer="acme", key_id="k")
PEM = SIGNER.public_key_pem()
LEGACY = {"keys": {"k": PEM}}
STRICT = ("confidential", "high-assurance", "secure-v1")
STRICT_KW = [
    "--max-age-seconds",
    "3600",
    "--replay-mode",
    "record",
    "--replay-db",
    "x.db",
    "--verifier-id",
    "reg",
]


def cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=cwd,
        check=False,
    )


def _says_the_right_thing(message: str) -> None:
    assert "trust add" in message and "docs/MIGRATION_0.3.md" in message
    assert (
        "Run: regaudit-fhe trust migrate" not in message
        and "See 'regaudit-fhe trust migrate'" not in message
    )
    assert "(regaudit-fhe trust migrate)" not in message


@pytest.mark.parametrize("profile", STRICT)
def test_the_policy_refusal_points_to_trust_add(profile, tmp_path):
    with pytest.raises(PolicyError) as caught:
        VerificationPolicy(
            profile=profile, trust_store=rf.TrustStore.from_dict(LEGACY), max_age=timedelta(hours=1), verifier_id="reg",
            replay_mode="record", replay_cache=SqliteReplayCache(tmp_path / "x.db"),
        )  # fmt: skip
    _says_the_right_thing(str(caught.value))
    assert "trust migrate" not in str(caught.value)


@pytest.mark.parametrize("profile", STRICT)
def test_the_refusal_of_a_migrated_store_points_to_trust_add(profile, tmp_path):
    (tmp_path / "old.json").write_text(json.dumps(LEGACY))
    assert (
        cli(
            "trust",
            "migrate",
            "--source",
            "old.json",
            "--target",
            "new.json",
            "--issuer",
            "k=acme",
            cwd=tmp_path,
        ).returncode
        == 0
    )
    with pytest.raises(PolicyError) as caught:
        VerificationPolicy(
            profile=profile, trust_store=rf.TrustStore.from_json(tmp_path / "new.json"), max_age=timedelta(hours=1),
            verifier_id="reg", replay_mode="record", replay_cache=SqliteReplayCache(tmp_path / "x.db"),
        )  # fmt: skip
    _says_the_right_thing(str(caught.value))


@pytest.fixture
def work(tmp_path: Path) -> Path:
    env = rf.envelope(
        "drift", rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])), signer=SIGNER
    )
    (tmp_path / "r.json").write_text(json.dumps(env.to_dict()))
    (tmp_path / "t.json").write_text(json.dumps(LEGACY))
    return tmp_path


def test_the_cli_refusal_points_to_trust_add(work):
    out = cli(
        "verify",
        "-i",
        "r.json",
        "--trusted-keys",
        "t.json",
        "--profile",
        "confidential",
        *STRICT_KW,
        cwd=work,
    )
    assert out.returncode == 2
    _says_the_right_thing(out.stderr)


def test_the_cli_warning_in_development_points_to_trust_add(work):
    out = cli("verify", "-i", "r.json", "--trusted-keys", "t.json", cwd=work)
    assert out.returncode == 0
    _says_the_right_thing(out.stderr)


def test_the_lenient_verifier_warning_points_to_trust_add():
    env = rf.envelope(
        "drift", rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])), signer=SIGNER
    )
    with pytest.warns(DeprecationWarning) as caught:
        rf.verify_envelope(env, trust_store=rf.TrustStore.from_dict(LEGACY))
    _says_the_right_thing(str(caught[0].message))


def test_the_cli_refusal_keeps_its_exit_and_code_for_the_store(work):
    out = cli(
        "verify",
        "-i",
        "r.json",
        "--trusted-keys",
        "t.json",
        "--profile",
        "secure-v1",
        *STRICT_KW,
        cwd=work,
    )
    assert out.returncode == 2 and "states the issuer of each key" in out.stderr and not out.stdout
