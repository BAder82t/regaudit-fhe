"""Deterministic corpus of signed reports and the policies they are checked under (P3-04 equivalence test).

Keys are fixed so the corpus is reproducible. ``golden_claims/verdicts.json`` holds the verdicts the engine gave
before the claim labels were added; the equivalence test replays the corpus and compares.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import regaudit_fhe as rf
from regaudit_fhe.replay import InMemoryReplayCache

ISSUER = "corpus-vendor.example"
KEY_ID = "corpus-key-1"
VERIFIER = "corpus-verifier"
NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
ISSUED = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)


def _signer(seed: int, key_id: str) -> rf.Signer:
    priv = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    return rf.Signer(issuer=ISSUER, key_id=key_id, private_key=priv, public_key=priv.public_key())


VENDOR = _signer(7, KEY_ID)
STRANGER = _signer(9, "corpus-stranger")

FHE_DECLARED = rf.ParameterSet(
    backend="tenseal-ckks",
    poly_modulus_degree=8192,
    security_bits=128,
    multiplicative_depth=6,
    coeff_mod_bit_sizes=(60, 40, 40, 60),
    scaling_factor_bits=40,
    backend_version="0.3.16",
)


def _report() -> Any:
    rng = np.random.default_rng(7)
    n = 32
    y_true = (rng.uniform(size=n) < 0.4).astype(float)
    y_pred = (rng.uniform(size=n) < 0.4).astype(float)
    group_a = (rng.uniform(size=n) < 0.5).astype(float)
    return rf.audit_fairness(y_true, y_pred, group_a, 1.0 - group_a, threshold=0.1)


def _v2(signer: rf.Signer, params: rf.ParameterSet | None, issued: datetime, run: str) -> str:
    return rf.envelope_v2(
        "fairness",
        _report(),
        signer=signer,
        deployment_id="prod-eu-1",
        audit_run_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, run)),
        audience=[VERIFIER],
        parameter_set=params,
        issued_at=issued,
    ).to_json()


def _v1(params: rf.ParameterSet | None) -> str:
    return rf.envelope("fairness", _report(), signer=VENDOR, parameter_set=params).to_json()


def store() -> rf.TrustStore:
    return rf.TrustStore.from_dict(
        {
            "entries": {
                KEY_ID: {
                    "issuer": ISSUER,
                    "public_key_pem": VENDOR.public_key_pem(),
                    "status": "active",
                }
            }
        }
    )


def policy(*, max_age: timedelta | None = None, replay: bool = False) -> rf.VerificationPolicy:
    kwargs: dict[str, Any] = {}
    if replay:
        kwargs.update(replay_cache=InMemoryReplayCache(), replay_mode="record")
    return rf.VerificationPolicy(
        trust_store=store(),
        verifier_id=VERIFIER,
        max_age=max_age,
        now=lambda: NOW,
        check_provenance=True,
        **kwargs,
    )


def build_texts() -> dict[str, str]:
    good = _v2(VENDOR, None, ISSUED, "run-plain")
    tampered = json.loads(good)
    tampered["result"]["demographic_parity_diff"] += 0.5
    return {
        "valid_plaintext_v2": good,
        "valid_fhe_declared_v2": _v2(VENDOR, FHE_DECLARED, ISSUED, "run-fhe"),
        "valid_v1_plaintext": _v1(None),
        "valid_v1_fhe_declared": _v1(FHE_DECLARED),
        "tampered_v2": json.dumps(tampered),
        "stranger_v2": _v2(STRANGER, None, ISSUED, "run-stranger"),
        "expired_v2": _v2(VENDOR, None, datetime(2024, 1, 1, tzinfo=timezone.utc), "run-old"),
        "replayed_v2": good,
    }


GOLDEN = Path(__file__).parent / "golden_claims" / "corpus.json"


def texts() -> dict[str, str]:
    """The frozen report texts (the v1 reports carry their signing time, so they are stored, not rebuilt)."""
    loaded: dict[str, str] = json.loads(GOLDEN.read_text())["texts"]
    return loaded


def scenarios() -> list[tuple[str, str, rf.VerificationPolicy, int]]:
    """(name, report text, policy, times to verify). The verdict kept is the last one."""
    t = texts()
    rows: list[tuple[str, str, rf.VerificationPolicy, int]] = []
    for name, text in t.items():
        if name == "expired_v2":
            rows.append((name, text, policy(max_age=timedelta(days=30)), 1))
        elif name == "replayed_v2":
            rows.append((name, text, policy(replay=True), 2))
        else:
            rows.append((name, text, policy(), 1))
    return rows


def run_all() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name, text, pol, times in scenarios():
        res = None
        for _ in range(times):
            res = rf.verify_report(rf.parse_envelope(text), pol)
        assert res is not None
        out[name] = res.to_dict()
    return out


CLI_CASES = (
    "valid_plaintext_v2",
    "valid_fhe_declared_v2",
    "valid_v1_plaintext",
    "tampered_v2",
    "stranger_v2",
    "expired_v2",
)


def run_cli(workdir: Path) -> dict[str, dict[str, Any]]:
    """Run ``regaudit-fhe verify`` in-process on the stored texts. Returns exit code, stdout JSON and stderr."""
    import contextlib
    import io

    import regaudit_fhe.cli as cli

    t = texts()
    store_path = workdir / "store.json"
    store_path.write_text(
        json.dumps(
            {
                "entries": {
                    KEY_ID: {
                        "issuer": ISSUER,
                        "public_key_pem": VENDOR.public_key_pem(),
                        "status": "active",
                    }
                }
            }
        )
    )
    out: dict[str, dict[str, Any]] = {}
    for name in CLI_CASES:
        report = workdir / f"{name}.json"
        report.write_text(t[name])
        argv = [
            "verify",
            "--input",
            str(report),
            "--trusted-keys",
            str(store_path),
            "--verifier-id",
            VERIFIER,
        ]
        if name == "expired_v2":
            argv += ["--max-age-seconds", "86400"]
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
        out[name] = {
            "exit": code,
            "stdout": json.loads(stdout.getvalue()) if stdout.getvalue().strip() else None,
            "stderr": stderr.getvalue(),
        }
    return out
