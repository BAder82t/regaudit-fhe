"""Quick start: create, sign and STRICTLY verify an audit report, on synthetic data.

Needs only ``pip install regaudit-fhe``. Nothing is read from the repository, so it runs
from an installed wheel in any directory::

    python strict_verification_quickstart.py [--out DIR]

The point of the script is the difference between two questions:

* "Is this file intact, and does its signature match the key inside it?"
  Anyone can make that true: an attacker signs with their own key and embeds it.
* "Was it signed by a key *I* approved?"  That needs a trust store the verifier wrote
  down beforehand. Only this one yields TRUSTED.

It exits 0 if every step behaved as described and 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np

import regaudit_fhe as rf

ISSUER, KEY_ID, DEPLOYMENT, VERIFIER = "acme-bank", "acme-2026-04", "prod-eu-1", "regulator-a"
failures: list[str] = []


def expect(label: str, ok: bool) -> None:
    print(f"      {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        failures.append(label)


def cli_verify(*args: str) -> tuple[int, dict | None]:
    """Run the real ``regaudit-fhe verify`` in a subprocess; return (exit code, JSON verdict)."""
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", "verify", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, (json.loads(proc.stdout) if proc.stdout.strip() else None)


def main(out: Path) -> int:
    rng = np.random.default_rng(7)  # synthetic data only
    n = 64
    group_a = (rng.uniform(size=n) < 0.5).astype(float)
    y_true = (rng.uniform(size=n) < 0.4).astype(float)
    y_pred = (rng.uniform(size=n) < 0.4).astype(float)

    print("[1] ISSUER: audit synthetic data and sign it with a long-lived key (report.v2)")
    signer = rf.Signer.generate(issuer=ISSUER, key_id=KEY_ID)  # a KMS/HSM key in production
    report = rf.audit_fairness(y_true, y_pred, group_a, 1.0 - group_a, threshold=0.1)
    env = rf.envelope_v2(
        "fairness", report, signer=signer, deployment_id=DEPLOYMENT, audience=[VERIFIER]
    )
    report_path = out / "report.json"
    report_path.write_text(env.to_json() + "\n", encoding="utf-8")
    print(f"      wrote {report_path}")

    print("[2] VERIFIER: write down which keys you approve (this file belongs to the verifier)")
    store_path = out / "trust_store.json"
    store = {
        "entries": {
            KEY_ID: {
                "issuer": ISSUER,
                "public_key_pem": signer.public_key_pem(),
                "status": "active",
            }
        }
    }
    store_path.write_text(json.dumps(store, indent=2) + "\n", encoding="utf-8")
    print(f"      wrote {store_path}")
    trust = rf.TrustStore.from_json(store_path)
    policy = rf.VerificationPolicy(trust_store=trust, verifier_id=VERIFIER)

    print("[3] STRICT verification against the trust store")
    res = rf.verify_report(rf.parse_envelope(report_path.read_text("utf-8")), policy)
    expect(
        "trust_status is TRUSTED and accepted is True",
        res.trust_status == "TRUSTED" and res.accepted,
    )

    print("[4] A valid signature is NOT a trusted signer: no trust store, embedded key only")
    loose = rf.verify_report(env, rf.VerificationPolicy(allow_self_signed=True))
    expect(
        "integrity_valid is True but trust_status is SELF_SIGNED_ONLY and accepted is False",
        loose.integrity_valid and loose.trust_status == "SELF_SIGNED_ONLY" and not loose.accepted,
    )
    try:
        rf.verify_report(env, rf.VerificationPolicy())
        expect("no trust material and no opt-in is refused", False)
    except rf.VerificationUnavailable:
        expect("no trust material and no opt-in is refused (VerificationUnavailable)", True)

    print("[5] An impostor signs a perfectly consistent report with their own key")
    impostor = rf.Signer.generate(issuer=ISSUER, key_id=KEY_ID)  # same names, different key
    forged = rf.envelope_v2(
        "fairness", report, signer=impostor, deployment_id=DEPLOYMENT, audience=[VERIFIER]
    )
    own = rf.verify_report(forged, rf.VerificationPolicy(allow_self_signed=True))
    expect("on its own the forgery looks fine (integrity_valid True)", own.integrity_valid)
    res = rf.verify_report(forged, policy)
    print(f"      against the trust store: {res.trust_status} {list(res.blocking_reasons)}")
    expect(
        "the trust store rejects it (INVALID, not accepted)",
        res.trust_status == "INVALID" and not res.accepted,
    )

    print("[6] Tampering with the signed result")
    body = json.loads(env.to_json())
    body["result"]["demographic_parity_diff"] += 0.5  # e.g. hide a disparity
    res = rf.verify_report(rf.parse_envelope(json.dumps(body)), policy)
    print(f"      {res.trust_status} {list(res.blocking_reasons)}")
    expect("a changed result is INVALID", res.trust_status == "INVALID" and not res.accepted)

    print("[7] The same checks through the command line (exit codes are the contract)")
    code, verdict = cli_verify(
        "-i", str(report_path), "--trusted-keys", str(store_path), "--verifier-id", VERIFIER
    )
    expect(
        "exit 0 and TRUSTED with --trusted-keys", code == 0 and verdict["trust_status"] == "TRUSTED"
    )
    code, verdict = cli_verify("-i", str(report_path), "--allow-self-signed")
    expect(
        "exit 1 and SELF_SIGNED_ONLY with --allow-self-signed only",
        code == 1 and verdict["trust_status"] == "SELF_SIGNED_ONLY",
    )
    code, _ = cli_verify("-i", str(report_path))
    expect("exit 2 with no trust material at all", code == 2)

    print()
    if failures:
        print(f"FAILED: {len(failures)} step(s) did not behave as documented")
        return 1
    print("OK. Remember: TRUSTED means 'signed by a key in YOUR trust store', and only that.")
    print("It says nothing about the audit being correct, complete or compliant.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--out", type=Path, help="directory for the files written (default: a temp dir)"
    )
    ns = parser.parse_args()
    if ns.out is not None:
        ns.out.mkdir(parents=True, exist_ok=True)
        raise SystemExit(main(ns.out))
    with tempfile.TemporaryDirectory(prefix="regaudit-quickstart-") as tmp:
        raise SystemExit(main(Path(tmp)))
