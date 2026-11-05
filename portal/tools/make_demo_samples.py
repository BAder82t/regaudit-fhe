"""Make the portal's synthetic demonstration reports, and the demonstration trust list that goes with them.

Run it from the portal folder with the published regaudit-fhe installed:

    python tools/make_demo_samples.py regaudit_portal/samples

A new throwaway key signs the reports. The key lives only in this process: it is never written to a file, a log or the
output, and it is thrown away when the script ends, so nothing in the output can sign anything. What is written is each
signed report (which carries the public key), the demonstration trust list (the public key and the issuer name, nothing
else) and the manifest the portal reads. All data is made up. The names say so.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

import regaudit_fhe as rf
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.reports import ParameterSet

ISSUER = "DEMO-ONLY synthetic issuer"
UNENROLLED = "DEMO-ONLY unenrolled signer"
VERIFIER = "demo-verifier"
DEPLOYMENT = "demonstration-only"
ISSUED_AT = datetime(
    2026, 10, 1, 9, 0, tzinfo=timezone.utc
)  # a fixed time, so the files do not change from run to run

SAMPLES = (
    (
        "trusted",
        "A report from the demonstration issuer",
        "Signed by the demonstration issuer, whose key is in the demonstration trust list. It shows what an accepted "
        "report looks like.",
    ),
    (
        "untrusted-signer",
        "A report signed by a key nobody enrolled",
        "Signed with a different throwaway key that is not in the demonstration trust list. It shows that a valid "
        "signature alone does not make a signer trusted.",
    ),
    (
        "modified",
        "A report changed after it was signed",
        "The trusted report with one field changed after it was signed. It shows how a changed report is caught.",
    ),
    (
        "plaintext-backend",
        "A report that says it was computed on plaintext",
        "The report states that no encryption was used. It shows the wording for a plaintext report.",
    ),
    (
        "declares-encrypted-backend",
        "A report that names an encrypted backend",
        "The report names an encrypted backend, but nothing was encrypted: the file only says so. It shows that the "
        "portal cannot verify such a statement.",
    ),
)


def _drift(signer: rf.Signer, sample_id: str, parameter_set: ParameterSet | None = None) -> dict:
    report = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    return _envelope("drift", report, signer, sample_id, parameter_set)


def _fairness(signer: rf.Signer, sample_id: str) -> dict:
    truth = np.array([1, 0, 1, 1, 0, 1, 0, 0], dtype=float)
    predicted = np.array([1, 0, 1, 0, 0, 1, 1, 0], dtype=float)
    group_a = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
    report = rf.audit_fairness(truth, predicted, group_a, 1.0 - group_a, threshold=0.1)
    return _envelope("fairness", report, signer, sample_id, None)


def _envelope(
    primitive: str, report: object, signer: rf.Signer, sample_id: str, parameter_set
) -> dict:
    envelope = envelope_v2(
        primitive,
        report,
        signer=signer,
        deployment_id=DEPLOYMENT,
        audience=[VERIFIER],
        parameter_set=parameter_set,
        issued_at=ISSUED_AT,
        audit_run_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"demonstration-only/{sample_id}")),
    )
    return envelope.to_dict()


def make(output: Path) -> None:
    """Write the reports, the trust list and the manifest under ``output``."""
    issuer = rf.Signer.generate(issuer=ISSUER, key_id="demo-only-synthetic-key")
    unenrolled = rf.Signer.generate(issuer=UNENROLLED, key_id="demo-only-unenrolled-key")
    trust_list = {
        "entries": {
            issuer.key_id: {
                "issuer": ISSUER,
                "public_key_pem": issuer.public_key_pem(),
                "status": "active",
            }
        }
    }
    trusted = _drift(issuer, "trusted")
    modified = json.loads(json.dumps(trusted))
    modified["deployment_id"] = "changed-after-signing"
    reports = {
        "trusted": trusted,
        "untrusted-signer": _drift(unenrolled, "untrusted-signer"),
        "modified": modified,
        "plaintext-backend": _fairness(issuer, "plaintext-backend"),
        "declares-encrypted-backend": _drift(
            issuer,
            "declares-encrypted-backend",
            ParameterSet(backend="tenseal-ckks", poly_modulus_degree=8192, security_bits=192),
        ),
    }
    (output / "reports").mkdir(parents=True, exist_ok=True)
    for sample_id, report in reports.items():
        (output / "reports" / f"{sample_id}.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "demo-trust-list.json").write_text(json.dumps(trust_list, indent=2) + "\n")
    manifest = {
        "issuer": ISSUER,
        "verifier_id": VERIFIER,
        "trust_list": "demo-trust-list.json",
        "samples": [
            {"id": sid, "file": f"reports/{sid}.json", "title": title, "description": text}
            for sid, title, text in SAMPLES
        ],
    }
    (output / "index.json").write_text(json.dumps(manifest, indent=2) + "\n")
    # The private keys end here. They were never written anywhere.
    del issuer, unenrolled


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) == 2 else None
    if target is None:
        sys.exit("usage: python tools/make_demo_samples.py OUTPUT_FOLDER")
    make(target)
    print(f"wrote the demonstration samples to {target}")
