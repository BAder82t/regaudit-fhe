"""A synthetic demonstration: a trust store, a configuration and sample reports. Nothing here is real evidence.

The private keys exist only while this runs and are not written anywhere.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

import regaudit_fhe as rf
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.reports import ParameterSet

ISSUER = "Example Synthetic Issuer"
VERIFIER = "demo-verifier"
MAX_REPORT_BYTES = 1 << 20


def _report(signer: rf.Signer, parameter_set: ParameterSet | None = None) -> str:
    report = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    env = envelope_v2(
        "drift",
        report,
        signer=signer,
        deployment_id="synthetic-demo",
        audience=[VERIFIER],
        parameter_set=parameter_set,
        issued_at=datetime.now(timezone.utc),
        audit_run_id=str(uuid.uuid4()),
    )
    return json.dumps(env.to_dict(), indent=2)


def create(directory: str | Path) -> Path:
    root = Path(directory).absolute()
    reports = root / "sample-reports"
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    reports.mkdir(mode=0o700)
    issuer = rf.Signer.generate(issuer=ISSUER, key_id="synthetic-issuer-key")
    outsider = rf.Signer.generate(issuer=ISSUER, key_id="synthetic-outsider-key")
    store = {
        "entries": {
            issuer.key_id: {
                "issuer": ISSUER,
                "public_key_pem": issuer.public_key_pem(),
                "status": "active",
            }
        }
    }
    (root / "trust-store.json").write_text(json.dumps(store, indent=2) + "\n")
    config = {
        "trust_store": "trust-store.json",
        "profile": "confidential",
        "verifier_id": VERIFIER,
        "max_age_days": 30,
        "replay_mode": "check",
        "replay_db": "replay.db",
    }
    (root / "portal-config.json").write_text(json.dumps(config, indent=2) + "\n")
    good = _report(issuer)
    (reports / "1-trusted.json").write_text(good)
    (reports / "2-untrusted-signer.json").write_text(_report(outsider))
    other_name = rf.Signer("Another Issuer", issuer.key_id, issuer.private_key, issuer.public_key)
    (reports / "3-valid-signature-wrong-issuer.json").write_text(_report(other_name))
    changed = json.loads(good)
    changed["deployment_id"] = "changed-after-signing"
    (reports / "4-changed-after-signing.json").write_text(json.dumps(changed, indent=2))
    (reports / "5-not-a-report.json").write_text('{"hello": "this is not a signed report"}\n')
    (reports / "6-too-large.json").write_text(" " * (MAX_REPORT_BYTES + 1))
    # Signed by the enrolled key and says it used an encrypted backend. Nothing was encrypted: the report only
    # says so, which is exactly what the portal cannot tell and says it cannot tell.
    declares = ParameterSet(backend="tenseal-ckks", poly_modulus_degree=8192, security_bits=192)
    (reports / "7-declares-encrypted-backend.json").write_text(_report(issuer, declares))
    for path in [root / "trust-store.json", root / "portal-config.json"]:
        os.chmod(path, 0o600)
    return root
