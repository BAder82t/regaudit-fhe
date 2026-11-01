"""Sign the published-version report vectors. Run once per PUBLISHED regaudit-fhe version, in an
environment that imports that version, and commit the output (tests only, synthetic data):

    python generate.py OUTDIR

The signing key is derived from a fixed public label, so it is a throwaway test key with no secrecy.
``issued_at`` is fixed; ``algorithm_version`` / ``library_version`` are whatever the signing version writes.
"""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import regaudit_fhe as rf

ISSUED = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
priv = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"published-vector-key").digest())
signer = rf.Signer(issuer="vector-issuer", key_id="vec-key", private_key=priv, public_key=priv.public_key())
report = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
run_id = "3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6"
vec = {
    "signed_by": rf.__version__,
    "public_key_pem": signer.public_key_pem(),
    "issuer": "vector-issuer",
    "key_id": "vec-key",
    "reports": {
        "v1": rf.envelope("drift", report, signer=signer).to_dict(),
        "v2-no-audience": rf.envelope_v2(
            "drift", report, signer=signer, deployment_id="dep", issued_at=ISSUED,
            audit_run_id=run_id + "01",
        ).to_dict(),
        "v2-audience": rf.envelope_v2(
            "drift", report, signer=signer, deployment_id="dep", issued_at=ISSUED,
            audit_run_id=run_id + "02", audience=["reg"],
        ).to_dict(),
    },
}  # fmt: skip
out = Path(sys.argv[1]) / f"by_{rf.__version__}.json"
out.write_text(json.dumps(vec, indent=1, sort_keys=True) + "\n", encoding="utf-8")
print("wrote", out, "signed by", rf.__version__)
