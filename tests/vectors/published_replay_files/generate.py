"""Write the replay-file fixture with a PUBLISHED regaudit-fhe (0.2.1), downloaded from PyPI with its SHA-256 checked.

    python generate.py VECTOR_JSON OUTDIR       (run where regaudit_fhe is the published 0.2.1 wheel)

The file is what that wheel's own code wrote, base64-encoded because the sdist manifest takes *.json under tests.
"""

import base64
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import regaudit_fhe as rf
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import parse_envelope
from regaudit_fhe.trust import TrustStore
from regaudit_fhe.verification import VerificationPolicy, verify

assert rf.__version__ == "0.2.1", rf.__version__
vec = json.loads(Path(sys.argv[1]).read_text())
report = vec["reports"]["v2-audience"]
env = parse_envelope(json.dumps(report))
store = TrustStore.from_dict(
    {
        "entries": {
            vec["key_id"]: {
                "issuer": vec["issuer"],
                "public_key_pem": vec["public_key_pem"],
                "status": "active",
            }
        }
    }
)
recorded = datetime(2026, 10, 25, 12, 1, tzinfo=timezone.utc)
with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "replay.db"
    result = verify(
        env,
        VerificationPolicy(
            profile="confidential",
            trust_store=store,
            max_age=timedelta(days=1),
            replay_mode="record",
            replay_cache=SqliteReplayCache(db),
            verifier_id="reg",
            now=lambda: recorded,
        ),
    )
    assert result.accepted and result.consumption == "RECORDED_LOCAL", result
    data = db.read_bytes()
out = {
    "written_by": rf.__version__,
    "max_age_s": 86400,
    "recorded_at": recorded.isoformat(),
    "file_b64": base64.b64encode(data).decode(),
    "report": report,
    "public_key_pem": vec["public_key_pem"],
    "issuer": vec["issuer"],
    "key_id": vec["key_id"],
}
Path(sys.argv[2], "by_0.2.1.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
print("wrote", len(data), "bytes signed and recorded by", rf.__version__)
