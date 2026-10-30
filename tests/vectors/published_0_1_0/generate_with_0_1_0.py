"""Generate report.v1 / report.v2 vectors with the PUBLISHED regaudit-fhe 0.1.0 (synthetic data, throwaway key).
Usage: python generate_with_0_1_0.py OUTDIR   (run in an environment where regaudit_fhe.__version__ == 0.1.0)"""

import hashlib
import json
import sys
from pathlib import Path

import numpy as np

import regaudit_fhe as rf
from regaudit_fhe.dp import DPSpec, privatize_report
from regaudit_fhe.reports import TimestampAuthority, commitments_for

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
assert rf.__version__ == "0.1.0", rf.__version__
sg = rf.Signer.generate(
    issuer="vector-issuer-010", key_id="vec010-key-1"
)  # throwaway; private key never saved
rng = np.random.default_rng(20260101)
n = 16
a = (rng.uniform(size=n) < 0.5).astype(float)
yt = (rng.uniform(size=n) < 0.4).astype(float)
yp = (rng.uniform(size=n) < 0.4).astype(float)
p = np.array([0.2, 0.3, 0.5])
q = np.array([0.25, 0.25, 0.5])
reports = {
    "fairness": rf.audit_fairness(yt, yp, a, 1 - a, threshold=0.1),
    "provenance": rf.audit_provenance(
        np.array([0.5, 0.1, 0.3, 0.9, 0.2, 0.4]), np.array([1, 2, 3, 4, 5, 6], dtype=np.int64), 4, 2
    ),
    "concordance": rf.audit_concordance(
        np.array([0.1, 0.4, 0.35, 0.8]),
        np.array([5.0, 4.0, 3.0, 2.0]),
        np.array([1.0, 1.0, 0.0, 1.0]),
    ),
    "calibration": rf.audit_calibration(np.array([0.1, 0.2, 0.3]), np.array([0.15, 0.25, 0.35])),
    "drift": rf.audit_drift(p, q, drift_threshold=0.05),
    "disagreement": rf.audit_disagreement(
        [[0.0, 1.0, 0.0, 0.0], [0.0, 0.9, 0.1, 0.0], [0.0, 1.1, 0.0, 0.05]],
        np.array([0.1, 0.2, 0.3]),
        threshold=0.05,
    ),
}
files = {}


def w(name, obj):
    (out / name).write_text(obj.to_json() + "\n", encoding="utf-8")
    files[name] = True


for prim, rep in reports.items():
    w(f"v1_{prim}.json", rf.envelope(prim, rep, signer=sg))
w(
    "v1_with_commitments.json",
    rf.envelope(
        "drift",
        reports["drift"],
        signer=sg,
        input_commitments=commitments_for({"p": p.tolist(), "q": q.tolist()}),
        regulations=["EU_AI_ACT_ART_15"],
    ),
)
w(
    "v1_with_timestamp_member.json",
    rf.envelope(
        "drift",
        reports["drift"],
        signer=sg,
        timestamp_authority=TimestampAuthority(
            issuer="synthetic-tsa", sign_callable=lambda b: hashlib.sha256(b).digest()
        ),
    ),
)
priv, dpb = privatize_report(
    reports["drift"],
    {"w1_distance": DPSpec(sensitivity=0.1, epsilon=1.0)},
    rng=np.random.default_rng(1),
)
w("v1_with_dp.json", rf.envelope("drift", priv, signer=sg, dp=dpb))
for prim, rep in reports.items():
    w(f"v2_{prim}.json", rf.envelope_v2(prim, rep, signer=sg, deployment_id="vec-deploy"))
w(
    "v2_full.json",
    rf.envelope_v2(
        "drift",
        reports["drift"],
        signer=sg,
        deployment_id="vec-deploy",
        audience=["verifier-a"],
        model_commitment={"name": "model", "sha256": "0" * 64},
        dataset_commitment={"name": "data", "sha256": "1" * 64},
        input_commitments=commitments_for({"p": p.tolist()}),
        dp=dpb,
    ),
)
store_entries = {
    "entries": {
        sg.key_id: {"issuer": sg.issuer, "public_key_pem": sg.public_key_pem(), "status": "active"}
    }
}
(out / "trust_store_entries.json").write_text(json.dumps(store_entries, indent=2) + "\n")
(out / "trust_store_legacy.json").write_text(
    json.dumps({"keys": {sg.key_id: sg.public_key_pem()}}, indent=2) + "\n"
)
man = {
    "generated_by": "regaudit-fhe",
    "version": rf.__version__,
    "source_commit": "600066fe7f3f4c0b85be057f2e5f1569083862af",
    "note": "synthetic data; throwaway Ed25519 key whose private half was discarded",
    "sha256": {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.glob("*.json"))
    },
}
(out / "MANIFEST.json").write_text(json.dumps(man, indent=2) + "\n")
print(len(list(out.glob("*.json"))), "files")
