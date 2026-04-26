"""Example 01 — Client-side local audit (no regulator round-trip).

Scenario: an HR-AI vendor must run a NYC LL144 fairness audit on an
internal evaluation set before deploying a screening model. The vendor
runs every primitive locally, archives the JSON envelopes, and never
ships raw labels or protected-attribute data anywhere.

Run:  python examples/01_client_local_audit.py
"""

from __future__ import annotations

import json
import numpy as np

import regaudit_fhe as rf


def main() -> None:
    rng = np.random.default_rng(2026)
    n = 256

    y_true = (rng.uniform(size=n) < 0.4).astype(float)
    y_pred = ((rng.uniform(size=n) < 0.4) | (y_true.astype(bool))).astype(float)
    group_a = (rng.uniform(size=n) < 0.5).astype(float)
    group_b = 1.0 - group_a

    fair = rf.audit_fairness(y_true, y_pred, group_a, group_b, threshold=0.1)
    fair_env = rf.envelope("fairness", fair)

    p_ref = rng.uniform(size=32)
    q_now = p_ref + rng.normal(scale=0.02, size=32)
    drift = rf.audit_drift(p_ref, q_now, drift_threshold=0.05)
    drift_env = rf.envelope("drift", drift)

    print("FAIRNESS ENVELOPE")
    print(fair_env.to_json())
    print("\nDRIFT ENVELOPE")
    print(drift_env.to_json())

    with open("audit_bundle.json", "w") as fh:
        json.dump({
            "fairness": fair_env.to_dict(),
            "drift": drift_env.to_dict(),
        }, fh, indent=2)
    print("\nWrote audit_bundle.json")


if __name__ == "__main__":
    main()
