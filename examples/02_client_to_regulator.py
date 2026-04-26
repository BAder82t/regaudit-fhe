"""Example 02 — Client packages an audit bundle for a regulator.

Scenario: an oncology-AI vendor must submit FDA SaMD post-market
concordance and conformal-calibration evidence each quarter. The vendor
runs the C-index and conformal primitives locally, attaches the receipts
to a regulator submission, and uploads the JSON bundle to the regulator
portal.

Run:  python examples/02_client_to_regulator.py
"""

from __future__ import annotations

import json
import numpy as np

import regaudit_fhe as rf


def main() -> None:
    rng = np.random.default_rng(7)
    n = 64

    risk = rng.standard_normal(n)
    time = np.abs(rng.standard_normal(n)) * 100
    event = (rng.uniform(size=n) < 0.7).astype(float)
    cindex = rf.audit_concordance(risk, time, event)
    cindex_env = rf.envelope("concordance", cindex)

    K = 16
    scores = rng.uniform(size=K)
    quantiles = np.full(K, 0.5)
    cal = rf.audit_calibration(scores, quantiles)
    cal_env = rf.envelope("calibration", cal)

    bundle = {
        "vendor": "Example Oncology AI Inc.",
        "submission_period": "2026-Q2",
        "envelopes": [cindex_env.to_dict(), cal_env.to_dict()],
    }
    with open("regulator_submission.json", "w") as fh:
        json.dump(bundle, fh, indent=2)
    print("Wrote regulator_submission.json")
    print(json.dumps(bundle, indent=2))


if __name__ == "__main__":
    main()
