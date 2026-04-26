# regaudit-fhe

**Encrypted regulatory audit primitives for AI systems.**

A small Python library of six audit operations that can be evaluated on
encrypted inputs under fully-homomorphic encryption (CKKS, multiplicative
depth six) without bootstrapping. Designed so a regulated AI vendor can
run mandatory audits — fairness, drift, calibration, provenance,
disagreement, survival concordance — without ever exposing raw labels,
predictions, protected attributes, or training data.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

> Maintained by **VaultBytes Innovations Ltd**. Licensed under
> **AGPL-3.0-or-later** — see [LICENSE](LICENSE).

---

## What it is for

```
┌──────────────┐      encrypted inputs       ┌────────────────┐
│ Regulated    │ ──────────────────────────► │ regaudit-fhe   │
│ AI vendor    │   (labels, preds, PHI,      │ d=6 CKKS audit │
│ (the client) │    protected attrs)         │ primitives     │
└──────────────┘                             └──────┬─────────┘
       ▲                                            │
       │                                            │ encrypted
       │   sealed envelope                          │ aggregate
       │   (JSON + receipt)                         │ scalars only
       │                                            ▼
       │                                     ┌────────────────┐
       └───────────────────────────────────► │ Regulator /    │
                                             │ external       │
              decrypt + verify receipt       │ auditor        │
                                             └────────────────┘
```

Two audiences are served by the same surface area:

| Audience       | Role                                | What they run                                        |
| -------------- | ----------------------------------- | ---------------------------------------------------- |
| **Client**     | Audited entity (vendor / operator). | `audit_*` primitives, `regaudit-fhe audit ...`.      |
| **Regulator**  | External or in-house auditor.       | `verify_receipt(...)`, `regaudit-fhe verify ...`.    |

A run produces an audit envelope (JSON) with a SHA-256 receipt. The
client archives it, ships it to the regulator, or both. The regulator
recomputes the receipt to detect tampering between issuance and review.

---

## The six primitives

| Module        | API                       | Depth | Use case                                                                 |
| ------------- | ------------------------- | ----- | ------------------------------------------------------------------------ |
| `egf_imss`    | `audit_fairness`          | 4     | NYC LL144, EU AI Act §10/§15, Colorado AI Act, CFPB.                     |
| `etk_fpa_hbc` | `audit_provenance`        | 3     | EU AI Act §10, 21 CFR Part 11, GDPR §22, HIPAA.                          |
| `esc_cia`     | `audit_concordance`       | 4     | FDA SaMD oncology PCCP, EU AI Act §15, EMA guidance.                     |
| `ecp_qssp`    | `audit_calibration`       | 3     | FDA SaMD UQ, EU AI Act §15, ISO/IEC 23053, UNECE WP.29.                  |
| `ew1_cdsf`    | `audit_drift`             | 3     | EU AI Act §15, FDA SaMD PCCP, Basel III.                                 |
| `ecmd_jps`    | `audit_disagreement`      | 5     | OCC SR 11-7, EU AI Act §15, FDA SaMD PCCP.                               |

Each primitive's depth budget — the number of multiplicative levels it
consumes inside the d=6 CKKS circuit — is shown above. All six fit
comfortably under six, leaving headroom for downstream commit-and-verify
chaining.

```
Depth budget visualisation (each ▮ = 1 level)

    primitive             0 1 2 3 4 5 6
    ─────────────────────────────────────
    audit_calibration     ▮ ▮ ▮ . . . .   3 of 6
    audit_provenance      ▮ ▮ ▮ . . . .   3 of 6
    audit_drift           ▮ ▮ ▮ . . . .   3 of 6
    audit_fairness        ▮ ▮ ▮ ▮ . . .   4 of 6
    audit_concordance     ▮ ▮ ▮ ▮ . . .   4 of 6
    audit_disagreement    ▮ ▮ ▮ ▮ ▮ . .   5 of 6
```

Each primitive's full specification, including its algorithm, depth
breakdown, and security analysis, is in
[`docs/specs/`](docs/specs/).

---

## Install

```bash
pip install regaudit-fhe
```

The plaintext model that runs the depth-budgeted slot-vector circuits
(used for testing, oracles, and CI) requires only `numpy>=1.26`. The
encrypted execution path lives behind the optional `[fhe]` extra:

```bash
pip install regaudit-fhe[fhe]    # adds OpenFHE
```

---

## Quick start

```python
import numpy as np
import regaudit_fhe as rf

y_true  = np.array([1, 0, 1, 1, 0, 1, 0, 0], dtype=float)
y_pred  = np.array([1, 0, 1, 0, 0, 1, 1, 0], dtype=float)
group_a = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
group_b = 1.0 - group_a

report = rf.audit_fairness(y_true, y_pred, group_a, group_b, threshold=0.1)
print(report.demographic_parity_diff, report.threshold_breached)

envelope = rf.envelope("fairness", report)
print(envelope.to_json())                     # ship this to the regulator

assert rf.verify_receipt(envelope) is True    # regulator-side check
```

### Same flow, command line

```bash
echo '{"y_true":[1,0,1,1],"y_pred":[1,0,0,0],"group_a":[1,1,0,0],"group_b":[0,0,1,1]}' \
  > input.json

regaudit-fhe audit fairness -i input.json -o envelope.json
regaudit-fhe verify -i envelope.json
```

`regaudit-fhe audit <primitive> --schema` prints the JSON shape that
each primitive expects.

---

## Audit envelope

Every `audit_*` call can be wrapped into a regulator-facing JSON
envelope by `regaudit_fhe.envelope(...)`:

```json
{
  "schema": "regaudit-fhe.report.v1",
  "primitive": "fairness",
  "regulations": ["NYC_LL144", "EU_AI_ACT_ART10",
                  "EU_AI_ACT_ART15", "COLORADO_AI_ACT",
                  "CFPB_ALG_DISCRIM"],
  "result": {
    "demographic_parity_diff": 0.083,
    "equal_opportunity_diff": 0.041,
    "predictive_parity_diff": 0.022,
    "threshold_breached": false
  },
  "depth_budget": {"declared": 6, "consumed": 4},
  "issued_at": "2026-04-26T20:30:11.482910+00:00",
  "receipt": {
    "sha256": "9f3c…b4a7",
    "version": "0.0.1"
  }
}
```

`schema` and `regulations` give a regulator the exact citation they
need. `receipt.sha256` is computed over the canonical JSON of every
other field; `verify_receipt(env)` returns `False` if anything changed.

---

## Examples

The [`examples/`](examples/) folder ships four end-to-end flows:

| File                                    | Flow                                                              |
| --------------------------------------- | ----------------------------------------------------------------- |
| `01_client_local_audit.py`              | Internal audit on synthetic data; archive JSON locally.           |
| `02_client_to_regulator.py`             | Build a regulator submission bundle.                              |
| `03_regulator_verify.py`                | Verify every envelope inside a submission bundle.                 |
| `04_cli_roundtrip.sh`                   | Pure CLI: input → audit → verify, no Python knowledge required.   |

Run any of them after `pip install -e .[dev]`.

---

## Layout

```
src/regaudit_fhe/      depth-tracked plaintext model + 6 primitives + reports + CLI
docs/specs/            per-primitive technical specifications
tests/                 pytest unit + integration tests
examples/              client + regulator end-to-end flows
benchmarks/            d=6 CKKS wall-clock + memory benchmarks (planned)
```

---

## Status

`regaudit-fhe` is at **v0.0.1**: the full plaintext model and audit
envelope are in place; the OpenFHE backend (`[fhe]` extra) and a
benchmark harness against OpenFHE / Concrete-ML at `N = 2^15` are the
next milestones.

Contributions welcome under AGPL-3.0. Commercial licensing inquiries:
**b@vaultbytes.com**.
