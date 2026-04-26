# regaudit-fhe

Depth-tracked regulatory audit primitives for privacy-preserving AI audits.

`regaudit-fhe` provides a plaintext slot-vector reference model, TenSEAL
CKKS backend support, signed audit envelopes, schema validation, and
regulatory audit-evidence helpers.

The default execution path is plaintext. Install the `[fhe]` extra to
enable the TenSEAL CKKS backend where supported. OpenFHE is not
included in this repository.

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

| Module        | API                       | Depth | Use case (technical evidence supporting…)                                |
| ------------- | ------------------------- | ----- | ------------------------------------------------------------------------ |
| `egf_imss`    | `audit_fairness`          | 4     | NYC LL144, EU AI Act §10/§15, Colorado AI Act, CFPB workflows.           |
| `etk_fpa_hbc` | `audit_provenance`        | 3     | EU AI Act §10, 21 CFR Part 11, GDPR §22, HIPAA workflows.                |
| `esc_cia`     | `audit_concordance`       | 4     | FDA SaMD oncology PCCP, EU AI Act §15, EMA workflows.                    |
| `ecp_qssp`    | `audit_calibration`       | 3     | FDA SaMD UQ, EU AI Act §15, ISO/IEC 23053, UNECE WP.29 workflows.        |
| `ew1_cdsf`    | `audit_drift`             | 3     | EU AI Act §15, FDA SaMD PCCP, Basel III workflows.                       |
| `ecmd_jps`    | `audit_disagreement`      | 5     | OCC SR 11-7, EU AI Act §15, FDA SaMD PCCP workflows.                     |

> **Compliance scope and disclaimer.** `regaudit-fhe` produces
> *technical evidence* — encrypted scalars, signed envelopes,
> parameter-set hashes, depth-budget attestations — that may support
> compliance workflows in the jurisdictions above. It does **not**
> constitute legal compliance, conformity assessment, regulatory
> acceptance, or a recognised audit. Read [COMPLIANCE.md](COMPLIANCE.md)
> for the binding scope statement and the
> "what-it-does-NOT-prove" mapping per regulation.

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
pip install regaudit-fhe[fhe]    # adds the TenSEAL CKKS backend
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

> **The HTTP server is NOT a privacy boundary by itself.** The default
> execution path is plaintext; the server runs in-process. Encrypted
> execution requires the `[fhe]` extra AND key custody held off-host.
> Read [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and
> [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before exposing publicly.
> Without the closed-source companion product, the server cannot mint
> regulator-trusted envelopes.

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
  "library_version": "current release",
  "primitive": "fairness",
  "backend": "plaintext-slotvec",
  "parameter_set_hash": "sha256:6b8aedc173e2c94e…",
  "input_commitments": {
    "y_true": "sha256:a5c4…",
    "y_pred": "sha256:7e91…"
  },
  "result": {
    "max_gap": 0.0312,
    "threshold_breached": false
  },
  "receipt": {
    "sha256":        "sha256:9f3c…b4a7",
    "signature_alg": "Ed25519",
    "signature":     "base64:MEUCIQDX…",
    "key_id":        "auditor-key-2026-04"
  }
}
```

`schema`, `parameter_set_hash`, and `input_commitments` give a
regulator the exact citation, parameter binding, and input fingerprint
they need. Unsigned SHA-256 receipts are useful for tamper evidence
only; signed receipts (the default since `regaudit-fhe` v0.0.2)
provide issuer authenticity when the verifier trusts the signing key.

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
docs/THREAT_MODEL.md   roles, key custody, public surface per primitive
schemas/               JSON Schemas (Draft 2020-12) for every input, output, and the envelope
tests/                 pytest unit, integration, edge-case, property-based, schema, security tests
examples/              client + regulator end-to-end flows
benchmarks/            d=6 CKKS wall-clock + memory benchmarks
```

## JSON schemas

Every primitive input, primitive output, and the audit envelope itself
ships with a Draft-2020-12 JSON Schema under [`schemas/`](schemas/).
Auditors and integrators can pin specific schema versions and reject
payloads that do not conform.

```bash
regaudit-fhe schema --list
regaudit-fhe schema fairness.input
regaudit-fhe schema envelope
```

The CLI and HTTP server validate every request body against the
matching schema before invoking the audit primitive; failures return
HTTP 422 / CLI exit-code 2 with a structured pointer to the offending
field. Programmatic access:

```python
import regaudit_fhe as rf
rf.list_schemas()                      # all 13 names
rf.load_schema("fairness.input")       # raw schema dict
rf.validate_input("fairness", payload) # raises rf.SchemaError on bad input
rf.validate_envelope(env_dict)         # check a regulator-side envelope
```

---

## Real CKKS benchmarks

The `[fhe]` extra ships a real TenSEAL CKKS backend; its measurements
are reproduced from `benchmarks/results/SUMMARY.md` (machine-readable
JSON in `benchmarks/results/bench_fhe_<N>.json`).

| Primitive    | N    | Slots  | Depth obs/decl | Rotations | ct×ct | ct×pt | Runtime | RAM    | Max abs err | Threshold flip |
|--------------|-----:|-------:|----------------|----------:|------:|------:|--------:|-------:|-------------|----------------|
| fairness     | 2^14 |  8 192 | 1/4            | 108       |   0   |   18  | 0.28 s  |  878 MB | 4.8 × 10⁻⁷ | 0.00% |
| provenance   | 2^14 |  8 192 | 1/3            | 288       |   0   |   48  | 0.71 s  |  885 MB | 7.9 × 10⁻⁶ | 0.00% |
| concordance  | 2^14 |  8 192 | 4/4            |   0       |   0   |    0  | 0.00 s  |  887 MB | 0          | 0.00% |
| calibration  | 2^14 |  8 192 | 0/3            |   0       |   0   |    0  | 0.01 s  |  890 MB | 0          | 0.00% |
| drift        | 2^14 |  8 192 | 2/2            |  36       |   3   |    6  | 0.18 s  |  968 MB | 2.3 × 10⁻⁶ | 0.00% |
| disagreement | 2^14 |  8 192 | 3/5            |   0       |  36   |    0  | 0.16 s  |  977 MB | 1.1 × 10⁻⁸ | 0.00% |
| fairness     | 2^15 | 16 384 | 1/4            | 108       |   0   |   18  | 0.58 s  | 2.7 GB  | 7.2 × 10⁻⁷ | 0.00% |
| provenance   | 2^15 | 16 384 | 1/3            | 288       |   0   |   48  | 1.52 s  | 2.7 GB  | 1.9 × 10⁻⁵ | 0.00% |
| drift        | 2^15 | 16 384 | 2/2            |  36       |   3   |    6  | 0.39 s  | 2.8 GB  | 1.1 × 10⁻⁵ | 0.00% |
| disagreement | 2^15 | 16 384 | 3/5            |   0       |  36   |    0  | 0.35 s  | 2.7 GB  | 1.4 × 10⁻⁸ | 0.00% |

Run yourself:

```bash
pip install regaudit-fhe[fhe]
python benchmarks/bench_fhe.py --rings 14 15 --reps 3
```

Add `--rings 16` for `N = 2^16` (slower; uses several GB of RAM).

The "Threshold flip" column is the rate at which CKKS noise causes the
encrypted circuit to disagree with the plaintext circuit on a boolean
breach decision over 10–20 trials with inputs sampled near the breach
boundary. Zero flips across both rings means CKKS noise does not
change a regulatory threshold decision at the audit precision targets.

## Maturity and status

> **Description today:** *Depth-tracked regulatory audit primitives
> for future FHE-CKKS execution.*
> **Description once the production OpenFHE / Lattigo backend ships
> (closed-source companion product):** *FHE-CKKS regulatory audit
> primitives for privacy-preserving AI system audits.*
>
> **Active backend in this open-source repo:** TenSEAL CKKS
> (`regaudit_fhe.fhe`). There is no OpenFHE backend in this repo;
> the OpenFHE-specific build is part of the closed-source platform
> roadmap.

The current release ships:

- the plaintext SlotVec model with strict depth-budget enforcement,
- a TenSEAL CKKS backend that mirrors the SlotVec algebra and passes
  end-to-end ciphertext / plaintext equivalence tests,
- the Ed25519-signed audit envelope with canonical-JSON rules,
  parameter-set hashing, and input commitments,
- JSON Schemas for every input, output, and the envelope itself,
- the hardened HTTP audit server with bearer-token auth, scopes, body-
  size limit, rate limiting, structured logs, and CORS controls,
- supply-chain controls: Trusted-Publisher PyPI release, Sigstore
  attestation, CycloneDX SBOM, `pip-audit`, weekly Dependabot.

The OpenFHE production backend at `N = 2^15`, calibrated polynomial
packs per vertical, KMS-backed signing key chains, and regulator-
portal connectors live in the closed-source companion product. Contact
**b@vaultbytes.com** for commercial licensing.

Contributions are not accepted — see [CONTRIBUTING.md](CONTRIBUTING.md).
