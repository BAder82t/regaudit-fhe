# regaudit-fhe

Depth-tracked regulatory audit primitives for privacy-preserving AI audits.

`regaudit-fhe` provides a plaintext slot-vector reference model, TenSEAL
CKKS backend support, signed audit envelopes, schema validation, and
regulatory audit-evidence helpers.

The default execution path is plaintext. Install the `[fhe]` extra to
enable the TenSEAL CKKS backend where supported. OpenFHE is not
included in this repository.

[![ci](https://github.com/BAder82t/regaudit-fhe/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/BAder82t/regaudit-fhe/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/regaudit-fhe.svg)](https://pypi.org/project/regaudit-fhe/)
[![Python](https://img.shields.io/pypi/pyversions/regaudit-fhe.svg)](https://pypi.org/project/regaudit-fhe/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

> Maintained by **VaultBytes Innovations Ltd**. **Dual-licensed**:
> AGPL-3.0-or-later (default — see [LICENSE](LICENSE)) or
> **VaultBytes Commercial License** for deployments where AGPL is not
> workable (see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md);
> contact **b@vaultbytes.com**).

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

| Audience       | Role                                | What they run                                                     |
| -------------- | ----------------------------------- | ----------------------------------------------------------------- |
| **Client**     | Audited entity (vendor / operator). | `audit_*` primitives, `regaudit-fhe audit ...`.                   |
| **Regulator**  | External or in-house auditor.       | `verify_envelope_or_raise(env, trust_store=...)` against a `TrustStore`; `regaudit-fhe verify --trusted-keys ...`. |

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
under six on the TenSEAL backend, leaving headroom for downstream
commit-and-verify chaining. The values below are observed at runtime
on the real CKKS execution path; the source of truth is
`benchmarks/results/SUMMARY.md` and the `last_depth(name)` /
`last_depths()` accessors in `regaudit_fhe.fhe.primitives` (the
underlying state is held in a `ContextVar` so concurrent encrypted
calls do not race on the depth record).

```
Depth budget visualisation (each ▮ = 1 consumed level; observed on TenSEAL)

    primitive             1 2 3 4 5 6
    ───────────────────────────────────
    audit_fairness        ▮ ▮ . . . .   2 of 6   (encrypt + mul_pt + mul_scalar)
    audit_provenance      ▮ ▮ . . . .   2 of 6   (encrypt + mul_pt fold per bucket)
    audit_drift           ▮ ▮ ▮ . . .   3 of 6   (mm_pt CDF + ct×ct square)
    audit_calibration     ▮ ▮ ▮ ▮ . .   4 of 6   (mul_pt scale + sign_poly_d3)
    audit_disagreement    ▮ ▮ ▮ ▮ ▮ .   5 of 6   (deg-3 poly + pairwise sq + scale)
    audit_concordance     ▮ ▮ ▮ ▮ ▮ ▮   6 of 6   (rotate via mm_pt + sign_poly_d3
                                                  + ct×ct event mask)
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

### Client side — produce an audit envelope

```python
import numpy as np
import regaudit_fhe as rf

y_true  = np.array([1, 0, 1, 1, 0, 1, 0, 0], dtype=float)
y_pred  = np.array([1, 0, 1, 0, 0, 1, 1, 0], dtype=float)
group_a = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
group_b = 1.0 - group_a

report = rf.audit_fairness(y_true, y_pred, group_a, group_b, threshold=0.1)
print(report.demographic_parity_diff, report.threshold_breached)

# Long-lived issuer key in production; ephemeral for demos.
signer = rf.Signer.generate(issuer="acme-bank", key_id="acme-2026-04")
envelope = rf.envelope("fairness", report, signer=signer)
print(envelope.to_json())                     # ship this to the regulator
```

### Regulator side — verify against a trust store (recommended)

```python
import regaudit_fhe as rf

# trust_store.json maps key_id -> PEM-encoded Ed25519 public key.
# Optional fields: "revoked": [...], "parameter_set_pins": {key_id: hex}.
trust_store = rf.TrustStore.from_json("trust_store.json")

env = rf.AuditEnvelope.from_dict(received_payload)
try:
    outcome = rf.verify_envelope_or_raise(env, trust_store=trust_store)
except rf.UntrustedIssuer:        # key_id unknown OR embedded PEM mismatch
    ...
except rf.RevokedIssuer:          # key_id is in trust_store.revoked
    ...
except rf.WrongParameterSet:      # parameter_set_hash != pinned value
    ...
except rf.HashMismatch:           # body changed since signing
    ...
except rf.InvalidSignature:       # Ed25519 verify failed
    ...
# All five subclass rf.EnvelopeVerificationError.
```

`verify_envelope_or_raise` returns the underlying `VerificationOutcome`
on success. Use it instead of the legacy bool-return path whenever you
need to react differently to each failure reason.

> **Why a trust store is required.** `verify_receipt(env)` (no
> arguments) only checks that the embedded SHA-256 receipt matches the
> canonical body and that the Ed25519 signature verifies against the
> embedded public key. That proves the bytes have not changed in
> transit — it does **not** prove the envelope was produced by an
> auditor the regulator approved. Calling without `trusted_keys` emits
> a one-time `UserWarning` so integrators do not silently rely on the
> weak path.

### Same flow, command line

```bash
# Client
echo '{"y_true":[1,0,1,1],"y_pred":[1,0,0,0],"group_a":[1,1,0,0],"group_b":[0,0,1,1]}' \
  > input.json
regaudit-fhe audit fairness -i input.json -o envelope.json

# Regulator
regaudit-fhe verify -i envelope.json --trusted-keys trust_store.json --strict
```

The regulator command exits 0 on success, 1 on a typed verification
failure (with a JSON body naming the `reason`), and 2 on bad CLI input.
`--strict` without `--trusted-keys` is a hard error: the strict path
demands an explicit trust store.

`regaudit-fhe audit <primitive> --schema` prints the JSON shape that
each primitive expects.

> **The HTTP server is NOT a privacy boundary by itself.** The default
> execution path is plaintext; the server runs in-process. Encrypted
> execution requires the `[fhe]` extra AND CKKS secret-key custody
> held off-host. Bearer-token authentication uses constant-time
> hashed comparison (no token timing leak) and `REGAUDIT_FHE_DEV_MODE=1`
> refuses to start on a non-loopback bind, but issuer authenticity
> still relies on the verifier's trust store. Read
> [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and
> [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before exposing
> publicly.

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

| File                                    | Flow                                                                                              |
| --------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `01_client_local_audit.py`              | Internal audit on synthetic data; archive JSON locally.                                           |
| `02_client_to_regulator.py`             | Build a regulator submission bundle.                                                              |
| `03_regulator_verify.py`                | Verify every envelope inside a bundle against a `TrustStore`; surfaces typed failure reasons.     |
| `04_cli_roundtrip.sh`                   | Pure CLI: input → audit → verify, no Python knowledge required.                                   |

Run any of them after `pip install -e .[dev]`.

---

## Layout

```
src/regaudit_fhe/
  _slot.py             plaintext SlotVec model with depth-budget enforcement
  _validation.py       finite/binary/length input guards
  cli.py               regaudit-fhe CLI entrypoint
  reports.py           audit envelope: canonical JSON, parameter-set hash,
                       input commitments, Ed25519 signing,
                       verify_envelope_or_raise()
  schemas.py           JSON Schema loader + validator
  trust.py             TrustStore + typed verification exceptions
                       (UntrustedIssuer, RevokedIssuer, WrongParameterSet,
                       HashMismatch, InvalidSignature, TimestampInvalid)
  schemas/             bundled Draft-2020-12 schemas (one per input/output + envelope)
  server.py            hardened FastAPI HTTP audit server
  egf_imss.py          fairness primitive
  etk_fpa_hbc.py       provenance primitive
  esc_cia.py           concordance primitive
  ecp_qssp.py          calibration primitive
  ew1_cdsf.py          drift primitive
  ecmd_jps.py          disagreement primitive
  fhe/                 TenSEAL CKKS encrypted backend (optional [fhe] extra):
    context.py           build_d6_context, CKKSContext
    params.py            validated CKKSParams
    slot_vec.py          EncryptedSlotVec mirroring the plaintext SlotVec API
    primitives.py        encrypted variants of every audit primitive

docs/specs/            per-primitive technical specifications
docs/THREAT_MODEL.md   roles, key custody, per-primitive public-surface tables
docs/COMPLIANCE.md     regulator-facing scope statement and disclaimers
docs/DEPLOYMENT.md     server hardening guide + production checklist
docs/SUPPLY_CHAIN.md   Sigstore verification, SBOM, reproducible build notes
docs/roadmap/          design notes for non-shipping work
schemas/               source-of-truth JSON Schemas
tests/                 unit, integration, edge-case, property-based, schema, security
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

| Primitive    | N    | Slots  | Depth obs/decl | Rotations | ct×ct | ct×pt | Runtime | RAM     | Max abs err | Threshold flip |
|--------------|-----:|-------:|----------------|----------:|------:|------:|--------:|--------:|-------------|----------------|
| fairness     | 2^14 |  8 192 | 1/4            |  36       |   0   |    6  | 0.33 s  |  887 MB | 4.8 × 10⁻⁷ | 0.00% |
| provenance   | 2^14 |  8 192 | 1/3            |  96       |   0   |   16  | 0.90 s  |  896 MB | 1.1 × 10⁻⁵ | 0.00% |
| concordance  | 2^14 |  8 192 | 5/5            |  36       |   8   |    3  | 5.26 s  | 2.3 GB  | 1.5 × 10⁻⁶ | 0.00% |
| calibration  | 2^14 |  8 192 | 3/4            |   0       |   2   |    1  | 0.03 s  | 2.3 GB  | 0          | 0.00% |
| drift        | 2^14 |  8 192 | 2/2            |  12       |   1   |    2  | 0.27 s  | 2.3 GB  | 2.2 × 10⁻⁶ | 0.00% |
| disagreement | 2^14 |  8 192 | 3/5            |   0       |  12   |    0  | 0.31 s  | 2.3 GB  | 1.2 × 10⁻⁸ | 0.00% |
| fairness     | 2^15 | 16 384 | 1/4            |  36       |   0   |    6  | 0.74 s  | 4.0 GB  | 9.6 × 10⁻⁷ | 0.00% |
| provenance   | 2^15 | 16 384 | 1/3            |  96       |   0   |   16  | 2.04 s  | 4.1 GB  | 5.2 × 10⁻⁶ | 0.00% |
| concordance  | 2^15 | 16 384 | 5/5            |  36       |   8   |    3  | 13.91 s | 6.9 GB  | 3.0 × 10⁻⁷ | 0.00% |
| calibration  | 2^15 | 16 384 | 3/4            |   0       |   2   |    1  | 0.08 s  | 6.9 GB  | 0          | 0.00% |
| drift        | 2^15 | 16 384 | 2/2            |  12       |   1   |    2  | 0.64 s  | 6.9 GB  | 7.1 × 10⁻⁶ | 0.00% |
| disagreement | 2^15 | 16 384 | 3/5            |   0       |  12   |    0  | 0.64 s  | 6.6 GB  | 1.3 × 10⁻⁸ | 0.00% |

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

## Verify a fresh clone

The release gate is one shell block. Anything that fails this block
is a release blocker:

```bash
git clone https://github.com/BAder82t/regaudit-fhe.git
cd regaudit-fhe
python -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

python -m py_compile src/regaudit_fhe/*.py src/regaudit_fhe/fhe/*.py tests/*.py
python -c "import regaudit_fhe; print(regaudit_fhe.__version__)"
regaudit-fhe --help
regaudit-fhe schema --list
pytest -q
```

CI runs an equivalent matrix on every push (see
[.github/workflows/ci.yml](.github/workflows/ci.yml)) and the badge at
the top of this README reflects the latest result.

---

## Production / regulator readiness — what is and isn't validated

> The release gate above guarantees the package builds, imports,
> exposes the documented CLI / API, and passes its test suite. That
> is **not** the same as being validated for regulated production use.
> The matrix below is the honest current state.

| Property                                | Status                                                                              |
| --------------------------------------- | ----------------------------------------------------------------------------------- |
| Python syntax + imports                 | Verified by CI on every push.                                                       |
| 275-test pytest suite                   | Verified by CI on every push (Linux py3.10–3.13 + macOS py3.12 / 3.13).             |
| Coverage gate                           | `--cov-fail-under=80` enforced in CI; baseline 84%.                                 |
| Type checking                           | `mypy` gates CI: zero errors across 19 source files.                                |
| Static security                         | `bandit` (medium+) gates CI; CodeQL (security-and-quality) runs on push and weekly. |
| Lint                                    | `ruff check` gates CI with E/F/W/B/S/UP/I/SIM/RUF/A rule set.                       |
| Real CKKS encrypted backend (TenSEAL)   | Shipped under `[fhe]`; equivalence-tested.                                          |
| Signed audit envelope (Ed25519)         | Shipped; canonical-JSON + tamper tests.                                             |
| Trust store + typed verifier failures   | `TrustStore` + six `EnvelopeVerificationError` subclasses; CLI `--trusted-keys`.    |
| JSON Schemas                            | Shipped; validated on every CLI / API request.                                      |
| Hardened HTTP server                    | Constant-time bearer compare, opaque key_id in logs, `DEV_MODE` non-loopback bind   |
|                                         | refusal, scopes, rate limit, CORS, audit log.                                       |
| Concurrency-safe depth state            | `ContextVar`-backed `last_depth` / `last_depths`; cross-thread / asyncio isolated.  |
| Reproducible wheel                      | CI builds twice with pinned `SOURCE_DATE_EPOCH`, asserts SHA-256 stable.            |
| Sigstore-signed wheel + sdist           | Keyless OIDC bundles attached to every GitHub Release.                              |
| Real benchmarks at N=2^14, N=2^15       | Shipped; reproducible from `benchmarks/bench_fhe.py`.                               |

`regaudit-fhe` is a dependency you can bring into a compliance
workflow today; it is not, by itself, a finished compliance product.
[COMPLIANCE.md](COMPLIANCE.md) lists what each primitive does NOT
prove, regulation by regulation.

---

## Maturity and status

> **Description:** *Depth-tracked regulatory audit primitives for
> privacy-preserving AI audits.*
>
> **Active backend:** TenSEAL CKKS (`regaudit_fhe.fhe`). OpenFHE is
> not currently included; see
> [docs/roadmap/openfhe_backend.md](docs/roadmap/openfhe_backend.md)
> for the design note.

The current release ships:

- the plaintext SlotVec model with strict depth-budget enforcement,
- a TenSEAL CKKS backend that mirrors the SlotVec algebra and passes
  end-to-end ciphertext / plaintext equivalence tests,
- the Ed25519-signed audit envelope with canonical-JSON rules,
  parameter-set hashing, and input commitments,
- a typed verifier surface — `TrustStore` (key_id → PEM, optional
  revocation, optional parameter-set pinning) plus
  `verify_envelope_or_raise` raising `UntrustedIssuer` /
  `RevokedIssuer` / `WrongParameterSet` / `HashMismatch` /
  `InvalidSignature` / `TimestampInvalid` for regulator-side use,
- JSON Schemas for every input, output, and the envelope itself,
- the hardened HTTP audit server with constant-time bearer-token
  compare, opaque hashed key_id in logs, scopes, body-size limit,
  rate limiting, structured logs, CORS controls, and a `DEV_MODE`
  non-loopback bind guard,
- concurrency-safe depth recording via `ContextVar` so concurrent
  encrypted requests cannot race on the depth state,
- supply-chain controls: Trusted-Publisher PyPI release, Sigstore
  keyless signing of the wheel + sdist, reproducible-build CI gate
  (pinned `SOURCE_DATE_EPOCH`, two builds, identical SHA),
  CycloneDX SBOM, `pip-audit`, CodeQL, weekly Dependabot.

Contributions are not accepted — see [CONTRIBUTING.md](CONTRIBUTING.md).
