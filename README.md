# regaudit-fhe

Depth-tracked regulatory audit primitives for privacy-preserving AI audits.

`regaudit-fhe` provides a plaintext slot-vector reference model, TenSEAL
CKKS backend support, signed audit envelopes, schema validation, and
regulatory audit-evidence helpers.

The default execution path is plaintext. Install the `[fhe]` extra to
enable the TenSEAL CKKS backend where supported. An **experimental**
OpenFHE CKKS backend (`regaudit_fhe.fhe.openfhe`) is also included; it
is opt-in via the `[openfhe]` extra and covers five of the six
primitives. The OpenFHE library itself is a third-party dependency
installed by that extra, not vendored in this repository.

## At a glance

* **What it does:** runs six regulatory audit calculations (fairness, provenance,
  concordance, calibration, drift, disagreement) that can work on *encrypted* data,
  and wraps each result in a **signed report** (an "envelope") that a regulator can
  check.
* **Who it is for:** a company that must show evidence to a regulator without handing
  over raw data, and the regulator or auditor who verifies that evidence.
* **What you get from verification:** a clear answer, `TRUSTED`, `SELF_SIGNED_ONLY`
  or `INVALID`, that separates *"the file is intact"* from *"a key I approved signed it"*.
* **Status:** a reference implementation. The verification ("trust") core is a
  **candidate, not production readiness**. The [last section](#production--regulator-readiness--what-is-and-isnt-validated)
  lists plainly what is and is not validated.

**Jump to:** [Install](#install) · [Quick start](#quick-start) ·
[How a report becomes trusted](#how-a-report-becomes-trusted-in-plain-english) ·
[Command line](#same-flow-command-line) · [What is and isn't validated](#production--regulator-readiness--what-is-and-isnt-validated) ·
[Trust specification](docs/TRUST_SPEC.md) · [Changelog](CHANGELOG.md)

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
| **Regulator**  | External or in-house auditor.       | `rf.verify_report(env, policy)` with a `VerificationPolicy` over a `TrustStore`; `regaudit-fhe verify --trusted-keys ...`. |

A run produces an audit envelope (JSON) with a SHA-256 receipt. The
client archives it, ships it to the regulator, or both. The regulator
recomputes the receipt to detect tampering between issuance and review.

---

## The six primitives

| Module        | API                       | Spec depth (budgeted) | Use case (technical evidence supporting…)                                |
| ------------- | ------------------------- | --------------------- | ------------------------------------------------------------------------ |
| `egf_imss`    | `audit_fairness`          | 4                     | NYC LL144, EU AI Act §10/§15, Colorado AI Act, CFPB workflows.           |
| `etk_fpa_hbc` | `audit_provenance`        | 3                     | EU AI Act §10, 21 CFR Part 11, GDPR §22, HIPAA workflows.                |
| `esc_cia`     | `audit_concordance`       | 4                     | FDA SaMD oncology PCCP, EU AI Act §15, EMA workflows.                    |
| `ecp_qssp`    | `audit_calibration`       | 3                     | FDA SaMD UQ, EU AI Act §15, ISO/IEC 23053, UNECE WP.29 workflows.        |
| `ew1_cdsf`    | `audit_drift`             | 1                     | EU AI Act §15, FDA SaMD PCCP, Basel III workflows.                       |
| `ecmd_jps`    | `audit_disagreement`      | 5                     | OCC SR 11-7, EU AI Act §15, FDA SaMD PCCP workflows.                     |

> **"Spec depth" is a design budget, not a measurement.** It is the
> multiplicative depth each primitive is *allowed* to consume in the
> plaintext slot-vector model, as written in `docs/specs/`. It is an
> upper-bound target, not what the encrypted backend actually uses.

> **Compliance scope and disclaimer.** `regaudit-fhe` produces
> *technical evidence* — encrypted scalars, signed envelopes,
> parameter-set hashes, depth-budget attestations — that may support
> compliance workflows in the jurisdictions above. It does **not**
> constitute legal compliance, conformity assessment, regulatory
> acceptance, or a recognised audit. Read [COMPLIANCE.md](COMPLIANCE.md)
> for the binding scope statement and the
> "what-it-does-NOT-prove" mapping per regulation.

<details>
<summary><strong>Technical detail: the three different "depth" numbers (spec, declared, observed)</strong></summary>

| Term                  | Meaning                                                                 | Where it lives                                                    |
| --------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------- |
| **Spec depth**        | Design budget in the plaintext model (table above). Theoretical.        | `docs/specs/*.md`                                                 |
| **Declared depth**    | Per-backend ceiling enforced at runtime on TenSEAL; the run fails if exceeded. It can be *higher* than spec depth because TenSEAL has no native rotation (rotation and prefix sums cost extra levels). | `DECLARED_DEPTH` in `regaudit_fhe.fhe.primitives` |
| **Observed depth**    | Levels actually consumed on the real CKKS execution path. Measured.     | `benchmarks/results/SUMMARY.md`, `last_depth(name)` / `last_depths()` |

Observed depth is always ≤ declared depth. It is **not** required to
equal spec depth: it can be lower (for example, fairness is budgeted at
4 but consumes 1) or the declared ceiling can exceed the spec budget
(concordance: spec 4, declared 5 on TenSEAL). All declared ceilings fit
within the d=6 CKKS circuit, leaving headroom for downstream
commit-and-verify chaining. The `last_depth` state is held in a
`ContextVar`, so concurrent encrypted calls do not race on it.

Observed vs. declared depth, measured on TenSEAL (identical at
N = 2^14 and 2^15):

```
Each ▮ = 1 consumed level (observed). "decl" = TenSEAL declared ceiling;
"spec" = design budget from the table above.

    primitive             1 2 3 4 5 6   observed  decl  spec
    ─────────────────────────────────────────────────────────
    audit_fairness        ▮ . . . . .      1       4     4
    audit_provenance      ▮ . . . . .      1       3     3
    audit_drift           ▮ ▮ . . . .      2       2     1
    audit_calibration     ▮ ▮ ▮ . . .      3       4     3
    audit_disagreement    ▮ ▮ ▮ . . .      3       5     5
    audit_concordance     ▮ ▮ ▮ ▮ ▮ .      5       5     4
```

</details>

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

### How a report becomes trusted (in plain English)

1. **The client signs.** The audited company runs an audit and signs the result with
   its private key. The result is a JSON file called an *envelope*.
2. **The regulator keeps its own list of approved keys**, called the *trust store*.
   The list belongs to the regulator; a report cannot add itself to it.
3. **The verifier checks the report against that list** and answers with exactly one
   of three words:

| Answer | In plain words | What to do |
| --- | --- | --- |
| `TRUSTED` | An approved key signed it, it has not been altered, and every rule you set was met. | Accept it. |
| `SELF_SIGNED_ONLY` | It has not been altered, but you gave no list of approved keys, so you cannot tell who signed it. | Do not rely on it. Useful only for development checks. |
| `INVALID` | It was altered, or the key is unknown, revoked or out of scope, or it is too old, replayed, or breaks a rule. | Reject it. `blocking_reasons` says why. |

Everything else in this section is detail layered on that one idea.

### Regulator side — verify a report (recommended)

**Step 1. Write down which keys you approve.** Each key records who it belongs to,
whether it is still active, and optionally where it may be used:

```json
{
  "entries": {
    "acme-2026-04": {
      "issuer": "acme-bank",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "status": "active",
      "not_before": "2026-04-01T00:00:00Z",
      "deployments": ["prod-eu-1"],
      "primitives": ["fairness", "calibration"]
    }
  }
}
```

A key can be listed under one name only, and it must be an Ed25519 key. (The older
flat format with `keys` / `revoked` / `parameter_set_pins` still works.)

**Step 2. Verify.**

```python
import regaudit_fhe as rf

trust_store = rf.TrustStore.from_json("trust_store.json")   # refuses to load if unusable
policy = rf.VerificationPolicy(trust_store=trust_store, verifier_id="regulator-a")

env = rf.parse_envelope(received_text)       # reads v1 or v2; rejects malformed JSON
result = rf.verify_report(env, policy)

if result.accepted:                          # the single yes/no decision
    print("trusted:", result.issuer, result.key_id)
else:
    print(result.trust_status, result.blocking_reasons)   # e.g. INVALID ['ISSUER_UNKNOWN']
```

Use `result.accepted` (or `result.trust_status`). Do not use `valid`; it is deprecated
and, without a trust store, only means "the file is intact".

<details>
<summary><strong>What else the result tells you</strong></summary>

| Field | Meaning |
| --- | --- |
| `accepted` | The final decision. True only when `trust_status` is `TRUSTED`. |
| `integrity_valid` | The hash and signature are consistent (checked against *your* registered key). |
| `issuer_trusted` | The key is registered, in scope, not revoked, and the signed issuer name matches. |
| `key_status` | `active`, `retired`, `compromised`, `revoked`, `unknown` or `none`. |
| `chronology` / `timestamp_status` | How well the signing time is established (see the rules below). |
| `blocking_reasons` | The codes that caused a refusal (for example `ISSUER_UNKNOWN`, `REPORT_TOO_OLD`). |
| `reasons` | Everything noted, including informational labels such as `LEGACY_V1_FORMAT`. |
| `consumption`, `replay_scope`, `replay_durable` | What the local replay check did (see the rules below). |

</details>

### Client side — `report.v2` (candidate)

`report.v2` signs more of the report's identity than `report.v1`: the issuer, key id
and fingerprint, deployment, a unique run id, and the intended audience.

```python
signer = rf.Signer.generate(issuer="acme-bank", key_id="acme-2026-04")   # a KMS/HSM in production
env = rf.envelope_v2(
    "fairness", report, signer=signer,
    deployment_id="prod-eu-1", audience=["regulator-a"],
)
print(env.to_json())
```

There is no default signer: you must name the key. Unknown fields, duplicate JSON keys,
`NaN`, non-canonical base64 and loose timestamps are refused.

<details>
<summary><strong>The rules in short (profiles, replay, key lifecycle, timestamps, v1)</strong></summary>

`VerificationPolicy` is applied the same way by the library, the CLI, the HTTP server
and `build_app()`. A *profile* (`development`, `confidential`, `high-assurance`) makes
it stricter: production profiles require a trust store, a maximum report age and a
persistent replay cache, and refuse development-only options.

* **Replay detection is local.** `consumption` is `NOT_CHECKED`,
  `CHECKED_NOT_CONSUMED` or `RECORDED_LOCAL`. `RECORDED_LOCAL` means "recorded in this
  verifier's own store at verification time"; it does not prove the authorised operation
  completed. `replay_durable` says whether that record survives a restart. It is never
  global single-use protection or an exactly-once guarantee.
* **Retired or compromised keys.** They are accepted for historical reports only with
  authenticated chronology *and* an authenticated trust history. **This release cannot
  authenticate a trust history, so such reports are refused by default.** Both
  boundaries are strict: the latest possible signing time must be **strictly earlier**
  than the retirement or compromise time, so equality is refused. If the compromise
  time is unknown, everything that key signed is refused.
* **Required timestamps** need authenticated evidence from a verifier *you* pin
  (`timestamp_verifier=`). A missing timestamp never satisfies the requirement, and no
  timestamp authority is bundled or trusted by default. A verified timestamp is
  **not** proof the key was never revoked.
* **`report.v1`** is still verified over its original bytes, but it is refused in the
  `confidential` and `high-assurance` profiles because it has no signed run id.

</details>

<details>
<summary><strong>Older API for <code>report.v1</code> (still supported)</strong></summary>

These functions enforce the same key scope for `report.v1` but return the older
`VerificationOutcome`:

```python
trust_store = rf.TrustStore.from_json("trust_store.json")
env = rf.AuditEnvelope.from_dict(received_payload)
try:
    outcome = rf.verify_envelope_or_raise(env, trust_store=trust_store)
except rf.UntrustedIssuer:        # unknown key_id, or the report is outside the key's registered scope
    ...
except rf.RevokedIssuer:          # revoked, retired or compromised key
    ...
except rf.WrongParameterSet:      # parameter_set_hash != pinned value
    ...
except rf.HashMismatch:           # body changed since signing
    ...
except rf.InvalidSignature:       # Ed25519 verify failed
    ...
except rf.TimestampInvalid:       # an attached timestamp failed validation
    ...
# All subclass rf.EnvelopeVerificationError.
```

* `verify_receipt(env)` with no trust material only checks that the hash and embedded
  signature agree. That proves the bytes did not change; it does **not** prove an
  approved auditor produced them, and it emits a one-time `UserWarning`. Pass
  `trust_store=` (recommended: it enforces revocation, pins and scope) or
  `trusted_keys=` (registration only). An empty `trusted_keys={}` trusts nobody.
* `valid` is deprecated and kept through the first `report.v2` release; reading it
  emits a `DeprecationWarning`.
* A `report.v1` timestamp is **not** proof of non-revocation: it covers the body only,
  not the signature or key, so it can never satisfy a required-timestamp policy.
  See [docs/TRUST_SPEC.md](docs/TRUST_SPEC.md) §5.4.

</details>

<details>
<summary><strong>Verifying over HTTP</strong></summary>

`POST /v1/verify` takes exactly `{"envelope": ...}` and **fails closed**: it needs
`REGAUDIT_FHE_TRUST_STORE` (or `serve --trust-store`) and returns 503 otherwise, and
also 503 if the replay store is unavailable outside development. It parses the body
strictly, bounds chunked uploads, and returns the fields above (with `valid` as an alias
of `accepted`). `serve --allow-self-signed` is a development-only option that can report
`SELF_SIGNED_ONLY` but never `TRUSTED`; it is refused outside the development profile,
over non-loopback or Unix-socket transports, and behind forwarding headers. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

</details>

### Same flow, command line

```bash
# Client
echo '{"y_true":[1,0,1,1],"y_pred":[1,0,0,0],"group_a":[1,1,0,0],"group_b":[0,0,1,1]}' \
  > input.json
regaudit-fhe audit fairness -i input.json -o envelope.json

# Regulator
regaudit-fhe verify -i envelope.json --trusted-keys trust_store.json
```

`regaudit-fhe audit` currently emits `report.v1` signed by an ephemeral key, so its
output can only ever verify as `SELF_SIGNED_ONLY` until you sign with a long-lived
key; `report.v2` is produced through the library API. Useful `verify` options:

| Option | Purpose |
| --- | --- |
| `--trusted-keys FILE` | Trust store JSON (required unless `--allow-self-signed`). |
| `--profile {development,confidential,high-assurance}` | Tighten the policy; production profiles require the options below. |
| `--verifier-id ID` | This verifier's audience identifier. |
| `--max-age-seconds N` | Refuse reports older than `N` seconds (positive, finite). |
| `--replay-db FILE`, `--replay-mode {off,check,record}` | Local persistent replay detection. |
| `--refuse-legacy-v1` | Refuse `report.v1` envelopes. |
| `--allow-self-signed` | Development-only integrity check; never accepts a report. |
| `--strict` | Kept for compatibility; trust material is always required. |

`regaudit-fhe verify` exits **0 only when the report is accepted** under the
configured policy:

| Exit | Meaning |
| ---- | ------- |
| `0` | accepted (`trust_status: TRUSTED`) |
| `1` | well-formed report refused by policy, including `SELF_SIGNED_ONLY`, a revoked/compromised issuer, a stale or replayed report (the JSON names the `reason`) |
| `2` | invalid input, command usage or an incompatible combination of options: a malformed report, running with neither `--trusted-keys` nor `--allow-self-signed`, `--allow-self-signed` with a non-development profile, a `confidential`/`high-assurance` profile without its required options (`--max-age-seconds`, replay options, `--verifier-id`) |
| `3` | a required trust or verification resource that **was specified** is unavailable or unusable: an unreadable, malformed or empty `--trusted-keys`, an unusable `--replay-db`, or a replay store that fails while verifying outside development |

`--allow-self-signed` is a development-only integrity check: it can report
`SELF_SIGNED_ONLY` but never accepts a report, and is refused outside the
development profile. See [docs/TRUST_SPEC.md](docs/TRUST_SPEC.md).

> **Breaking change:** a consistent self-signed report used to exit `0` and now
> exits `1`; an unreadable or malformed `--trusted-keys` file used to exit `2` and
> now exits `3`. See the [changelog](CHANGELOG.md) for the full list.

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

**Resource limits (0.1.1).** `/v1/audit` refuses oversized inputs with `413`
(`INPUT_LIMIT_EXCEEDED`): 131072 elements per array, 524288 in total, nesting
depth 4, 8192 concordance samples, 32 disagreement models and 1024 provenance
buckets. Beyond 2 running and 4 queued audits it answers `503` (`SERVER_BUSY`,
with `Retry-After`), and the request timeout cancels queued work. Malformed or
non-strict JSON, non-finite numbers and a non-string `primitive` get `422`.
Invalid numeric settings stop the server from starting. Every limit is an
environment setting, listed with its default in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#resource-bounds). These limits reduce
denial-of-service exposure; they do not remove it. An exposed deployment still
needs a reverse proxy that limits request-body size, connections, timeouts and
request rates, and the known open items are listed under "Known limitations"
in the [changelog](CHANGELOG.md).

---

## Audit envelope

An audit result is wrapped into a regulator-facing, signed JSON envelope.
`regaudit_fhe.envelope(...)` (and `regaudit-fhe audit`) produce `report.v1`;
`regaudit_fhe.envelope_v2(...)` produces `report.v2`. An abridged `report.v2`:

```json
{
  "schema": "regaudit-fhe.report.v2",
  "schema_version": "regaudit-fhe.report.v2",
  "algorithm_version": "0.1.1",
  "primitive": "fairness",
  "backend": "plaintext",
  "parameter_set": { "...": "..." },
  "parameter_set_hash": "6b8aedc173e2c94e…",
  "regulations": ["NYC_LL144"],
  "result": { "breach": false, "disparity": 0.25 },
  "input_commitments": [{ "name": "y_true", "sha256": "a5c4…" }],
  "depth_budget": { "declared": 6, "consumed": 2 },
  "issued_at": "2026-10-01T12:00:00+00:00",
  "issuer": "acme-bank",
  "key_id": "acme-2026-04",
  "public_key_fingerprint": "f5a124b4…",
  "deployment_id": "prod-eu-1",
  "audit_run_id": "3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f7",
  "trust_policy_version": 1,
  "audience": ["regulator-a"],
  "receipt": {
    "sha256": "26af001f…",
    "signature_alg": "Ed25519",
    "signature_b64": "lVI6L7um…",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----…"
  },
  "timestamps": []
}
```

Everything above `receipt` is **signed** (`audience`, `model_commitment`,
`dataset_commitment` and `dp` are optional and omitted when absent). The signature is
over a domain-separated encoding of the strict canonical JSON of that body, and the
receipt's `public_key_pem` is a convenience only: a verifier checks the signature
against the key **it** registered, never the embedded one. `timestamps` sit outside
the signature and bind a *sealed digest* of the signed body plus the signature. The
canonical test vectors under [`tests/vectors/report_v2/`](tests/vectors/report_v2/)
pin the exact bytes.

`report.v1` keeps its original canonical bytes and fields: `key_id` and the public
key live in the unsigned receipt, so a v1 report cannot bind its issuer key,
deployment or run identity. It remains verifiable, with weaker historical guarantees
documented in [docs/TRUST_SPEC.md](docs/TRUST_SPEC.md) (Appendix C). Unsigned
SHA-256 receipts are useful for tamper evidence only.

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
  reports.py           report.v1 envelope: canonical JSON, parameter-set hash,
                       input commitments, Ed25519 signing, legacy
                       verify_envelope / verify_envelope_or_raise()
  report_v2.py         report.v2 envelope: signed identity, domain-separated
                       signing, strict parsing, sealed digest, parse_envelope()
  canonical.py         strict v2 canonical JSON policy + canonical base64
  verification.py      VerificationPolicy / verify / VerificationResult:
                       the shared trust engine (library, CLI, HTTP)
  replay.py            local in-memory and sqlite replay caches
  trust.py             TrustStore (key lifecycle, scope) + typed verification
                       exceptions (UntrustedIssuer, RevokedIssuer,
                       WrongParameterSet, HashMismatch, InvalidSignature,
                       TimestampInvalid, TimestampUnverified)
  schemas.py           JSON Schema loader + validator (envelope, envelope.v2)
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
docs/TRUST_SPEC.md     trust specification: key lifecycle, chronology, replay, outcomes
docs/THREAT_MODEL.md   roles, key custody, per-primitive public-surface tables
docs/COMPLIANCE.md     regulator-facing scope statement and disclaimers
docs/DEPLOYMENT.md     server hardening guide + production checklist
docs/SUPPLY_CHAIN.md   Sigstore verification, SBOM, reproducible build notes
docs/roadmap/          design notes for non-shipping work
schemas/               copy of the JSON Schemas (the package loads src/regaudit_fhe/schemas/; a test keeps them identical)
tests/                 unit, integration, edge-case, property-based, schema, security,
                       canonical report.v2 vectors (tests/vectors/), exit-code tests
scripts/               build helpers and the mutation-sensitivity check
examples/              client + regulator end-to-end flows
benchmarks/            d=6 CKKS wall-clock + memory benchmarks
```

## JSON schemas

Every primitive input, primitive output, and the audit envelope itself
ships with a Draft-2020-12 JSON Schema under [`schemas/`](schemas/) (the copy inside the installed package is `src/regaudit_fhe/schemas/`; a test keeps the two byte-identical).
Auditors and integrators can pin specific schema versions and reject
payloads that do not conform.

```bash
regaudit-fhe schema --list
regaudit-fhe schema fairness.input
regaudit-fhe schema envelope        # report.v1
regaudit-fhe schema envelope.v2     # report.v2
```

The CLI and HTTP server validate every request body against the
matching schema before invoking the audit primitive; failures return
HTTP 422 / CLI exit-code 2 with a structured pointer to the offending
field. Programmatic access:

```python
import regaudit_fhe as rf
rf.list_schemas()                      # all 14 names
rf.load_schema("fairness.input")       # raw schema dict
rf.validate_input("fairness", payload) # raises rf.SchemaError on bad input
rf.validate_envelope(env_dict)         # check a report.v1 envelope
rf.validate_envelope_v2(env_dict)      # check a report.v2 envelope
```

---

## Real CKKS benchmarks

The `[fhe]` extra ships a real TenSEAL CKKS backend; its measurements
are reproduced from `benchmarks/results/SUMMARY.md` (machine-readable
JSON in `benchmarks/results/bench_fhe_<N>.json`).

| Primitive    | N    | Slots  | Depth obs/decl (TenSEAL) | Rotations | ct×ct | ct×pt | Runtime | RAM     | Max abs err | Threshold flip |
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

**In short:** the library is ready to *evaluate and integrate*. It is not a finished
compliance product, and the verification core is a candidate. The tables below say
exactly what is checked automatically, what is only partly done, and what is not provided.

> The release gate above guarantees the package builds, imports,
> exposes the documented CLI / API, and passes its test suite. That
> is **not** the same as being validated for regulated production use.
> The matrix below is the honest current state.

| Property                                | Status                                                                              |
| --------------------------------------- | ----------------------------------------------------------------------------------- |
| Python syntax + imports                 | Verified by CI on every push.                                                       |
| pytest suite (800+ tests)               | Verified by CI on every push (Linux py3.10–3.13 + macOS py3.12 / 3.13).             |
| Coverage gate                           | `--cov-fail-under=80` enforced in CI; currently about 89%.                          |
| Type checking                           | `mypy` gates CI: zero errors across the 29 source files.                            |
| Static security                         | `bandit` (medium+) gates CI; CodeQL (security-and-quality) runs on push and weekly. |
| Lint                                    | `ruff check` gates CI with E/F/W/B/S/UP/I/SIM/RUF/A rule set.                       |
| Real CKKS encrypted backend (TenSEAL)   | Shipped under `[fhe]`; equivalence-tested.                                          |
| OpenFHE CKKS backend (experimental)     | Shipped under `[openfhe]`; registry-selectable; equivalence-tested for 5/6          |
|                                         | primitives (concordance pending rectangular `mm_pt`). Not the verified reference.   |
| External key custody (KMS / HSM)        | `CallableKeyProvider` keeps the signing key off-host; fails closed on bad sig.      |
| Differential-privacy output noise       | Optional `regaudit_fhe.dp` (Laplace / Gaussian); signed `dp` block. Sensitivity is  |
|                                         | the deployer's responsibility — the library calibrates, it does not bound.          |
| Generated API reference                 | `pdoc` HTML built in CI (`docs.yml`); see [docs/API.md](docs/API.md).               |
| Signed audit envelope (Ed25519)         | `report.v1` and `report.v2`; canonical-JSON + tamper tests.                         |
| `report.v2` signed identity (candidate) | Issuer, key id + fingerprint, deployment, run id, audience signed under a           |
|                                         | domain-separated signature; strict parser; golden test vectors.                     |
| Shared verification policy (candidate)  | One engine for library, CLI, HTTP and `build_app()`: `TRUSTED` / `SELF_SIGNED_ONLY` |
|                                         | / `INVALID`, key lifecycle and scope, strict chronology, freshness, audience.       |
| Trust store + typed verifier failures   | `TrustStore` (flat and `entries` forms) + typed `EnvelopeVerificationError`s.       |
| CLI exit codes                          | `verify`: 0 accepted / 1 refused / 2 usage / 3 resource unusable; process-tested.   |
| Local replay detection                  | In-memory and sqlite caches; `RECORDED_LOCAL`, durability disclosed. Local only.    |
| Mutation-sensitivity check              | `scripts/mutation_check_phase3a.py`: trust-core tests catch deliberate bugs.        |
| JSON Schemas                            | Shipped; validated on every CLI / API request.                                      |
| Hardened HTTP server                    | Constant-time bearer compare, opaque key_id in logs, `DEV_MODE` non-loopback bind   |
|                                         | refusal, scopes, rate limit, CORS, audit log.                                       |
| Concurrency-safe depth state            | `ContextVar`-backed `last_depth` / `last_depths`; cross-thread / asyncio isolated.  |
| Reproducible wheel                      | CI builds twice with pinned `SOURCE_DATE_EPOCH`, asserts SHA-256 stable.            |
| Sigstore-signed wheel + sdist           | Keyless OIDC bundles attached to every GitHub Release.                              |
| Real benchmarks at N=2^14, N=2^15       | Shipped; reproducible from `benchmarks/bench_fhe.py`.                               |

**Not provided or not validated**

| Property                                | Status                                                                              |
| --------------------------------------- | ----------------------------------------------------------------------------------- |
| Trust-anchor distribution, signed trust-store bundles | Not implemented. A trust store is a local file; its completeness and freshness   |
|                                         | cannot be authenticated, so historical acceptance of retired/compromised keys is refused. |
| Timestamp authority                     | None bundled. Required timestamps need a verifier you pin; none is trusted by default. |
| Global / shared replay protection       | Not provided. Replay detection is local and not coupled to any operation.           |
| High-assurance historical verification  | Not implemented.                                                                    |
| Evaluator / key-holder separation       | The encrypted path still encrypts, evaluates and decrypts in one process.           |
| External security audit                 | Not performed. Reviews of the trust core were internal.                             |
| `report.v2` from the CLI / HTTP audit   | Not yet: `regaudit-fhe audit` and `/v1/audit/*` emit `report.v1` (ephemeral key).  |
| Post-quantum authentication             | Not provided (Ed25519).                                                             |

`regaudit-fhe` is a dependency you can bring into a compliance
workflow today; it is not, by itself, a finished compliance product.
[COMPLIANCE.md](COMPLIANCE.md) lists what each primitive does NOT
prove, regulation by regulation.

---

## Maturity and status

> **Description:** *Depth-tracked regulatory audit primitives for
> privacy-preserving AI audits.*
>
> **Backends:** TenSEAL CKKS is the verified reference backend
> (`regaudit_fhe.fhe`). An **experimental** OpenFHE CKKS backend
> (`regaudit_fhe.fhe.openfhe`) is also selectable through the backend
> registry; it covers every primitive except encrypted concordance
> (which needs rectangular `mm_pt`). See
> [docs/roadmap/openfhe_backend.md](docs/roadmap/openfhe_backend.md)
> for the design note.

The current release ships:

- the plaintext SlotVec model with strict depth-budget enforcement,
- a TenSEAL CKKS backend that mirrors the SlotVec algebra and passes
  end-to-end ciphertext / plaintext equivalence tests,
- a pluggable backend registry (`regaudit_fhe.fhe.get_backend` /
  `available_backends`) with an experimental OpenFHE CKKS backend that
  runs the same circuits via the Halevi–Shoup diagonal method,
- the Ed25519-signed audit envelope with canonical-JSON rules,
  parameter-set hashing, and input commitments,
- a typed verifier surface — `TrustStore` (key_id → PEM, revocation,
  parameter-set pinning, and the `entries` form with key status, validity and
  issuer / deployment / primitive scope) plus `verify_envelope_or_raise`
  raising `UntrustedIssuer` / `RevokedIssuer` / `WrongParameterSet` /
  `HashMismatch` / `InvalidSignature` / `TimestampInvalid` for regulator-side
  use,
- a **candidate `report.v2` trust core**: a signed issuer / key / deployment /
  audit-run identity, strict canonical JSON, a shared `VerificationPolicy`
  (`verify_report`) with explicit `trust_status` and `accepted` outcomes,
  fail-closed key-lifecycle and chronology rules, local replay detection with
  disclosed durability, and `regaudit-fhe verify` exit codes 0/1/2/3. It is
  verified by process-level, golden-vector and mutation-sensitivity tests, and it
  explicitly refuses configurations it cannot support (see the table above),
- a key-custody seam — `CallableKeyProvider` keeps the Ed25519 signing
  key in a KMS/HSM, so only a public PEM and a sign-callable enter the
  audit host,
- an optional differential-privacy output-perturbation layer
  (`regaudit_fhe.dp`: Laplace / Gaussian mechanisms, a basic-composition
  accountant, and a signed `dp` disclosure block in the envelope),
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
