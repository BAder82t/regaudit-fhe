# Primitives, depth and benchmarks

The six audit calculations, how encrypted execution works today, and what was measured. Start at the [main README](../README.md) if you are new here.

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

The diagram shows the intended encrypted flow. The default path is plaintext, and the encrypted path
today encrypts, evaluates and decrypts in one process (see [Encrypted execution](#encrypted-execution-needs-fhe)).

Two audiences are served by the same surface area:

| Audience       | Role                                | What they run                                                     |
| -------------- | ----------------------------------- | ----------------------------------------------------------------- |
| **Client**     | Audited entity (vendor / operator). | `audit_*` primitives, `regaudit-fhe audit ...`.                   |
| **Regulator**  | External or in-house auditor.       | `rf.verify_report(env, policy)` with a `VerificationPolicy` over a `TrustStore`; `regaudit-fhe verify --trusted-keys ...`. |

A run produces an audit envelope (JSON) with a SHA-256 receipt. The
client archives it, ships it to the regulator, or both. The regulator
recomputes the receipt to detect tampering between issuance and review.

## The six primitives

| Module        | API                       | Spec depth (plaintext model) | Declared depth (TenSEAL) | Use case (technical evidence supporting…)                                |
| ------------- | ------------------------- | ---------------------------- | ------------------------ | ------------------------------------------------------------------------ |
| `egf_imss`    | `audit_fairness`          | 4                            | 4                        | NYC LL144, EU AI Act Art. 10/15, Colorado SB26-189 (fit unconfirmed), ECOA and Regulation B workflows. |
| `etk_fpa_hbc` | `audit_provenance`        | 3                            | 3                        | EU AI Act Art. 10, 21 CFR Part 11, GDPR Art. 22, HIPAA workflows.        |
| `esc_cia`     | `audit_concordance`       | 4                            | 5                        | FDA SaMD oncology PCCP, EU AI Act Art. 15/72, EMA workflows.             |
| `ecp_qssp`    | `audit_calibration`       | 3                            | 4                        | FDA SaMD UQ, EU AI Act Art. 15/72, ISO/IEC 23053, UNECE WP.29 workflows. |
| `ew1_cdsf`    | `audit_drift`             | 1                            | 2                        | EU AI Act Art. 15/72, FDA SaMD PCCP, Basel III workflows.                |
| `ecmd_jps`    | `audit_disagreement`      | 5                            | 5                        | SR 26-2 and OCC Bulletin 2026-13, EU AI Act Art. 15/72, FDA SaMD PCCP workflows. |

Default reports still sign
older labels such as `OCC_SR_11_7` and `COLORADO_AI_ACT` from `REGULATION_MAP`.

> **"Spec depth" is a design budget, not a measurement.** It is the
> multiplicative depth each primitive is *allowed* to consume in the
> plaintext slot-vector model, as written in `docs/specs/`. It is an
> upper-bound target, not what the encrypted backend actually uses.
> "Declared depth" is `DECLARED_DEPTH` in `regaudit_fhe.fhe.primitives`. It
> differs from the spec for concordance, calibration and drift.

> **`depth_budget.consumed` in a report is not measured by default.**
> `envelope()` and `envelope_v2()` set `depth_consumed` to 6 unless the caller
> passes a value. The CLI and the HTTP server do not pass one, so their reports
> say `"consumed": 6` for each primitive even though they run the plaintext path.
> A report would only have another number if the caller has passed one, for
> example `last_depth(name)` after an encrypted call. `declared` is always 6, the
> circuit-wide ceiling, and it is not the value of `DECLARED_DEPTH`.

> **Compliance scope and disclaimer.** `regaudit-fhe` produces
> *technical evidence* (encrypted scalars, signed envelopes,
> parameter-set hashes, depth-budget fields) that may support
> compliance workflows in the jurisdictions above. It does **not**
> constitute legal compliance, conformity assessment, regulatory
> acceptance, or a recognised audit. Read [COMPLIANCE.md](../COMPLIANCE.md)
> for the binding scope statement and the
> "what-it-does-NOT-prove" mapping per regulation.

<details>
<summary><strong>Technical detail: the three different "depth" numbers (spec, declared, observed)</strong></summary>

| Term                  | Meaning                                                                 | Where it lives                                                    |
| --------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------- |
| **Spec depth**        | Design budget in the plaintext model (table above). Theoretical.        | `docs/specs/*.md`                                                 |
| **Declared depth**    | Per-backend ceiling checked at runtime on TenSEAL; the run fails if the observed-depth counter exceeds it. It can be *higher* than spec depth because TenSEAL has no native rotation (rotation and prefix sums cost extra levels). | `DECLARED_DEPTH` in `regaudit_fhe.fhe.primitives` |
| **Observed depth**    | The `EncryptedSlotVec.depth` counter after an encrypted call. It is not a reading of the modulus chain. | `benchmarks/results/SUMMARY.md`, `last_depth(name)` / `last_depths()` |

Observed depth is always ≤ declared depth. It is **not** required to
equal spec depth: it can be lower (for example, fairness is budgeted at
4 but counts 1) or the declared ceiling can exceed the spec budget
(concordance: spec 4, declared 5 on TenSEAL). All declared ceilings fit
within the d=6 CKKS circuit, leaving headroom for downstream
commit-and-verify chaining. The `last_depth` state is held in a
`ContextVar`, so concurrent encrypted calls do not race on it.

The counter does not count `mul_scalar` or negation, and TenSEAL spends a level on
both. The runtime check only compares the declared ceiling with this counter. We
counted the levels left on the output ciphertext with TenSEAL 0.3.18 at N = 2^14,
on the default 400-bit chain and on the 360-bit chain, and both gave the same result.
The levels used were fairness 2, provenance 1, concordance 6, calibration 5, drift 2
and disagreement 5 (with non-zero polynomial coefficients). For concordance and
calibration this is above the declared depth of 5 and 4. All of them fit in the 6
levels of the 360-bit chain. We did not run this count at N = 2^15.

Observed vs. declared depth, as counted on TenSEAL (identical at
N = 2^14 and 2^15):

```
Each ▮ = 1 counted level (observed). "decl" = TenSEAL declared ceiling;
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
[`docs/specs/`](specs/).

## Backends

`regaudit-fhe` provides a plaintext slot-vector reference model, TenSEAL
CKKS backend support, signed audit envelopes, schema validation, and
regulatory audit-evidence helpers.

The default execution path is plaintext. Install the `[fhe]` extra to
enable the TenSEAL CKKS backend where supported. An **experimental**
OpenFHE CKKS backend (`regaudit_fhe.fhe.openfhe`) is also included; it
is opt-in via the `[openfhe]` extra and covers five of the six
primitives. The OpenFHE library itself is a third-party dependency
installed by that extra, not vendored in this repository.

## Encrypted execution (needs `[fhe]`)

```python
import numpy as np
import regaudit_fhe as rf
from regaudit_fhe.fhe import build_d6_context
from regaudit_fhe.fhe import primitives as enc

ctx = build_d6_context()  # CKKS context; takes a few seconds
y_true = np.array([1, 0, 1, 1, 0, 1, 0, 0.0])
y_pred = np.array([1, 0, 1, 0, 0, 1, 1, 0.0])
a = np.array([1, 1, 1, 1, 0, 0, 0, 0.0])
report = enc.fairness_encrypted(
    ctx, y_true, y_pred, a, 1.0 - a
)  # same report type as audit_fairness
```

`ctx` holds the secret key and the call decrypts the aggregate scalars, so in this form the
same process sees both the inputs and the result: it demonstrates that the encrypted circuit
matches the plaintext one, not a deployment where the data holder and the evaluator differ.
`rf.envelope(...)` records `backend: "plaintext"` unless you pass a `parameter_set=`
(see `examples/signed_envelope.py`), so describe the backend in the parameter set when you
sign an encrypted-path result. In that default case it also signs `security_bits: 128`, which is a field default
and not a security level: the signed parameter set describes no encryption, even when the calculation ran on TenSEAL. The number is never measured or checked in any case:
see [REPORT_FORMAT.md](REPORT_FORMAT.md#what-parameter_set-and-security_bits-mean).

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
pip install "regaudit-fhe[fhe]"
python benchmarks/bench_fhe.py --rings 14 15 --reps 3
```

Add `--rings 16` for `N = 2^16` (slower; uses several GB of RAM).

The "Threshold flip" column is the rate at which the encrypted circuit
disagrees with the plaintext circuit on a boolean breach decision. The default
is 20 trials per primitive, and the result files do not record the number used.

The benchmark only measures this rate for fairness, drift and disagreement.
For provenance, concordance and calibration `bench_fhe.py` writes a fixed `0.0`
since those primitives have no breach boolean. Therefore the `0.00%` in those
rows is a placeholder and not a result.

The inputs in the three measured samplers are not close to the threshold. From
2000 plaintext draws of each sampler, the fairness inputs were at least about
0.01 from the threshold and usually about 0.23. The drift inputs were at least
about 0.002 away. The disagreement sampler is one fixed input about 0.005 away.
The biggest absolute errors in the table for those primitives are about 7e-6 or
smaller. Zero flips shows that noise did not change the decision for these inputs.
This does not show that noise cannot change a decision close to the threshold.
