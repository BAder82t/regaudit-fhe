# ESC-CIA — Encrypted Survival-Curve Concordance (Harrell C-Index)

**Module:** `regaudit_fhe.esc_cia`
**Public API:** `regaudit_fhe.audit_concordance(...)`
**Depth budget:** 4 of 6 *(spec budget, plaintext model — not the observed encrypted depth; see README "Three different depth numbers")*
**Author:** VaultBytes Innovations Ltd

> **Design specification, not a statement of what ships.** This page describes the
> intended encrypted design. The encrypted functions are experimental and have not been
> independently qualified. They encrypt, evaluate and decrypt in one process that holds
> the key and the plaintext inputs, and the command line and HTTP server run the plaintext
> path only. Security statements below are properties assumed of CKKS at the stated
> parameters. This repository does not measure or verify them. Where the code differs, the
> code is what runs. The concordant and comparable counts come from a degree-3 sign polynomial and are approximations of the Harrell counts, not exact values.

## What it does

Computes the encrypted Harrell concordance index between a vector of
risk-prediction scores and observed `(time, event)` survival outcomes,
within a single CKKS circuit that respects the depth-six budget.

## Why it exists

| Regulation                       | Jurisdiction | What it requires                            |
| -------------------------------- | ------------ | ------------------------------------------- |
| FDA Predetermined Change-Control | US           | Concordance audit for AI/ML SaMD oncology.  |
| EU AI Act, Article 15            | EU           | Post-market surveillance for high-risk AI.  |
| EMA AI Guidance                  | EU           | Survival-AI performance attestation.        |

Oncology and survival-model vendors must report C-index against
observed outcomes. The C-index is intrinsically `O(N²)` over patient
pairs and exposes PHI when computed by the vendor over plaintext
records. Existing FHE-Cox tooling fits the model under encryption but
does not produce a concordance audit primitive.

## Inputs

| Argument | Type         | Description                                            |
| -------- | ------------ | ------------------------------------------------------ |
| `risk`   | `np.ndarray` | Risk-prediction scores.                                |
| `time`   | `np.ndarray` | Observed times.                                        |
| `event`  | `np.ndarray` | Event indicators (`1` = observed, `0` = censored).     |

## Output

`CIndexReport(concordant_pairs, comparable_pairs, c_index)`

The encrypted boundary returns the concordant and comparable counts;
the ratio is computed plaintext-side after decryption to keep the
spec depth at four (five on the TenSEAL backend, see below). No per-row PHI leaves the encrypted domain.

## Algorithm

```
encrypted_risk, encrypted_time, encrypted_event = encrypt(...)

for shift in 1..N-1:
    risk_diff       = (risk - rotate(risk, shift)) / span
    time_diff       = (rotate(time, shift) - time) / span
    sgn_risk        = sign_poly_3(risk_diff)            # depth 2
    sgn_time        = sign_poly_3(time_diff)            # depth 2
    concordance_bit = sgn_risk * sgn_time * event       # depth 4
    comparable_bit  = sgn_time * event                  # depth 3
concordant = sum across all shifts and slots
comparable = sum across all shifts and slots
c_index    = concordant / comparable                    # plaintext
```

## Depth budget (spec, plaintext model)

```
two sign-polynomials       : +2 levels each
mul of two signs           : +1 level
mul of result × event      : +1 level
                            ───────
                             4 of 6
```

> **TenSEAL backend:** rotation is emulated with `mm_pt`, costing one extra level per shift, so the declared ceiling is 5 and the observed depth is 5 (see README benchmarks).

## Security analysis

Per-patient values are encrypted during evaluation, and only the three
aggregates are decrypted. Both signs are produced by a public deg-3 polynomial,
which approximates the sign only away from zero; the event indicator gates
contribution to the concordant count. The ciphertext security of CKKS at 128 bits is
an assumption at the stated parameters, not measured here.

## Reference deployment

- Bench targets: TCGA-BRCA (de-identified) and SUPPORT2 at
  `N ∈ {500, 1 000, 2 000}`.
- Goal wall-clock: ≤ 3 min per audit at `N = 1 000`.

## Related primitives

- Upstream: an encrypted Cox model produces `risk`.
- Downstream: `regaudit_fhe.ecmd_jps` for champion-versus-challenger
  joint concordance.
