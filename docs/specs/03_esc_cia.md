# ESC-CIA — Encrypted Survival-Curve Concordance (Harrell C-Index)

**Module:** `regaudit_fhe.esc_cia`
**Public API:** `regaudit_fhe.audit_concordance(...)`
**Depth budget:** 4 of 6
**Author:** VaultBytes Innovations Ltd

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
on-encrypted depth at four. No per-row PHI leaves the encrypted domain.

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

## Depth budget

```
two sign-polynomials       : +2 levels each
mul of two signs           : +1 level
mul of result × event      : +1 level
                            ───────
                             4 of 6
```

## Security analysis

PHI never leaves the encrypted domain. Both signs are produced by a
public deg-3 polynomial; the event indicator gates contribution to the
concordant count. IND-CPA at 128-bit is preserved.

## Reference deployment

- Bench targets: TCGA-BRCA (de-identified) and SUPPORT2 at
  `N ∈ {500, 1 000, 2 000}`.
- Goal wall-clock: ≤ 3 min per audit at `N = 1 000`.

## Related primitives

- Upstream: an encrypted Cox model produces `risk`.
- Downstream: `regaudit_fhe.ecmd_jps` for champion-versus-challenger
  joint concordance.
