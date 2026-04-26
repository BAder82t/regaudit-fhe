# EW1-CDSF — Encrypted CDF Distance for Distribution-Shift Detection

**Module:** `regaudit_fhe.ew1_cdsf`
**Public API:** `regaudit_fhe.audit_drift(...)`
**Depth budget:** 1 of 6
**Author:** VaultBytes Innovations Ltd

## What it does

Computes an encrypted Cramer-von-Mises-style distribution distance —
the L2-squared norm of the cumulative-distribution-function difference
between two histograms — within a single CKKS circuit at multiplicative
depth one. The plaintext oracle reports both the L2-squared distance
and a Wasserstein-1 reference for cross-comparison.

## Why CDF-L2-squared rather than W1

The natural Wasserstein-1 distance is `sum_k |F_p(k) - F_q(k)|`. Under
encryption, the absolute-value step requires a sign-polynomial
approximation that introduces 5–15 percent relative error and consumes
extra multiplicative depth. The L2-squared variant
`sum_k (F_p(k) - F_q(k))^2` is mathematically equivalent for
drift-detection purposes (zero iff distributions agree, monotonic in
the magnitude of shift), is numerically exact under encryption, and
fits in a single multiplicative level. This is the canonical depth-budget
trade in production FHE drift-monitoring deployments.

## Why it exists

| Regulation                    | Jurisdiction | What it requires                                  |
| ----------------------------- | ------------ | ------------------------------------------------- |
| EU AI Act, Article 15         | EU           | Post-market drift monitoring for high-risk AI.    |
| FDA SaMD predetermined change | US           | Drift detection for AI/ML SaMD updates.           |
| Basel III model risk          | Banking      | Distribution-shift evidence for credit models.    |

## Inputs

| Argument           | Type         | Description                                |
| ------------------ | ------------ | ------------------------------------------ |
| `p`                | `np.ndarray` | Reference histogram (will be normalised).  |
| `q`                | `np.ndarray` | Current histogram (will be normalised).    |
| `drift_threshold`  | `float`      | L2-squared magnitude flagged as drift. 0.005. |

## Output

`DriftReport(distance, w1_distance, drift_bit)`

- `distance`: encrypted-domain L2-squared CDF distance.
- `w1_distance`: plaintext-side W1 reference (provided for
  cross-comparison; not part of the encrypted boundary).
- `drift_bit`: `True` iff `distance > drift_threshold`.

## Algorithm

```
encrypted_p, encrypted_q = encrypt(normalise(p)), encrypt(normalise(q))
F = cdf_in_place(encrypted_p)        # depth 0  (prefix-sum tree)
G = cdf_in_place(encrypted_q)
diff = F - G                          # depth 0
sq = diff * diff                      # depth 1
distance = sum_slots(sq)              # depth 1
```

## Depth budget

```
prefix-sum CDF : +0 levels (rotate-and-add only)
diff           : +0 levels
ct x ct square : +1 level
sum            : +0 levels
                ───────
                 1 of 6
```

## Security analysis

All operations are CKKS additions, multiplications, and rotations, so
IND-CPA at 128-bit is preserved. No per-bin counts leave the encrypted
boundary.

## Reference deployment

- Bench targets: drift detection over `B ∈ {16, 32, 64, 128}`-bin
  histograms; integration tests against COMPAS, MIMIC-CXR feature
  histograms.

## Related primitives

- Upstream: any feature extractor produces `p`, `q`.
- Downstream: `regaudit_fhe.egf_imss` re-runs fairness when drift fires.
