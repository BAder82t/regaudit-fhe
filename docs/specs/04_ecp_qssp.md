# ECP-QSSP — Encrypted Conformal Prediction Set Compactor

**Module:** `regaudit_fhe.ecp_qssp`
**Public API:** `regaudit_fhe.audit_calibration(...)`
**Depth budget:** 3 of 6
**Author:** VaultBytes Innovations Ltd

## What it does

Computes the conformal prediction-set membership bitmask over `K`
candidate labels in a single CKKS circuit by pre-encoding all per-class
calibration quantile thresholds into one packed plaintext vector, then
producing an encrypted membership signal via a depth-2 polynomial.

## Why it exists

| Regulation                       | Jurisdiction | What it requires                              |
| -------------------------------- | ------------ | --------------------------------------------- |
| FDA AI-SaMD UQ guidance          | US           | Distribution-free uncertainty quantification. |
| EU AI Act, Article 15            | EU           | Calibrated confidence intervals.              |
| ISO/IEC 23053                    | ISO          | UQ in trustworthy AI.                         |
| UNECE WP.29                      | UN ECE       | UQ in autonomous-vehicle AI.                  |

Conformal prediction is the standard distribution-free UQ method, but
naive FHE conformal evaluation runs `K` separate per-class quantile
circuits, multiplying wall-clock by `K` and leaking via output
cardinality. The slot-packed approach folds all `K` comparisons into
one circuit.

## Inputs

| Argument      | Type           | Description                                |
| ------------- | -------------- | ------------------------------------------ |
| `scores`      | `np.ndarray`   | Per-class non-conformity scores.           |
| `quantiles`   | `np.ndarray`   | Per-class calibration quantile thresholds. |

## Output

`ConformalReport(membership, set_size)`

`membership[i] = 1` indicates that class `i` is included in the
conformal prediction set; `set_size` is its cardinality.

## Algorithm

```
encrypted_scores  = encrypt(pad_pow2(scores))
plaintext_thresh  = pad_pow2(quantiles)
diff              = (plaintext_thresh - encrypted_scores) / span   # depth 1
member_signal     = sign_poly_3(diff)                              # depth 3
membership        = (member_signal > 0)
```

The `quantiles` vector is auditor-public per the security model.

## Depth budget

```
plaintext-sub + plaintext-mul rescale : +1 level
sign-poly                             : +2 levels
                                       ───────
                                        3 of 6
```

## Security analysis

The slot permutation that routes scores into matched class slots is
class-invariant and therefore reveals nothing per-test-point. IND-CPA
at 128-bit is preserved.

## Reference deployment

- Bench targets: CIFAR-100, MIMIC-CXR conformal calibration sets at
  `K ∈ {10, 100, 1 000}`.
- Goal wall-clock: ≤ 30 s per inference at `K = 100`.

## Related primitives

- Upstream: any encrypted classifier produces `scores`.
- Downstream: `regaudit_fhe.etk_fpa_hbc` for top-K extraction.
