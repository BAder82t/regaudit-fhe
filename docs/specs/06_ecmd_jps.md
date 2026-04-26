# ECMD-JPS — Encrypted Cross-Model Disagreement Score

**Module:** `regaudit_fhe.ecmd_jps`
**Public API:** `regaudit_fhe.audit_disagreement(...)`
**Depth budget:** 5 of 6
**Author:** VaultBytes Innovations Ltd

## What it does

Computes an encrypted disagreement score across `M ≥ 3` model versions
evaluated on a common encrypted input. Each model is represented as a
public degree-3 polynomial surrogate; the circuit accumulates the
average pairwise squared difference within the depth budget.

## Why it exists

| Regulation                       | Jurisdiction | What it requires                              |
| -------------------------------- | ------------ | --------------------------------------------- |
| OCC Supervisory Letter SR 11-7   | US (banks)   | Challenger-model comparison for MRM.          |
| EU AI Act, Article 15            | EU           | Post-market surveillance for high-risk AI.    |
| FDA Predetermined Change-Control | US (FDA)     | Comparison of new vs. baseline AI versions.   |

Naive FHE deployments run `M`-many separate inference circuits and
pairwise compares, exposing per-version predictions. This primitive
evaluates the joint disagreement variance in one circuit.

## Inputs

| Argument             | Type                       | Description                                     |
| -------------------- | -------------------------- | ----------------------------------------------- |
| `model_polynomials`  | `Sequence[(a0,a1,a2,a3)]`  | Per-model degree-3 surrogate coefficients.      |
| `test_input`         | `np.ndarray`               | Encrypted test-input vector.                    |
| `threshold`          | `float`                    | Disagreement breach threshold. 0.05.            |

## Output

`DisagreementReport(pairwise_variance, breach, per_model_outputs)`

## Algorithm

```
encrypted_x = encrypt(test_input)
x_sq, x_cube = encrypted_x², encrypted_x³                # depth 2
for each model i:
    P[i] = a0 + a1*x + a2*x² + a3*x³                      # depth 3
for each i < j:
    diff = P[i] - P[j]                                    # depth 3
    sq   = diff * diff                                    # depth 4
    var_acc += sq
avg_var = var_acc * (1 / pair_count)                      # depth 5
```

The breach indicator is decided plaintext-side after the auditor
decrypts `avg_var`, keeping the on-encrypted depth strictly below six.

## Depth budget

```
x², x³                          : +2 levels
linear combination Pi(x)        : +1 level   = depth 3
diff                            : +0 levels  = depth 3
square (Pi - Pj)²               : +1 level   = depth 4
sum over pairs                  : +0 levels
plaintext rescale by 1/pairs    : +1 level   = depth 5
                                 ───────
                                  5 of 6
```

## Security analysis

Polynomial coefficients are auditor-public; the encrypted input is
never decrypted server-side. IND-CPA at 128-bit is preserved.

## Reference deployment

- Bench targets: synthetic banking A/B logs with `M ∈ {3, 5}` model
  versions.
- Goal wall-clock: ≤ 60 s per shadow eval at `d = 6`.

## Related primitives

- Upstream: per-version inference produces the polynomial surrogates.
- Downstream: `regaudit_fhe.esc_cia` for champion-vs-challenger
  concordance audit.
