# EGF-IMSS — Encrypted Group-Fairness Disparity Aggregator

**Module:** `regaudit_fhe.egf_imss`
**Public API:** `regaudit_fhe.audit_fairness(...)`
**Depth budget:** 4 of 6 *(spec budget, plaintext model — not the observed encrypted depth; see README "Three different depth numbers")*
**Author:** VaultBytes Innovations Ltd

> **Design specification, not a statement of what ships.** This page describes the
> intended encrypted design. The encrypted functions are experimental and have not been
> independently qualified. They encrypt, evaluate and decrypt in one process that holds
> the key and the plaintext inputs, and the command line and HTTP server run the plaintext
> path only. Security statements below are properties assumed of CKKS at the stated
> parameters. This repository does not measure or verify them. Where the code differs, the
> code is what runs. In `fairness_encrypted` only `y_pred` is encrypted; `y_true` and the group masks are plaintext multipliers, and the breach decision is a plaintext comparison of the decrypted metrics with `threshold`, not an encrypted sign polynomial.

## What it does

Computes three group-fairness disparity metrics — demographic parity,
equal opportunity, and predictive parity — between two protected groups
in a single CKKS evaluation that fits within multiplicative depth six
without bootstrapping.

## Why it exists

| Regulation                       | Jurisdiction | Effective                |
| -------------------------------- | ------------ | ------------------------ |
| NYC Local Law 144                | New York     | Active                   |
| EU AI Act, Articles 10 + 15      | EU           | High-risk AI, May 2026   |
| Colorado AI Act                  | Colorado     | February 2026            |
| CFPB algorithmic discrimination  | US           | Active                   |

The naive workflow ships labels and protected-attribute vectors to a
third-party auditor, conflicting with GDPR, HIPAA, CCPA, and most
internal data-handling policies. EGF-IMSS keeps both inputs encrypted
end-to-end, returning only the three disparity scalars and a single
threshold-breach indicator.

## Inputs

| Argument    | Type           | Description                                       |
| ----------- | -------------- | ------------------------------------------------- |
| `y_true`    | `np.ndarray`   | Binary outcome labels.                            |
| `y_pred`    | `np.ndarray`   | Binary model predictions.                         |
| `group_a`   | `np.ndarray`   | Protected-group A indicator (`0`/`1` per row).    |
| `group_b`   | `np.ndarray`   | Protected-group B indicator (`0`/`1` per row).    |
| `threshold` | `float`        | Disparity magnitude that triggers a breach. 0.1.  |

## Output

`FairnessReport(demographic_parity_diff, equal_opportunity_diff,
predictive_parity_diff, threshold_breached)`

## Algorithm

```
group_count_a, group_count_b   ← plaintext (auditor-public)

# encrypted slot-vector evaluation
for each metric m in {DP, EO, PP}:
    numerator_a   = sum_slots(y_pred * mask_a_for_m)        # depth 1
    numerator_b   = sum_slots(y_pred * mask_b_for_m)
    rate_a        = numerator_a * (1 / denominator_a)        # depth 2
    rate_b        = numerator_b * (1 / denominator_b)
    disparity_m   = rate_a - rate_b                          # depth 2
breached         = sign_poly_3(max(|disparity|) - threshold) # depth 4
```

## Depth budget (spec, plaintext model)

```
plaintext-mul masks         : +1 level   ──┐
cross-slot sum              : +0 levels    │  numerator_*
plaintext-mul reciprocal    : +1 level   ──┘  rate_*
sub between groups          : +0 levels        disparity_*
sign-poly threshold         : +2 levels        breached
                             ───────
                              4 of 6
```

## Security analysis

All ciphertext operations are CKKS Add, Mul (plaintext × ciphertext and
ciphertext × ciphertext), and Rotate. The scheme's IND-CPA security at 128
bits is an assumption about CKKS at the chosen parameters (the code's `CKKSParams`
default is `N = 2^15` with a 360-bit chain), not something this repository measures.
The code does not set a key-switching `dnum`. Group cardinalities and label-positive counts are
auditor-public; deployments that cannot leak these counts can hide
them with composite-output noise flooding before decryption.

## Reference deployment

- Active backend: TenSEAL CKKS (`pip install "regaudit-fhe[fhe]"`).
  An OpenFHE backend is on the roadmap but not currently included
  (see `docs/roadmap/openfhe_backend.md`).
- Bench targets: COMPAS, Folktables-Adult, BRSET-fairness.
- Goal wall-clock: ≤ 90 s per 1 k-row audit at `d = 6`, `N = 2^15`.

## Related primitives

- `regaudit_fhe.etk_fpa_hbc` — training-data provenance feeding fairness.
- `regaudit_fhe.ew1_cdsf` — drift monitoring after fairness passes.
