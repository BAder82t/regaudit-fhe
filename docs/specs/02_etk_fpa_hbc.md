# ETK-FPA-HBC — Encrypted Top-K Training-Data Provenance

**Module:** `regaudit_fhe.etk_fpa_hbc`
**Public API:** `regaudit_fhe.audit_provenance(...)`
**Depth budget:** 3 of 6
**Author:** VaultBytes Innovations Ltd

## What it does

Aggregates encrypted per-row attribution scores into a small fixed
number of provenance buckets via a public hash, then identifies the
top-K bucket identifiers entirely under encryption.

## Why it exists

| Regulation              | Jurisdiction | What it requires                                |
| ----------------------- | ------------ | ----------------------------------------------- |
| EU AI Act, Article 10   | EU           | Training-data governance evidence.              |
| 21 CFR Part 11          | US (FDA)     | Training-data audit for AI/ML SaMD.             |
| GDPR, Article 22        | EU           | Algorithmic-decision review.                    |
| HIPAA                   | US           | PHI-bounded training-data attribution.          |

Per-row influence-function logging exposes individual training rows to
anyone with audit access. Bucket-aggregated provenance hides
row-identity information while still letting an auditor identify the
training-data clusters most responsible for a model's downstream
behaviour.

## Inputs

| Argument        | Type         | Description                                    |
| --------------- | ------------ | ---------------------------------------------- |
| `attributions`  | `np.ndarray` | Per-row influence / attribution magnitudes.    |
| `row_ids`       | `np.ndarray` | Per-row training-data identifiers.             |
| `n_buckets`     | `int`        | Target number of provenance buckets `B`.       |
| `k`             | `int`        | Number of top buckets to report.               |

## Output

`ProvenanceReport(bucket_aggregates, topk_indices, topk_indicator)`

## Algorithm

```
bucket_id[r]      = universal_hash(row_id[r]) mod B   # plaintext
encrypted_attr    = encrypt(attributions)
for each bucket b in 0..B-1:
    masked         = encrypted_attr * bucket_mask[b]   # depth 1
    aggregate[b]   = sum_slots(masked)
threshold         = (k-th largest of aggregate)         # plaintext
selector_signal   = sign_poly_3(aggregate - threshold)  # depth 3
top_k             = bucket-ids selected by the signal
```

## Depth budget

```
plaintext-mul bucket-mask  : +1 level    aggregate[b]
cross-slot sum             : +0 levels
sign-poly top-K selector   : +2 levels
                            ───────
                             3 of 6
```

## Security analysis

The hash is public; bucket assignments leak only group cardinality at
the bucket level. Combined with attribution-magnitude noise flooding
before decryption (optional), no per-row data is recoverable. IND-CPA
at 128-bit is inherited from the underlying CKKS scheme.

## Reference deployment

- Bench targets: CIFAR-10 + Folktables influence audits, MIMIC training-row
  attribution.
- Goal wall-clock: ≤ 2 min per `N = 10 k`-row provenance audit at `d = 6`.

## Related primitives

- Upstream: an encrypted influence-function pass produces
  `attributions`.
- Downstream: `regaudit_fhe.egf_imss` chains provenance into a fairness
  audit for end-to-end accountability.
