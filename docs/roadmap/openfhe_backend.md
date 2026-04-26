# OpenFHE backend — design note (NOT IMPLEMENTED)

> **Status: roadmap, not shipping.** This file documents the
> integration surface for a future OpenFHE-CKKS backend. It is **not
> installed by the `[fhe]` extra** — that extra installs **TenSEAL**
> today. The repository's only encrypted backend is TenSEAL CKKS at
> `regaudit_fhe.fhe`.

## Why a separate OpenFHE build is on the roadmap

1. **Native rotation primitive.** OpenFHE exposes
   `EvalRotate(ct, k)` directly, so the rotation-based prefix-sum and
   slot-shift implementations of the audit primitives stay at depth
   zero. The TenSEAL backend lacks this primitive at the
   `CKKSVector` level and substitutes a depth-1 plaintext-matrix
   multiply for prefix-sum (see `regaudit_fhe.fhe.slot_vec.mm_pt`).
2. **Calibrated polynomial libraries.** OpenFHE ships
   minimax-calibrated sign and reciprocal polynomials at higher
   degrees, supporting tighter precision bounds than the textbook
   degree-3 polynomials shipped today.
3. **Bootstrapping support.** Even though the audit primitives are
   designed to run inside the d=6 budget without bootstrapping, an
   OpenFHE build can support depth-7+ extensions if needed.

## Integration surface (target)

A future ``regaudit_fhe.fhe.openfhe_slot_vec.EncryptedSlotVec`` would
mirror the existing TenSEAL slot-vector API:

| TenSEAL backend (today)                        | OpenFHE backend (target)                       |
| ---------------------------------------------- | ---------------------------------------------- |
| `regaudit_fhe.fhe.context.build_d6_context`    | `build_d6_openfhe_context(...)`                |
| `regaudit_fhe.fhe.slot_vec.EncryptedSlotVec`   | `OpenFHEEncryptedSlotVec`                      |
| `EncryptedSlotVec.sum_all` via `tenseal.sum()` | `EvalSum(ct)` (native rotation tree)           |
| `EncryptedSlotVec.mm_pt` (depth +1 substitute) | `EvalRotate(ct, k)` (depth +0)                 |

The audit primitive surface (`fairness_encrypted`, …) would not
change: the SlotVec algebra is identical.

## What we will NOT do

- We will not silently swap backends behind the same import path. If
  and when this backend ships, it will be loaded explicitly and the
  `parameter_set.backend` field of the audit envelope will read
  `openfhe-ckks`.
- We will not add OpenFHE as a hard dependency of the open-source
  package. It will live behind a separate extra (`[openfhe]`) so the
  baseline install footprint stays small.
- We will not move OpenFHE into the repo without first shipping a
  full equivalence-test matrix against the existing TenSEAL backend.

## How to follow this work

Outside contributions are not accepted — see
[CONTRIBUTING.md](../../CONTRIBUTING.md). Track the roadmap by
watching the repository or the `[fhe]` extra contents in the next
release.
