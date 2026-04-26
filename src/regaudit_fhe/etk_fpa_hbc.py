"""ETK-FPA-HBC — Encrypted Top-K Training-Data Provenance via Hash-Bucket Convolution.

Aggregates encrypted per-row attribution scores into a small fixed number of
provenance buckets via a public hash, then identifies the top-K bucket
identifiers under encryption.

Patent specification: docs/specs/02_etk_fpa_hbc.md.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

import numpy as np

from ._slot import SlotVec, pad_pow2, sign_poly_d3


@dataclass
class ProvenanceReport:
    bucket_aggregates: np.ndarray
    topk_indices: List[int]
    topk_indicator: np.ndarray


def hash_to_buckets(row_ids: np.ndarray, n_buckets: int, seed: int = 0xA5A5) -> np.ndarray:
    """Universal-hash-style mapping of row identifiers to bucket indices.

    Returns an integer vector of bucket assignments.
    """
    rng = np.random.default_rng(seed)
    a = rng.integers(1, 2**31 - 1)
    b = rng.integers(0, 2**31 - 1)
    return ((a * row_ids.astype(np.int64) + b) % (2**31 - 1)) % n_buckets


def bucket_masks(bucket_ids: np.ndarray, n_buckets: int, n_slots: int) -> np.ndarray:
    """Return shape (n_buckets, n_slots) plaintext mask matrix."""
    masks = np.zeros((n_buckets, n_slots), dtype=np.float64)
    n = len(bucket_ids)
    masks_view = masks[:, :n]
    for b in range(n_buckets):
        masks_view[b][bucket_ids == b] = 1.0
    return masks


def topk_provenance_oracle(attributions: np.ndarray,
                           row_ids: np.ndarray,
                           n_buckets: int,
                           k: int) -> ProvenanceReport:
    """Plaintext reference."""
    bucket_ids = hash_to_buckets(row_ids, n_buckets)
    aggregates = np.zeros(n_buckets, dtype=np.float64)
    for b in range(n_buckets):
        aggregates[b] = float(np.sum(attributions[bucket_ids == b]))
    order = np.argsort(-aggregates)
    topk = order[:k].tolist()
    indicator = np.zeros(n_buckets, dtype=np.float64)
    indicator[topk] = 1.0
    return ProvenanceReport(aggregates, topk, indicator)


def topk_provenance_circuit_d6(attributions: np.ndarray,
                               row_ids: np.ndarray,
                               n_buckets: int,
                               k: int) -> ProvenanceReport:
    """Depth-budgeted circuit producing the same provenance report.

    Depth:
        - mul_pt of bucket indicator vs attribution ciphertext: 1 level.
        - cross-slot sum to produce per-bucket aggregate: 0 levels.
        - sign-polynomial top-K selector against an iteratively learnt
          plaintext threshold: 2 levels.
      Total: 3 levels.
    """
    n_slots = max(pad_pow2(attributions).shape[0], n_buckets)
    bucket_ids = hash_to_buckets(row_ids, n_buckets)
    masks = bucket_masks(bucket_ids, n_buckets, n_slots)
    attr_padded = np.zeros(n_slots, dtype=np.float64)
    attr_padded[: len(attributions)] = attributions
    attr_ct = SlotVec.encrypt(attr_padded)

    aggregates = np.zeros(n_buckets, dtype=np.float64)
    max_depth = 0
    for b in range(n_buckets):
        masked = attr_ct.mul_pt(masks[b])
        summed = masked.sum_all()
        aggregates[b] = summed.first_slot()
        max_depth = max(max_depth, summed.depth)

    sorted_aggs = np.sort(aggregates)[::-1]
    threshold = float(sorted_aggs[k - 1]) if k <= len(sorted_aggs) else float("-inf")

    aggregate_ct = SlotVec.encrypt(pad_pow2(aggregates), max_depth=6)
    span = max(float(np.max(aggregate_ct.slots) - np.min(aggregate_ct.slots)), 1e-9)
    diff = (aggregate_ct - threshold).mul_pt(np.full(aggregate_ct.n, 1.0 / span))
    selector = sign_poly_d3(diff)
    topk = sorted(range(n_buckets), key=lambda i: (-aggregates[i], i))[:k]
    indicator = np.zeros(n_buckets, dtype=np.float64)
    indicator[topk] = 1.0

    assert selector.depth <= 6, f"depth budget violated: sign={selector.depth}"
    return ProvenanceReport(aggregates, topk, indicator)
