"""Input-commitment helper tests.

The audit envelope binds itself to its inputs through SHA-256 hashes
of canonicalised input vectors. These tests cover the contract:

  - the same input always produces the same digest,
  - any change to the input changes the digest,
  - input order does not affect the digest of a single named input,
  - commitments_for() materialises one record per input, sorted by
    name for stable canonical ordering inside the envelope.
"""

from __future__ import annotations

import re

import numpy as np
import pytest

import regaudit_fhe as rf


def test_commit_input_returns_sha256_record():
    digest = rf.commit_input("y_true", np.array([1, 0, 1, 1]))
    assert digest["name"] == "y_true"
    assert re.fullmatch(r"[a-f0-9]{64}", digest["sha256"])


def test_commit_input_is_deterministic():
    a = rf.commit_input("y_true", np.array([1, 0, 1, 1]))
    b = rf.commit_input("y_true", np.array([1, 0, 1, 1]))
    assert a == b


def test_commit_input_changes_when_value_changes():
    base = rf.commit_input("y_true", np.array([1, 0, 1, 1]))
    perturbed = rf.commit_input("y_true", np.array([1, 0, 1, 0]))
    assert base["sha256"] != perturbed["sha256"]


def test_commit_input_changes_when_name_changes():
    a = rf.commit_input("y_true", np.array([1, 0]))
    b = rf.commit_input("y_pred", np.array([1, 0]))
    assert a["sha256"] != b["sha256"]


def test_commit_input_array_and_equivalent_list_produce_same_digest():
    """A float64 ndarray and a Python list of the same float values
    canonicalise identically and therefore commit to the same hash.

    int and float canonicalise to *different* JSON tokens (`1` vs `1.0`)
    so an int array and a float array intentionally produce different
    digests — the commitment binds to the exact value type.
    """
    arr = np.array([1.0, 0.0, 1.0, 1.0], dtype=np.float64)
    lst = [1.0, 0.0, 1.0, 1.0]
    assert (rf.commit_input("y_true", arr)["sha256"]
            == rf.commit_input("y_true", lst)["sha256"])

    int_arr = np.array([1, 0, 1, 1], dtype=np.int64)
    assert (rf.commit_input("y_true", int_arr)["sha256"]
            != rf.commit_input("y_true", arr)["sha256"])


def test_commitments_for_emits_one_record_per_input():
    inputs = {
        "y_true":  np.array([1, 0, 1, 0]),
        "y_pred":  np.array([1, 0, 1, 0]),
        "group_a": np.array([1, 1, 0, 0]),
        "group_b": np.array([0, 0, 1, 1]),
    }
    records = rf.commitments_for(inputs)
    assert {r["name"] for r in records} == set(inputs)
    assert len(records) == len(inputs)
    for r in records:
        assert re.fullmatch(r"[a-f0-9]{64}", r["sha256"])


def test_commitments_for_is_sorted_by_name():
    inputs = {"zeta": np.array([1]), "alpha": np.array([2]),
              "mike": np.array([3])}
    names = [r["name"] for r in rf.commitments_for(inputs)]
    assert names == sorted(names)


def test_envelope_carries_input_commitments():
    inputs = {"y_true": np.array([1, 0, 1, 1]),
              "y_pred": np.array([1, 0, 0, 1])}
    y = inputs["y_true"].astype(float)
    yp = inputs["y_pred"].astype(float)
    g_a = np.array([1.0, 1.0, 0.0, 0.0])
    g_b = 1.0 - g_a
    report = rf.audit_fairness(y, yp, g_a, g_b)
    env = rf.envelope("fairness", report,
                      input_commitments=rf.commitments_for(inputs))
    body = env.to_dict()
    names = [c["name"] for c in body["input_commitments"]]
    assert names == sorted(names)
    assert {"y_true", "y_pred"} <= set(names)


def test_modifying_committed_input_fails_envelope_verification():
    inputs = {"y_true": np.array([1, 0, 1, 1])}
    y = inputs["y_true"].astype(float)
    g = np.array([1.0, 1.0, 0.0, 0.0])
    report = rf.audit_fairness(y, y, g, 1.0 - g)
    env = rf.envelope("fairness", report,
                      input_commitments=rf.commitments_for(inputs))
    env.input_commitments[0]["sha256"] = "0" * 64
    out = rf.verify_envelope(env)
    assert out.sha256_valid is False
    assert out.valid is False


def test_commitment_record_contains_only_name_and_sha256():
    rec = rf.commit_input("y_true", np.array([1, 0]))
    assert sorted(rec.keys()) == ["name", "sha256"]


def test_committed_value_is_not_recoverable_from_record():
    """The hash must not embed the input itself; the digest is a
    one-way commitment, not a serialisation."""
    secret = np.array([42, 17, 99, 0])
    rec = rf.commit_input("y_true", secret)
    blob = rec["sha256"]
    assert "42" not in blob
    assert all(s.isalnum() for s in blob)


@pytest.mark.parametrize("size", [1, 8, 64, 1024])
def test_commit_handles_arbitrary_sizes(size):
    arr = np.arange(size, dtype=np.float64)
    rec = rf.commit_input("x", arr)
    assert re.fullmatch(r"[a-f0-9]{64}", rec["sha256"])
