"""Wall-clock + correctness benchmark for the six audit primitives.

Runs each primitive at multiple input sizes, records oracle-vs-circuit
agreement, depth consumed, and per-call latency. Output is a Markdown
table written to stdout and a JSON dump under benchmarks/results/.

Run:  python benchmarks/bench_all.py
"""

from __future__ import annotations

import json
import statistics
import time
from pathlib import Path
from typing import Any, Callable, Dict, List

import numpy as np

import regaudit_fhe as rf


RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)
RNG = np.random.default_rng(20260426)


def _time(fn: Callable[[], Any], reps: int = 5) -> Dict[str, float]:
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return {
        "median_s": statistics.median(samples),
        "mean_s": statistics.mean(samples),
        "min_s": min(samples),
        "max_s": max(samples),
    }


def bench_fairness(n: int) -> Dict[str, Any]:
    y_true = (RNG.uniform(size=n) < 0.4).astype(float)
    y_pred = ((RNG.uniform(size=n) < 0.4) | y_true.astype(bool)).astype(float)
    g_a = (RNG.uniform(size=n) < 0.5).astype(float)
    g_b = 1.0 - g_a
    oracle_t = _time(lambda: rf.fairness_oracle(y_true, y_pred, g_a, g_b))
    circuit_t = _time(lambda: rf.audit_fairness(y_true, y_pred, g_a, g_b))
    o = rf.fairness_oracle(y_true, y_pred, g_a, g_b)
    c = rf.audit_fairness(y_true, y_pred, g_a, g_b)
    return {
        "primitive": "fairness", "size": n, "oracle_t": oracle_t,
        "circuit_t": circuit_t,
        "dp_err": abs(c.demographic_parity_diff - o.demographic_parity_diff),
        "eo_err": abs(c.equal_opportunity_diff - o.equal_opportunity_diff),
        "pp_err": abs(c.predictive_parity_diff - o.predictive_parity_diff),
        "breach_match": c.threshold_breached == o.threshold_breached,
    }


def bench_provenance(n: int) -> Dict[str, Any]:
    attr = np.abs(RNG.standard_normal(n))
    rows = np.arange(n)
    n_buckets, k = 16, 4
    oracle_t = _time(lambda: rf.topk_provenance_oracle(attr, rows, n_buckets, k))
    circuit_t = _time(lambda: rf.audit_provenance(attr, rows, n_buckets, k))
    o = rf.topk_provenance_oracle(attr, rows, n_buckets, k)
    c = rf.audit_provenance(attr, rows, n_buckets, k)
    return {
        "primitive": "provenance", "size": n, "oracle_t": oracle_t,
        "circuit_t": circuit_t,
        "topk_match": sorted(c.topk_indices) == sorted(o.topk_indices),
        "agg_err_max": float(np.max(np.abs(c.bucket_aggregates - o.bucket_aggregates))),
    }


def bench_concordance(n: int) -> Dict[str, Any]:
    risk = RNG.standard_normal(n)
    time_v = np.abs(RNG.standard_normal(n)) * 100
    event = (RNG.uniform(size=n) < 0.7).astype(float)
    oracle_t = _time(lambda: rf.c_index_oracle(risk, time_v, event), reps=3)
    circuit_t = _time(lambda: rf.audit_concordance(risk, time_v, event), reps=3)
    o = rf.c_index_oracle(risk, time_v, event)
    c = rf.audit_concordance(risk, time_v, event)
    return {
        "primitive": "concordance", "size": n, "oracle_t": oracle_t,
        "circuit_t": circuit_t,
        "c_index_err": abs(c.c_index - o.c_index),
        "concordant_pairs_err": abs(c.concordant_pairs - o.concordant_pairs),
    }


def bench_calibration(K: int) -> Dict[str, Any]:
    scores = RNG.uniform(size=K)
    quantiles = np.full(K, 0.5)
    oracle_t = _time(lambda: rf.conformal_oracle(scores, quantiles))
    circuit_t = _time(lambda: rf.audit_calibration(scores, quantiles))
    o = rf.conformal_oracle(scores, quantiles)
    c = rf.audit_calibration(scores, quantiles)
    agree = float(np.mean(c.membership == o.membership))
    return {
        "primitive": "calibration", "size": K, "oracle_t": oracle_t,
        "circuit_t": circuit_t,
        "membership_agreement": agree,
        "set_size_circuit": c.set_size,
        "set_size_oracle": o.set_size,
    }


def bench_drift(B: int) -> Dict[str, Any]:
    p = RNG.uniform(size=B)
    q = p + RNG.normal(scale=0.05, size=B)
    q = np.maximum(q, 0)
    oracle_t = _time(lambda: rf.cvm_oracle(p, q))
    circuit_t = _time(lambda: rf.audit_drift(p, q))
    o = rf.cvm_oracle(p, q)
    c = rf.audit_drift(p, q)
    return {
        "primitive": "drift", "size": B, "oracle_t": oracle_t,
        "circuit_t": circuit_t,
        "cvm_oracle": o,
        "cvm_circuit": c.distance,
        "cvm_rel_err": abs(c.distance - o) / max(o, 1e-9),
    }


def bench_disagreement(M: int, n_input: int = 32) -> Dict[str, Any]:
    coeffs = [(0.0, 1.0 + 0.1 * i, 0.0, 0.0) for i in range(M)]
    x = np.linspace(-0.5, 0.5, n_input)
    pred_grid = np.stack([c[0] + c[1] * x + c[2] * x ** 2 + c[3] * x ** 3
                          for c in coeffs])
    oracle_t = _time(lambda: rf.disagreement_oracle(pred_grid))
    circuit_t = _time(lambda: rf.audit_disagreement(coeffs, x))
    o = rf.disagreement_oracle(pred_grid)
    c = rf.audit_disagreement(coeffs, x)
    return {
        "primitive": "disagreement", "size": M, "oracle_t": oracle_t,
        "circuit_t": circuit_t,
        "var_err": abs(c.pairwise_variance - o.pairwise_variance),
    }


def main() -> None:
    rows: List[Dict[str, Any]] = []
    print("Running benchmarks (plaintext model)...\n")

    for n in [64, 256, 1024]:
        rows.append(bench_fairness(n))
    for n in [64, 256, 1024]:
        rows.append(bench_provenance(n))
    for n in [16, 32, 64]:
        rows.append(bench_concordance(n))
    for K in [16, 64, 256]:
        rows.append(bench_calibration(K))
    for B in [16, 64, 256]:
        rows.append(bench_drift(B))
    for M in [3, 5, 8]:
        rows.append(bench_disagreement(M))

    out_md = ["| Primitive | Size | Oracle (ms) | Circuit (ms) | Match |",
              "|---|---:|---:|---:|---|"]
    for r in rows:
        ot = r["oracle_t"]["median_s"] * 1000
        ct = r["circuit_t"]["median_s"] * 1000
        match_field = next((k for k in r if k.endswith("_match")
                            or k.endswith("_err")
                            or k.endswith("agreement")), None)
        match_v = r[match_field] if match_field else "n/a"
        out_md.append(f"| {r['primitive']} | {r['size']} | "
                      f"{ot:.2f} | {ct:.2f} | "
                      f"{match_field}={match_v} |")
    print("\n".join(out_md))

    out_path = RESULTS_DIR / "bench_all.json"
    out_path.write_text(json.dumps(rows, indent=2, default=str))
    print(f"\nResults written to {out_path}")


if __name__ == "__main__":
    main()
