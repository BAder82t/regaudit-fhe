"""Example — reproduce a small slice of the README benchmark table.

Re-runs the FHE benchmark for two primitives at ``N = 2^14`` so a
reviewer can spot-check the numbers without a multi-GB RAM budget.
The full matrix lives in ``benchmarks/bench_fhe.py``; the JSON results
under ``benchmarks/results/`` are what the README quotes.

Requires the ``[fhe]`` extra::

    pip install regaudit-fhe[fhe]

Run::

    python examples/benchmark_reproduce.py
"""

from __future__ import annotations

import statistics
import sys
import time

import numpy as np

try:
    import psutil
except Exception:
    psutil = None

import regaudit_fhe as rf

try:
    from regaudit_fhe.fhe import build_d6_context
    from regaudit_fhe.fhe import primitives as fhe_p
    from regaudit_fhe.fhe import slot_vec as sv
except RuntimeError as exc:
    sys.exit(f"[fhe] extra not installed: {exc}")


REPS = 3


def _rss_mb() -> float:
    if psutil is None:
        return float("nan")
    return psutil.Process().memory_info().rss / (1024 * 1024)


def _time(fn, reps: int = REPS):
    samples = []
    out = None
    for _ in range(reps):
        t0 = time.perf_counter()
        out = fn()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples), out


def main() -> int:
    print("regaudit-fhe — benchmark reproduction (N=2^14, two primitives)\n")
    ctx = build_d6_context()
    print(f"context: ring_dim={ctx.poly_modulus_degree} "
          f"slots={ctx.n_slots} rss={_rss_mb():.0f} MB\n")

    rng = np.random.default_rng(20260426)
    rows = []

    # Fairness
    n = 64
    y_true = (rng.uniform(size=n) < 0.4).astype(float)
    y_pred = ((rng.uniform(size=n) < 0.4) | y_true.astype(bool)).astype(float)
    g_a = (rng.uniform(size=n) < 0.5).astype(float)
    g_b = 1.0 - g_a

    sv.reset_op_counters()
    fhe_p.reset_last_depth()
    median_t, enc = _time(
        lambda: fhe_p.fairness_encrypted(ctx, y_true, y_pred, g_a, g_b))
    plain = rf.audit_fairness(y_true, y_pred, g_a, g_b)
    counters = sv.snapshot_op_counters()
    err = max(abs(plain.demographic_parity_diff - enc.demographic_parity_diff),
              abs(plain.equal_opportunity_diff - enc.equal_opportunity_diff),
              abs(plain.predictive_parity_diff - enc.predictive_parity_diff))
    rows.append(("fairness", fhe_p.last_depth("fairness"),
                 fhe_p.declared_depth("fairness"),
                 counters["rotations"], counters["ct_ct_muls"],
                 counters["ct_pt_muls"], median_t, err))

    # Drift
    bins = 16
    p = rng.uniform(size=bins)
    q = p + rng.normal(scale=0.05, size=bins)
    q = np.maximum(q, 0)

    sv.reset_op_counters()
    fhe_p.reset_last_depth()
    median_t, enc = _time(lambda: fhe_p.w1_encrypted(ctx, p, q))
    plain = rf.audit_drift(p, q)
    counters = sv.snapshot_op_counters()
    err = abs(plain.distance - enc.distance)
    rows.append(("drift", fhe_p.last_depth("drift"),
                 fhe_p.declared_depth("drift"),
                 counters["rotations"], counters["ct_ct_muls"],
                 counters["ct_pt_muls"], median_t, err))

    print(f"{'primitive':<14}{'depth':>10}{'rotations':>11}"
          f"{'ct×ct':>8}{'ct×pt':>8}{'runtime':>10}{'max abs err':>14}")
    for r in rows:
        prim, dep_obs, dep_dec, rot, ctct, ctpt, rt, err = r
        print(f"{prim:<14}{dep_obs:>3}/{dep_dec:<5}"
              f"{rot:>11}{ctct:>8}{ctpt:>8}"
              f"{rt*1000:>9.2f}ms"
              f"{err:>14.2e}")
    print()

    print("OK — numbers should match the small-N rows in "
          "benchmarks/results/SUMMARY.md.")
    print("Full matrix: python benchmarks/bench_fhe.py --rings 14 15")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
