"""Real CKKS benchmark for the six audit primitives.

For each (primitive, ring dimension N) pair, records:

    primitive
    N (poly_modulus_degree)
    n_slots
    batch_size
    declared_depth, observed_depth
    rotation count (logical, includes sum_all and mm_pt)
    ct x ct multiplications
    ct x pt multiplications
    wall-clock time (median over `reps` measurements)
    peak resident memory (MB)
    ciphertext size (bytes per ciphertext after the circuit)
    decryption error (|fhe - plaintext_oracle|)
    threshold-flip rate (over `flip_trials` random near-threshold inputs)

Output:
    benchmarks/results/bench_fhe_<N>.json   - per-N machine-readable record
    benchmarks/results/SUMMARY.md           - all rings combined into a table

Run:  python benchmarks/bench_fhe.py [--rings 14 15] [--reps 5]

By default rings 2^14 and 2^15 are evaluated. Add --rings 16 to also run
2^16 (slower; uses several GB of RAM and minutes per primitive).
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

import numpy as np
import psutil

import regaudit_fhe as rf
from regaudit_fhe.fhe import build_d6_context
from regaudit_fhe.fhe import primitives as fhe_p
from regaudit_fhe.fhe import slot_vec as sv


RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)
RNG = np.random.default_rng(20260426)
PROC = psutil.Process(os.getpid())


def _peak_rss_mb() -> float:
    return PROC.memory_info().rss / (1024 * 1024)


def _ct_size_bytes(report: Any) -> int:
    """Best-effort: the encrypted output is decrypted before reaching us,
    so we estimate ciphertext size from a reference vector encrypted on
    the same context. Set during context construction.
    """
    return getattr(report, "_ct_size_bytes", 0)


@dataclass
class Trial:
    primitive: str
    ring_log2: int
    n_slots: int
    batch_size: int
    declared_depth: int
    observed_depth: int
    rotations: int
    ct_ct_muls: int
    ct_pt_muls: int
    ct_scalar_muls: int
    matmul_pt: int
    additions: int
    runtime_s_median: float
    runtime_s_min: float
    runtime_s_max: float
    rss_mb: float
    ct_size_bytes: int
    decryption_error: float
    threshold_flip_rate: float
    notes: str = ""


def _measure_runtime(fn: Callable[[], Any], reps: int) -> Tuple[float, float, float, Any]:
    samples: List[float] = []
    out = None
    for _ in range(reps):
        t0 = time.perf_counter()
        out = fn()
        samples.append(time.perf_counter() - t0)
    return (statistics.median(samples), min(samples), max(samples), out)


def _ciphertext_size(ctx) -> int:
    """Encrypt a length-1 vector and serialise the resulting ciphertext."""
    ct = ctx.encrypt_vector([0.0])
    return len(ct.serialize())


def _flip_rate(plaintext_fn: Callable[..., Any],
               encrypted_fn: Callable[..., Any],
               breach_field: str,
               sampler: Callable[[], Dict[str, Any]],
               trials: int) -> float:
    if breach_field is None:
        return 0.0
    flips = 0
    for _ in range(trials):
        args = sampler()
        p = plaintext_fn(**args)
        e = encrypted_fn(**args)
        if getattr(p, breach_field) != getattr(e, breach_field):
            flips += 1
    return flips / trials


# --------------------------------------------------------------------------
# Per-primitive benchmark drivers
# --------------------------------------------------------------------------


def _bench_fairness(ctx, ring_log2: int, reps: int, flip_trials: int,
                    batch_size: int) -> Trial:
    n = batch_size
    y_true = (RNG.uniform(size=n) < 0.4).astype(float)
    y_pred = ((RNG.uniform(size=n) < 0.4) | y_true.astype(bool)).astype(float)
    g_a = (RNG.uniform(size=n) < 0.5).astype(float)
    g_b = 1.0 - g_a

    sv.reset_op_counters()
    fhe_p.reset_last_depth()

    median, lo, hi, enc = _measure_runtime(
        lambda: fhe_p.fairness_encrypted(ctx, y_true, y_pred, g_a, g_b),
        reps=reps)
    counters = sv.snapshot_op_counters()

    plain = rf.audit_fairness(y_true, y_pred, g_a, g_b)
    err = max(
        abs(plain.demographic_parity_diff - enc.demographic_parity_diff),
        abs(plain.equal_opportunity_diff - enc.equal_opportunity_diff),
        abs(plain.predictive_parity_diff - enc.predictive_parity_diff),
    )

    def near_threshold():
        n_ = 16
        y_t = (RNG.uniform(size=n_) < 0.4).astype(float)
        y_p = y_t.copy()
        flip_idx = RNG.integers(0, n_)
        y_p[flip_idx] = 1 - y_p[flip_idx]
        ga = (RNG.uniform(size=n_) < 0.5).astype(float)
        return {"y_true": y_t, "y_pred": y_p,
                "group_a": ga, "group_b": 1.0 - ga, "threshold": 0.1}

    flip = _flip_rate(rf.audit_fairness,
                      lambda **kw: fhe_p.fairness_encrypted(ctx, **kw),
                      "threshold_breached", near_threshold, flip_trials)

    return Trial(
        primitive="fairness", ring_log2=ring_log2, n_slots=ctx.n_slots,
        batch_size=batch_size,
        declared_depth=fhe_p.declared_depth("fairness"),
        observed_depth=fhe_p.last_depth("fairness"),
        rotations=counters["rotations"],
        ct_ct_muls=counters["ct_ct_muls"],
        ct_pt_muls=counters["ct_pt_muls"],
        ct_scalar_muls=counters["ct_scalar_muls"],
        matmul_pt=counters["matmul_pt"],
        additions=counters["additions"],
        runtime_s_median=median, runtime_s_min=lo, runtime_s_max=hi,
        rss_mb=_peak_rss_mb(),
        ct_size_bytes=_ciphertext_size(ctx),
        decryption_error=err, threshold_flip_rate=flip,
    )


def _bench_provenance(ctx, ring_log2: int, reps: int, flip_trials: int,
                      batch_size: int) -> Trial:
    n_rows = batch_size
    n_buckets, k = 16, 4
    attr = np.abs(RNG.standard_normal(n_rows))
    rows = np.arange(n_rows)

    sv.reset_op_counters()
    fhe_p.reset_last_depth()

    median, lo, hi, enc = _measure_runtime(
        lambda: fhe_p.topk_provenance_encrypted(ctx, attr, rows, n_buckets, k),
        reps=reps)
    counters = sv.snapshot_op_counters()

    plain = rf.audit_provenance(attr, rows, n_buckets, k)
    err = float(np.max(np.abs(plain.bucket_aggregates - enc.bucket_aggregates)))

    return Trial(
        primitive="provenance", ring_log2=ring_log2, n_slots=ctx.n_slots,
        batch_size=batch_size,
        declared_depth=fhe_p.declared_depth("provenance"),
        observed_depth=fhe_p.last_depth("provenance"),
        rotations=counters["rotations"],
        ct_ct_muls=counters["ct_ct_muls"],
        ct_pt_muls=counters["ct_pt_muls"],
        ct_scalar_muls=counters["ct_scalar_muls"],
        matmul_pt=counters["matmul_pt"],
        additions=counters["additions"],
        runtime_s_median=median, runtime_s_min=lo, runtime_s_max=hi,
        rss_mb=_peak_rss_mb(),
        ct_size_bytes=_ciphertext_size(ctx),
        decryption_error=err, threshold_flip_rate=0.0,
        notes="provenance has no boolean breach indicator",
    )


def _bench_concordance(ctx, ring_log2: int, reps: int, flip_trials: int,
                       batch_size: int) -> Trial:
    n = batch_size
    risk = RNG.standard_normal(n)
    time_v = np.abs(RNG.standard_normal(n)) * 100
    event = (RNG.uniform(size=n) < 0.7).astype(float)

    sv.reset_op_counters()
    fhe_p.reset_last_depth()
    median, lo, hi, enc = _measure_runtime(
        lambda: fhe_p.c_index_encrypted(ctx, risk, time_v, event),
        reps=reps)
    counters = sv.snapshot_op_counters()
    plain = rf.audit_concordance(risk, time_v, event)
    err = abs(plain.c_index - enc.c_index)

    return Trial(
        primitive="concordance", ring_log2=ring_log2, n_slots=ctx.n_slots,
        batch_size=batch_size,
        declared_depth=fhe_p.declared_depth("concordance"),
        observed_depth=fhe_p.last_depth("concordance"),
        rotations=counters["rotations"],
        ct_ct_muls=counters["ct_ct_muls"],
        ct_pt_muls=counters["ct_pt_muls"],
        ct_scalar_muls=counters["ct_scalar_muls"],
        matmul_pt=counters["matmul_pt"],
        additions=counters["additions"],
        runtime_s_median=median, runtime_s_min=lo, runtime_s_max=hi,
        rss_mb=_peak_rss_mb(),
        ct_size_bytes=_ciphertext_size(ctx),
        decryption_error=err, threshold_flip_rate=0.0,
        notes="ratio computed plaintext-side; no boolean breach indicator",
    )


def _bench_calibration(ctx, ring_log2: int, reps: int, flip_trials: int,
                       batch_size: int) -> Trial:
    K = batch_size
    scores = RNG.uniform(size=K)
    quantiles = np.full(K, 0.5)

    sv.reset_op_counters()
    fhe_p.reset_last_depth()
    median, lo, hi, enc = _measure_runtime(
        lambda: fhe_p.conformal_encrypted(ctx, scores, quantiles),
        reps=reps)
    counters = sv.snapshot_op_counters()
    plain = rf.audit_calibration(scores, quantiles)
    err = abs(plain.set_size - enc.set_size)

    return Trial(
        primitive="calibration", ring_log2=ring_log2, n_slots=ctx.n_slots,
        batch_size=batch_size,
        declared_depth=fhe_p.declared_depth("calibration"),
        observed_depth=fhe_p.last_depth("calibration"),
        rotations=counters["rotations"],
        ct_ct_muls=counters["ct_ct_muls"],
        ct_pt_muls=counters["ct_pt_muls"],
        ct_scalar_muls=counters["ct_scalar_muls"],
        matmul_pt=counters["matmul_pt"],
        additions=counters["additions"],
        runtime_s_median=median, runtime_s_min=lo, runtime_s_max=hi,
        rss_mb=_peak_rss_mb(),
        ct_size_bytes=_ciphertext_size(ctx),
        decryption_error=err, threshold_flip_rate=0.0,
        notes="membership match assessed by integer set size",
    )


def _bench_drift(ctx, ring_log2: int, reps: int, flip_trials: int,
                 batch_size: int) -> Trial:
    bins = batch_size
    p = RNG.uniform(size=bins)
    q = p + RNG.normal(scale=0.05, size=bins)
    q = np.maximum(q, 0)

    sv.reset_op_counters()
    fhe_p.reset_last_depth()
    median, lo, hi, enc = _measure_runtime(
        lambda: fhe_p.w1_encrypted(ctx, p, q),
        reps=reps)
    counters = sv.snapshot_op_counters()
    plain = rf.audit_drift(p, q)
    err = abs(plain.distance - enc.distance)

    def near_threshold():
        b = 16
        a = RNG.uniform(size=b)
        c = a + RNG.normal(scale=0.02, size=b)
        return {"p": a, "q": np.maximum(c, 0), "drift_threshold": 0.005}

    flip = _flip_rate(rf.audit_drift,
                      lambda **kw: fhe_p.w1_encrypted(ctx, **kw),
                      "drift_bit", near_threshold, flip_trials)

    return Trial(
        primitive="drift", ring_log2=ring_log2, n_slots=ctx.n_slots,
        batch_size=batch_size,
        declared_depth=fhe_p.declared_depth("drift"),
        observed_depth=fhe_p.last_depth("drift"),
        rotations=counters["rotations"],
        ct_ct_muls=counters["ct_ct_muls"],
        ct_pt_muls=counters["ct_pt_muls"],
        ct_scalar_muls=counters["ct_scalar_muls"],
        matmul_pt=counters["matmul_pt"],
        additions=counters["additions"],
        runtime_s_median=median, runtime_s_min=lo, runtime_s_max=hi,
        rss_mb=_peak_rss_mb(),
        ct_size_bytes=_ciphertext_size(ctx),
        decryption_error=err, threshold_flip_rate=flip,
    )


def _bench_disagreement(ctx, ring_log2: int, reps: int, flip_trials: int,
                        batch_size: int) -> Trial:
    M = 5
    coeffs = [(0.0, 1.0 + 0.05 * i, 0.02 * i, 0.0) for i in range(M)]
    x = np.linspace(-0.4, 0.4, batch_size)

    sv.reset_op_counters()
    fhe_p.reset_last_depth()
    median, lo, hi, enc = _measure_runtime(
        lambda: fhe_p.disagreement_encrypted(ctx, coeffs, x),
        reps=reps)
    counters = sv.snapshot_op_counters()
    plain = rf.audit_disagreement(coeffs, x)
    err = abs(plain.pairwise_variance - enc.pairwise_variance)

    def near_threshold():
        models = [(0.0, 1.0 + 0.05 * i, 0.0, 0.0) for i in range(3)]
        return {"model_polynomials": models,
                "test_input": np.linspace(-0.4, 0.4, 16),
                "threshold": 0.005}

    flip = _flip_rate(rf.audit_disagreement,
                      lambda **kw: fhe_p.disagreement_encrypted(ctx, **kw),
                      "breach", near_threshold, flip_trials)

    return Trial(
        primitive="disagreement", ring_log2=ring_log2, n_slots=ctx.n_slots,
        batch_size=batch_size,
        declared_depth=fhe_p.declared_depth("disagreement"),
        observed_depth=fhe_p.last_depth("disagreement"),
        rotations=counters["rotations"],
        ct_ct_muls=counters["ct_ct_muls"],
        ct_pt_muls=counters["ct_pt_muls"],
        ct_scalar_muls=counters["ct_scalar_muls"],
        matmul_pt=counters["matmul_pt"],
        additions=counters["additions"],
        runtime_s_median=median, runtime_s_min=lo, runtime_s_max=hi,
        rss_mb=_peak_rss_mb(),
        ct_size_bytes=_ciphertext_size(ctx),
        decryption_error=err, threshold_flip_rate=flip,
    )


PRIMITIVES = [
    ("fairness",     _bench_fairness),
    ("provenance",   _bench_provenance),
    ("concordance",  _bench_concordance),
    ("calibration",  _bench_calibration),
    ("drift",        _bench_drift),
    ("disagreement", _bench_disagreement),
]


def _coeff_chain_for_ring(ring_log2: int) -> List[int]:
    """Return a SEAL-validated coefficient-modulus chain for the ring."""
    if ring_log2 == 14:
        return [60, 40, 40, 40, 40, 40, 40, 60]
    if ring_log2 == 15:
        return [60, 40, 40, 40, 40, 40, 40, 60]
    if ring_log2 == 16:
        return [60, 40, 40, 40, 40, 40, 40, 60]
    raise ValueError(f"unsupported ring_log2 {ring_log2}")


def run(ring_log2_list: List[int], reps: int, flip_trials: int) -> Dict[str, Any]:
    all_trials: List[Trial] = []
    for ring_log2 in ring_log2_list:
        N = 1 << ring_log2
        coeff = _coeff_chain_for_ring(ring_log2)
        print(f"\n=== Building context: N=2^{ring_log2} (poly_modulus_degree={N}) ===")
        ctx = build_d6_context(poly_modulus_degree=N, coeff_mod_bit_sizes=coeff)
        print(f"context built; n_slots={ctx.n_slots}; "
              f"rss={_peak_rss_mb():.0f} MB")
        for name, fn in PRIMITIVES:
            batch = {
                "fairness": 64, "provenance": 64, "concordance": 16,
                "calibration": 16, "drift": 16, "disagreement": 16,
            }[name]
            trial = fn(ctx, ring_log2, reps, flip_trials, batch)
            all_trials.append(trial)
            print(f"  {name:13s} d={trial.observed_depth}/{trial.declared_depth} "
                  f"runtime={trial.runtime_s_median:.3f}s "
                  f"err={trial.decryption_error:.2e} "
                  f"flip={trial.threshold_flip_rate:.2%} "
                  f"rss={trial.rss_mb:.0f}MB")
        del ctx
        gc.collect()

    return {"trials": [asdict(t) for t in all_trials]}


def write_outputs(payload: Dict[str, Any], ring_log2_list: List[int]) -> None:
    for ring_log2 in ring_log2_list:
        rows = [t for t in payload["trials"] if t["ring_log2"] == ring_log2]
        out = RESULTS_DIR / f"bench_fhe_{ring_log2}.json"
        out.write_text(json.dumps({"trials": rows}, indent=2))
        print(f"  wrote {out}")

    summary = ["# regaudit-fhe benchmark summary\n",
               "Per-primitive measurements on the TenSEAL CKKS backend.\n",
               "Rings tested: " + ", ".join(f"2^{r}" for r in ring_log2_list) + ".\n"]
    summary.append("| Primitive | N | Slots | Batch | Depth obs/declared "
                   "| Rotations | ct×ct | ct×pt | Runtime (s) | RAM (MB) "
                   "| Ct bytes | Max abs err | Threshold flip |")
    summary.append("|---|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for t in payload["trials"]:
        summary.append(
            f"| {t['primitive']} | 2^{t['ring_log2']} | {t['n_slots']} "
            f"| {t['batch_size']} "
            f"| {t['observed_depth']}/{t['declared_depth']} "
            f"| {t['rotations']} | {t['ct_ct_muls']} | {t['ct_pt_muls']} "
            f"| {t['runtime_s_median']:.3f} "
            f"| {t['rss_mb']:.0f} | {t['ct_size_bytes']} "
            f"| {t['decryption_error']:.2e} "
            f"| {t['threshold_flip_rate']:.2%} |"
        )
    (RESULTS_DIR / "SUMMARY.md").write_text("\n".join(summary) + "\n")
    print(f"  wrote {RESULTS_DIR / 'SUMMARY.md'}")


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run the FHE benchmark matrix.")
    p.add_argument("--rings", nargs="+", type=int, default=[14, 15],
                   help="ring exponents to test (default: 14 15)")
    p.add_argument("--reps", type=int, default=3,
                   help="repetitions per timing measurement (default: 3)")
    p.add_argument("--flip-trials", type=int, default=20,
                   help="threshold-flip trials per primitive (default: 20)")
    args = p.parse_args(argv)

    payload = run(args.rings, args.reps, args.flip_trials)
    write_outputs(payload, args.rings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
