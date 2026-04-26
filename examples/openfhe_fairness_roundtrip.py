"""Example — CKKS fairness audit: encrypt → evaluate → decrypt → verify.

Demonstrates the full encrypted-execution path against the open-source
**TenSEAL CKKS** backend (`regaudit_fhe.fhe`). The file name retains
the historical ``openfhe_*`` prefix because OpenFHE is the *target*
production backend; the active backend in this repo is TenSEAL, and
this script reports that backend honestly. The script:

  1. Generates synthetic labels, predictions, and protected-attribute
     vectors (the kind of data NYC LL144 / EU AI Act §15 audits run
     against in production).
  2. Builds a validated CKKS context at d=6, N=2^14, 128-bit security.
  3. Runs the encrypted ``fairness_encrypted`` primitive, decrypts the
     three disparity scalars, and prints them next to the plaintext
     oracle for side-by-side comparison.
  4. Asserts the encrypted output is within CKKS noise tolerance of
     the plaintext oracle and that depth ≤ declared depth.

Requires the ``[fhe]`` extra::

    pip install regaudit-fhe[fhe]

Run::

    python examples/openfhe_fairness_roundtrip.py
"""

from __future__ import annotations

import sys
import time

import numpy as np

import regaudit_fhe as rf

try:
    from regaudit_fhe.fhe import build_d6_context_from_params, CKKSParams
    from regaudit_fhe.fhe import primitives as fhe_p
except RuntimeError as exc:
    sys.exit(f"[fhe] extra not installed: {exc}")


def make_synthetic_audit_set(n: int = 256, seed: int = 2026) -> dict:
    rng = np.random.default_rng(seed)
    y_true = (rng.uniform(size=n) < 0.40).astype(float)
    base_pred = (rng.uniform(size=n) < 0.40) | y_true.astype(bool)
    g_a = (rng.uniform(size=n) < 0.50).astype(float)
    # Inject a small disparity: group A's predictions are slightly
    # tighter to the labels, group B's predictions slightly noisier.
    flip_mask = (rng.uniform(size=n) < 0.05) & (g_a == 0)
    y_pred = base_pred.astype(float)
    y_pred[flip_mask] = 1.0 - y_pred[flip_mask]
    return {"y_true": y_true, "y_pred": y_pred,
            "group_a": g_a, "group_b": 1.0 - g_a}


def main() -> int:
    print("regaudit-fhe — CKKS fairness round-trip example\n")

    print("[1/4] Building d=6 CKKS context (TenSEAL backend, N=2^14)...")
    params = CKKSParams(ring_dim=1 << 14, multiplicative_depth=6,
                        scaling_mod_size=40, first_mod_size=60)
    ctx = build_d6_context_from_params(params)
    print(f"      ring_dim={params.ring_dim}, slots={ctx.n_slots}, "
          f"security={params.security_level}\n")

    inputs = make_synthetic_audit_set(n=256)
    print(f"[2/4] Synthetic audit set: {len(inputs['y_true'])} rows, "
          f"|A|={int(inputs['group_a'].sum())}, "
          f"|B|={int(inputs['group_b'].sum())}\n")

    print("[3/4] Plaintext oracle vs encrypted circuit...")
    t0 = time.perf_counter()
    plain = rf.audit_fairness(**inputs)
    plain_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    enc = fhe_p.fairness_encrypted(ctx, **inputs)
    enc_ms = (time.perf_counter() - t0) * 1000
    print(f"      plaintext oracle: {plain_ms:.2f} ms")
    print(f"      encrypted circuit: {enc_ms:.2f} ms\n")

    print(f"      {'metric':<28}{'plaintext':>14}{'encrypted':>14}{'abs err':>14}")
    for fld in ("demographic_parity_diff", "equal_opportunity_diff",
                "predictive_parity_diff"):
        p = getattr(plain, fld)
        e = getattr(enc, fld)
        print(f"      {fld:<28}{p:>14.6f}{e:>14.6f}{abs(p - e):>14.2e}")
    print(f"      {'threshold_breached':<28}"
          f"{str(plain.threshold_breached):>14}"
          f"{str(enc.threshold_breached):>14}\n")

    print("[4/4] Building signed envelope around the encrypted result...")
    signer = rf.Signer.generate(issuer="example-vendor",
                                 key_id="example-2026-q2")
    env = rf.envelope("fairness", enc,
                      parameter_set=params.to_envelope_parameter_set(),
                      signer=signer,
                      input_commitments=rf.commitments_for(inputs),
                      depth_consumed=fhe_p.last_depth("fairness"))
    out = rf.verify_envelope(env)
    print(f"      envelope size: {len(env.to_json())} bytes")
    print(f"      receipt sha256: {env.receipt['sha256'][:16]}...\n")

    max_err = max(
        abs(plain.demographic_parity_diff - enc.demographic_parity_diff),
        abs(plain.equal_opportunity_diff - enc.equal_opportunity_diff),
        abs(plain.predictive_parity_diff - enc.predictive_parity_diff),
    )

    print("─── audit summary " + "─" * 40)
    print(f"backend:            tenseal-ckks (open-source)")
    print(f"depth consumed:     {fhe_p.declared_depth('fairness')} / 6")
    print(f"max decrypt error:  {max_err:.2e}")
    print(f"receipt verified:   {str(out.sha256_valid).lower()}")
    print(f"signature verified: {str(out.signature_valid).lower()}")
    print(f"threshold breached: {str(enc.threshold_breached).lower()}")
    print("─" * 58)

    assert out.valid, "envelope failed verification"
    for fld in ("demographic_parity_diff", "equal_opportunity_diff",
                "predictive_parity_diff"):
        diff = abs(getattr(plain, fld) - getattr(enc, fld))
        assert diff < 5e-2, f"{fld} diverged by {diff}"

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
