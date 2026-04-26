"""Example — Ed25519-signed envelope: build, archive, tamper-test.

Walks through the signing surface that lets a regulator decide three
questions in constant time:

    1. Who issued the envelope?         (issuer + key_id + public_key_pem)
    2. Has it been modified?            (sha256 over canonical body)
    3. Are the inputs as claimed?       (input_commitments)

Run::

    python examples/signed_envelope.py
"""

from __future__ import annotations

import json

import numpy as np

import regaudit_fhe as rf


def main() -> int:
    print("regaudit-fhe — signed envelope example\n")

    rng = np.random.default_rng(42)
    n = 64
    inputs = {
        "y_true":  (rng.uniform(size=n) < 0.4).astype(float),
        "y_pred":  (rng.uniform(size=n) < 0.4).astype(float),
        "group_a": (rng.uniform(size=n) < 0.5).astype(float),
    }
    inputs["group_b"] = 1.0 - inputs["group_a"]

    print("[1/4] Generating Ed25519 issuing key...")
    signer = rf.Signer.generate(issuer="example-vendor.com",
                                 key_id="example-2026-q2")
    print(f"      key_id: {signer.key_id}")
    print(f"      public PEM (first line): "
          f"{signer.public_key_pem().splitlines()[1]}\n")

    print("[2/4] Running audit and binding to a parameter set + commitments...")
    report = rf.audit_fairness(**inputs)
    params = rf.ParameterSet(backend="tenseal-ckks",
                             poly_modulus_degree=32768,
                             multiplicative_depth=6,
                             coeff_mod_bit_sizes=(60, 40, 40, 40, 40, 40, 40, 60),
                             scaling_factor_bits=40,
                             backend_version="0.3.16")
    env = rf.envelope("fairness", report,
                      parameter_set=params,
                      signer=signer,
                      input_commitments=rf.commitments_for(inputs))

    body = env.to_dict()
    print(f"      schema:             {body['schema']}")
    print(f"      algorithm_version:  {body['algorithm_version']}")
    print(f"      backend:            {body['backend']}")
    print(f"      parameter_set_hash: {body['parameter_set_hash'][:16]}...")
    print(f"      receipt.sha256:     {body['receipt']['sha256'][:16]}...")
    print(f"      receipt.alg:        {body['receipt']['signature_alg']}")
    print(f"      input_commitments:  {len(body['input_commitments'])}\n")

    print("[3/4] Verifying the freshly built envelope...")
    outcome = rf.verify_envelope(env)
    print(f"      valid:            {outcome.valid}")
    print(f"      sha256_valid:     {outcome.sha256_valid}")
    print(f"      signature_valid:  {outcome.signature_valid}")
    print(f"      issuer_trusted:   {outcome.issuer_trusted}\n")
    assert outcome.valid

    print("[4/4] Tampering with the result and re-verifying...")
    env.result["demographic_parity_diff"] = 999.0
    bad = rf.verify_envelope(env)
    print(f"      after tamper — valid: {bad.valid}")
    print(f"                     sha256_valid:    {bad.sha256_valid}")
    print(f"                     signature_valid: {bad.signature_valid}")
    assert bad.valid is False
    print("\nOK — fresh envelope verified, tampered envelope rejected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
