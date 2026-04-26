"""Example — regulator-side envelope verification with a trusted-keys store.

Mirrors what a regulator portal does when ingesting a signed audit
submission from a regulated AI vendor:

  1. Pin the vendor's public key by ``key_id``.
  2. Receive the JSON envelope.
  3. Verify the SHA-256 receipt is consistent with the canonical body.
  4. Verify the Ed25519 signature is valid for the embedded public key.
  5. Confirm the embedded public key matches the pinned one — i.e.
     the issuer is on the trusted list.
  6. Reject envelopes that fail ANY of (3)–(5) or whose
     ``parameter_set_hash`` does not match the regulator's pinned set.

Run::

    python examples/regulator_verify_signature.py
"""

from __future__ import annotations

import json

import numpy as np

import regaudit_fhe as rf


def issue_one(signer: rf.Signer, params: rf.ParameterSet) -> rf.AuditEnvelope:
    rng = np.random.default_rng(7)
    n = 32
    y_true = (rng.uniform(size=n) < 0.4).astype(float)
    y_pred = (rng.uniform(size=n) < 0.4).astype(float)
    g_a = (rng.uniform(size=n) < 0.5).astype(float)
    inputs = {"y_true": y_true, "y_pred": y_pred,
              "group_a": g_a, "group_b": 1.0 - g_a}
    return rf.envelope("fairness", rf.audit_fairness(**inputs),
                       parameter_set=params,
                       signer=signer,
                       input_commitments=rf.commitments_for(inputs))


def main() -> int:
    print("regaudit-fhe — regulator verification example\n")

    # ---- Issuer side --------------------------------------------------
    print("[Vendor] generating Ed25519 signing key + issuing envelope...")
    signer = rf.Signer.generate(issuer="example-vendor.com",
                                 key_id="vendor-2026-q2")
    pinned_params = rf.ParameterSet(backend="tenseal-ckks",
                                    poly_modulus_degree=32768,
                                    multiplicative_depth=6,
                                    coeff_mod_bit_sizes=(60, 40, 40, 40, 40, 40, 40, 60),
                                    scaling_factor_bits=40,
                                    backend_version="0.3.16")
    env = issue_one(signer, pinned_params)
    print(f"         issued envelope key_id={env.receipt['key_id']} "
          f"sha256={env.receipt['sha256'][:12]}...\n")

    # ---- Regulator side -----------------------------------------------
    print("[Regulator] receiving envelope JSON...")
    envelope_json = env.to_json()
    parsed = rf.AuditEnvelope.from_dict(json.loads(envelope_json))
    print(f"            primitive={parsed.primitive} "
          f"issued_at={parsed.issued_at}")

    print("[Regulator] checking schema, parameter-set hash, "
          "and signature against trusted-keys store...")
    trusted_keys = {"vendor-2026-q2": signer.public_key_pem()}
    accepted_param_hashes = {pinned_params.hash()}

    rf.validate_envelope(parsed.to_dict())
    out = rf.verify_envelope(parsed, trusted_keys=trusted_keys)
    param_ok = parsed.parameter_set_hash in accepted_param_hashes

    print(f"            schema_valid:       True")
    print(f"            sha256_valid:       {out.sha256_valid}")
    print(f"            signature_valid:    {out.signature_valid}")
    print(f"            issuer_trusted:     {out.issuer_trusted}")
    print(f"            parameter_set_ok:   {param_ok}")
    print(f"            timestamp_valid:    {out.timestamp_valid}\n")

    if out.valid and param_ok:
        print("[Regulator] ACCEPT — envelope passes every binding check.\n")
    else:
        print("[Regulator] REJECT — envelope failed verification.\n")
        return 1

    # ---- Tamper test ---------------------------------------------------
    print("[Regulator] adversarial test: malicious actor swaps the signing key...")
    impostor = rf.Signer.generate(issuer="example-vendor.com",
                                   key_id="vendor-2026-q2")
    parsed.receipt["public_key_pem"] = impostor.public_key_pem()
    bad = rf.verify_envelope(parsed, trusted_keys=trusted_keys)
    print(f"            valid: {bad.valid} "
          f"signature_valid: {bad.signature_valid} "
          f"issuer_trusted: {bad.issuer_trusted}\n")
    assert bad.valid is False
    print("            REJECT — embedded public key does not match "
          "the trusted-keys store entry for vendor-2026-q2.")

    print("\nOK — regulator-side verification works end-to-end with "
          "trusted-keys pinning + parameter-set pinning + tamper detection.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
