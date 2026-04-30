"""Example 03 — Regulator-side verification of an audit submission.

Scenario: the regulator receives a JSON bundle from the client (see
example 02), iterates each envelope, and rejects any envelope whose
receipt fails verification against the regulator's trust store.

The regulator MUST authenticate the issuer; the bare
``verify_receipt(env)`` path only checks the embedded signature
against the embedded public key, which proves only that the bytes have
not changed in transit. To prove the envelope was produced by an
auditor the regulator approved, load a :class:`TrustStore` from a JSON
file mapping ``key_id`` to PEM-encoded public key and pass it to
:func:`verify_envelope_or_raise` — failures raise a typed exception
that names the specific reason (untrusted issuer, revoked issuer,
parameter-set mismatch, hash mismatch, bad signature).

Run:

    python examples/03_regulator_verify.py \\
        --bundle regulator_submission.json \\
        --trust-store trust_store.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import regaudit_fhe as rf


def main(bundle_path: str, trust_store_path: str) -> int:
    trust_store = rf.TrustStore.from_json(trust_store_path)
    bundle = json.loads(Path(bundle_path).read_text())
    failures = 0
    for raw in bundle["envelopes"]:
        env = rf.AuditEnvelope.from_dict(raw)
        try:
            rf.verify_envelope_or_raise(env, trust_store=trust_store)
            flag, detail = "OK   ", ""
        except rf.EnvelopeVerificationError as exc:
            failures += 1
            flag = "FAIL "
            detail = f"  reason={type(exc).__name__}: {exc}"
        print(f"{flag} {env.primitive:13s}  issued_at={env.issued_at}  "
              f"regs={','.join(env.regulations)}{detail}")
    if failures:
        print(f"\nREJECT: {failures} envelope(s) failed verification.")
        return 1
    print("\nACCEPT: all envelopes verified against the trust store.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--bundle", "-b", default="regulator_submission.json",
                        help="Audit bundle JSON to verify (from example 02).")
    parser.add_argument("--trust-store", "-t", required=True,
                        help="Trust-store JSON: key_id -> PEM, optional "
                             "'revoked' list and 'parameter_set_pins'.")
    args = parser.parse_args()
    raise SystemExit(main(args.bundle, args.trust_store))
