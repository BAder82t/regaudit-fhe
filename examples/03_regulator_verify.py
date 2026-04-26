"""Example 03 — Regulator-side verification of an audit submission.

Scenario: the regulator receives a JSON bundle from the client (see
example 02), iterates each envelope, recomputes its receipt, and rejects
any envelope whose receipt fails verification.

Run:  python examples/03_regulator_verify.py regulator_submission.json
"""

from __future__ import annotations

import json
import sys

import regaudit_fhe as rf


def main(path: str) -> int:
    bundle = json.loads(open(path).read())
    failures = 0
    for raw in bundle["envelopes"]:
        env = rf.AuditEnvelope.from_dict(raw)
        ok = rf.verify_receipt(env)
        flag = "OK   " if ok else "FAIL "
        print(f"{flag} {env.primitive:13s}  issued_at={env.issued_at}  "
              f"regs={','.join(env.regulations)}")
        if not ok:
            failures += 1
    if failures:
        print(f"\nREJECT: {failures} envelope(s) failed receipt verification.")
        return 1
    print("\nACCEPT: all envelopes verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "regulator_submission.json"))
