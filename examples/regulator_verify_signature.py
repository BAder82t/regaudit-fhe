"""Example: a regulator-side check of three submitted reports, with an explicit trust policy.

Needs only the base install (``pip install regaudit-fhe``), runs offline and writes nothing to disk::

    python examples/regulator_verify_signature.py

The regulator builds its own trust store (the keys it approved out of band) and a
``VerificationPolicy`` around it, then runs ``rf.verify_report`` on three submissions:

(a) a report signed by an enrolled issuer          -> TRUSTED
(b) a self-signed report from a stranger's key     -> INVALID (the key is not enrolled)
(c) the enrolled issuer's report, edited afterwards -> INVALID (the signature no longer matches)

What the outcomes mean: ``TRUSTED`` says an enrolled key signed these exact bytes and the
policy rules were met. It does not say the audit is correct, that anything ran encrypted, that
privacy holds, or that any legal requirement is met. A signed report can authenticate a claim
without proving that claim is true. Encrypted execution not established. The reports here are
made on synthetic data and declare the default plaintext backend, which is a declaration and
not an observation.

It exits 0 if every outcome is the expected one, and 1 otherwise.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import numpy as np

import regaudit_fhe as rf
from regaudit_fhe import claim_labels

ISSUER, KEY_ID, VERIFIER = "example-vendor.example", "vendor-2026-q2", "regulator-a"


@dataclass(frozen=True)
class Outcome:
    label: str
    trust_status: str
    accepted: bool
    blocking_reasons: tuple[str, ...]


def make_report_text(signer: rf.Signer) -> str:
    """Audit synthetic data on the plaintext path and sign it as a ``report.v2`` document."""
    rng = np.random.default_rng(7)
    n = 32
    y_true = (rng.uniform(size=n) < 0.4).astype(float)
    y_pred = (rng.uniform(size=n) < 0.4).astype(float)
    group_a = (rng.uniform(size=n) < 0.5).astype(float)
    report = rf.audit_fairness(y_true, y_pred, group_a, 1.0 - group_a, threshold=0.1)
    return rf.envelope_v2(
        "fairness", report, signer=signer, deployment_id="prod-eu-1", audience=[VERIFIER]
    ).to_json()


def build_policy(enrolled: rf.Signer) -> rf.VerificationPolicy:
    """The regulator's explicit policy: only the key it enrolled out of band is trusted."""
    store = rf.TrustStore.from_dict(
        {
            "entries": {
                KEY_ID: {
                    "issuer": ISSUER,
                    "public_key_pem": enrolled.public_key_pem(),
                    "status": "active",
                }
            }
        }
    )
    return rf.VerificationPolicy(trust_store=store, verifier_id=VERIFIER)


def check(label: str, text: str, policy: rf.VerificationPolicy) -> Outcome:
    """Receive a submission as text and decide it against the policy."""
    res = rf.verify_report(rf.parse_envelope(text), policy)
    return Outcome(label, res.trust_status, res.accepted, tuple(res.blocking_reasons))


def run_scenarios() -> list[Outcome]:
    vendor = rf.Signer.generate(issuer=ISSUER, key_id=KEY_ID)
    stranger = rf.Signer.generate(
        issuer=ISSUER, key_id="stranger-key"
    )  # claims the same issuer name
    policy = build_policy(vendor)

    good = make_report_text(vendor)
    forged = make_report_text(stranger)
    edited = json.loads(good)
    edited["result"]["demographic_parity_diff"] += 0.5  # e.g. hide a disparity

    return [
        check("(a) enrolled issuer", good, policy),
        check("(b) stranger, self-signed", forged, policy),
        check("(c) enrolled issuer, edited after signing", json.dumps(edited), policy),
    ]


def main() -> int:
    print("regaudit-fhe: regulator verification example (synthetic data, plaintext path)\n")
    print(f"[Regulator] trust store: one enrolled key, {KEY_ID!r}, issuer {ISSUER!r}")
    print(
        f"[Regulator] policy: development profile, trust store required, verifier_id {VERIFIER!r}\n"
    )
    outcomes = run_scenarios()
    for o in outcomes:
        print(f"{o.label}")
        print(
            f"    trust_status: {o.trust_status}   accepted: {o.accepted}   blocking_reasons: {list(o.blocking_reasons)}"
        )
    expected = ["TRUSTED", "INVALID", "INVALID"]
    ok = [o.trust_status for o in outcomes] == expected and [o.accepted for o in outcomes] == [
        True,
        False,
        False,
    ]
    # The stranger and the edited report fail for different reasons; keep them apart.
    ok = ok and outcomes[1].blocking_reasons != outcomes[2].blocking_reasons

    print("\nWhat this shows")
    print(
        "  - TRUSTED: a key in the regulator's own trust store signed these exact bytes, and the policy's rules were met."
    )
    print(
        "  - INVALID for (b): the signature is internally consistent, but the key was never enrolled. A report cannot enrol itself."
    )
    print(
        "  - INVALID for (c): the content changed after signing, so the signature no longer matches."
    )
    print("\nWhat this does not show")
    print(f"  - {claim_labels.NOT_ESTABLISHED}")
    print(f"  - {claim_labels.INVARIANT}")
    print(
        "  - These reports declare a plaintext backend (the default). That is a declaration, not an observation,"
    )
    print("    and a signature shows who signed, not what was computed.")
    print(
        "  - It does not show that the audit is correct, that anything ran encrypted, that privacy holds,"
    )
    print("    or that any law or regulation is met.")
    print(
        "\n"
        + (
            "OK: all three outcomes were as expected."
            if ok
            else "FAILED: an outcome was not as expected."
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
