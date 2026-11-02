"""The opt-in versioned verification response.

The default response is unchanged and says nothing about revocation. An existing client may parse it strictly, so no
field was added to it. A client that asks for this format gets an explicit ``revocation_evaluation``:

* ``not_evaluated``: no usable revocation data was consulted for this result. Nothing is known about revocation;
* ``evaluated``: fresh signed revocation data was consulted. "Verified as of" is the most it can say, and the report
  may still be refused because of what it said;
* ``required_but_unavailable``: revocation was required and could not be established. Never trusted.

``TRUSTED`` keeps its meaning: signed by a key in the verifier's trust store, under its policy. None of these values
strengthens it, and no shipped path satisfies a revocation-aware high-assurance profile, which is unavailable.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from typing import Any

RESPONSE_FORMAT_V2 = "regaudit-fhe.verification-response.v2"
NOT_EVALUATED = "not_evaluated"
EVALUATED = "evaluated"
REQUIRED_BUT_UNAVAILABLE = "required_but_unavailable"

NOT_EVALUATED_NOTE = (
    "Revocation was not evaluated. Nothing is known here about whether this issuer has revoked this key, and this "
    "result does not satisfy any revocation-aware profile."
)
GOVERNANCE_NOTE = (
    "The enrolled pin and recovery anchor are the root and the list signer is a delegate. There is no independent "
    "approver and no quorum in this profile."
)


def revocation_evaluation(disclosure: dict[str, Any] | None) -> str:
    """The value for one verification. ``disclosure`` is the gate's, or ``None`` when no gate ran."""
    if disclosure is None:
        return NOT_EVALUATED
    gate = disclosure.get("gate")
    if gate == "ok":
        return EVALUATED
    if gate != "not-applicable" and disclosure.get("mode") == "required":
        return REQUIRED_BUT_UNAVAILABLE
    return NOT_EVALUATED


def policy_evidence(disclosure: dict[str, Any] | None) -> dict[str, Any]:
    """The versioned section: the value, what the gate disclosed, and the governance limit."""
    value = revocation_evaluation(disclosure)
    section: dict[str, Any] = {"revocation_evaluation": value}
    if disclosure is None:
        section.update(mode="off", note=NOT_EVALUATED_NOTE)
    else:
        section.update(disclosure)
        section.setdefault("revocation_evidence", "unproven")
    section["satisfies_revocation_aware_high_assurance"] = False
    return {
        "policy_evidence_version": 1,
        "revocation": section,
        "governance": {
            "authority_model": "pin-and-recovery-anchor-root-with-delegate-signer",
            "independent_approver": False,
            "quorum": False,
            "note": GOVERNANCE_NOTE,
        },
    }


def issuer_binding(result: dict[str, Any]) -> str:
    """What the report's issuer name was compared with. No value here means an authenticated enrollment: none exists."""
    if "ISSUER_UNBOUND" in result["reasons"]:
        return "not_bound"  # the store states no issuer, so the name in the report is only a claim
    if not result["issuer_trusted"]:
        return "not_established"
    return "operator_declared" if "ISSUER_OPERATOR_DECLARED" in result["reasons"] else "store_entry"


def response_v2(result: dict[str, Any], disclosure: dict[str, Any] | None) -> dict[str, Any]:
    """``result`` is ``VerificationResult.to_dict()``. Its fields are kept exactly and these are added."""
    value = revocation_evaluation(disclosure)
    if value == REQUIRED_BUT_UNAVAILABLE and (
        result["accepted"] or result["valid"] or result["trust_status"] == "TRUSTED"
    ):
        raise RuntimeError("required_but_unavailable can never be represented as trusted")
    return {
        **result,
        "response_format": RESPONSE_FORMAT_V2,
        "revocation_evaluation": value,
        "issuer_binding": issuer_binding(result),
        "policy_evidence": policy_evidence(disclosure),
    }
