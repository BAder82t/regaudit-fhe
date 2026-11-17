"""Five separate statements that explain a verification result: signature, issuer trust, freshness, repeat check and
encryption claims.

Nothing here decides anything or changes a value. Each statement is derived only from what the engine returned for the
report (its result and its reason codes), from the policy the portal gave the engine, and, for the encryption claims,
from the signer's own declaration as ``explain.declarations`` reads it. Where the engine returned nothing that settles a
statement, the statement says "not checked" and why, and never guesses. The verdict stays ``verification.trust_status``:
these statements explain it and are not further verdicts.

The sentences are fixed text. The only report content that can appear is the one value ``explain.declarations`` already
neutralises for the encryption claims, and the signing time, which is passed through ``explain.printable``.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from regaudit_fhe.verification import (
    CONSUMPTION_CHECKED,
    CONSUMPTION_RECORDED_LOCAL,
    DEFAULT_RETENTION,
    VerificationPolicy,
)

from .explain import (
    _LIFECYCLE_BLOCKS,
    _REASONS,
    _WITHDRAWN,
    DEMONSTRATION_LABEL,
    FHE_NOTICE,
    NOT_A_CLAIM,
    REPLAY_LOCAL_ONLY_TEXT,
    _about_the_demonstration,
    _issuer_line,
    _signature_failed,
    _signature_line,
    printable,
)

SCHEMA = "regaudit-portal-statuses/1"

NOTE = (
    "These statements explain the verdict in verification.trust_status. They are not additional verdicts. "
    "This is not a regulatory certification and not proof of encrypted computation."
)

# What each statement can never mean. Fixed, and shown beside the statement.
_SIGNATURE_LIMIT = (
    "A matching signature shows the contents have not changed since they were signed with that key. It does not "
    "show who holds the key."
)
_ISSUER_LIMIT = (
    "This is a match against your administrator's list of keys. It is not an independent check of who the issuer is, "
    "and a valid signature alone does not make an issuer trusted."
)
_TIME_LIMIT = _REASONS["CHRONOLOGY_UNAUTHENTICATED"]
_TRUST_LIST_LIMIT = "Nothing proves your administrator's trust list is up to date. A key withdrawn elsewhere may not be marked in it."
_REPLAY_LIMIT = REPLAY_LOCAL_ONLY_TEXT


@dataclass(frozen=True)
class PolicyFacts:
    """The parts of the policy the portal gave the engine that the freshness and repeat statements speak of."""

    profile: str
    max_age: timedelta | None
    clock_skew: timedelta
    replay_mode: str  # the engine's own: "off", "check" or "record"

    @classmethod
    def of(cls, policy: VerificationPolicy) -> PolicyFacts:
        # The engine's rule: an explicit maximum age, else the replay retention when repeats are checked, else none.
        max_age = policy.max_age
        if max_age is None and policy.replay_mode != "off":
            max_age = DEFAULT_RETENTION
        return cls(policy.profile, max_age, policy.clock_skew, policy.replay_mode)


def _span(value: timedelta) -> str:
    seconds = int(value.total_seconds())
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size and seconds % size == 0:
            count = seconds // size
            return f"{count} {unit}{'' if count == 1 else 's'}"
    return f"{seconds} second{'' if seconds == 1 else 's'}"


def _status(
    state: str, text: str, limit: str | None, derived_from: list[str], **details: Any
) -> dict[str, Any]:
    return {
        "state": state,
        "text": text,
        "limit": limit,
        "derived_from": derived_from,
        "details": details,
    }


def _signature(result: dict[str, Any]) -> dict[str, Any]:
    sources = ["integrity_valid", "blocking_reasons"]
    if result["integrity_valid"] is True:
        state = "passed"
    elif _signature_failed(result):
        state = "failed"
    else:
        # Either no enrolled key existed to check with (ISSUER_UNKNOWN) or the engine did not settle it.
        state = "not_checked"
    text = _signature_line(result)
    if state == "not_checked" and text == "Not confirmed.":
        text = (
            "Not checked: the verifier did not establish whether the contents match the signature."
        )
    return _status(
        state, text, _SIGNATURE_LIMIT, sources, integrity_valid=result["integrity_valid"]
    )


def _issuer(result: dict[str, Any]) -> dict[str, Any]:
    sources = ["issuer_trusted", "key_status", "blocking_reasons"]
    blocking = set(result["blocking_reasons"])
    if result["issuer_trusted"] is True:
        withdrawn = result["key_status"] in _WITHDRAWN
        if "KEY_NOT_YET_VALID" in blocking or (withdrawn and blocking & _LIFECYCLE_BLOCKS):
            state = "not_established"
        elif withdrawn:
            state = "established_with_limit"
        elif result["key_status"] == "active":
            state = "established"
        else:
            state = "not_established"
    else:
        state = "not_established"
    return _status(
        state,
        _issuer_line(result),
        _ISSUER_LIMIT,
        sources,
        issuer_trusted=result["issuer_trusted"],
        key_status=result["key_status"],
    )


def _freshness(result: dict[str, Any], facts: PolicyFacts) -> dict[str, Any]:
    sources = ["blocking_reasons", "reasons", "chronology", "issued_at", "trust_history"]
    blocking = set(result["blocking_reasons"])
    stated = printable(result.get("issued_at", ""))
    if result["chronology"] == "AUTHENTICATED":
        time_source = "authenticated"
    elif result["chronology"] == "SIGNER_ASSERTED":
        time_source = "signer_stated"
    else:
        # The engine withholds chronology for a report whose issuer it could not tie to the trust list.
        time_source = "not_established"
    skew = _span(facts.clock_skew)
    if facts.max_age is None:
        state = "not_checked"
        text = "Not checked: this policy sets no maximum age, so the age of the report was not compared with anything."
    elif "MALFORMED_ENVELOPE" in blocking:
        state = "not_checked"
        text = "Not checked: the report's signing time could not be read, so its age could not be compared."
    elif "REPORT_FROM_FUTURE" in blocking:
        state = "from_future"
        text = (
            f"Failed: the report states it was issued in the future, beyond the {skew} of clock difference this "
            "policy allows."
        )
    elif "REPORT_TOO_OLD" in blocking:
        state = "too_old"
        text = f"Failed: the report states it was issued more than the maximum age of {_span(facts.max_age)} ago."
    else:
        state = "within_limit"
        text = (
            f"Passed: the signing time the report states is within the maximum age of {_span(facts.max_age)}, "
            f"allowing {skew} of clock difference."
        )
    trust_list = None
    if result["trust_history"] != "FRESH":
        trust_list = {"state": result["trust_history"], "text": _TRUST_LIST_LIMIT}
    return _status(
        state,
        text,
        _TIME_LIMIT,
        sources,
        profile=facts.profile,
        max_age_seconds=int(facts.max_age.total_seconds()) if facts.max_age is not None else None,
        clock_skew_seconds=int(facts.clock_skew.total_seconds()),
        issued_at_as_stated=stated,
        time_source=time_source,
        trust_list=trust_list,
    )


def _replay(result: dict[str, Any], facts: PolicyFacts) -> dict[str, Any]:
    sources = ["consumption", "reasons", "blocking_reasons", "replay_scope", "replay_durable"]
    blocking, reasons = set(result["blocking_reasons"]), set(result["reasons"])
    consumption = result["consumption"]
    if "REPLAY_DETECTED" in blocking:
        state = "repeat_detected"
        text = "This report has already been recorded here, so it was refused as a repeat."
    elif "REPLAY_STATE_UNAVAILABLE" in reasons:
        state = "state_unavailable"
        text = "Not checked: the record of seen reports could not be used, so no decision could safely be made."
    elif consumption == CONSUMPTION_RECORDED_LOCAL:
        state = "recorded"
        text = "Recorded: this check added the report to this portal's record, so the same report is refused here from now on."
    elif consumption == CONSUMPTION_CHECKED:
        state = "checked_not_seen"
        text = (
            "Checked: the report was not in this portal's record. This check did not record it, so the same report "
            "would pass here again."
        )
    elif "REPLAY_ID_MISSING" in reasons:
        state = "not_checked"
        text = "Not checked: the report has no run identifier, so a repeat could not be detected."
    elif facts.replay_mode == "off":
        state = "not_checked"
        text = "Not checked: this policy keeps no record of seen reports."
    elif blocking:
        state = "not_checked"
        text = (
            "Not checked: a repeat is looked for last, and only for a report that nothing else has refused, so "
            "this report was not looked up in the record."
        )
    else:
        state = "not_checked"
        text = "Not checked: the verifier did not report a repeat check."
    return _status(
        state,
        text,
        _REPLAY_LIMIT,
        sources,
        replay_mode=facts.replay_mode,
        consumption=consumption,
        replay_scope=result["replay_scope"],
        durable=result["replay_durable"],
    )


def _encryption(declared: dict[str, Any]) -> dict[str, Any]:
    state = {
        "PLAINTEXT": "plaintext_stated",
        "ENCRYPTED_BACKEND_DECLARED": "declared_by_signer",
        "UNRECOGNIZED_BACKEND": "declared_by_signer",
    }.get(declared["kind"], "not_stated")
    return _status(
        state,
        declared["statement"],
        FHE_NOTICE,
        [
            "parameter_set.backend (as stated in the report)",
            "parameter_set.security_bits (as stated)",
        ],
        kind=declared["kind"],
        backend=declared["backend"],
        backend_shortened=declared["backend_shortened"],
        security_bits_text=declared["security_bits_text"],
        encryption_verified=False,
        note=declared["note"],
    )


def build(
    result: dict[str, Any],
    declared: dict[str, Any],
    policy: VerificationPolicy,
    *,
    trust_mode: str,
    demonstration: bool,
) -> dict[str, Any]:
    """The five statements for one result. ``result`` is the engine's own, ``declared`` is ``explain.declarations``."""
    facts = PolicyFacts.of(policy)
    made = {
        "signature": _signature(result),
        "issuer_trust": _issuer(result),
        "freshness": _freshness(result, facts),
        "replay": _replay(result, facts),
        "encryption_claims": _encryption(declared),
    }
    for entry in made.values():
        if demonstration:
            for name in ("text", "limit"):
                entry[name] = _about_the_demonstration(entry[name])
            trust_list = entry["details"].get("trust_list")
            if trust_list is not None:
                trust_list["text"] = _about_the_demonstration(trust_list["text"])
        # On every statement, so a statement that is copied out alone still says what kind of trust it came from.
        entry["trust_mode"] = trust_mode
        if demonstration:
            entry["demonstration_label"] = DEMONSTRATION_LABEL
    return {
        "schema": SCHEMA,
        "trust_mode": trust_mode,
        **({"demonstration_label": DEMONSTRATION_LABEL} if demonstration else {}),
        "verdict": result["trust_status"],
        "note": NOTE,
        "not_a_claim": NOT_A_CLAIM,
        "fhe_notice": FHE_NOTICE,
        **made,
    }
