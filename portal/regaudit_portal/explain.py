"""Plain words for what the verifier returned. Nothing here decides anything or changes a value.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any

NOT_A_CLAIM = (
    "This checks a signature and the trust rules set by your administrator. It is not a regulatory certification "
    "and not proof of encrypted computation."
)

# Shown on every result, whatever the verdict, and carried in every saved result. Do not make it conditional.
FHE_NOTICE = (
    "Signature verification does not verify that any FHE (encrypted) computation was executed."
)

TRUSTED_MEANS = (
    "This means it came from an issuer your administrator approved and has not changed since it was signed. It does "
    "not mean the report's findings are correct."
)

_VERDICTS = {
    "TRUSTED": (
        "Signature and configured trust rules verified. This is not a regulatory certification and not proof of "
        "encrypted computation."
    ),
    "SELF_SIGNED_ONLY": (
        "The report matches its own signature, but only its own embedded key vouches for it. Nobody your "
        "administrator trusts has been shown to have signed it. It was not accepted."
    ),
    "INVALID": "Not accepted.",
}
_UNKNOWN_VERDICT = "This verdict is not one this portal knows. Treat the report as not accepted."

_REASONS = {
    "AUDIENCE_MISMATCH": "The report was issued for a different recipient.",
    "CHRONOLOGY_UNAUTHENTICATED": "The time of signing is only what the signer stated. Nothing independent confirms it.",
    "DEPLOYMENT_NOT_ALLOWED": "The report comes from a deployment this key is not allowed to sign for.",
    "FINGERPRINT_MISMATCH": "The key does not match the fingerprint your administrator enrolled.",
    "HASH_MISMATCH": "The report's contents do not match what was signed. It may have been changed after signing.",
    "ISSUER_MISMATCH": "The report names a different issuer from the one enrolled for this key.",
    "ISSUER_UNKNOWN": "The signing key is not in your administrator's list of trusted keys.",
    "KEY_COMPROMISED_NO_CHRONOLOGY": "This key is marked compromised, and nothing independent shows when the report was signed.",
    "KEY_EMBEDDED_MISMATCH": "The key inside the report differs from the key your administrator enrolled.",
    "KEY_NOT_YET_VALID": "The report was signed before this key became valid.",
    "KEY_RETIRED_NO_CHRONOLOGY": "This key is retired, and nothing independent shows when the report was signed.",
    "KEY_REVOKED": "This key is marked as revoked in your administrator's trust list.",
    "LEGACY_V1_FORMAT": (
        "The report is in the older v1 format, which cannot tie its issuer key, deployment or run to the signature."
    ),
    "MALFORMED_ENVELOPE": "The report's structure could not be accepted.",
    "PIN_MISMATCH": "The report's parameters differ from those your administrator pinned for this key.",
    "PRIMITIVE_NOT_ALLOWED": "This key is not allowed to sign this type of report.",
    "PROVENANCE_CONTRADICTION": "The report's stated parameters contradict each other.",
    "PROVENANCE_UNVERIFIABLE": "The report's stated parameters could not be checked.",
    "REPLAY_DETECTED": "This report has already been recorded here, so it was refused as a repeat.",
    "REPLAY_ID_MISSING": "The report has no run identifier, so a repeat could not be detected.",
    "REPLAY_STATE_UNAVAILABLE": "The record of seen reports could not be used, so no decision could safely be made.",
    "REPORT_FROM_FUTURE": "The report says it was issued in the future.",
    "REPORT_TOO_OLD": "The report is older than your administrator's maximum age.",
    "SELF_SIGNED_NO_TRUST_MATERIAL": "Only the report's own embedded key vouches for it.",
    "SIGNATURE_INVALID": "The signature does not check out against the key. The report may have been changed.",
    "SIGNED_AFTER_COMPROMISE": "The report was signed after this key was marked compromised.",
    "SIGNED_AFTER_RETIREMENT": "The report was signed after this key was retired.",
    "TIMESTAMP_FAILED": "The report's timestamp could not be verified.",
    "TIMESTAMP_REQUIRED": "A verified timestamp is required and there is none.",
    "TRUST_STORE_FRESHNESS_UNPROVEN": "Nothing proves your administrator's trust list is up to date.",
}
_UNKNOWN_REASON = "No plain-language explanation is available for this code."


def _reasons(result: dict[str, Any]) -> list[dict[str, Any]]:
    blocking = list(result["blocking_reasons"])
    others = [code for code in result["reasons"] if code not in blocking]
    return [
        {"code": code, "blocking": is_blocking, "meaning": _REASONS.get(code, _UNKNOWN_REASON)}
        for codes, is_blocking in ((blocking, True), (others, False))
        for code in codes
    ]


def _warnings(result: dict[str, Any], profile: str) -> list[dict[str, str]]:
    """What an accepted result does not establish. A rejected report's reasons are its own explanation."""
    found = []

    def warn(code: str, message: str) -> None:
        found.append({"code": code, "message": message})

    if result["trust_status"] == "TRUSTED":
        if result["consumption"] != "RECORDED_LOCAL":
            warn(
                "REPLAY_NOT_RECORDED",
                "This check did not record the report as used, so the same report would pass here again. "
                "Do not rely on this result to stop a report being used twice.",
            )
        if result["replay_durable"] is not True:
            warn(
                "REPLAY_NOT_DURABLE",
                "No durable local record of seen reports was available for this check.",
            )
        if result["consumption"] == "RECORDED_LOCAL":
            warn(
                "REPLAY_LOCAL_ONLY",
                "Repeats are detected only against this portal's own record file. The same report could still be "
                "used somewhere else.",
            )
        if result["chronology"] != "AUTHENTICATED":
            warn("TIME_NOT_INDEPENDENT", "The signing time is only what the signer stated.")
        if result["trust_history"] != "FRESH":
            warn(
                "TRUST_LIST_FRESHNESS_UNPROVEN",
                "Nothing proves your administrator's trust list is up to date. A key withdrawn elsewhere may not be "
                "marked in it.",
            )
    if not result["issuer_trusted"]:
        warn(
            "ISSUER_NOT_ASSURED",
            "This report could not be tied to an issuer your administrator trusts.",
        )
    if profile == "development":
        warn(
            "DEVELOPMENT_PROFILE",
            "The administrator has set the development profile. Do not rely on this result.",
        )
    return found


def _signature_failed(result: dict[str, Any]) -> bool:
    return bool({"HASH_MISMATCH", "SIGNATURE_INVALID"} & set(result["blocking_reasons"]))


def _signature_line(result: dict[str, Any]) -> str:
    """``integrity_valid`` false has two meanings: the check failed, or there was no trusted key to check with."""
    if result["integrity_valid"] is True:
        return "Passed: the contents match the signature, checked with the key your administrator enrolled."
    if _signature_failed(result):
        return "Failed: the contents and signature do not match. The report may have been changed."
    if "ISSUER_UNKNOWN" in result["blocking_reasons"]:
        return "Not checked: this key is not on your administrator's list, so there is no enrolled key to check it with."
    return "Not confirmed."


_LIFECYCLE_BLOCKS = frozenset(
    {
        "KEY_NOT_YET_VALID",
        "KEY_REVOKED",
        "KEY_COMPROMISED_NO_CHRONOLOGY",
        "SIGNED_AFTER_COMPROMISE",
        "KEY_RETIRED_NO_CHRONOLOGY",
        "SIGNED_AFTER_RETIREMENT",
        "TRUST_STORE_FRESHNESS_UNPROVEN",
    }
)
_WITHDRAWN = ("revoked", "compromised", "retired")


def _issuer_line(result: dict[str, Any]) -> str:
    """The verifier's ``issuer_trusted`` means the key is enrolled for this issuer. It does not mean the key is in use.

    It stays true for a key that is revoked, compromised, retired or not yet valid, and the reasons say what then
    blocked the report. The line must not read as "approved" in those cases.
    """
    if result["issuer_trusted"] is True:
        blocking = set(result["blocking_reasons"])
        status = result["key_status"]
        matches = "the key matches the one enrolled for this issuer"
        if "KEY_NOT_YET_VALID" in blocking:
            return f"Not approved for this report: {matches}, but the report was signed before the key became valid."
        if status in _WITHDRAWN:
            if blocking & _LIFECYCLE_BLOCKS:
                return (
                    f"Not approved: {matches}, but your administrator marked it {status}, and this report does not "
                    f"meet your administrator's rules for a {status} key."
                )
            return (
                f"Accepted with a limit: {matches}, but your administrator marked it {status}. This report was "
                "accepted only under your administrator's rules for a key that is no longer active."
            )
        if status == "active":
            return "Passed: this key is approved for this issuer under your administrator's rules."
        return f"Not confirmed: {matches}, but its status is not one this portal knows."
    if _signature_failed(result):
        return "Not confirmed, because the signature check failed."
    return "Failed: not trusted. A valid signature alone does not make an issuer trusted."


def _verdict(result: dict[str, Any]) -> str:
    verdict = _VERDICTS.get(result["trust_status"], _UNKNOWN_VERDICT)
    if result["trust_status"] != "INVALID":
        return verdict
    blocking = result["blocking_reasons"]
    if blocking:
        verdict = f"{verdict} {_REASONS.get(blocking[0], _UNKNOWN_REASON)}"
    return f"{verdict} Do not rely on this report. Ask whoever sent it for a new copy, or ask your administrator."


# Unicode categories that can reorder, hide or break up text: controls (including the bidirectional overrides and
# isolates), invisible formatting characters, lone surrogates, private use, and line and paragraph separators.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
_MAX_ISSUER_SHOWN = 200


def _safe(text: str, limit: int) -> tuple[str, bool]:
    """Text the page can show without it changing how the text around it reads: each unsafe character becomes a
    visible ``\\u{XXXX}`` and the length is capped. Returns the text and whether it was cut short."""
    cut = text[:limit]
    shown = "".join(
        f"\\u{{{ord(char):04X}}}" if unicodedata.category(char) in _UNSAFE_CATEGORIES else char
        for char in cut
    )
    return shown, len(text) > limit


def printable(value: Any, limit: int = _MAX_ISSUER_SHOWN) -> str:
    """For text the signer controls. The saved result keeps the verifier's exact value beside this."""
    shown, cut = _safe(value if isinstance(value, str) else str(value), limit)
    return f"{shown} (shortened)" if cut else shown


_KNOWN_ENCRYPTED_BACKENDS = frozenset({"tenseal-ckks", "openfhe-ckks"})
_MAX_SHOWN = 64
_NOT_SUBSTANTIATED = (
    "A valid signature does not substantiate these declarations. Verification does not show that any encrypted "
    "(FHE) computation happened."
)
_PLAINTEXT = "No encryption: this report states it was computed on plaintext."
_ENCRYPTED = (
    "The signer declares an encrypted backend. This portal cannot verify that encryption was used."
)
_UNRECOGNIZED = (
    "The signer declares a backend this portal does not recognize. This portal cannot verify what it is or that "
    "encryption was used."
)
_NOT_STATED = (
    "The report does not name a backend. This portal cannot tell whether encryption was used."
)
_BITS_PLAINTEXT = "legacy field, not a security level"
_BITS_TOO_LARGE = 10**6
_BITS_DECLARED = "declared by the signer, not verified"
_ACCEPTED_SOURCE = (
    "These are claims made by the signer. The trust rules checked who signed the report. They did not check "
    "these claims."
)
_REJECTED_SOURCE = "The report was not accepted, so these statements are only what the file says. Nothing has established them."


def declarations(env: Any, trust_status: str) -> dict[str, Any]:
    """What the signer says about encryption, worded so that it is never mistaken for a finding.

    ``backend`` and ``parameter_set.security_bits`` are values the signer chose. This reads them from the report and
    labels them. It does not run, test or measure anything, and ``encryption_verified`` is always false.
    """
    backend = getattr(env, "backend", None)
    parameter_set = getattr(env, "parameter_set", None)
    present = isinstance(parameter_set, dict) and "security_bits" in parameter_set
    bits = parameter_set["security_bits"] if present else None
    if isinstance(backend, str) and backend:
        shown, _ = _safe(backend, _MAX_SHOWN)
        if backend == "plaintext":
            kind, statement, bits_note = "PLAINTEXT", _PLAINTEXT, _BITS_PLAINTEXT
        elif backend in _KNOWN_ENCRYPTED_BACKENDS:
            kind, statement, bits_note = "ENCRYPTED_BACKEND_DECLARED", _ENCRYPTED, _BITS_DECLARED
        else:
            kind, statement, bits_note = "UNRECOGNIZED_BACKEND", _UNRECOGNIZED, _BITS_DECLARED
    else:
        shown = None
        kind, statement, bits_note = "NOT_STATED", _NOT_STATED, _BITS_DECLARED
    if not present:
        state, shown_bits, bits_text = (
            "ABSENT",
            None,
            "none (the report has no security_bits field)",
        )
    elif type(bits) is not int:
        state, shown_bits = "NOT_A_WHOLE_NUMBER", None
        bits_text = f"a value that is not a whole number ({bits_note})"
    elif abs(bits) >= _BITS_TOO_LARGE:
        state, shown_bits = "TOO_LARGE", None
        bits_text = f"a value too large to display ({bits_note})"
    else:
        state, shown_bits = "SHOWN", bits
        bits_text = f"{bits} ({bits_note})"
    source = _ACCEPTED_SOURCE if trust_status == "TRUSTED" else _REJECTED_SOURCE
    return {
        "kind": kind,
        "statement": statement,
        "backend": shown,
        "backend_shortened": isinstance(backend, str) and len(backend) > _MAX_SHOWN,
        "security_bits": shown_bits,
        "security_bits_state": state,
        "security_bits_note": bits_note if state != "ABSENT" else None,
        "security_bits_text": bits_text,
        "encryption_verified": False,
        "note": f"{source} {_NOT_SUBSTANTIATED}",
    }


def _issuer_named_note(result: dict[str, Any]) -> str:
    if result["issuer_trusted"] is not True:
        return "as stated in the report, not confirmed"
    if result.get("accepted") is not True:
        return "matches your administrator's list, but the report was not accepted"
    return ""


def _display(result: dict[str, Any]) -> dict[str, str]:
    """Copies of the text a signer controls, made safe to show. The verifier's own result is not touched."""
    return {
        "issuer": printable(result.get("issuer", "")),
        "issuer_note": _issuer_named_note(result),
        "issued_at": printable(result.get("issued_at", "")),
        # JSON escapes every non-ASCII character, so a signer's control characters stay visible as \\uXXXX.
        "technical_details": json.dumps(result, indent=2),
    }


def describe(result: dict[str, Any], profile: str) -> dict[str, Any]:
    """Added beside the verifier's result, which is returned untouched."""
    return {
        "verdict": _verdict(result),
        "means": TRUSTED_MEANS if result["trust_status"] == "TRUSTED" else None,
        "signature": _signature_line(result),
        "issuer": _issuer_line(result),
        "reasons": _reasons(result),
        "warnings": _warnings(result, profile),
        "display": _display(result),
    }
