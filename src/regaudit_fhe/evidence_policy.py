"""Buyer-side policy checks over verified ``ai_run`` evidence.

Verification answers "who signed this, and do I trust that key". A policy answers "does what they signed
meet my bar". The two are kept apart: a policy can only narrow what verification accepted. It cannot enrol
an issuer, and a trust store cannot satisfy a rule.

``evaluate_evidence`` runs verification itself, so there is no way to hand it an unverified report. Every
failed rule yields one reason code. A policy that does not parse is refused with
:class:`PolicyFormatError`; nothing defaults to accept.

A passing decision means: a trusted issuer signed a statement that meets your rules. It does not mean the
model was tested, the metric is true, or any regulation is satisfied.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from ._time import parse_rfc3339
from .ai_run import CLAIM_KINDS, PRIMITIVE
from .canonical import CanonicalError, loads_strict
from .report_v2 import AuditEnvelopeV2, EnvelopeFormatError, parse_envelope_strict
from .trust import TrustStore
from .trusted import verify_trusted
from .verification import VerificationPolicy

POLICY_VERSION = 1
COMPARISONS = (">=", ">", "<=", "<", "==")
MAX_RULES = 64
MAX_LIST = 256
MAX_AGE_DAYS = 3650
FUTURE_SKEW = timedelta(minutes=5)

_POLICY_KEYS = frozenset({"policy_version", "require"})
_POLICY_OPTIONAL = frozenset(
    {"allowed_issuers", "allowed_key_ids", "max_age_days", "subject_sha256"}
)
_RULE_KEYS = frozenset({"kind", "metric", "comparison", "threshold"})
_RULE_OPTIONAL = frozenset({"unit", "dataset_sha256"})


class PolicyFormatError(ValueError):
    """The policy does not conform to its format. A policy is never partly applied."""


@dataclass(frozen=True)
class Rule:
    metric: str
    comparison: str
    threshold: int | float
    unit: str | None = None
    dataset_sha256: str | None = None
    kind: str = "evaluation_metric"


@dataclass(frozen=True)
class EvidencePolicy:
    rules: tuple[Rule, ...]
    allowed_issuers: frozenset[str] | None = None
    allowed_key_ids: frozenset[str] | None = None
    max_age_days: int | None = None
    subject_sha256: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    """Accept or reject. ``reasons`` has one code per failed check, in a fixed order."""

    accepted: bool
    reasons: tuple[str, ...]

    def __bool__(self) -> bool:  # an easy truthiness mistake would be an acceptance bug
        raise TypeError("test PolicyDecision.accepted explicitly")

    def to_dict(self) -> dict[str, Any]:
        return {"accepted": self.accepted, "reasons": list(self.reasons)}


def _closed(
    value: Any, name: str, required: frozenset[str], optional: frozenset[str]
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyFormatError(f"{name} must be an object")
    extra = set(value) - required - optional
    if extra:
        raise PolicyFormatError(f"{name}: unknown field(s) {sorted(extra)}")
    missing = required - set(value)
    if missing:
        raise PolicyFormatError(f"{name}: missing field(s) {sorted(missing)}")
    return value


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


def _names(value: Any, name: str) -> frozenset[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_LIST:
        raise PolicyFormatError(f"{name} must be a non-empty list of at most {MAX_LIST} strings")
    if not all(isinstance(v, str) and 0 < len(v) <= 256 for v in value):
        raise PolicyFormatError(f"{name} must contain non-empty strings")
    return frozenset(value)


def parse_policy(data: str | bytes | Mapping[str, Any]) -> EvidencePolicy:
    """Strictly parse a policy given as JSON text or an already-parsed mapping."""
    if isinstance(data, str | bytes | bytearray):
        try:
            data = loads_strict(data)
        except (CanonicalError, ValueError) as exc:
            raise PolicyFormatError(f"policy is not strict JSON: {exc}") from exc
    doc = _closed(
        data if isinstance(data, dict) else None, "policy", _POLICY_KEYS, _POLICY_OPTIONAL
    )
    if doc["policy_version"] != POLICY_VERSION or isinstance(doc["policy_version"], bool):
        raise PolicyFormatError(f"policy_version must be {POLICY_VERSION}")
    raw_rules = doc["require"]
    if not isinstance(raw_rules, list) or not raw_rules or len(raw_rules) > MAX_RULES:
        raise PolicyFormatError(f"require must be a non-empty list of at most {MAX_RULES} rules")
    rules: list[Rule] = []
    for raw in raw_rules:
        r = _closed(raw, "rule", _RULE_KEYS, _RULE_OPTIONAL)
        if r["kind"] not in CLAIM_KINDS:
            raise PolicyFormatError(f"rule kind must be one of {list(CLAIM_KINDS)}")
        if not isinstance(r["metric"], str) or not 0 < len(r["metric"]) <= 128:
            raise PolicyFormatError("rule metric must be a non-empty string")
        if r["comparison"] not in COMPARISONS:
            raise PolicyFormatError(f"rule comparison must be one of {list(COMPARISONS)}")
        thr = r["threshold"]
        if (
            isinstance(thr, bool)
            or not isinstance(thr, int | float)
            or (isinstance(thr, float) and not math.isfinite(thr))
        ):
            raise PolicyFormatError("rule threshold must be a finite number")
        unit = r.get("unit")
        if unit is not None and (not isinstance(unit, str) or not 0 < len(unit) <= 128):
            raise PolicyFormatError("rule unit must be a non-empty string")
        ds = r.get("dataset_sha256")
        if ds is not None and not _is_hex64(ds):
            raise PolicyFormatError("rule dataset_sha256 must be 64 lowercase hex characters")
        rules.append(Rule(r["metric"], r["comparison"], thr, unit, ds, r["kind"]))
    age = doc.get("max_age_days")
    if "max_age_days" in doc and (
        isinstance(age, bool) or not isinstance(age, int) or not 1 <= age <= MAX_AGE_DAYS
    ):
        raise PolicyFormatError(f"max_age_days must be an integer 1..{MAX_AGE_DAYS}")
    subject = doc.get("subject_sha256")
    if "subject_sha256" in doc and not _is_hex64(subject):
        raise PolicyFormatError("subject_sha256 must be 64 lowercase hex characters")
    return EvidencePolicy(
        rules=tuple(rules),
        allowed_issuers=_names(doc["allowed_issuers"], "allowed_issuers")
        if "allowed_issuers" in doc
        else None,
        allowed_key_ids=_names(doc["allowed_key_ids"], "allowed_key_ids")
        if "allowed_key_ids" in doc
        else None,
        max_age_days=age,
        subject_sha256=subject,
    )


def _holds(value: int | float, comparison: str, threshold: int | float) -> bool:
    if comparison == ">=":
        return value >= threshold
    if comparison == ">":
        return value > threshold
    if comparison == "<=":
        return value <= threshold
    if comparison == "<":
        return value < threshold
    return value == threshold


def _rule_code(index: int, rule: Rule, env: AuditEnvelopeV2) -> str | None:
    input_digest = {i["name"]: i["sha256"] for i in env.result["inputs"]}
    named = [
        c for c in env.result["claims"] if c["kind"] == rule.kind and c["metric"] == rule.metric
    ]
    if rule.dataset_sha256 is not None:
        named = [c for c in named if input_digest.get(c.get("dataset", "")) == rule.dataset_sha256]
    if not named:
        return f"RULE_{index}_CLAIM_MISSING"
    if rule.unit is not None:
        named = [c for c in named if c["unit"] == rule.unit]
        if not named:
            return f"RULE_{index}_UNIT_MISMATCH"
    # Every matching claim must meet the bar: a lower value on another dataset is not hidden by a higher one.
    if not all(_holds(c["value"], rule.comparison, rule.threshold) for c in named):
        return f"RULE_{index}_THRESHOLD_NOT_MET"
    return None


def evaluate_evidence(
    report: str | bytes | Mapping[str, Any],
    trust_store: TrustStore,
    policy: EvidencePolicy,
    *,
    verification_policy: VerificationPolicy | None = None,
    now: datetime | None = None,
) -> PolicyDecision:
    """Verify ``report`` against ``trust_store``, then apply ``policy``.

    Accepted only if verification returns ``TRUSTED`` and every check of the policy holds.
    """
    if not isinstance(policy, EvidencePolicy):
        raise TypeError("policy must be an EvidencePolicy; build one with parse_policy()")
    verdict = verify_trusted(report, trust_store, policy=verification_policy)
    if not verdict.trusted:
        return PolicyDecision(False, ("NOT_TRUSTED",))
    try:
        source = report.to_dict() if isinstance(report, AuditEnvelopeV2) else report
        env = parse_envelope_strict(source)
    except (EnvelopeFormatError, CanonicalError, json.JSONDecodeError):
        return PolicyDecision(False, ("NOT_TRUSTED",))
    if not isinstance(env, AuditEnvelopeV2) or env.primitive != PRIMITIVE:
        return PolicyDecision(False, ("WRONG_PRIMITIVE",))

    clock = now if now is not None else datetime.now(timezone.utc)
    if clock.tzinfo is None or clock.utcoffset() is None:
        raise ValueError("now must be an aware datetime")
    reasons: list[str] = []
    if policy.allowed_issuers is not None and env.issuer not in policy.allowed_issuers:
        reasons.append("ISSUER_NOT_ALLOWED")
    if policy.allowed_key_ids is not None and env.key_id not in policy.allowed_key_ids:
        reasons.append("KEY_NOT_ALLOWED")
    issued = parse_rfc3339(env.issued_at)
    if issued - clock > FUTURE_SKEW:
        reasons.append("FUTURE_DATED")
    elif policy.max_age_days is not None and clock - issued > timedelta(days=policy.max_age_days):
        reasons.append("TOO_OLD")
    if (
        policy.subject_sha256 is not None
        and env.result["subject"]["sha256"] != policy.subject_sha256
    ):
        reasons.append("SUBJECT_MISMATCH")
    for index, rule in enumerate(policy.rules):
        code = _rule_code(index, rule, env)
        if code is not None:
            reasons.append(code)
    return PolicyDecision(not reasons, tuple(reasons))
