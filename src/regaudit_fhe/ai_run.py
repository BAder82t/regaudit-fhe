"""``ai_run`` evidence: an issuer's signed statement about one AI evaluation run.

An ``ai_run`` report is a ``regaudit-fhe.report.v2`` envelope whose ``primitive`` is ``ai_run``. It
therefore uses the same signature, trust-store, key-lifecycle, replay and timestamp checks as every other
report.

What it means: the named issuer, holding a key in your trust store, signed these statements about a model
digest, the digests of the inputs used and the metric values it reports.

What it does not mean: the verifier does not fetch the model or the dataset, does not re-run the evaluation
and cannot tell whether a reported value is true. It is attribution of a claim, not certification, audit or
regulatory approval, and the envelope carries no regulation mapping.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import copy
import math
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from .report_v2 import (
    AuditEnvelopeV2,
    EnvelopeFormatError,
    _hex64,
    _ident,
    envelope_v2,
)
from .reports import KeyProvider

PRIMITIVE = "ai_run"
RESULT_VERSION = "regaudit-fhe.ai-run.v1"
STATEMENT = "issuer statement; the verifier does not re-run or check it"
CLAIM_KINDS = ("evaluation_metric",)
INPUT_ROLES = ("evaluation_dataset", "inference_input", "configuration")

MAX_INPUTS = 64
MAX_CLAIMS = 64
MAX_ENVIRONMENT = 32
MAX_TEXT = 1000
MAX_SHORT = 128

_RESULT_KEYS = frozenset(
    {"ai_run_version", "statement", "subject", "inputs", "environment", "claims"}
)
_CLAIM_KEYS = frozenset({"kind", "metric", "value", "unit", "method", "dataset"})


def _bad(message: str) -> EnvelopeFormatError:
    return EnvelopeFormatError("BAD_VALUE", message)


def _closed(
    value: Any, name: str, required: frozenset[str], optional: frozenset[str] = frozenset()
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EnvelopeFormatError("BAD_TYPE", f"{name} must be an object")
    extra = set(value) - required - optional
    if extra:
        raise EnvelopeFormatError("UNKNOWN_FIELD", f"{name}: unknown field(s) {sorted(extra)}")
    missing = required - set(value)
    if missing:
        raise EnvelopeFormatError("MISSING_FIELD", f"{name}: missing field(s) {sorted(missing)}")
    return value


def _short(value: Any, name: str) -> str:
    text = _ident(value, name)
    if len(text) > MAX_SHORT:
        raise _bad(f"{name} must be at most {MAX_SHORT} characters")
    return text


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise EnvelopeFormatError("BAD_TYPE", f"{name} must be a string")
    if not value or len(value) > MAX_TEXT:
        raise _bad(f"{name} must be 1..{MAX_TEXT} characters")
    return value


def _number(value: Any, name: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise EnvelopeFormatError("BAD_TYPE", f"{name} must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise _bad(f"{name} must be finite")
    return value


def _digest_ref(value: Any, name: str) -> dict[str, str]:
    obj = _closed(value, name, frozenset({"name", "sha256"}))
    return {
        "name": _short(obj["name"], f"{name}.name"),
        "sha256": _hex64(obj["sha256"], f"{name}.sha256"),
    }


def validate_result(result: Any) -> dict[str, Any]:
    """Strictly validate an ``ai_run`` result and return a normalised copy.

    The vocabulary is closed: unknown fields, unknown claim kinds and unknown input roles are refused.
    Raises :class:`EnvelopeFormatError`.
    """
    obj = _closed(result, "ai_run result", _RESULT_KEYS)
    if obj["ai_run_version"] != RESULT_VERSION:
        raise _bad(f"ai_run_version must be {RESULT_VERSION!r}")
    if obj["statement"] != STATEMENT:
        raise _bad("statement must be the fixed attribution notice")
    subject = _digest_ref(obj["subject"], "subject")

    raw_inputs = obj["inputs"]
    if not isinstance(raw_inputs, list):
        raise EnvelopeFormatError("BAD_TYPE", "inputs must be a list")
    if len(raw_inputs) > MAX_INPUTS:
        raise _bad(f"at most {MAX_INPUTS} inputs")
    inputs: list[dict[str, str]] = []
    roles: dict[str, str] = {}
    for item in raw_inputs:
        entry = _closed(item, "inputs entry", frozenset({"role", "name", "sha256"}))
        role = entry["role"]
        if not isinstance(role, str) or role not in INPUT_ROLES:
            raise _bad(f"inputs role must be one of {list(INPUT_ROLES)}")
        name = _short(entry["name"], "inputs.name")
        if name in roles:
            raise _bad(f"duplicate input name {name!r}")
        roles[name] = role
        inputs.append(
            {"role": role, "name": name, "sha256": _hex64(entry["sha256"], "inputs.sha256")}
        )

    env_in = obj["environment"]
    if not isinstance(env_in, dict):
        raise EnvelopeFormatError("BAD_TYPE", "environment must be an object")
    if len(env_in) > MAX_ENVIRONMENT:
        raise _bad(f"at most {MAX_ENVIRONMENT} environment entries")
    environment = {
        _short(k, "environment key"): _short(v, "environment value") for k, v in env_in.items()
    }

    raw_claims = obj["claims"]
    if not isinstance(raw_claims, list):
        raise EnvelopeFormatError("BAD_TYPE", "claims must be a list")
    if not raw_claims:
        raise _bad("at least one claim is required")
    if len(raw_claims) > MAX_CLAIMS:
        raise _bad(f"at most {MAX_CLAIMS} claims")
    claims: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()
    for item in raw_claims:
        claim = _closed(item, "claims entry", _CLAIM_KEYS - {"dataset"}, frozenset({"dataset"}))
        kind = claim["kind"]
        if not isinstance(kind, str) or kind not in CLAIM_KINDS:
            raise _bad(f"claim kind must be one of {list(CLAIM_KINDS)}")
        metric = _short(claim["metric"], "claims.metric")
        dataset = _short(claim["dataset"], "claims.dataset") if "dataset" in claim else None
        if dataset is not None and roles.get(dataset) != "evaluation_dataset":
            raise _bad(f"claim dataset {dataset!r} is not an evaluation_dataset input")
        key = (metric, dataset)
        if key in seen:
            raise _bad(f"duplicate claim for metric {metric!r} and dataset {dataset!r}")
        seen.add(key)
        out: dict[str, Any] = {
            "kind": kind,
            "metric": metric,
            "value": _number(claim["value"], "claims.value"),
            "unit": _short(claim["unit"], "claims.unit"),
            "method": _text(claim["method"], "claims.method"),
        }
        if dataset is not None:
            out["dataset"] = dataset
        claims.append(out)

    return {
        "ai_run_version": RESULT_VERSION,
        "statement": STATEMENT,
        "subject": subject,
        "inputs": inputs,
        "environment": environment,
        "claims": claims,
    }


def ai_run_envelope(
    *,
    signer: KeyProvider,
    deployment_id: str,
    subject: Mapping[str, str],
    inputs: Sequence[Mapping[str, str]],
    claims: Sequence[Mapping[str, Any]],
    environment: Mapping[str, str] | None = None,
    audit_run_id: str | None = None,
    audience: Sequence[str] | None = None,
    issued_at: datetime | None = None,
    trust_policy_version: int = 1,
) -> AuditEnvelopeV2:
    """Build and sign an ``ai_run`` report.

    ``subject`` is ``{"name": ..., "sha256": ...}``: the digest the issuer names for the model. The signed
    body also carries it as ``model_commitment`` so audience and model checks work as for other reports.
    Raises :class:`EnvelopeFormatError` if the statement does not satisfy the closed vocabulary.
    """
    result = validate_result(
        {
            "ai_run_version": RESULT_VERSION,
            "statement": STATEMENT,
            "subject": dict(subject),
            "inputs": [dict(i) for i in inputs],
            "environment": dict(environment or {}),
            "claims": [copy.deepcopy(dict(c)) for c in claims],
        }
    )
    return envelope_v2(
        PRIMITIVE,
        result,
        signer=signer,
        deployment_id=deployment_id,
        audit_run_id=audit_run_id,
        audience=audience,
        model_commitment=result["subject"],
        regulations=[],
        trust_policy_version=trust_policy_version,
        issued_at=issued_at,
    )
