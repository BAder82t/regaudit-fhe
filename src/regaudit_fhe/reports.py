"""Audit report serialisation, regulation tagging, and receipt issuance.

All six audit primitives produce typed dataclass reports. This module wraps
those reports into a uniform regulator-facing JSON envelope:

    {
      "schema": "regaudit-fhe.report.v1",
      "primitive": "fairness" | "drift" | ...,
      "regulations": ["NYC_LL144", "EU_AI_ACT_ART15", ...],
      "result": <primitive-specific dict>,
      "depth_budget": {"declared": 6, "consumed": <int>},
      "issued_at": "<iso8601>",
      "receipt": {"sha256": "<hex>", "version": "0.0.1"}
    }

A receipt is a SHA-256 hash of the canonicalised result, providing a
tamper-evident audit-trail anchor. Both clients (the entity being audited)
and regulators (the entity verifying the audit) use the same envelope.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping

import numpy as np


SCHEMA_VERSION = "regaudit-fhe.report.v1"
LIB_VERSION = "0.0.1"


REGULATION_MAP: Dict[str, List[str]] = {
    "fairness": ["NYC_LL144", "EU_AI_ACT_ART10", "EU_AI_ACT_ART15",
                 "COLORADO_AI_ACT", "CFPB_ALG_DISCRIM"],
    "provenance": ["EU_AI_ACT_ART10", "21_CFR_PART_11", "GDPR_ART22", "HIPAA"],
    "concordance": ["FDA_SAMD_PCCP", "EU_AI_ACT_ART15", "EMA_AI_GUIDANCE"],
    "calibration": ["FDA_SAMD_UQ", "EU_AI_ACT_ART15", "ISO_IEC_23053",
                    "UNECE_WP29"],
    "drift": ["EU_AI_ACT_ART15", "FDA_SAMD_PCCP", "BASEL_III"],
    "disagreement": ["OCC_SR_11_7", "EU_AI_ACT_ART15", "FDA_SAMD_PCCP"],
}


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(v) for v in value]
    if isinstance(value, Mapping):
        return {k: _to_jsonable(v) for k, v in value.items()}
    return value


def report_to_dict(report: Any) -> Dict[str, Any]:
    if dataclasses.is_dataclass(report):
        raw = dataclasses.asdict(report)
    else:
        raw = dict(report)
    return {k: _to_jsonable(v) for k, v in raw.items()}


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def issue_receipt(payload: Mapping[str, Any]) -> Dict[str, str]:
    body = _canonical_json(payload).encode("utf-8")
    digest = hashlib.sha256(body).hexdigest()
    return {"sha256": digest, "version": LIB_VERSION}


@dataclass
class AuditEnvelope:
    schema: str
    primitive: str
    regulations: List[str]
    result: Dict[str, Any]
    depth_budget: Dict[str, int]
    issued_at: str
    receipt: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "primitive": self.primitive,
            "regulations": list(self.regulations),
            "result": dict(self.result),
            "depth_budget": dict(self.depth_budget),
            "issued_at": self.issued_at,
            "receipt": dict(self.receipt),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AuditEnvelope":
        return cls(
            schema=data["schema"],
            primitive=data["primitive"],
            regulations=list(data["regulations"]),
            result=dict(data["result"]),
            depth_budget=dict(data["depth_budget"]),
            issued_at=data["issued_at"],
            receipt=dict(data["receipt"]),
        )


def envelope(primitive: str,
             report: Any,
             *,
             depth_consumed: int = 6,
             regulations: Iterable[str] | None = None) -> AuditEnvelope:
    regs = list(regulations) if regulations is not None else REGULATION_MAP.get(
        primitive, []
    )
    result = report_to_dict(report)
    payload = {
        "primitive": primitive,
        "regulations": regs,
        "result": result,
        "depth_budget": {"declared": 6, "consumed": int(depth_consumed)},
    }
    issued = _dt.datetime.now(_dt.timezone.utc).isoformat()
    receipt = issue_receipt(payload | {"issued_at": issued})
    return AuditEnvelope(
        schema=SCHEMA_VERSION,
        primitive=primitive,
        regulations=regs,
        result=result,
        depth_budget=payload["depth_budget"],
        issued_at=issued,
        receipt=receipt,
    )


def verify_receipt(env: AuditEnvelope) -> bool:
    """Recompute the receipt and confirm it matches the envelope's claim.

    Used by regulator-side verifiers to detect tampering between the moment
    the envelope was issued and the moment it was received.
    """
    payload = {
        "primitive": env.primitive,
        "regulations": env.regulations,
        "result": env.result,
        "depth_budget": env.depth_budget,
        "issued_at": env.issued_at,
    }
    return issue_receipt(payload)["sha256"] == env.receipt["sha256"]
