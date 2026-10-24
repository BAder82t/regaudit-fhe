"""``regaudit-fhe.report.v2`` envelope.

Differences from ``report.v1`` (which is unchanged and still verifiable):

* The signed body carries the complete security identity: ``issuer``,
  ``key_id``, ``public_key_fingerprint``, ``deployment_id``, ``audit_run_id``,
  an optional ``audience`` and optional ``model_commitment`` /
  ``dataset_commitment``. In v1 ``key_id`` and the public key lived in the
  unsigned receipt.
* Signing is domain separated: the signature is over
  ``SIGN_DOMAIN || canonical_bytes(signed_body)``, so a v2 signature can never
  validate as a v1 signature and vice versa.
* Canonicalisation uses the strict policy in :mod:`regaudit_fhe.canonical`.
* Unknown fields anywhere in the envelope structure are refused.
* Timestamp evidence (``timestamps``, a list) stays outside the signed body and
  binds the **sealed digest**: a domain-separated hash of the signed body, the
  signature and (via the body) the signer-key identity.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ._keys import spki_fingerprint
from ._time import parse_rfc3339
from .canonical import CanonicalError, canonical_bytes, check_value, loads_strict
from .reports import (
    LIB_VERSION,
    REGULATION_MAP,
    SIGNATURE_ALG,
    AuditEnvelope,
    KeyProvider,
    ParameterSet,
    _to_jsonable,
    report_to_dict,
    sha256_hex,
)
from .schemas import PRIMITIVES

SCHEMA_V2 = "regaudit-fhe.report.v2"
SCHEMA_V1 = "regaudit-fhe.report.v1"
SIGN_DOMAIN = b"regaudit-fhe/report/v2/sign\x00"
SEAL_DOMAIN = b"regaudit-fhe/sealed-envelope/v2\x00"

_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$")
_MAX_IDENT = 256

_BODY_REQUIRED = (
    "schema",
    "schema_version",
    "algorithm_version",
    "primitive",
    "backend",
    "parameter_set",
    "parameter_set_hash",
    "regulations",
    "result",
    "input_commitments",
    "depth_budget",
    "issued_at",
    "issuer",
    "key_id",
    "public_key_fingerprint",
    "deployment_id",
    "audit_run_id",
    "trust_policy_version",
)
_BODY_OPTIONAL = ("audience", "model_commitment", "dataset_commitment", "dp")
_OUTER = ("receipt", "timestamps")
_RECEIPT_KEYS = frozenset({"sha256", "signature_alg", "signature_b64", "public_key_pem"})
_TIMESTAMP_KEYS = frozenset({"issuer", "token_b64", "issued_at"})


class EnvelopeFormatError(ValueError):
    """The envelope does not conform to its declared format.

    ``code`` is one of ``BAD_SCHEMA``, ``UNKNOWN_FIELD``, ``MISSING_FIELD``,
    ``BAD_TYPE`` or ``BAD_VALUE``.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


# ---------------------------------------------------------------------------
# Small validators
# ---------------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _ident(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise EnvelopeFormatError("BAD_TYPE", f"{name} must be a string")
    if not value or len(value) > _MAX_IDENT:
        raise EnvelopeFormatError("BAD_VALUE", f"{name} must be 1..{_MAX_IDENT} characters")
    return value


def _hex64(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise EnvelopeFormatError("BAD_TYPE", f"{name} must be a string")
    if not _HEX64.match(value):
        raise EnvelopeFormatError("BAD_VALUE", f"{name} must be 64 lowercase hex characters")
    return value


def _timestamp_str(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise EnvelopeFormatError("BAD_TYPE", f"{name} must be a string")
    try:
        parse_rfc3339(value)
    except ValueError as exc:
        raise EnvelopeFormatError("BAD_VALUE", f"{name}: {exc}") from exc
    return value


def _commitment(value: Any, name: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise EnvelopeFormatError("BAD_TYPE", f"{name} must be an object")
    extra = set(value) - {"name", "sha256"}
    if extra:
        raise EnvelopeFormatError("UNKNOWN_FIELD", f"{name}: unknown field(s) {sorted(extra)}")
    if set(value) != {"name", "sha256"}:
        raise EnvelopeFormatError("MISSING_FIELD", f"{name} requires name and sha256")
    return {"name": _ident(value["name"], f"{name}.name"), "sha256": _hex64(value["sha256"], name)}


def _audience(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise EnvelopeFormatError("BAD_TYPE", "audience must be a list")
    if not value:
        raise EnvelopeFormatError("BAD_VALUE", "audience must not be empty when present")
    out = [_ident(v, "audience entry") for v in value]
    if len(set(out)) != len(out):
        raise EnvelopeFormatError("BAD_VALUE", "audience entries must be unique")
    return out


def _uuid(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise EnvelopeFormatError("BAD_TYPE", f"{name} must be a string")
    try:
        canonical = str(uuid.UUID(value))
    except ValueError as exc:
        raise EnvelopeFormatError("BAD_VALUE", f"{name} is not a UUID") from exc
    if canonical != value:
        raise EnvelopeFormatError("BAD_VALUE", f"{name} must be a lowercase hyphenated UUID")
    return value


def public_key_fingerprint(pem: str) -> str:
    """SHA-256 (lowercase hex) of the SubjectPublicKeyInfo DER of a PEM Ed25519 key."""
    try:
        return spki_fingerprint(pem)
    except ValueError as exc:
        raise EnvelopeFormatError("BAD_VALUE", str(exc)) from exc


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


@dataclass
class AuditEnvelopeV2:
    schema: str
    schema_version: str
    algorithm_version: str
    primitive: str
    backend: str
    parameter_set: dict[str, Any]
    parameter_set_hash: str
    regulations: list[str]
    result: dict[str, Any]
    input_commitments: list[dict[str, str]]
    depth_budget: dict[str, int]
    issued_at: str
    issuer: str
    key_id: str
    public_key_fingerprint: str
    deployment_id: str
    audit_run_id: str
    trust_policy_version: int
    receipt: dict[str, str]
    audience: list[str] | None = None
    model_commitment: dict[str, str] | None = None
    dataset_commitment: dict[str, str] | None = None
    dp: dict[str, Any] | None = None
    timestamps: list[dict[str, str]] = field(default_factory=list)

    # ----- signed / sealed byte strings -----------------------------------

    def signed_body(self) -> dict[str, Any]:
        """The exact object the signature covers (everything except the
        receipt and the timestamps)."""
        body = self.to_dict()
        for key in _OUTER:
            body.pop(key, None)
        return body

    def signing_input(self) -> bytes:
        """Domain-separated bytes that are hashed into the receipt and signed."""
        return SIGN_DOMAIN + canonical_bytes(self.signed_body())

    def sealed_digest(self) -> bytes:
        """Digest a timestamp or witness token must bind.

        Covers the canonical signed body, the signature and (through the
        body) the signer-key identity. Excludes the timestamps themselves and
        the embedded PEM, so attaching a token never changes what it binds.
        """
        sealed = {
            "signed_body": self.signed_body(),
            "signature_alg": self.receipt.get("signature_alg"),
            "signature_b64": self.receipt.get("signature_b64"),
        }
        return hashlib.sha256(SEAL_DOMAIN + canonical_bytes(sealed)).digest()

    # ----- serialisation ---------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "algorithm_version": self.algorithm_version,
            "primitive": self.primitive,
            "backend": self.backend,
            "parameter_set": copy.deepcopy(self.parameter_set),
            "parameter_set_hash": self.parameter_set_hash,
            "regulations": list(self.regulations),
            "result": copy.deepcopy(self.result),
            "input_commitments": [dict(c) for c in self.input_commitments],
            "depth_budget": dict(self.depth_budget),
            "issued_at": self.issued_at,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "public_key_fingerprint": self.public_key_fingerprint,
            "deployment_id": self.deployment_id,
            "audit_run_id": self.audit_run_id,
            "trust_policy_version": self.trust_policy_version,
            "receipt": dict(self.receipt),
        }
        if self.audience is not None:
            out["audience"] = list(self.audience)
        if self.model_commitment is not None:
            out["model_commitment"] = dict(self.model_commitment)
        if self.dataset_commitment is not None:
            out["dataset_commitment"] = dict(self.dataset_commitment)
        if self.dp is not None:
            out["dp"] = copy.deepcopy(self.dp)
        if self.timestamps:
            out["timestamps"] = [dict(t) for t in self.timestamps]
        return out

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def with_timestamp(self, *, issuer: str, token: bytes, issued_at: datetime) -> AuditEnvelopeV2:
        """Return a copy with a timestamp token attached (outside the signature)."""
        if issued_at.tzinfo is None or issued_at.utcoffset() is None:
            raise ValueError("issued_at must be an aware datetime")
        entry = {
            "issuer": issuer,
            "token_b64": base64.b64encode(token).decode("ascii"),
            "issued_at": issued_at.isoformat(),
        }
        clone = copy.deepcopy(self)
        clone.timestamps = [*self.timestamps, entry]
        return clone

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AuditEnvelopeV2:
        """Strictly parse a v2 envelope; any deviation raises
        :class:`EnvelopeFormatError`."""
        if not isinstance(data, Mapping):
            raise EnvelopeFormatError("BAD_TYPE", "envelope must be an object")
        if any(not isinstance(k, str) for k in data):
            raise EnvelopeFormatError("BAD_TYPE", "envelope keys must be strings")
        allowed = set(_BODY_REQUIRED) | set(_BODY_OPTIONAL) | set(_OUTER)
        unknown = set(data) - allowed
        if unknown:
            raise EnvelopeFormatError("UNKNOWN_FIELD", f"unknown field(s) {sorted(unknown)}")
        missing = [k for k in (*_BODY_REQUIRED, "receipt") if k not in data]
        if missing:
            raise EnvelopeFormatError("MISSING_FIELD", f"missing field(s) {missing}")

        if data["schema"] != SCHEMA_V2:
            raise EnvelopeFormatError("BAD_SCHEMA", f"schema must be {SCHEMA_V2!r}")
        if data["schema_version"] != SCHEMA_V2:
            raise EnvelopeFormatError("BAD_VALUE", "schema_version must equal schema")

        algorithm_version = data["algorithm_version"]
        if not isinstance(algorithm_version, str) or not _SEMVER.match(algorithm_version):
            raise EnvelopeFormatError("BAD_VALUE", "algorithm_version must be a semantic version")
        primitive = data["primitive"]
        if not isinstance(primitive, str) or primitive not in PRIMITIVES:
            raise EnvelopeFormatError("BAD_VALUE", f"primitive must be one of {list(PRIMITIVES)}")
        backend = _ident(data["backend"], "backend")

        parameter_set = data["parameter_set"]
        result = data["result"]
        dp = data.get("dp")
        for name, value in (("parameter_set", parameter_set), ("result", result)):
            if not isinstance(value, dict):
                raise EnvelopeFormatError("BAD_TYPE", f"{name} must be an object")
        if "dp" in data and not isinstance(dp, dict):
            raise EnvelopeFormatError("BAD_TYPE", "dp must be an object when present")
        # Free-form signed content must obey the canonical policy (finite
        # numbers, string keys, valid Unicode, bounded depth) *before* it is
        # copied or signed; otherwise signing_input() could fail later.
        for name, value in (("parameter_set", parameter_set), ("result", result), ("dp", dp)):
            if value is None:
                continue
            try:
                check_value(value)
            except CanonicalError as exc:
                raise EnvelopeFormatError("BAD_VALUE", f"{name}: {exc}") from exc

        regulations = data["regulations"]
        if not isinstance(regulations, list) or not all(isinstance(r, str) for r in regulations):
            raise EnvelopeFormatError("BAD_TYPE", "regulations must be a list of strings")

        commitments = data["input_commitments"]
        if not isinstance(commitments, list):
            raise EnvelopeFormatError("BAD_TYPE", "input_commitments must be a list")
        input_commitments = [_commitment(c, "input_commitments entry") for c in commitments]

        depth = data["depth_budget"]
        if not isinstance(depth, dict):
            raise EnvelopeFormatError("BAD_TYPE", "depth_budget must be an object")
        if set(depth) - {"declared", "consumed"}:
            raise EnvelopeFormatError("UNKNOWN_FIELD", "depth_budget: unknown field")
        if set(depth) != {"declared", "consumed"}:
            raise EnvelopeFormatError("MISSING_FIELD", "depth_budget needs declared and consumed")
        for k, v in depth.items():
            if not _is_int(v) or not 0 <= v <= 6:
                raise EnvelopeFormatError("BAD_VALUE", f"depth_budget.{k} must be an int in 0..6")

        tpv = data["trust_policy_version"]
        if not _is_int(tpv) or tpv < 0:
            raise EnvelopeFormatError("BAD_VALUE", "trust_policy_version must be an int >= 0")

        receipt = data["receipt"]
        if not isinstance(receipt, dict):
            raise EnvelopeFormatError("BAD_TYPE", "receipt must be an object")
        if set(receipt) - _RECEIPT_KEYS:
            raise EnvelopeFormatError(
                "UNKNOWN_FIELD", f"receipt: unknown field(s) {sorted(set(receipt) - _RECEIPT_KEYS)}"
            )
        if set(receipt) != _RECEIPT_KEYS:
            raise EnvelopeFormatError("MISSING_FIELD", "receipt is missing field(s)")
        if receipt["signature_alg"] != SIGNATURE_ALG:
            raise EnvelopeFormatError("BAD_VALUE", f"signature_alg must be {SIGNATURE_ALG!r}")
        _hex64(receipt["sha256"], "receipt.sha256")
        _b64(receipt["signature_b64"], "receipt.signature_b64", length=64)
        if not isinstance(receipt["public_key_pem"], str) or not receipt["public_key_pem"]:
            raise EnvelopeFormatError("BAD_VALUE", "receipt.public_key_pem must be a string")

        raw_ts = data.get("timestamps", [])
        if not isinstance(raw_ts, list):
            raise EnvelopeFormatError("BAD_TYPE", "timestamps must be a list")
        timestamps: list[dict[str, str]] = []
        for item in raw_ts:
            if not isinstance(item, dict):
                raise EnvelopeFormatError("BAD_TYPE", "timestamps entry must be an object")
            if set(item) - _TIMESTAMP_KEYS:
                raise EnvelopeFormatError("UNKNOWN_FIELD", "timestamps entry: unknown field")
            if set(item) != _TIMESTAMP_KEYS:
                raise EnvelopeFormatError("MISSING_FIELD", "timestamps entry is missing field(s)")
            timestamps.append(
                {
                    "issuer": _ident(item["issuer"], "timestamps.issuer"),
                    "token_b64": _b64(item["token_b64"], "timestamps.token_b64"),
                    "issued_at": _timestamp_str(item["issued_at"], "timestamps.issued_at"),
                }
            )

        return cls(
            schema=SCHEMA_V2,
            schema_version=SCHEMA_V2,
            algorithm_version=algorithm_version,
            primitive=primitive,
            backend=backend,
            parameter_set=copy.deepcopy(parameter_set),
            parameter_set_hash=_hex64(data["parameter_set_hash"], "parameter_set_hash"),
            regulations=list(regulations),
            result=copy.deepcopy(result),
            input_commitments=input_commitments,
            depth_budget={"declared": depth["declared"], "consumed": depth["consumed"]},
            issued_at=_timestamp_str(data["issued_at"], "issued_at"),
            issuer=_ident(data["issuer"], "issuer"),
            key_id=_ident(data["key_id"], "key_id"),
            public_key_fingerprint=_hex64(data["public_key_fingerprint"], "public_key_fingerprint"),
            deployment_id=_ident(data["deployment_id"], "deployment_id"),
            audit_run_id=_uuid(data["audit_run_id"], "audit_run_id"),
            trust_policy_version=tpv,
            receipt={k: receipt[k] for k in sorted(_RECEIPT_KEYS)},
            audience=_audience(data["audience"]) if "audience" in data else None,
            model_commitment=_commitment(data["model_commitment"], "model_commitment")
            if "model_commitment" in data
            else None,
            dataset_commitment=_commitment(data["dataset_commitment"], "dataset_commitment")
            if "dataset_commitment" in data
            else None,
            dp=copy.deepcopy(dp) if "dp" in data else None,
            timestamps=timestamps,
        )


def _b64(value: Any, name: str, *, length: int | None = None) -> str:
    """Canonical standard-alphabet base64 only: re-encoding the decoded bytes
    must reproduce the text exactly, so unused trailing bits cannot be varied
    to change the text without changing the bytes."""
    if not isinstance(value, str) or not value:
        raise EnvelopeFormatError("BAD_VALUE", f"{name} must be a non-empty string")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise EnvelopeFormatError("BAD_VALUE", f"{name} is not valid base64") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise EnvelopeFormatError("BAD_VALUE", f"{name} is not canonical base64")
    if length is not None and len(raw) != length:
        raise EnvelopeFormatError("BAD_VALUE", f"{name} must decode to {length} bytes")
    return value


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def envelope_v2(
    primitive: str,
    report: Any,
    *,
    signer: KeyProvider,
    deployment_id: str,
    audit_run_id: str | None = None,
    audience: Sequence[str] | None = None,
    model_commitment: Mapping[str, str] | None = None,
    dataset_commitment: Mapping[str, str] | None = None,
    regulations: Iterable[str] | None = None,
    parameter_set: ParameterSet | None = None,
    input_commitments: Sequence[Mapping[str, str]] | None = None,
    depth_consumed: int = 6,
    dp: Mapping[str, Any] | None = None,
    trust_policy_version: int = 1,
    issued_at: datetime | None = None,
) -> AuditEnvelopeV2:
    """Build and sign a ``report.v2`` envelope.

    There is no ephemeral-signer default: v2 identity only means something if
    the caller names the key. The result is round-tripped through the strict
    parser, so this function cannot emit an envelope the verifier would refuse
    to read.
    """
    params = parameter_set or ParameterSet()
    regs = list(regulations) if regulations is not None else REGULATION_MAP.get(primitive, [])
    when = (issued_at or datetime.now(timezone.utc)).isoformat()
    body: dict[str, Any] = {
        "schema": SCHEMA_V2,
        "schema_version": SCHEMA_V2,
        "algorithm_version": LIB_VERSION,
        "primitive": primitive,
        "backend": params.backend,
        "parameter_set": params.to_dict(),
        "parameter_set_hash": params.hash(),
        "regulations": regs,
        "result": report_to_dict(report),
        "input_commitments": [dict(c) for c in (input_commitments or [])],
        "depth_budget": {"declared": 6, "consumed": int(depth_consumed)},
        "issued_at": when,
        "issuer": signer.issuer,
        "key_id": signer.key_id,
        "public_key_fingerprint": public_key_fingerprint(signer.public_key_pem()),
        "deployment_id": deployment_id,
        "audit_run_id": audit_run_id if audit_run_id is not None else str(uuid.uuid4()),
        "trust_policy_version": trust_policy_version,
    }
    if audience is not None:
        body["audience"] = list(audience)
    if model_commitment is not None:
        body["model_commitment"] = dict(model_commitment)
    if dataset_commitment is not None:
        body["dataset_commitment"] = dict(dataset_commitment)
    if dp is not None:
        body["dp"] = _to_jsonable(dict(dp))
    return sign_body_v2(body, signer)


def sign_body_v2(body: Mapping[str, Any], signer: KeyProvider) -> AuditEnvelopeV2:
    """Sign an assembled v2 signed body and return the envelope.

    The body is normalised to plain JSON types (tuples -> lists, numpy ->
    python) so that ``to_dict()``/``from_dict()`` round-trip exactly and the
    signed bytes are stable, then parsed strictly, so this cannot emit an
    envelope the verifier would refuse to read. Used by :func:`envelope_v2`
    and by the canonical test vectors.
    """
    plain = json.loads(canonical_bytes(_to_jsonable(dict(body))))
    unsigned = AuditEnvelopeV2.from_dict(
        {
            **plain,
            "receipt": {
                "sha256": "0" * 64,
                "signature_alg": SIGNATURE_ALG,
                "signature_b64": base64.b64encode(bytes(64)).decode("ascii"),
                "public_key_pem": signer.public_key_pem(),
            },
        }
    )
    signing_input = unsigned.signing_input()
    signature = signer.sign(signing_input)
    unsigned.receipt = {
        "sha256": sha256_hex(signing_input),
        "signature_alg": SIGNATURE_ALG,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "public_key_pem": signer.public_key_pem(),
    }
    return unsigned


# ---------------------------------------------------------------------------
# Format dispatch
# ---------------------------------------------------------------------------


def parse_envelope(data: Mapping[str, Any] | str | bytes) -> AuditEnvelope | AuditEnvelopeV2:
    """Parse an envelope of either format by its declared ``schema``.

    Text input is parsed under the strict policy (duplicate keys, non-finite
    numbers, BOM and the like are refused). v1 envelopes keep their original
    lenient field handling and original canonical bytes; v2 envelopes are
    parsed strictly. Unknown schemas are refused.
    """
    if isinstance(data, str | bytes | bytearray):
        data = loads_strict(data)
    if not isinstance(data, Mapping):
        raise EnvelopeFormatError("BAD_TYPE", "envelope must be a JSON object")
    schema = data.get("schema")
    if schema == SCHEMA_V2:
        return AuditEnvelopeV2.from_dict(data)
    if schema == SCHEMA_V1:
        try:
            return AuditEnvelope.from_dict(data)
        except (KeyError, TypeError, ValueError) as exc:
            raise EnvelopeFormatError("BAD_VALUE", f"malformed v1 envelope: {exc}") from exc
    raise EnvelopeFormatError("BAD_SCHEMA", f"unknown envelope schema {schema!r}")
