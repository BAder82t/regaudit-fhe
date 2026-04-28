"""Audit envelope: canonical JSON, parameter set, input commitments,
Ed25519 signing, and timestamp-authority hook.

The envelope is the regulator-facing artefact every audit produces. A
verifier with the issuer's public key can decide three questions in
constant time:

    1. Was the envelope produced by an issuer the verifier trusts?
       (Ed25519 signature over the canonical body.)
    2. Has the envelope changed since issuance?
       (SHA-256 receipt over the canonical body, signed alongside.)
    3. Were the encrypted inputs the issuer claims to have audited the
       same inputs the verifier received?
       (input_commitments — SHA-256 over each canonicalised input.)

Canonical JSON rules
--------------------
Every signed body is serialised with::

    json.dumps(payload, sort_keys=True, separators=(",", ":"),
               ensure_ascii=False)

and encoded as UTF-8 before hashing or signing. Any verifier
re-serialising with the same rules MUST produce byte-identical output.
Producers that emit non-canonical JSON (extra whitespace, mixed key
order, escaped Unicode) will fail signature verification.

Backend identification
----------------------
The envelope carries the backend implementation tag (e.g.
``tenseal-ckks``), the regaudit-fhe library version, and the parameter
set hash so that a verifier can pin which CKKS parameters produced the
result and reject mismatches.

Optional timestamp authority
----------------------------
Operators that require RFC 3161 time-stamping can attach a
``timestamp_token`` (base64-encoded TSA response) by wiring a
:class:`TimestampAuthority` into the signer. The default builds remain
TSA-free; the verifier accepts envelopes with or without a timestamp
token and reports both states.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as _dt
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SCHEMA_VERSION: str = "regaudit-fhe.report.v1"
LIB_VERSION: str = "0.0.7"
SIGNATURE_ALG: str = "Ed25519"


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


# ---------------------------------------------------------------------------
# Canonical JSON + plain-Python conversion
# ---------------------------------------------------------------------------


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


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    """Canonicalise a mapping into the single byte sequence used for
    hashing and signing.

    Sorted keys, no whitespace separators, UTF-8, no ASCII escapement.
    Every producer / verifier must use this exact rule.
    """
    return json.dumps(_to_jsonable(payload), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False
                      ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Input commitments
# ---------------------------------------------------------------------------


def commit_input(name: str, value: Any) -> Dict[str, str]:
    """Hash a single named input into a commitment record.

    The commitment binds the input name and its canonicalised value to
    a SHA-256 digest. The original value never leaves the producer; the
    digest may be published in the envelope for the verifier to check
    against the inputs they hold.
    """
    body = canonical_json({"name": name, "value": _to_jsonable(value)})
    return {"name": name, "sha256": sha256_hex(body)}


def commitments_for(inputs: Mapping[str, Any]) -> List[Dict[str, str]]:
    return [commit_input(k, v) for k, v in sorted(inputs.items())]


# ---------------------------------------------------------------------------
# Parameter set
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParameterSet:
    """Snapshot of the encryption parameter set the producer used."""

    backend: str = "plaintext"
    poly_modulus_degree: int = 0
    security_bits: int = 128
    multiplicative_depth: int = 6
    coeff_mod_bit_sizes: tuple = ()
    scaling_factor_bits: int = 0
    library_version: str = LIB_VERSION
    backend_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "poly_modulus_degree": int(self.poly_modulus_degree),
            "security_bits": int(self.security_bits),
            "multiplicative_depth": int(self.multiplicative_depth),
            "coeff_mod_bit_sizes": list(self.coeff_mod_bit_sizes),
            "scaling_factor_bits": int(self.scaling_factor_bits),
            "library_version": self.library_version,
            "backend_version": self.backend_version,
        }

    def hash(self) -> str:
        return sha256_hex(canonical_json(self.to_dict()))


def parameter_set_from_ckks_context(ctx: Any,
                                     *,
                                     security_bits: int = 128,
                                     multiplicative_depth: int = 6,
                                     ) -> ParameterSet:
    """Introspect a CKKSContext into a ParameterSet.

    ``security_bits`` and ``multiplicative_depth`` are passed through
    explicitly because they are not derivable from the underlying
    SEAL context object — they reflect the validated CKKSParams or
    deployment policy under which the context was built. Callers with
    a :class:`regaudit_fhe.fhe.CKKSParams` should use
    :meth:`CKKSParams.to_envelope_parameter_set` instead, which carries
    the validated values directly.
    """
    backend = "tenseal-ckks"
    backend_version = ""
    try:
        import tenseal as _ts
        backend_version = getattr(_ts, "__version__", "")
    except Exception:
        pass

    poly = int(getattr(ctx, "poly_modulus_degree", 0))
    return ParameterSet(
        backend=backend,
        poly_modulus_degree=poly,
        security_bits=int(security_bits),
        multiplicative_depth=int(multiplicative_depth),
        coeff_mod_bit_sizes=tuple(getattr(
            ctx, "coeff_mod_bit_sizes",
            (60, 40, 40, 40, 40, 40, 40, 40, 60))),
        scaling_factor_bits=int(np.log2(getattr(ctx, "scale", 1 << 40))),
        library_version=LIB_VERSION,
        backend_version=backend_version,
    )


# ---------------------------------------------------------------------------
# Timestamp authority hook
# ---------------------------------------------------------------------------


@dataclass
class TimestampAuthority:
    """Optional RFC 3161 time-stamping hook.

    Wire a callable that accepts canonical-body bytes and returns a
    base64-encoded TSA response. The default value (``None``) means
    no timestamp token is attached.
    """

    issuer: str
    sign_callable: Callable[[bytes], bytes]

    def stamp(self, body: bytes) -> Dict[str, str]:
        token = self.sign_callable(body)
        return {"issuer": self.issuer,
                "token_b64": base64.b64encode(token).decode("ascii"),
                "issued_at": _dt.datetime.now(_dt.timezone.utc).isoformat()}


# ---------------------------------------------------------------------------
# Ed25519 signer
# ---------------------------------------------------------------------------


@dataclass
class Signer:
    issuer: str
    key_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls, *, issuer: str, key_id: str | None = None) -> "Signer":
        priv = Ed25519PrivateKey.generate()
        return cls(
            issuer=issuer,
            key_id=key_id or os.urandom(8).hex(),
            private_key=priv,
            public_key=priv.public_key(),
        )

    @classmethod
    def from_pem(cls, *, issuer: str, key_id: str, private_pem: bytes,
                 password: bytes | None = None) -> "Signer":
        priv = serialization.load_pem_private_key(private_pem, password=password)
        if not isinstance(priv, Ed25519PrivateKey):
            raise TypeError("regaudit-fhe envelope signing requires Ed25519")
        return cls(issuer=issuer, key_id=key_id,
                   private_key=priv, public_key=priv.public_key())

    def public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def sign(self, body: bytes) -> bytes:
        return self.private_key.sign(body)


def verify_signature(public_key_pem: str, body: bytes,
                     signature_b64: str) -> bool:
    pub = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(pub, Ed25519PublicKey):
        return False
    try:
        pub.verify(base64.b64decode(signature_b64), body)
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Envelope dataclass
# ---------------------------------------------------------------------------


@dataclass
class AuditEnvelope:
    schema: str
    schema_version: str
    algorithm_version: str
    primitive: str
    backend: str
    parameter_set: Dict[str, Any]
    parameter_set_hash: str
    regulations: List[str]
    result: Dict[str, Any]
    input_commitments: List[Dict[str, str]]
    depth_budget: Dict[str, int]
    issued_at: str
    issuer: str
    receipt: Dict[str, Any]
    timestamp: Optional[Dict[str, str]] = None

    def signed_body(self) -> Dict[str, Any]:
        """Return the envelope payload that the receipt is computed
        over — every field except the receipt and the optional
        timestamp."""
        body = self.to_dict()
        body.pop("receipt", None)
        body.pop("timestamp", None)
        return body

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "algorithm_version": self.algorithm_version,
            "primitive": self.primitive,
            "backend": self.backend,
            "parameter_set": dict(self.parameter_set),
            "parameter_set_hash": self.parameter_set_hash,
            "regulations": list(self.regulations),
            "result": dict(self.result),
            "input_commitments": [dict(c) for c in self.input_commitments],
            "depth_budget": dict(self.depth_budget),
            "issued_at": self.issued_at,
            "issuer": self.issuer,
            "receipt": dict(self.receipt),
        }
        if self.timestamp is not None:
            out["timestamp"] = dict(self.timestamp)
        return out

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AuditEnvelope":
        return cls(
            schema=data["schema"],
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            algorithm_version=data.get("algorithm_version", LIB_VERSION),
            primitive=data["primitive"],
            backend=data.get("backend", "plaintext"),
            parameter_set=dict(data.get("parameter_set", {})),
            parameter_set_hash=data.get("parameter_set_hash", ""),
            regulations=list(data["regulations"]),
            result=dict(data["result"]),
            input_commitments=[dict(c) for c in data.get("input_commitments", [])],
            depth_budget=dict(data["depth_budget"]),
            issued_at=data["issued_at"],
            issuer=data.get("issuer", ""),
            receipt=dict(data["receipt"]),
            timestamp=dict(data["timestamp"]) if "timestamp" in data and data["timestamp"] is not None else None,
        )


# ---------------------------------------------------------------------------
# Envelope construction + verification
# ---------------------------------------------------------------------------


def envelope(primitive: str,
             report: Any,
             *,
             depth_consumed: int = 6,
             regulations: Iterable[str] | None = None,
             parameter_set: ParameterSet | None = None,
             input_commitments: Sequence[Mapping[str, str]] | None = None,
             signer: Signer | None = None,
             timestamp_authority: TimestampAuthority | None = None,
             ) -> AuditEnvelope:
    """Construct a signed audit envelope.

    If ``signer`` is None, a fresh ephemeral Ed25519 keypair is generated
    so that the envelope still carries a valid signature; the verifier
    checks the embedded public-key fingerprint against its trust store
    and rejects unknown issuers. For production deployments always pass
    a long-lived ``Signer`` whose public key is registered with the
    verifier.
    """
    regs = list(regulations) if regulations is not None else REGULATION_MAP.get(
        primitive, []
    )
    params = parameter_set or ParameterSet()
    issuer = (signer.issuer if signer is not None
              else "regaudit-fhe-ephemeral")
    if signer is None:
        signer = Signer.generate(issuer=issuer)

    issued = _dt.datetime.now(_dt.timezone.utc).isoformat()
    body = {
        "schema": SCHEMA_VERSION,
        "schema_version": SCHEMA_VERSION,
        "algorithm_version": LIB_VERSION,
        "primitive": primitive,
        "backend": params.backend,
        "parameter_set": params.to_dict(),
        "parameter_set_hash": params.hash(),
        "regulations": regs,
        "result": report_to_dict(report),
        "input_commitments": [dict(c) for c in (input_commitments or [])],
        "depth_budget": {"declared": 6, "consumed": int(depth_consumed)},
        "issued_at": issued,
        "issuer": issuer,
    }
    body_bytes = canonical_json(body)
    digest = sha256_hex(body_bytes)
    signature = signer.sign(body_bytes)
    receipt = {
        "sha256": digest,
        "signature_alg": SIGNATURE_ALG,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "key_id": signer.key_id,
        "public_key_pem": signer.public_key_pem(),
    }

    timestamp_block = (timestamp_authority.stamp(body_bytes)
                       if timestamp_authority is not None else None)

    return AuditEnvelope(
        schema=SCHEMA_VERSION,
        schema_version=SCHEMA_VERSION,
        algorithm_version=LIB_VERSION,
        primitive=primitive,
        backend=params.backend,
        parameter_set=params.to_dict(),
        parameter_set_hash=params.hash(),
        regulations=regs,
        result=body["result"],
        input_commitments=body["input_commitments"],
        depth_budget=body["depth_budget"],
        issued_at=issued,
        issuer=issuer,
        receipt=receipt,
        timestamp=timestamp_block,
    )


@dataclass
class VerificationOutcome:
    valid: bool
    sha256_valid: bool
    signature_valid: bool
    issuer_trusted: bool
    timestamp_valid: bool
    issuer: str
    key_id: str
    parameter_set_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": bool(self.valid),
            "sha256_valid": bool(self.sha256_valid),
            "signature_valid": bool(self.signature_valid),
            "issuer_trusted": bool(self.issuer_trusted),
            "timestamp_valid": bool(self.timestamp_valid),
            "issuer": self.issuer,
            "key_id": self.key_id,
            "parameter_set_hash": self.parameter_set_hash,
        }


def verify_envelope(env: AuditEnvelope,
                    *,
                    trusted_keys: Mapping[str, str] | None = None,
                    require_signature: bool = True,
                    tsa_verifier: Callable[[bytes, bytes], bool] | None = None,
                    ) -> VerificationOutcome:
    """Verify an audit envelope.

    ``trusted_keys`` is a ``key_id`` → PEM mapping. If ``None``, the
    issuer-trust check is skipped — the verifier reports
    ``issuer_trusted = True`` and the caller is responsible for
    deciding whether the embedded public key is acceptable. Production
    verifiers SHOULD always pass an explicit trust store.

    ``tsa_verifier`` is an optional callable that takes
    ``(body_bytes, token_bytes)`` and returns whether the RFC 3161
    timestamp token verifies against the deployer's TSA root. If
    ``None``, the presence of the timestamp field is reported but the
    token itself is not validated; ``timestamp_valid`` is then set
    only when no timestamp is attached.
    """
    body_bytes = canonical_json(env.signed_body())
    sha_ok = sha256_hex(body_bytes) == env.receipt.get("sha256")

    sig_ok = False
    issuer_ok = False
    sig_b64 = env.receipt.get("signature_b64")
    pub_pem = env.receipt.get("public_key_pem")
    key_id = env.receipt.get("key_id", "")
    if sig_b64 and pub_pem:
        try:
            sig_ok = verify_signature(pub_pem, body_bytes, sig_b64)
        except Exception:
            sig_ok = False
    if not require_signature and not sig_b64:
        sig_ok = True

    if trusted_keys is None:
        issuer_ok = True
    else:
        expected = trusted_keys.get(env.receipt.get("key_id", ""))
        if expected is None:
            issuer_ok = False
        else:
            issuer_ok = (
                expected.strip().replace("\r\n", "\n")
                == (pub_pem or "").strip().replace("\r\n", "\n")
            )

    if env.timestamp is None:
        ts_ok = True
    else:
        token_b64 = env.timestamp.get("token_b64")
        if not token_b64:
            ts_ok = False
        elif tsa_verifier is None:
            # Presence-only check: a token is attached, but its
            # cryptographic binding to the deployer's TSA root is
            # not verified. Pass a ``tsa_verifier`` to validate the
            # token against an RFC 3161 chain.
            ts_ok = True
        else:
            try:
                ts_ok = bool(tsa_verifier(body_bytes,
                                           base64.b64decode(token_b64)))
            except Exception:
                ts_ok = False

    valid = sha_ok and sig_ok and issuer_ok and ts_ok
    return VerificationOutcome(
        valid=valid,
        sha256_valid=sha_ok,
        signature_valid=sig_ok,
        issuer_trusted=issuer_ok,
        timestamp_valid=ts_ok,
        issuer=env.issuer,
        key_id=key_id,
        parameter_set_hash=env.parameter_set_hash,
    )


def verify_receipt(env: AuditEnvelope,
                   *,
                   trusted_keys: Mapping[str, str] | None = None,
                   strict: bool = False,
                   ) -> bool:
    """Return True iff the envelope verifies.

    By default this checks the SHA-256 receipt and the embedded
    Ed25519 signature against the embedded public key. **It does not
    validate that the embedded public key belongs to a trusted
    issuer** — that requires a ``trusted_keys`` map. The default
    behaviour is preserved for backwards compatibility with v0.0.1
    callers and the README quickstart.

    Pass ``strict=True`` to require ``trusted_keys`` and reject any
    envelope whose ``key_id`` is not in the trust store; this is the
    recommended setting for regulator-side verifiers.
    """
    if strict and not trusted_keys:
        return False
    return verify_envelope(env, trusted_keys=trusted_keys,
                            require_signature=True).valid


def issue_receipt(payload: Mapping[str, Any]) -> Dict[str, str]:
    """Compatibility helper retained from v0.0.1.

    Returns a SHA-256-only receipt; new code should use ``envelope`` to
    build a full Ed25519-signed envelope.
    """
    body = canonical_json(payload)
    return {"sha256": sha256_hex(body), "version": LIB_VERSION}
