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
import contextlib
import dataclasses
import datetime as _dt
import hashlib
import json
import math
import os
import threading
import warnings
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import numpy as np
from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._time import parse_rfc3339
from .canonical import decode_canonical_b64
from .trust import TrustStore

SCHEMA_VERSION: str = "regaudit-fhe.report.v1"
LIB_VERSION: str = "0.1.0"
SIGNATURE_ALG: str = "Ed25519"


REGULATION_MAP: dict[str, list[str]] = {
    "fairness": [
        "NYC_LL144",
        "EU_AI_ACT_ART10",
        "EU_AI_ACT_ART15",
        "COLORADO_AI_ACT",
        "CFPB_ALG_DISCRIM",
    ],
    "provenance": ["EU_AI_ACT_ART10", "21_CFR_PART_11", "GDPR_ART22", "HIPAA"],
    "concordance": ["FDA_SAMD_PCCP", "EU_AI_ACT_ART15", "EMA_AI_GUIDANCE"],
    "calibration": ["FDA_SAMD_UQ", "EU_AI_ACT_ART15", "ISO_IEC_23053", "UNECE_WP29"],
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


def _require_finite(value: Any, where: str) -> None:
    """Refuse NaN/Infinity anywhere in ``value``.

    ``canonical_json`` would sign the non-standard literals ``NaN``/``Infinity``, but every
    standards-conforming JSON writer (including the HTTP layer) delivers ``null`` instead, so the
    delivered report could no longer match its own signature.
    """
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{where} contains a non-finite number; refusing to sign it")
    elif isinstance(value, Mapping):
        for item in value.values():
            _require_finite(item, where)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _require_finite(item, where)


def report_to_dict(report: Any) -> dict[str, Any]:
    if dataclasses.is_dataclass(report) and not isinstance(report, type):
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
    return json.dumps(
        _to_jsonable(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Input commitments
# ---------------------------------------------------------------------------


def commit_input(name: str, value: Any) -> dict[str, str]:
    """Hash a single named input into a commitment record.

    The commitment binds the input name and its canonicalised value to
    a SHA-256 digest. The original value never leaves the producer; the
    digest may be published in the envelope for the verifier to check
    against the inputs they hold.
    """
    body = canonical_json({"name": name, "value": _to_jsonable(value)})
    return {"name": name, "sha256": sha256_hex(body)}


def commitments_for(inputs: Mapping[str, Any]) -> list[dict[str, str]]:
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

    def to_dict(self) -> dict[str, Any]:
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


def parameter_set_from_ckks_context(
    ctx: Any,
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
    with contextlib.suppress(Exception):
        import tenseal as _ts

        backend_version = getattr(_ts, "__version__", "")

    poly = int(getattr(ctx, "poly_modulus_degree", 0))
    return ParameterSet(
        backend=backend,
        poly_modulus_degree=poly,
        security_bits=int(security_bits),
        multiplicative_depth=int(multiplicative_depth),
        coeff_mod_bit_sizes=tuple(
            getattr(ctx, "coeff_mod_bit_sizes", (60, 40, 40, 40, 40, 40, 40, 40, 60))
        ),
        scaling_factor_bits=int(np.log2(getattr(ctx, "scale", 1 << 40))),
        library_version=LIB_VERSION,
        backend_version=backend_version,
    )


def parameter_set_from_openfhe_context(
    ctx: Any,
    *,
    security_bits: int = 128,
    multiplicative_depth: int = 6,
) -> ParameterSet:
    """Introspect an :class:`regaudit_fhe.fhe.openfhe.OpenFHEContext` into a
    ``ParameterSet`` tagged ``openfhe-ckks``.

    The envelope's ``parameter_set_hash`` therefore pins the OpenFHE
    backend distinctly from TenSEAL, so a verifier can require a specific
    implementation. ``scaling_factor_bits`` is read from the context's
    ``scale_bits``; the multiplicative depth reflects the audit budget,
    not the larger modulus chain the context provisions for headroom.
    """
    backend_version = ""
    with contextlib.suppress(Exception):
        import openfhe as _openfhe

        backend_version = getattr(_openfhe, "__version__", "")

    n_slots = int(getattr(ctx, "n_slots", 0))
    return ParameterSet(
        backend="openfhe-ckks",
        poly_modulus_degree=n_slots * 2,
        security_bits=int(security_bits),
        multiplicative_depth=int(multiplicative_depth),
        coeff_mod_bit_sizes=(),
        scaling_factor_bits=int(getattr(ctx, "scale_bits", 40)),
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

    def stamp(self, body: bytes) -> dict[str, str]:
        token = self.sign_callable(body)
        return {
            "issuer": self.issuer,
            "token_b64": base64.b64encode(token).decode("ascii"),
            "issued_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# Key custody seam
# ---------------------------------------------------------------------------


@runtime_checkable
class KeyProvider(Protocol):
    """The signing capability the envelope builder depends on.

    Anything that can name an issuer + key, expose an Ed25519 public key
    as PEM, and produce a detached signature over canonical-body bytes is
    a valid key provider. The in-process :class:`Signer` is one
    implementation; :class:`CallableKeyProvider` wraps an external
    custodian (AWS KMS, GCP KMS, a PKCS#11 HSM, a remote signing service)
    so the private key never enters the audit host's address space — the
    deployment posture the server module and threat model call for.
    """

    issuer: str
    key_id: str

    def public_key_pem(self) -> str:  # pragma: no cover - structural
        ...

    def sign(self, body: bytes) -> bytes:  # pragma: no cover - structural
        ...


@dataclass
class CallableKeyProvider:
    """Key provider backed by an out-of-process signing callable.

    The private key is held by an external custodian; only its Ed25519
    public key (as PEM) and a ``sign_callable`` that returns a 64-byte
    detached Ed25519 signature over the given bytes cross into this
    process. Use this to keep envelope signing keys in a KMS/HSM.

    Example (AWS KMS, Ed25519 / "EdDSA" key)::

        import boto3
        kms = boto3.client("kms")

        def kms_sign(body: bytes) -> bytes:
            resp = kms.sign(
                KeyId="alias/regaudit-issuer",
                Message=body,
                MessageType="RAW",
                SigningAlgorithm="EDDSA",
            )
            return resp["Signature"]

        provider = CallableKeyProvider(
            issuer="acme-health",
            key_id="alias/regaudit-issuer",
            public_pem=open("issuer.pub.pem").read(),
            sign_callable=kms_sign,
        )
        env = envelope("fairness", report, signer=provider)

    The provided ``public_pem`` is validated as an Ed25519 key at
    construction time, and every signature the callable returns is
    verified against it before the envelope is emitted, so a
    misconfigured custodian fails closed instead of shipping an
    unverifiable envelope.
    """

    issuer: str
    key_id: str
    public_pem: str
    sign_callable: Callable[[bytes], bytes]

    def __post_init__(self) -> None:
        pub = serialization.load_pem_public_key(self.public_pem.encode("ascii"))
        if not isinstance(pub, Ed25519PublicKey):
            raise TypeError("CallableKeyProvider requires an Ed25519 public key PEM")
        self._public_key = pub

    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def sign(self, body: bytes) -> bytes:
        signature = self.sign_callable(body)
        if not isinstance(signature, (bytes, bytearray)):
            raise TypeError("sign_callable must return raw signature bytes")
        signature = bytes(signature)
        try:
            self._public_key.verify(signature, body)
        except _CryptoInvalidSignature as exc:
            raise ValueError(
                "external sign_callable returned a signature that does not "
                "verify against the configured public key"
            ) from exc
        return signature


# ---------------------------------------------------------------------------
# Ed25519 signer (in-process key custody)
# ---------------------------------------------------------------------------


@dataclass
class Signer:
    issuer: str
    key_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls, *, issuer: str, key_id: str | None = None) -> Signer:
        priv = Ed25519PrivateKey.generate()
        return cls(
            issuer=issuer,
            key_id=key_id or os.urandom(8).hex(),
            private_key=priv,
            public_key=priv.public_key(),
        )

    @classmethod
    def from_pem(
        cls, *, issuer: str, key_id: str, private_pem: bytes, password: bytes | None = None
    ) -> Signer:
        priv = serialization.load_pem_private_key(private_pem, password=password)
        if not isinstance(priv, Ed25519PrivateKey):
            raise TypeError("regaudit-fhe envelope signing requires Ed25519")
        return cls(issuer=issuer, key_id=key_id, private_key=priv, public_key=priv.public_key())

    def public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def sign(self, body: bytes) -> bytes:
        return self.private_key.sign(body)


def verify_signature(public_key_pem: str, body: bytes, signature_b64: str) -> bool:
    pub = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(pub, Ed25519PublicKey):
        return False
    try:
        # Canonical base64 only: the receipt text is outside the v1 signature, so a
        # lenient decoder would let anyone vary it without changing the bytes.
        signature = decode_canonical_b64(signature_b64, length=64)
    except ValueError:
        return False
    try:
        pub.verify(signature, body)
        return True
    except _CryptoInvalidSignature:
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
    parameter_set: dict[str, Any]
    parameter_set_hash: str
    regulations: list[str]
    result: dict[str, Any]
    input_commitments: list[dict[str, str]]
    depth_budget: dict[str, int]
    issued_at: str
    issuer: str
    receipt: dict[str, Any]
    timestamp: dict[str, str] | None = None
    dp: dict[str, Any] | None = None

    def signed_body(self) -> dict[str, Any]:
        """Return the envelope payload that the receipt is computed
        over — every field except the receipt and the optional
        timestamp. The ``dp`` block, when present, IS signed: a verifier
        must be able to trust the disclosed noise parameters."""
        body = self.to_dict()
        body.pop("receipt", None)
        body.pop("timestamp", None)
        return body

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
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
        if self.dp is not None:
            out["dp"] = _to_jsonable(self.dp)
        if self.timestamp is not None:
            out["timestamp"] = dict(self.timestamp)
        return out

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AuditEnvelope:
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
            timestamp=dict(data["timestamp"])
            if "timestamp" in data and data["timestamp"] is not None
            else None,
            dp=dict(data["dp"]) if "dp" in data and data["dp"] is not None else None,
        )


# ---------------------------------------------------------------------------
# Envelope construction + verification
# ---------------------------------------------------------------------------


def envelope(
    primitive: str,
    report: Any,
    *,
    depth_consumed: int = 6,
    regulations: Iterable[str] | None = None,
    parameter_set: ParameterSet | None = None,
    input_commitments: Sequence[Mapping[str, str]] | None = None,
    signer: Signer | KeyProvider | None = None,
    timestamp_authority: TimestampAuthority | None = None,
    dp: Mapping[str, Any] | None = None,
) -> AuditEnvelope:
    """Construct a signed audit envelope.

    If ``signer`` is None, a fresh ephemeral Ed25519 keypair is generated
    so that the envelope still carries a valid signature; the verifier
    checks the embedded public-key fingerprint against its trust store
    and rejects unknown issuers. For production deployments always pass
    a long-lived ``Signer`` whose public key is registered with the
    verifier.

    ``dp`` is the optional differential-privacy disclosure block returned
    by :func:`regaudit_fhe.dp.privatize_report`. When present it is folded
    into the signed body so a verifier can trust the disclosed mechanism,
    epsilon, and sensitivity alongside the noised ``result``.
    """
    regs = list(regulations) if regulations is not None else REGULATION_MAP.get(primitive, [])
    params = parameter_set or ParameterSet()
    issuer = signer.issuer if signer is not None else "regaudit-fhe-ephemeral"
    if signer is None:
        signer = Signer.generate(issuer=issuer)

    issued = _dt.datetime.now(_dt.timezone.utc).isoformat()
    result_dict: dict[str, Any] = report_to_dict(report)
    commitments_list: list[dict[str, str]] = [dict(c) for c in (input_commitments or [])]
    # "declared" is the circuit-wide ceiling (MAX_DEPTH), not the per-primitive
    # DECLARED_DEPTH; "consumed" is the observed depth for this call.
    depth_budget_dict: dict[str, int] = {
        "declared": 6,
        "consumed": int(depth_consumed),
    }
    dp_block: dict[str, Any] | None = _to_jsonable(dict(dp)) if dp is not None else None
    _require_finite(result_dict, "the audit result")
    _require_finite(dp_block, "the dp block")
    body: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "schema_version": SCHEMA_VERSION,
        "algorithm_version": LIB_VERSION,
        "primitive": primitive,
        "backend": params.backend,
        "parameter_set": params.to_dict(),
        "parameter_set_hash": params.hash(),
        "regulations": regs,
        "result": result_dict,
        "input_commitments": commitments_list,
        "depth_budget": depth_budget_dict,
        "issued_at": issued,
        "issuer": issuer,
    }
    if dp_block is not None:
        body["dp"] = dp_block
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

    timestamp_block = (
        timestamp_authority.stamp(body_bytes) if timestamp_authority is not None else None
    )

    return AuditEnvelope(
        schema=SCHEMA_VERSION,
        schema_version=SCHEMA_VERSION,
        algorithm_version=LIB_VERSION,
        primitive=primitive,
        backend=params.backend,
        parameter_set=params.to_dict(),
        parameter_set_hash=params.hash(),
        regulations=regs,
        result=result_dict,
        input_commitments=commitments_list,
        depth_budget=depth_budget_dict,
        issued_at=issued,
        issuer=issuer,
        receipt=receipt,
        timestamp=timestamp_block,
        dp=dp_block,
    )


TRUST_TRUSTED = "TRUSTED"
TRUST_SELF_SIGNED_ONLY = "SELF_SIGNED_ONLY"
TRUST_INVALID = "INVALID"

TS_ABSENT = "ABSENT"
TS_UNVERIFIED = "UNVERIFIED"
TS_VERIFIED = "VERIFIED"
TS_FAILED = "FAILED"


@dataclass
class VerificationOutcome:
    """Result of :func:`verify_envelope`.

    ``trust_status`` is the field to branch on:

    * ``TRUSTED`` — integrity holds AND the issuer key is registered in the
      supplied trust material, not revoked, and matches any pin.
    * ``SELF_SIGNED_ONLY`` — integrity holds but no trust material was
      supplied, so the issuer is unauthenticated.
    * ``INVALID`` — integrity, issuer, revocation, pin or timestamp policy
      failed.

    ``valid`` keeps its v1 meaning (integrity, plus issuer match when trust
    material is supplied) so existing callers keep working. It does NOT imply
    that the issuer is trusted when no trust material was supplied; use
    ``trust_status == "TRUSTED"`` for that.
    """

    # Backing store of the deprecated ``valid`` property (use ``trust_status`` or
    # ``regaudit_fhe.verify_report(...).accepted``). Excluded from repr/eq.
    _valid: bool = field(repr=False, compare=False)
    sha256_valid: bool
    signature_valid: bool
    issuer_trusted: bool
    timestamp_valid: bool
    issuer: str
    key_id: str
    parameter_set_hash: str
    trust_status: str = TRUST_SELF_SIGNED_ONLY
    timestamp_status: str = TS_ABSENT
    revoked: bool = False
    pin_ok: bool = True

    @property
    def valid(self) -> bool:
        """Deprecated alias; branch on ``trust_status`` instead."""
        warnings.warn(
            "VerificationOutcome.valid is deprecated; branch on `trust_status` (or use "
            "regaudit_fhe.verify_report(...).accepted). It is kept for compatibility.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._valid

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": bool(self._valid),
            "sha256_valid": bool(self.sha256_valid),
            "signature_valid": bool(self.signature_valid),
            "issuer_trusted": bool(self.issuer_trusted),
            "timestamp_valid": bool(self.timestamp_valid),
            "issuer": self.issuer,
            "key_id": self.key_id,
            "parameter_set_hash": self.parameter_set_hash,
            "trust_status": self.trust_status,
            "timestamp_status": self.timestamp_status,
            "revoked": bool(self.revoked),
            "pin_ok": bool(self.pin_ok),
        }


def _norm_pem(pem: str) -> str:
    return pem.strip().replace("\r\n", "\n")


def _timestamp_status(
    env: AuditEnvelope,
    body_bytes: bytes,
    tsa_verifier: Callable[[bytes, bytes], bool] | None,
) -> str:
    if env.timestamp is None:
        return TS_ABSENT
    token_b64 = env.timestamp.get("token_b64")
    if not token_b64:
        return TS_FAILED
    if tsa_verifier is None:
        # A token is attached but nothing validated it. Never report this
        # as VERIFIED: the timestamp block is also outside the v1 signed body.
        return TS_UNVERIFIED
    try:
        token = decode_canonical_b64(token_b64)
        return TS_VERIFIED if tsa_verifier(body_bytes, token) else TS_FAILED
    except Exception:
        return TS_FAILED


def _v1_entry_scope_ok(entry: Any, env: AuditEnvelope) -> bool:
    """Whether a v1 report is within the scope registered for its key."""
    if entry is None:
        return False
    if entry.issuer is not None and env.issuer != entry.issuer:
        return False
    if entry.deployments is not None:  # v1 carries no deployment_id, so it cannot match
        return False
    if entry.primitives is not None and (
        not isinstance(env.primitive, str) or env.primitive not in entry.primitives
    ):
        return False
    if entry.not_before is not None:
        try:
            if parse_rfc3339(env.issued_at) < entry.not_before:
                return False
        except ValueError:
            return False
    return True


def verify_envelope(
    env: AuditEnvelope,
    *,
    trusted_keys: Mapping[str, str] | TrustStore | None = None,
    trust_store: TrustStore | None = None,
    require_signature: bool = True,
    tsa_verifier: Callable[[bytes, bytes], bool] | None = None,
    require_verified_timestamp: bool = False,
) -> VerificationOutcome:
    """Verify an audit envelope.

    Trust material is a :class:`~regaudit_fhe.trust.TrustStore` (preferred;
    passed as ``trust_store`` or, for convenience, as ``trusted_keys``) or a
    legacy ``key_id`` → PEM mapping. A plain mapping cannot express
    revocation or pins, so only a ``TrustStore`` enforces them. When trust
    material is supplied the signature is verified against the *registered*
    key, never the key embedded in the envelope, and the result is
    ``INVALID`` unless the issuer is registered, not revoked and matches any
    pin.

    With no trust material the envelope can only be ``SELF_SIGNED_ONLY``:
    integrity is checked but the issuer is unauthenticated, and
    ``issuer_trusted`` is ``False``.

    ``tsa_verifier`` takes ``(body_bytes, token_bytes)`` and returns whether
    the RFC 3161 token verifies against the deployer's TSA root. Without it
    an attached timestamp is ``UNVERIFIED`` (``timestamp_valid`` is False).
    ``require_verified_timestamp`` makes anything other than ``VERIFIED`` or
    ``ABSENT`` fail the trust decision. A verified timestamp never overrides
    revocation.
    """
    store: TrustStore | None = trust_store
    keys: Mapping[str, str] | None = None
    if isinstance(trusted_keys, TrustStore):
        store = store if store is not None else trusted_keys
    elif trusted_keys is not None:
        keys = trusted_keys
    has_trust_material = store is not None or keys is not None

    body_bytes = canonical_json(env.signed_body())
    sha_ok = sha256_hex(body_bytes) == env.receipt.get("sha256")

    sig_b64 = env.receipt.get("signature_b64")
    pub_pem = env.receipt.get("public_key_pem") or ""
    key_id = env.receipt.get("key_id", "")

    revoked = False
    pin_ok = True
    registered_pem: str | None = None
    if store is not None:
        registered_pem = store.expected_pem(key_id)
        revoked = store.is_revoked(key_id)
        pinned = store.expected_parameter_set_hash(key_id)
        pin_ok = pinned is None or pinned == env.parameter_set_hash
    elif keys is not None:
        registered_pem = keys.get(key_id)

    issuer_ok = False
    if has_trust_material and registered_pem is not None:
        issuer_ok = _norm_pem(registered_pem) == _norm_pem(pub_pem) and not revoked and pin_ok
        if issuer_ok and store is not None:
            # An ``entries`` store also scopes a key: the signed issuer name,
            # the primitive, the deployment (a v1 report names none) and the
            # validity start. The shared engine enforces the same rules.
            issuer_ok = _v1_entry_scope_ok(store.entry(key_id), env)

    # Verify against the registered key when we have one; the embedded key is
    # only authoritative when there is no trust material at all.
    verify_pem = registered_pem if has_trust_material else pub_pem
    sig_ok = False
    sig_verified = False
    if sig_b64 and verify_pem:
        try:
            sig_ok = verify_signature(verify_pem, body_bytes, sig_b64)
        except Exception:
            sig_ok = False
        sig_verified = sig_ok
    if not require_signature and not sig_b64 and not has_trust_material:
        # Unsigned envelopes are only tolerated when no issuer is being
        # authenticated; with trust material a signature is always required.
        sig_ok = True

    ts_status = _timestamp_status(env, body_bytes, tsa_verifier)
    ts_ok = ts_status in (TS_ABSENT, TS_VERIFIED)
    ts_policy_ok = ts_ok if require_verified_timestamp else ts_status != TS_FAILED

    integrity_ok = sha_ok and sig_ok
    if has_trust_material:
        valid = integrity_ok and issuer_ok and ts_policy_ok
        trusted = valid and sig_verified
        trust_status = TRUST_TRUSTED if trusted else TRUST_INVALID
    else:
        valid = integrity_ok and ts_policy_ok
        trust_status = TRUST_SELF_SIGNED_ONLY if valid else TRUST_INVALID

    return VerificationOutcome(
        _valid=valid,
        sha256_valid=sha_ok,
        signature_valid=sig_ok,
        issuer_trusted=has_trust_material and issuer_ok,
        timestamp_valid=ts_ok,
        issuer=env.issuer,
        key_id=key_id,
        parameter_set_hash=env.parameter_set_hash,
        trust_status=trust_status,
        timestamp_status=ts_status,
        revoked=revoked,
        pin_ok=pin_ok,
    )


def verify_envelope_or_raise(
    env: AuditEnvelope,
    *,
    trust_store: TrustStore | None = None,
    tsa_verifier: Callable[[bytes, bytes], bool] | None = None,
    require_verified_timestamp: bool = False,
) -> VerificationOutcome:
    """Verify an envelope and raise a typed exception on the first
    failure reason, ordered most-specific first.

    Use this in regulator-side code that wants to react differently to
    each failure mode (untrusted issuer, revoked issuer, parameter-set
    mismatch, hash mismatch, bad signature, timestamp) instead of a flat
    boolean. Returns the underlying :class:`VerificationOutcome` on success.

    A ``TrustStore`` is required: this function never silently accepts
    self-asserted issuers. Callers that genuinely want the legacy weak
    path should call :func:`verify_envelope` or :func:`verify_receipt`
    directly. With ``require_verified_timestamp`` an attached timestamp that
    no ``tsa_verifier`` validated raises ``TimestampUnverified``; a timestamp
    that fails validation always raises ``TimestampInvalid``.
    """
    from .trust import (
        HashMismatch,
        InvalidSignature,
        RevokedIssuer,
        TimestampInvalid,
        TimestampUnverified,
        UntrustedIssuer,
        WrongParameterSet,
    )

    if trust_store is None or not isinstance(trust_store, TrustStore):
        raise TypeError(
            "verify_envelope_or_raise requires a TrustStore; pass one "
            "loaded with TrustStore.from_json(...). The legacy untrusted "
            "path is available via verify_envelope() / verify_receipt()."
        )

    key_id = env.receipt.get("key_id", "")

    if not trust_store.is_known(key_id):
        raise UntrustedIssuer(f"key_id {key_id!r} is not in the trust store")
    if trust_store.is_revoked(key_id):
        raise RevokedIssuer(f"key_id {key_id!r} is in the trust store's revocation set")
    pinned_hash = trust_store.expected_parameter_set_hash(key_id)
    if pinned_hash is not None and pinned_hash != env.parameter_set_hash:
        raise WrongParameterSet(
            f"key_id {key_id!r}: envelope parameter_set_hash="
            f"{env.parameter_set_hash!r} does not match pinned value "
            f"{pinned_hash!r}"
        )

    outcome = verify_envelope(
        env,
        trust_store=trust_store,
        require_signature=True,
        tsa_verifier=tsa_verifier,
    )

    if not outcome.sha256_valid:
        raise HashMismatch("SHA-256 receipt does not match canonical body")
    if not outcome.signature_valid:
        raise InvalidSignature(
            "Ed25519 signature does not verify against the key registered in the trust store"
        )
    if not outcome.issuer_trusted:
        # Reaching this branch means the trust store had the key_id but
        # the embedded PEM disagreed with the registered PEM.
        raise UntrustedIssuer(
            f"key_id {key_id!r}: the report is not authorised by the trust store (embedded "
            f"key, issuer name, primitive, deployment or validity start does not match "
            f"the registered entry)"
        )
    if outcome.timestamp_status == TS_FAILED:
        raise TimestampInvalid(
            "RFC 3161 timestamp token failed validation against the deployer's TSA root"
        )
    if require_verified_timestamp and outcome.timestamp_status == TS_UNVERIFIED:
        raise TimestampUnverified(
            "a timestamp is attached but no tsa_verifier validated it, and the "
            "policy requires verified timestamp evidence"
        )
    return outcome


class _OnceFlag:
    """A thread-safe "first caller wins" flag.

    Replaces a module-level boolean mutated through ``global``: the check and the
    set happen under one lock, so a warning guarded by it fires exactly once even
    when many threads reach it together, and tests can ``reset()`` it.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._done = False

    def first(self) -> bool:
        """True for exactly one caller until :meth:`reset`."""
        with self._lock:
            if self._done:
                return False
            self._done = True
            return True

    def reset(self) -> None:
        with self._lock:
            self._done = False


_WEAK_WARNING = _OnceFlag()


def verify_receipt(
    env: AuditEnvelope,
    *,
    trusted_keys: Mapping[str, str] | TrustStore | None = None,
    trust_store: TrustStore | None = None,
    strict: bool = False,
) -> bool:
    """Return True iff the envelope verifies.

    By default this checks the SHA-256 receipt and the embedded
    Ed25519 signature against the embedded public key. **It does not
    validate that the embedded public key belongs to a trusted
    issuer** — that requires trust material. The default behaviour is
    preserved for backwards compatibility with v0.0.1 callers and the README
    quickstart; use :func:`verify_envelope` and branch on ``trust_status``
    when you need to tell self-signed from trusted.

    Trust material is a :class:`~regaudit_fhe.trust.TrustStore`
    (``trust_store=``, or passed as ``trusted_keys``) which enforces
    registration, revocation and parameter-set pins, or a legacy
    ``key_id`` → PEM mapping, which enforces registration only.

    Pass ``strict=True`` to require trust material and reject any
    envelope whose ``key_id`` is not registered; this is the recommended
    setting for regulator-side verifiers. Calling without trust material
    emits a one-time ``UserWarning`` so integrators do not silently rely on
    hash-and-self-signature verification.
    """
    # ``is not None``, not truthiness: an empty mapping is trust material that
    # trusts nobody (e.g. a map that failed to load), never the self-signed path.
    has_material = trust_store is not None or trusted_keys is not None
    if strict and not has_material:
        return False
    if not has_material and _WEAK_WARNING.first():
        warnings.warn(
            "verify_receipt() called without trust material: this verifies "
            "the embedded signature against the embedded public key only "
            "and does NOT authenticate the issuer. Pass trust_store=TrustStore(...) "
            "or trusted_keys={key_id: pem} (and strict=True for regulator-side "
            "verifiers) to bind the envelope to an approved issuer.",
            UserWarning,
            stacklevel=2,
        )
    outcome = verify_envelope(
        env,
        trusted_keys=trusted_keys,
        trust_store=trust_store,
        require_signature=True,
    )
    return bool(outcome._valid)


def issue_receipt(payload: Mapping[str, Any]) -> dict[str, str]:
    """Compatibility helper retained from v0.0.1.

    Returns a SHA-256-only receipt; new code should use ``envelope`` to
    build a full Ed25519-signed envelope.
    """
    body = canonical_json(payload)
    return {"sha256": sha256_hex(body), "version": LIB_VERSION}
