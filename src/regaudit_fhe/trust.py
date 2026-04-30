"""Trust-store types for regulator-side verifiers.

A :class:`TrustStore` binds Ed25519 ``key_id`` values to the PEM-encoded
public keys the verifier is willing to accept, plus optional revocation
and parameter-set pinning. It is the canonical input to
:func:`regaudit_fhe.reports.verify_envelope_or_raise`; passing a hand-
rolled ``dict[str, str]`` to ``trusted_keys`` still works for backward
compatibility, but verifiers SHOULD prefer ``TrustStore`` so the file
shape is validated and revocation/pinning are first-class.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class TrustStoreError(ValueError):
    """Raised when a trust-store payload is malformed."""


# ---------------------------------------------------------------------------
# Verification exceptions (typed reasons for verify_envelope_or_raise)
# ---------------------------------------------------------------------------


class EnvelopeVerificationError(Exception):
    """Base class for typed envelope verification failures."""


class HashMismatch(EnvelopeVerificationError):
    """The SHA-256 receipt does not match the canonical body."""


class InvalidSignature(EnvelopeVerificationError):
    """The Ed25519 signature does not verify against the embedded key."""


class UntrustedIssuer(EnvelopeVerificationError):
    """The envelope's ``key_id`` is not in the trust store, or the
    embedded public key disagrees with the registered key."""


class RevokedIssuer(EnvelopeVerificationError):
    """The envelope's ``key_id`` is present in the trust store's
    revocation set."""


class WrongParameterSet(EnvelopeVerificationError):
    """The envelope's ``parameter_set_hash`` does not match the value
    pinned for this issuer."""


class TimestampInvalid(EnvelopeVerificationError):
    """The RFC 3161 timestamp token did not verify against the
    deployer's TSA root (only raised when a ``tsa_verifier`` was
    supplied)."""


# ---------------------------------------------------------------------------
# TrustStore
# ---------------------------------------------------------------------------


def _normalise_pem(pem: str) -> str:
    """Canonicalise a PEM string for byte-stable comparison."""
    return pem.strip().replace("\r\n", "\n")


@dataclass(frozen=True)
class TrustStore:
    """Mapping of ``key_id`` to PEM-encoded Ed25519 public key, with
    optional revocation and parameter-set pinning.

    Use :meth:`from_json` / :meth:`from_dict` to load; do not construct
    directly unless you have already validated the inputs.
    """

    keys: Mapping[str, str]
    revoked: frozenset[str] = field(default_factory=frozenset)
    parameter_set_pins: Mapping[str, str] = field(default_factory=dict)

    # ----- Loaders --------------------------------------------------------

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TrustStore:
        """Build a TrustStore from a JSON-shaped mapping.

        Accepted shapes:

        * ``{"key_id": "PEM", ...}`` — bare mapping (legacy / minimal).
        * ``{"keys": {"key_id": "PEM", ...},
              "revoked": ["key_id", ...],
              "parameter_set_pins": {"key_id": "hex", ...}}`` — full.
        """
        keys: dict[str, str]
        revoked: set[str] = set()
        pins: dict[str, str] = {}

        if "keys" in payload and isinstance(payload["keys"], Mapping):
            raw_keys = payload["keys"]
            raw_revoked = payload.get("revoked", [])
            raw_pins = payload.get("parameter_set_pins", {})
            if not isinstance(raw_revoked, Iterable) or isinstance(
                raw_revoked, (str, bytes)
            ):
                raise TrustStoreError(
                    "trust-store 'revoked' must be a list of key_ids"
                )
            if not isinstance(raw_pins, Mapping):
                raise TrustStoreError(
                    "trust-store 'parameter_set_pins' must be a mapping"
                )
            revoked = {str(r) for r in raw_revoked}
            pins = {str(k): str(v) for k, v in raw_pins.items()}
        else:
            raw_keys = payload

        if not isinstance(raw_keys, Mapping) or not raw_keys:
            raise TrustStoreError(
                "trust-store must declare at least one key_id -> PEM entry"
            )
        keys = {}
        for key_id, pem in raw_keys.items():
            if not isinstance(key_id, str) or not isinstance(pem, str):
                raise TrustStoreError(
                    "trust-store keys must map str key_id to str PEM"
                )
            if "BEGIN PUBLIC KEY" not in pem:
                raise TrustStoreError(
                    f"trust-store entry {key_id!r} is not a PEM public key"
                )
            keys[key_id] = _normalise_pem(pem)

        if revoked - set(keys):
            unknown = sorted(revoked - set(keys))
            raise TrustStoreError(
                f"trust-store 'revoked' references unknown key_id(s): "
                f"{unknown!r}"
            )
        if set(pins) - set(keys):
            unknown = sorted(set(pins) - set(keys))
            raise TrustStoreError(
                f"trust-store 'parameter_set_pins' references unknown "
                f"key_id(s): {unknown!r}"
            )

        return cls(
            keys=keys,
            revoked=frozenset(revoked),
            parameter_set_pins=pins,
        )

    @classmethod
    def from_json(cls, path: str | Path) -> TrustStore:
        """Load a TrustStore from a JSON file."""
        body = Path(path).read_text(encoding="utf-8")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise TrustStoreError(
                f"trust-store {str(path)!r} is not valid JSON: {exc}"
            ) from exc
        return cls.from_dict(payload)

    # ----- Queries --------------------------------------------------------

    def is_known(self, key_id: str) -> bool:
        return key_id in self.keys

    def is_revoked(self, key_id: str) -> bool:
        return key_id in self.revoked

    def expected_pem(self, key_id: str) -> str | None:
        return self.keys.get(key_id)

    def expected_parameter_set_hash(self, key_id: str) -> str | None:
        return self.parameter_set_pins.get(key_id)

    def as_legacy_dict(self) -> dict[str, str]:
        """Render as the ``trusted_keys`` mapping accepted by
        :func:`regaudit_fhe.verify_envelope` and :func:`verify_receipt`."""
        return dict(self.keys)
