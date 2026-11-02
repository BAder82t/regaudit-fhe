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

import os
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from ._keys import spki_fingerprint
from ._time import parse_rfc3339
from .canonical import CanonicalError, loads_strict


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
    """The RFC 3161 timestamp token failed validation: the supplied
    ``tsa_verifier`` rejected it or raised, or the token is missing."""


class TimestampUnverified(EnvelopeVerificationError):
    """A timestamp is attached but no ``tsa_verifier`` was configured, and
    the verification policy requires verified timestamp evidence."""


# ---------------------------------------------------------------------------
# TrustStore
# ---------------------------------------------------------------------------


def _normalise_pem(pem: str) -> str:
    """Canonicalise a PEM string for byte-stable comparison."""
    return pem.strip().replace("\r\n", "\n")


MAX_TRUST_STORE_BYTES = 4 * 1024 * 1024
# Beside a migrated store, because the published versions refuse any unknown member in the store itself. See _read_declared.
ISSUER_PROVENANCE_SUFFIX = ".issuer-provenance.json"
_STATUSES = ("active", "retired", "compromised")
_PRIMITIVE_NAMES = ("fairness", "provenance", "concordance", "calibration", "drift", "disagreement")
_ENTRY_KEYS = frozenset(
    {
        "issuer",
        "public_key_pem",
        "status",
        "not_before",
        "retired_at",
        "compromised_from",
        "deployments",
        "primitives",
        "parameter_set_pin",
    }
)


# Blank or invisible, and not in a category that says so. The rest of what renders as nothing is category C or Z.
_BLANK_CODE_POINTS = frozenset(
    {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2800, 0x3164, 0xFFA0}
    | set(range(0x180B, 0x1810))
    | set(range(0xFE00, 0xFE10))
    | set(range(0xE0100, 0xE01F0))
)


def issuer_name_problem(name: Any) -> str | None:
    """Why ``name`` cannot identify an issuer, or ``None``. The one rule for enrollment, trust-store parsing and migration.

    A name that reads as empty, or that renders the same as another one, is ambiguous, and a comparison is byte for byte. So it
    is refused, and never normalised into another issuer: empty, leading or trailing whitespace, whitespace other than U+0020,
    and control, format (zero-width, bidi), unassigned, private-use or blank characters anywhere. It says nothing about
    look-alike letters, double spaces or Unicode normalisation form: those remain different names.
    """
    if type(name) is not str or not name:
        return "must be a non-empty string"
    if name != name.strip():
        return "must not have leading or trailing whitespace"
    for char in name:
        category = unicodedata.category(char)
        if category[0] == "C" or ord(char) in _BLANK_CODE_POINTS:
            return f"must not contain the invisible or control character U+{ord(char):04X}"
        if category[0] == "Z" and char != " ":
            return f"must not contain whitespace other than U+0020 (found U+{ord(char):04X})"
    return None


@dataclass(frozen=True)
class KeyEntry:
    """One registered signing key and its lifecycle.

    ``status`` is ``active``, ``retired`` (planned rotation; ``retired_at``
    required), ``compromised`` (``compromised_from`` is the earliest time of
    possible exposure; ``None`` means unknown, which is treated as "all
    signatures by this key are untrusted") or ``revoked`` (the legacy flat
    revocation set, equivalent to ``compromised`` with an unknown boundary).
    ``issuer`` is ``None`` only for entries synthesised from the legacy
    ``key_id`` -> PEM mapping.
    """

    key_id: str
    public_key_pem: str
    status: str = "active"
    issuer: str | None = None
    not_before: datetime | None = None
    retired_at: datetime | None = None
    compromised_from: datetime | None = None
    deployments: frozenset[str] | None = None
    primitives: frozenset[str] | None = None
    parameter_set_pin: str | None = None


def _read_declared(path: str | Path) -> frozenset[str]:
    """The keys a migration recorded as operator-declared, from the file beside the store.

    This records what happened, and it is a label: deleting the file, copying the store without it, or loading the JSON with
    ``from_dict`` loses it, and anyone who can write the file can write anything. A store loaded without it is not thereby
    authenticated. It is not in the store itself because every published version refuses an unknown member there, and the
    published versions must keep reading a migrated store. A file that is present and unusable is refused.
    """
    side = Path(os.path.realpath(path) + ISSUER_PROVENANCE_SUFFIX)
    try:
        if side.stat().st_size > MAX_TRUST_STORE_BYTES:
            raise TrustStoreError(f"issuer provenance {str(side)!r} is too large")
        payload = loads_strict(side.read_bytes(), max_bytes=MAX_TRUST_STORE_BYTES)
    except FileNotFoundError:
        return frozenset()
    except (OSError, CanonicalError, RecursionError) as exc:
        raise TrustStoreError(f"issuer provenance {str(side)!r} is unusable: {exc}") from exc
    key_ids = payload.get("key_ids") if isinstance(payload, Mapping) else None
    if (
        not isinstance(payload, Mapping)
        or payload.get("kind") != "operator-declared"
        or not isinstance(key_ids, list)
        or not all(isinstance(k, str) for k in key_ids)
    ):
        raise TrustStoreError(f"issuer provenance {str(side)!r} is not in the expected form")
    return frozenset(key_ids)


def _is_validated_record(key_id: Any, entry: Any, pem: Any) -> bool:
    """A record of exactly the types the parser builds. Nothing here can answer a comparison in its own way."""
    if not (type(key_id) is str and type(entry) is KeyEntry and type(pem) is str):
        return False
    return (
        all(type(v) is str for v in (entry.key_id, entry.public_key_pem, entry.status, entry.issuer))
        and (entry.parameter_set_pin is None or type(entry.parameter_set_pin) is str)
        and all(
            v is None or type(v) is datetime for v in (entry.not_before, entry.retired_at, entry.compromised_from)
        )
        and all(
            v is None or (type(v) is frozenset and all(type(item) is str for item in v))
            for v in (entry.deployments, entry.primitives)
        )
    )


def _checked_pem(key_id: str, pem: Any) -> str:
    """A PEM that parses as an Ed25519 public key; returns it normalised."""
    if not isinstance(pem, str):
        raise TrustStoreError(f"trust-store entry {key_id!r} is not a PEM public key")
    try:
        spki_fingerprint(pem)
    except ValueError as exc:
        what = "not an Ed25519 public key" if "Ed25519" in str(exc) else "not a PEM public key"
        raise TrustStoreError(f"trust-store entry {key_id!r} is {what}") from exc
    return _normalise_pem(pem)


def _require_unique_keys(pems: Mapping[str, str]) -> None:
    """One public key may be registered under one key_id only, or a compromised
    or retired key could be relabelled with another key_id."""
    seen: dict[str, str] = {}
    for key_id, pem in pems.items():
        fp = spki_fingerprint(pem)
        if fp in seen:
            raise TrustStoreError(
                f"trust-store key_ids {seen[fp]!r} and {key_id!r} register the same public key"
            )
        seen[fp] = key_id


def _entry_time(key_id: str, entry: Mapping[str, Any], name: str) -> datetime | None:
    if name not in entry:
        return None
    raw = entry[name]
    if not isinstance(raw, str):
        raise TrustStoreError(f"trust-store entry {key_id!r}: {name} must be an RFC 3339 string")
    try:
        return parse_rfc3339(raw)
    except ValueError as exc:
        raise TrustStoreError(f"trust-store entry {key_id!r}: {name}: {exc}") from exc


def _entry_set(
    key_id: str, entry: Mapping[str, Any], name: str, allowed: tuple[str, ...] | None
) -> frozenset[str] | None:
    if name not in entry:
        return None
    raw = entry[name]
    if (
        not isinstance(raw, list)
        or not raw
        or not all(isinstance(v, str) and v for v in raw)
        or len(set(raw)) != len(raw)
    ):
        raise TrustStoreError(
            f"trust-store entry {key_id!r}: {name} must be a non-empty list of unique strings"
        )
    if allowed is not None and not set(raw) <= set(allowed):
        raise TrustStoreError(f"trust-store entry {key_id!r}: {name} has unknown value(s)")
    return frozenset(raw)


def _parse_entry(key_id: str, entry: Any) -> KeyEntry:
    if not isinstance(key_id, str) or not key_id:
        raise TrustStoreError("trust-store entry key_id must be a non-empty string")
    if not isinstance(entry, Mapping):
        raise TrustStoreError(f"trust-store entry {key_id!r} must be an object")
    unknown = set(entry) - _ENTRY_KEYS
    if unknown:
        raise TrustStoreError(f"trust-store entry {key_id!r}: unknown field(s) {sorted(unknown)}")
    issuer = entry.get("issuer")
    if not isinstance(issuer, str) or not issuer:
        raise TrustStoreError(f"trust-store entry {key_id!r}: issuer is required")
    problem = issuer_name_problem(issuer)
    if problem is not None:
        raise TrustStoreError(f"trust-store entry {key_id!r}: issuer {problem}")
    pem = _checked_pem(key_id, entry.get("public_key_pem"))
    status = entry.get("status")
    if status not in _STATUSES:
        raise TrustStoreError(f"trust-store entry {key_id!r}: status must be one of {_STATUSES}")
    retired_at = _entry_time(key_id, entry, "retired_at")
    compromised_from = _entry_time(key_id, entry, "compromised_from")
    if status == "retired" and retired_at is None:
        raise TrustStoreError(f"trust-store entry {key_id!r}: retired keys require retired_at")
    if status != "retired" and retired_at is not None:
        raise TrustStoreError(f"trust-store entry {key_id!r}: retired_at needs status 'retired'")
    if status != "compromised" and compromised_from is not None:
        raise TrustStoreError(
            f"trust-store entry {key_id!r}: compromised_from needs status 'compromised'"
        )
    pin = entry.get("parameter_set_pin")
    if pin is not None and (
        not isinstance(pin, str) or len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin)
    ):
        raise TrustStoreError(f"trust-store entry {key_id!r}: parameter_set_pin must be 64-hex")
    return KeyEntry(
        key_id=key_id,
        public_key_pem=pem,
        status=status,
        issuer=issuer,
        not_before=_entry_time(key_id, entry, "not_before"),
        retired_at=retired_at,
        compromised_from=compromised_from,
        deployments=_entry_set(key_id, entry, "deployments", None),
        primitives=_entry_set(key_id, entry, "primitives", _PRIMITIVE_NAMES),
        parameter_set_pin=pin,
    )


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
    entries: Mapping[str, KeyEntry] = field(default_factory=dict)
    # Operator-asserted snapshot time. In Phase 3A the store is a local file
    # with no authenticated provenance, so this is informational only.
    as_of: datetime | None = None
    # Keys whose issuer a migration recorded as an operator's statement. A label, and not authentication: see _read_declared.
    issuer_declared: frozenset[str] = field(default_factory=frozenset, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Copy and freeze: a caller must not be able to change trust material
        # after construction, nor through the dict they passed in.
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))
        object.__setattr__(self, "revoked", frozenset(self.revoked))
        object.__setattr__(
            self, "parameter_set_pins", MappingProxyType(dict(self.parameter_set_pins))
        )
        object.__setattr__(self, "entries", MappingProxyType(dict(self.entries)))
        object.__setattr__(self, "issuer_declared", frozenset(self.issuer_declared))
        if not self.issuer_declared <= set(self.entries):
            raise TrustStoreError("issuer_declared names a key_id that is not in entries")
        # Direct construction is held to the same rules as the loaders: every key
        # must be a real Ed25519 public key, and no key may sit under two ids (a
        # revoked or compromised key must not be re-labelled to regain trust).
        for key_id, pem in self.keys.items():
            _checked_pem(key_id, pem)
        _require_unique_keys(self.keys)
        for map_key, entry in self.entries.items():
            if entry.key_id != map_key:
                raise TrustStoreError(
                    f"trust-store entry stored under {map_key!r} names key_id {entry.key_id!r}"
                )
            problem = None if entry.issuer is None else issuer_name_problem(entry.issuer)
            if problem is not None:
                raise TrustStoreError(f"trust-store entry {map_key!r}: issuer {problem}")
        if self.entries:
            # The legacy views feed the older API and the entries feed the engine;
            # they must describe the same store or the two would disagree.
            expected_keys = {k: e.public_key_pem for k, e in self.entries.items()}
            expected_revoked = frozenset(k for k, e in self.entries.items() if e.status != "active")
            expected_pins = {
                k: e.parameter_set_pin for k, e in self.entries.items() if e.parameter_set_pin
            }
            if (
                dict(self.keys) != expected_keys
                or self.revoked != expected_revoked
                or dict(self.parameter_set_pins) != expected_pins
            ):
                raise TrustStoreError(
                    "trust-store keys/revoked/parameter_set_pins are inconsistent with entries"
                )
        # Worked out once, here, from the validated records. Malicious code in this process can still change it
        # (object.__setattr__), and that is outside what this library can guarantee.
        object.__setattr__(
            self,
            "_binds_issuers",
            bool(self.entries)
            and all(
                _is_validated_record(key_id, entry, self.keys.get(key_id))
                for key_id, entry in self.entries.items()
            ),
        )

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
        if "entries" in payload:
            return cls._from_entries(payload)
        keys: dict[str, str]
        revoked: set[str] = set()
        pins: dict[str, str] = {}

        if "keys" in payload and isinstance(payload["keys"], Mapping):
            unknown_members = set(payload) - {"keys", "revoked", "parameter_set_pins"}
            if unknown_members:
                # A misspelt "revoked" would otherwise load as an empty revocation list and fail open.
                raise TrustStoreError(
                    f"trust-store has unknown member(s) {sorted(unknown_members)!r}; "
                    "expected only keys, revoked and parameter_set_pins"
                )
            raw_keys = payload["keys"]
            raw_revoked = payload.get("revoked", [])
            raw_pins = payload.get("parameter_set_pins", {})
            if not isinstance(raw_revoked, Iterable) or isinstance(raw_revoked, (str, bytes)):
                raise TrustStoreError("trust-store 'revoked' must be a list of key_ids")
            if not isinstance(raw_pins, Mapping):
                raise TrustStoreError("trust-store 'parameter_set_pins' must be a mapping")
            revoked = {str(r) for r in raw_revoked}
            pins = {str(k): str(v) for k, v in raw_pins.items()}
        else:
            raw_keys = payload

        if not isinstance(raw_keys, Mapping) or not raw_keys:
            raise TrustStoreError("trust-store must declare at least one key_id -> PEM entry")
        keys = {}
        for key_id, pem in raw_keys.items():
            if not isinstance(key_id, str) or not isinstance(pem, str):
                raise TrustStoreError("trust-store keys must map str key_id to str PEM")
            keys[key_id] = _checked_pem(key_id, pem)
        _require_unique_keys(keys)

        if revoked - set(keys):
            unknown = sorted(revoked - set(keys))
            raise TrustStoreError(
                f"trust-store 'revoked' references unknown key_id(s): {unknown!r}"
            )
        if set(pins) - set(keys):
            unknown = sorted(set(pins) - set(keys))
            raise TrustStoreError(
                f"trust-store 'parameter_set_pins' references unknown key_id(s): {unknown!r}"
            )

        return cls(
            keys=keys,
            revoked=frozenset(revoked),
            parameter_set_pins=pins,
        )

    @classmethod
    def from_json(cls, path: str | Path) -> TrustStore:
        """Load a TrustStore from a JSON file."""
        try:
            size = Path(path).stat().st_size
            if size > MAX_TRUST_STORE_BYTES:
                raise TrustStoreError(
                    f"trust-store {str(path)!r} size {size} exceeds {MAX_TRUST_STORE_BYTES} bytes"
                )
            body = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise TrustStoreError(f"trust-store {str(path)!r} is unreadable: {exc}") from exc
        try:
            # strict JSON: a duplicated key must not silently replace an earlier entry or the revoked list
            payload = loads_strict(body, max_bytes=MAX_TRUST_STORE_BYTES)
        except CanonicalError as exc:
            raise TrustStoreError(
                f"trust-store {str(path)!r} is not valid JSON under the strict policy: {exc}"
            ) from exc
        except RecursionError as exc:
            raise TrustStoreError(f"trust-store {str(path)!r} is nested too deeply") from exc
        if not isinstance(payload, Mapping):
            raise TrustStoreError(f"trust-store {str(path)!r} must be a JSON object")
        store = cls.from_dict(payload)
        declared = _read_declared(path) & set(store.entries)
        return replace(store, issuer_declared=declared) if declared else store

    @classmethod
    def _from_entries(cls, payload: Mapping[str, Any]) -> TrustStore:
        extra = set(payload) - {"entries", "as_of"}
        if extra:
            raise TrustStoreError(
                f"trust-store 'entries' form cannot be mixed with {sorted(extra)}; "
                "use either the legacy keys/revoked/parameter_set_pins form or entries"
            )
        raw = payload["entries"]
        if not isinstance(raw, Mapping) or not raw:
            raise TrustStoreError("trust-store 'entries' must be a non-empty object")
        entries = {key_id: _parse_entry(key_id, e) for key_id, e in raw.items()}
        _require_unique_keys({k: e.public_key_pem for k, e in entries.items()})
        as_of: datetime | None = None
        if "as_of" in payload:
            raw_as_of = payload["as_of"]
            try:
                as_of = parse_rfc3339(raw_as_of) if isinstance(raw_as_of, str) else None
            except ValueError as exc:
                raise TrustStoreError(f"trust-store as_of: {exc}") from exc
            if as_of is None:
                raise TrustStoreError("trust-store as_of must be an RFC 3339 string")
        return cls(
            keys={k: e.public_key_pem for k, e in entries.items()},
            revoked=frozenset(k for k, e in entries.items() if e.status != "active"),
            parameter_set_pins={
                k: e.parameter_set_pin for k, e in entries.items() if e.parameter_set_pin
            },
            entries=entries,
            as_of=as_of,
        )

    # ----- Queries --------------------------------------------------------

    def entry(self, key_id: str) -> KeyEntry | None:
        """The lifecycle entry for ``key_id``, synthesised for legacy stores."""
        found = self.entries.get(key_id)
        if found is not None:
            return found
        pem = self.keys.get(key_id)
        if pem is None:
            return None
        return KeyEntry(
            key_id=key_id,
            public_key_pem=pem,
            status="revoked" if key_id in self.revoked else "active",
            parameter_set_pin=self.parameter_set_pins.get(key_id),
        )

    @property
    def binds_issuers(self) -> bool:
        """Whether this store states, for every key, the issuer name the operator enrolled it for.

        A bare or ``keys`` store does not, whatever its number of keys or the shape of its key ids. Nothing else can
        supply that statement: the report's own issuer name is what is being checked.
        """
        return bool(self._binds_issuers)  # type: ignore[attr-defined]

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
