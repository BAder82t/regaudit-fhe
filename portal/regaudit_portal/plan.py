"""An administrator setup plan: what it may hold, how it is checked, and exactly what applying it would write.

Two places use this: the portal's stateless prepare route, and the separate apply command, which the portal process never
imports. Nothing here writes, keeps or enrols anything. It reads the bytes it is given and returns values: it opens no
file, makes no folder and changes nothing on disk. It never decides where anything is written either; a plan cannot
name a place.

Keys are parsed and fingerprinted only by the engine's own code, the code that ``regaudit-fhe trust add`` uses. A plan
holds no fingerprint: the fingerprint is always computed from the key, and applying a plan needs the administrator to
type each issuer's fingerprint as received from that issuer by another route. A plan's ``content_sha256`` only shows
that the file is intact. Anyone can compute it, so it says nothing about who made the plan.

Private or secret key material is refused wherever it appears, with a message that says why, and it is never repeated
back.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from regaudit_fhe._keys import load_ed25519_public_key, spki_fingerprint
from regaudit_fhe.canonical import CanonicalError, canonical_bytes, loads_strict
from regaudit_fhe.trust import TrustStore, TrustStoreError

from . import demonstration
from .paths import CONFIG_NAME
from .profiles import PROFILE_NAMES, REPLAY_MODES, explain, replay_text

PLAN_FORMAT = "regaudit-portal-setup-plan"
PLAN_VERSION = 1
FIRST_SETUP = "first-setup"
ADD_ISSUERS = "add-issuers"
MODES = (FIRST_SETUP, ADD_ISSUERS)
TRUST_LIST_NAME = "trust-store.json"
REPLAY_NAME = "replay.db"
MAX_PLAN_BYTES = 64 * 1024
MAX_ISSUERS = 10
MAX_NAME = 256  # the same limit as ``trust add``
MAX_KEY_ID = 128
MAX_VERIFIER_ID = 200
MAX_PUBLIC_KEY_CHARS = 2048
MAX_FINGERPRINT_CHARS = 200
MAX_AGE_DAYS = 3650

_PLAN_MEMBERS = {"format", "version", "mode", "issuers", "content_sha256"}
_REQUEST_MEMBERS = {"mode", "issuers"}
_CONFIGURATION_MEMBERS = {"profile", "verifier_id", "max_age_days", "replay_mode"}
_PLAN_ISSUER_MEMBERS = {"issuer", "key_id", "public_key_pem"}
_REQUEST_ISSUER_MEMBERS = {"issuer", "key_id", "public_key", "fingerprint"}

# Controls (escape sequences among them), invisible formatting characters such as the bidirectional overrides and
# zero-width characters, lone surrogates, private use, unassigned code points, and line and paragraph separators.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_FINGERPRINT = re.compile(r"[0-9A-Fa-f]{64}")
_PEM_BODY = re.compile(r"[A-Za-z0-9+/=]+")
_BASE64ISH = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_HEXISH = re.compile(r"[0-9A-Fa-f]+")
_BEGIN_PUBLIC = "-----BEGIN PUBLIC KEY-----"
_END_PUBLIC = "-----END PUBLIC KEY-----"

# Text that only private or secret key material carries, in the forms people are likely to paste: PEM and PGP private
# key blocks (PKCS#8, encrypted PKCS#8, RSA, EC, DSA, OpenSSH), PuTTY key files, age and minisign or signify secret
# keys, the OpenSSH private key magic in base64, a JSON Web Key's private member, and the base64 start that every
# unencrypted Ed25519 PKCS#8 private key has (so its body is caught even cut short or with characters added).
_SECRET_MARKERS = re.compile(
    r"-----BEGIN[^\n-]*(PRIVATE|SECRET)|(PRIVATE|SECRET)\s+KEY\s*(BLOCK\s*)?-----|PuTTY-User-Key-File|"
    r"Private-Lines\s*:|AGE-SECRET-KEY-|b3BlbnNzaC1rZXktdjE|openssh-key-v1|secret\s+key\s*$|"
    r"\"d\"\s*:\s*\"[A-Za-z0-9_-]{20,}|MC4CAQAwBQYDK2VwBCIEI",
    re.IGNORECASE | re.MULTILINE,
)
# In the box meant for a public key, any mention of these words is enough to refuse.
_SECRET_WORDS = re.compile(r"PRIVATE|SECRET", re.IGNORECASE)
# Byte lengths of a raw Ed25519 seed (32), a seed with its public half (64), and a PKCS#8 Ed25519 private key (48).
_RAW_SECRET_LENGTHS = frozenset({32, 48, 64})

KEY_MATERIAL_MESSAGE = (
    "This looks like private (secret) key material, so it was refused. The portal never accepts a private key, and "
    "it did not keep or show back what was entered. Paste the issuer's public key instead. It starts with "
    "-----BEGIN PUBLIC KEY-----."
)
RAW_KEY_MESSAGE = (
    "This looks like raw key bytes. They could be a secret key, so they were refused and not shown back. Paste the "
    "issuer's public key in PEM form instead. It starts with -----BEGIN PUBLIC KEY-----."
)
NAME_KEY_MESSAGE = (
    "This looks like raw key bytes, which could be a secret key, so it was refused and not shown back. A name is "
    "never key material."
)
OWN_SEED_MESSAGE = (
    "This is the private key of one of the public keys in this plan, so it was refused and not shown back. A private "
    "key belongs only on the issuer's own system and never in a plan."
)
HEX_KEY_MESSAGE = (
    "This is 64 hexadecimal characters. It could be a fingerprint or a raw secret key, so it was refused and not "
    "shown back. The public key box needs the issuer's public key, which starts with -----BEGIN PUBLIC KEY-----."
)


class PlanProblem(Exception):
    """The plan, or the request to prepare one, cannot be used. The message never repeats what was entered."""

    def __init__(self, message: str, code: str = "invalid_plan", where: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.where = where

    def __str__(self) -> str:
        return f"{self.where}: {self.message}" if self.where else self.message


class SecretMaterial(PlanProblem):
    def __init__(self, message: str = KEY_MATERIAL_MESSAGE, where: str | None = None) -> None:
        super().__init__(message, "secret_key_material", where)


class FingerprintMismatch(PlanProblem):
    """A fingerprint typed for an issuer does not match the key. ``checks`` says, per issuer, only whether it matched.

    The fingerprint computed from the key is never in it: the administrator must get that value from the issuer by
    another route, so the portal never offers it, not even after a mismatch.
    """

    def __init__(self, message: str, checks: list[dict[str, Any]]) -> None:
        super().__init__(message, "fingerprint_mismatch")
        self.checks = checks


@dataclass(frozen=True)
class Issuer:
    issuer: str
    key_id: str
    public_key_pem: str  # as the engine's key library writes it
    fingerprint: str  # computed from the key by the engine's own code, never read from a plan


@dataclass(frozen=True)
class Plan:
    mode: str
    issuers: tuple[Issuer, ...]
    profile: str | None = None
    verifier_id: str | None = None
    max_age_days: int | None = None
    replay_mode: str | None = None

    def content(self) -> dict[str, Any]:
        body: dict[str, Any] = {"format": PLAN_FORMAT, "version": PLAN_VERSION, "mode": self.mode}
        if self.mode == FIRST_SETUP:
            body["configuration"] = {
                "profile": self.profile,
                "verifier_id": self.verifier_id,
                "max_age_days": self.max_age_days,
                "replay_mode": self.replay_mode,
            }
        body["issuers"] = [
            {"issuer": i.issuer, "key_id": i.key_id, "public_key_pem": i.public_key_pem}
            for i in self.issuers
        ]
        return body

    @property
    def content_sha256(self) -> str:
        """SHA-256 of the canonical JSON of the content. It shows the file is intact, not who made it."""
        return hashlib.sha256(canonical_bytes(self.content())).hexdigest()

    def text(self) -> str:
        """The plan file, byte for byte. ASCII only: any other character is written as a JSON escape."""
        document = {**self.content(), "content_sha256": self.content_sha256}
        return json.dumps(document, indent=2) + "\n"

    def file_name(self) -> str:
        return f"setup-plan-{self.content_sha256[:12]}.json"

    def configuration_text(self) -> str | None:
        """The configuration file a first setup writes, byte for byte. ``None`` when adding issuers."""
        if self.mode != FIRST_SETUP:
            return None
        settings = {
            "trust_store": TRUST_LIST_NAME,
            "profile": self.profile,
            "verifier_id": self.verifier_id,
            "max_age_days": self.max_age_days,
            "replay_mode": self.replay_mode,
            "replay_db": REPLAY_NAME,
            "trust_mode": "customer",  # written out, so the mode is explicit; a plan can never choose another
        }
        return json.dumps(settings, indent=2) + "\n"

    def new_entries(self) -> dict[str, dict[str, str]]:
        """Each issuer's trust-list entry, in the form ``trust add`` writes it."""
        return {
            i.key_id: {
                "issuer": i.issuer,
                "public_key_pem": i.public_key_pem.strip().replace("\r\n", "\n") + "\n",
                "status": "active",
            }
            for i in self.issuers
        }

    def trust_list_text(self, existing: dict[str, Any] | None = None) -> str:
        """The trust list after enrolment, byte for byte as ``trust add`` writes it, starting from ``existing``.

        The apply command compares this with what the engine's own ``trust add`` code produced and refuses if they
        differ, so what is shown before applying is what is written.
        """
        payload = json.loads(json.dumps(existing)) if existing is not None else {"entries": {}}
        payload["entries"].update(self.new_entries())
        return json.dumps(payload, indent=2) + "\n"


# ----------------------------------------------------------------------------- showing text safely


def shown(text: str, limit: int = 300) -> str:
    """Text that is safe to print to a terminal, a log or a page: each control or invisible character becomes a
    visible ``\\u{XXXX}``, and the length is capped. Names in a plan are refused if they hold such characters, so for
    them this changes nothing; it is here for everything else."""
    cut = text[:limit]
    safe = "".join(
        f"\\u{{{ord(c):04X}}}" if unicodedata.category(c) in _UNSAFE_CATEGORIES else c for c in cut
    )
    return safe + (" (shortened)" if len(text) > limit else "")


def quoted(text: str) -> str:
    return f'"{shown(text)}"'


# ----------------------------------------------------------------------------- key material


def _decodes_to_private_key(raw: bytes) -> bool:
    for load in (
        lambda data: serialization.load_der_private_key(data, password=None),
        lambda data: serialization.load_pem_private_key(data, password=None),
        lambda data: serialization.load_ssh_private_key(data, password=None),
    ):
        try:
            load(raw)
            return True
        except TypeError:  # an encrypted private key, which needs a password: still a private key
            return True
        except Exception:  # noqa: S112 - anything else means this loader does not read it as a private key
            continue
    return False


def _raw_bytes(text: str) -> bytes | None:
    """The bytes a bare hex or base64 string decodes to, or ``None`` if it is neither."""
    compact = "".join(text.split())
    if _HEXISH.fullmatch(compact) and len(compact) % 2 == 0:
        return bytes.fromhex(compact)
    if _BASE64ISH.fullmatch(compact):
        padded = compact.replace("-", "+").replace("_", "/")
        padded += "=" * (-len(padded) % 4)
        try:
            return base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            return None
    return None


def _looks_like_raw_key(value: str) -> bool:
    """A name that is one token of hexadecimal or base64 the size of a raw Ed25519 secret key.

    Base64 counts only with digits and both cases in it, as random bytes almost always have, so a long one-word name
    is not mistaken for a key.
    """
    if any(c.isspace() for c in value):
        return False
    if _HEXISH.fullmatch(value):
        return len(value) in (64, 96, 128)
    if not _BASE64ISH.fullmatch(value) or not (
        any(c.isdigit() for c in value)
        and any(c.islower() for c in value)
        and any(c.isupper() for c in value)
    ):
        return False
    raw = _raw_bytes(value)
    return raw is not None and len(raw) in _RAW_SECRET_LENGTHS


def refuse_secret(
    value: str, where: str | None = None, *, key_box: bool = False, name: bool = False
) -> None:
    """Raise :class:`SecretMaterial` if ``value`` looks like private or secret key material. Never repeats it."""
    if name and _looks_like_raw_key(value):
        raise SecretMaterial(NAME_KEY_MESSAGE, where)
    if _SECRET_MARKERS.search(value) or (key_box and _SECRET_WORDS.search(value)):
        raise SecretMaterial(where=where)
    if "-----BEGIN" in value and _decodes_to_private_key(value.encode("utf-8", "replace")):
        raise SecretMaterial(where=where)
    raw = _raw_bytes(value) if len(value) <= 4 * MAX_PUBLIC_KEY_CHARS else None
    if raw is not None and len(raw) >= 16 and _decodes_to_private_key(raw):
        raise SecretMaterial(where=where)
    if key_box and raw is not None:
        compact = "".join(value.split())
        if _HEXISH.fullmatch(compact) and len(compact) == 64:
            raise SecretMaterial(HEX_KEY_MESSAGE, where)
        if len(raw) in _RAW_SECRET_LENGTHS:
            raise SecretMaterial(RAW_KEY_MESSAGE, where)


_FIELD_WORDS = {
    "issuer": "name",
    "key_id": "key id",
    "public_key": "public key",
    "public_key_pem": "public key",
    "fingerprint": "fingerprint",
    "verifier_id": "verifier id",
}
_KEY_MEMBERS = frozenset({"public_key", "public_key_pem"})


def _place(path: tuple[Any, ...]) -> str:
    """Where in a request or a plan a value is, in words, for a message that must not repeat the value."""
    if (
        len(path) == 3
        and path[0] == "issuers"
        and isinstance(path[1], int)
        and path[2] in _FIELD_WORDS
    ):
        return f"issuer {path[1] + 1}, {_FIELD_WORDS[path[2]]}"
    if len(path) == 2 and path[0] == "configuration" and path[1] in _FIELD_WORDS:
        return f"configuration, {_FIELD_WORDS[path[1]]}"
    return "a field"


def _refuse_secrets_anywhere(value: Any, path: tuple[Any, ...] = ()) -> None:
    """Look at every string in a request or a plan, member names included, before anything else reads it."""
    if len(path) > 8:
        raise PlanProblem("It is nested more deeply than a setup plan ever is.")
    if isinstance(value, str):
        last = path[-1] if path else None
        refuse_secret(value, _place(path), key_box=last in _KEY_MEMBERS, name=last == "issuer")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _refuse_secrets_anywhere(item, (*path, index))
    elif isinstance(value, dict):
        for key, item in value.items():
            refuse_secret(key, "a member name")
            _refuse_secrets_anywhere(item, (*path, key))


def public_key(value: Any, where: str) -> tuple[str, str]:
    """An issuer's public key as entered: refused unless it is one Ed25519 public key in PEM form and nothing else.

    Returns the key as the engine's key library writes it, and its fingerprint as the engine computes it.
    """
    if type(value) is not str:
        raise PlanProblem("The public key must be text.", where=where)
    refuse_secret(value, where, key_box=True)
    if len(value) > MAX_PUBLIC_KEY_CHARS:
        raise PlanProblem(
            f"The public key is longer than {MAX_PUBLIC_KEY_CHARS} characters. An Ed25519 public key is "
            "about 113.",
            where=where,
        )
    lines = [line.strip() for line in value.strip().replace("\r\n", "\n").split("\n")]
    if (
        len(lines) < 3
        or lines[0] != _BEGIN_PUBLIC
        or lines[-1] != _END_PUBLIC
        or not all(_PEM_BODY.fullmatch(line) for line in lines[1:-1])
    ):
        if any("CERTIFICATE" in line for line in lines):
            raise PlanProblem(
                "This is a certificate. Paste the issuer's public key itself, which starts with "
                f"{_BEGIN_PUBLIC}.",
                where=where,
            )
        raise PlanProblem(
            f"This is not one public key in PEM form. It must start with {_BEGIN_PUBLIC}, end with {_END_PUBLIC}, "
            "and hold nothing else.",
            where=where,
        )
    text = "\n".join(lines) + "\n"
    try:
        key = load_ed25519_public_key(text)
    except ValueError as exc:
        what = "an Ed25519 key" if "Ed25519" in str(exc) else "a public key the engine can read"
        raise PlanProblem(
            f"This is not {what}. Only Ed25519 public keys are accepted.", where=where
        ) from exc
    canonical = key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    fingerprint = spki_fingerprint(canonical)
    if demonstration.is_demonstration_key(fingerprint):
        raise PlanProblem(
            "This is one of the portal's demonstration keys. It signs only the made-up sample reports, and it can "
            "never be enrolled as a real issuer.",
            "demonstration_key",
            where,
        )
    return canonical, fingerprint


def typed_fingerprint(value: Any, where: str) -> str:
    """A fingerprint as typed: 64 hexadecimal characters, upper or lower case, with spaces allowed only around it.

    This is no looser than ``trust add``, which compares after removing surrounding white space and lowering the case.
    It is stricter: colons, spaces or dashes inside, and characters from other alphabets that only look like these, are
    refused instead of being compared. What was typed is never repeated back.
    """
    if type(value) is not str:
        raise PlanProblem("The fingerprint must be text.", where=where)
    refuse_secret(value, where)
    text = value.strip(" \t\r\n")
    if not text:
        raise PlanProblem("No fingerprint was typed.", "fingerprint_missing", where)
    if not text.isascii():
        raise PlanProblem(
            "The fingerprint holds characters other than 0-9 and a-f, for example a character from another "
            "alphabet that looks like one of them. Type the 64 characters 0-9 and a-f as the issuer gave them.",
            "fingerprint_format",
            where,
        )
    if len(text) <= MAX_FINGERPRINT_CHARS and any(sep in text for sep in ": -\t"):
        raise PlanProblem(
            "The fingerprint has colons, spaces or dashes in it. Type the 64 characters without separators.",
            "fingerprint_format",
            where,
        )
    if not _FINGERPRINT.fullmatch(text):
        raise PlanProblem(
            "A fingerprint is 64 characters, each 0-9 or a-f. What was typed is not.",
            "fingerprint_format",
            where,
        )
    return text.lower()


def _refuse_own_private_keys(issuers: list[Issuer], values: list[tuple[str, Any]]) -> None:
    """Refuse a value that is the raw private seed of one of the plan's own public keys, in whatever box it was put.

    Any other hexadecimal or base64 id is accepted: an id derived from a key's fingerprint looks exactly like random
    secret bytes, so only this exact match can be refused without refusing real ids. The check derives the public
    key from the candidate with the cryptography library and compares it with the plan's keys.
    """
    publics = {
        load_ed25519_public_key(i.public_key_pem).public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        for i in issuers
    }
    for where, value in values:
        raw = _raw_bytes(value) if isinstance(value, str) and len(value) <= 400 else None
        if raw is None or len(raw) not in (32, 64):
            continue
        public = Ed25519PrivateKey.from_private_bytes(raw[:32]).public_key()
        if (
            public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            in publics
        ):
            raise SecretMaterial(OWN_SEED_MESSAGE, where)


def fingerprints_match(typed: str, computed: str) -> bool:
    return hmac.compare_digest(typed.encode("ascii"), computed.encode("ascii"))


# ----------------------------------------------------------------------------- the other fields


def _text(value: Any, what: str, limit: int, where: str) -> str:
    if type(value) is not str:
        raise PlanProblem(f"The {what} must be text.", where=where)
    if not value:
        raise PlanProblem(f"The {what} is empty.", where=where)
    if len(value) > limit:
        raise PlanProblem(f"The {what} is longer than {limit} characters.", where=where)
    if any(unicodedata.category(c) in _UNSAFE_CATEGORIES for c in value):
        raise PlanProblem(
            f"The {what} holds a control or invisible character. That is refused because it could change how the "
            "text reads in a terminal, a log or a page.",
            where=where,
        )
    if value != value.strip():
        raise PlanProblem(f"The {what} starts or ends with a space.", where=where)
    return value


def _key_id(value: Any, where: str) -> str:
    key_id = _text(value, "key id", MAX_KEY_ID, where)
    if not _KEY_ID.fullmatch(key_id) or ".." in key_id:
        raise PlanProblem(
            "A key id may use only letters A-Z and a-z, digits, dots, dashes and underscores, must start with a "
            "letter or a digit, and must not contain two dots in a row. It must not look like a file path.",
            where=where,
        )
    return key_id


def _members(raw: Any, expected: set[str], what: str, where: str | None = None) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PlanProblem(f"The {what} must be a JSON object.", where=where)
    unknown = set(raw) - expected
    missing = expected - set(raw)
    if unknown:
        names = sorted(n for n in unknown if re.fullmatch(r"[a-z_]{1,40}", n))
        named = f" ({', '.join(names)})" if names and len(names) == len(unknown) else ""
        raise PlanProblem(
            f"The {what} has members a setup plan never has{named}. This version can only make a first setup or add "
            "issuers: it cannot remove, revoke or replace keys, or choose where files go.",
            where=where,
        )
    if missing:
        raise PlanProblem(f"The {what} is missing {', '.join(sorted(missing))}.", where=where)
    return raw


def _configuration(raw: Any) -> tuple[str, str, int, str]:
    where = "configuration"
    found = _members(raw, _CONFIGURATION_MEMBERS, "configuration", where)
    profile = found["profile"]
    if type(profile) is not str or profile not in PROFILE_NAMES:
        raise PlanProblem(f"Choose one of the profiles {', '.join(PROFILE_NAMES)}.", where=where)
    verifier_id = _text(found["verifier_id"], "verifier id", MAX_VERIFIER_ID, where)
    days = found["max_age_days"]
    if type(days) is not int or not 1 <= days <= MAX_AGE_DAYS:
        raise PlanProblem(
            f"The maximum report age must be a whole number of days from 1 to {MAX_AGE_DAYS}.",
            where=where,
        )
    replay_mode = found["replay_mode"]
    if type(replay_mode) is not str or replay_mode not in REPLAY_MODES:
        raise PlanProblem("The replay mode must be check or record.", where=where)
    return profile, verifier_id, days, replay_mode


def _issuer_list(raw: Any) -> list[Any]:
    if not isinstance(raw, list) or not raw:
        raise PlanProblem("A plan needs at least one issuer.")
    if len(raw) > MAX_ISSUERS:
        raise PlanProblem(f"A plan can hold at most {MAX_ISSUERS} issuers.")
    return raw


def _issuer(
    raw: Any, number: int, key_member: str, members: set[str]
) -> tuple[Issuer, dict[str, Any]]:
    where = f"issuer {number}"
    found = _members(raw, members, "issuer", where)
    name = _text(found["issuer"], "issuer name", MAX_NAME, f"{where}, name")
    key_id = _key_id(found["key_id"], f"{where}, key id")
    pem, fingerprint = public_key(found[key_member], f"{where}, public key")
    return Issuer(name, key_id, pem, fingerprint), found


def _id_values(
    issuers: list[Issuer], configuration: tuple | None, more: list[tuple[str, Any]]
) -> list[tuple[str, Any]]:
    """Every box a private seed could be pasted into by mistake, with where it is."""
    found = [(f"issuer {n}, key id", i.key_id) for n, i in enumerate(issuers, start=1)]
    found += [(f"issuer {n}, name", i.issuer) for n, i in enumerate(issuers, start=1)]
    if configuration is not None:
        found.append(("configuration, verifier id", configuration[1]))
    return found + more


def _checked(mode: str, issuers: list[Issuer], configuration: tuple | None) -> Plan:
    key_ids = [i.key_id for i in issuers]
    if len(set(key_ids)) != len(key_ids):
        raise PlanProblem("Two issuers have the same key id. Each key needs its own key id.")
    if len({i.fingerprint for i in issuers}) != len(issuers):
        raise PlanProblem("The same public key appears twice. A key can be enrolled only once.")
    if configuration is None:
        plan = Plan(mode, tuple(issuers))
    else:
        profile, verifier_id, days, replay_mode = configuration
        plan = Plan(mode, tuple(issuers), profile, verifier_id, days, replay_mode)
    try:
        TrustStore.from_dict(
            {"entries": plan.new_entries()}
        )  # the validation the engine applies to a trust list
    except TrustStoreError as exc:
        raise PlanProblem(f"The engine refuses these entries: {shown(str(exc))}") from exc
    return plan


def _mode(raw: dict[str, Any]) -> str:
    mode = raw.get("mode")
    if type(mode) is not str or mode not in MODES:
        raise PlanProblem("The mode must be first-setup or add-issuers.")
    return mode


def _parse_json(data: bytes, what: str) -> Any:
    if len(data) > MAX_PLAN_BYTES:
        raise PlanProblem(
            f"The {what} is larger than {MAX_PLAN_BYTES // 1024} KB, far more than a setup plan needs.",
            "too_large",
        )
    try:
        return loads_strict(data, max_bytes=MAX_PLAN_BYTES)
    except (CanonicalError, RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise PlanProblem(
            f"The {what} is not plain UTF-8 JSON (for example it has a byte order mark, a repeated member, a "
            "number that is not finite, text after the end, or nesting that is too deep).",
            "not_json",
        ) from exc


# ----------------------------------------------------------------------------- a plan file


def read_plan(data: bytes) -> Plan:
    """Check a plan file's bytes and return the plan. Anything unexpected is refused, and its checksum must match.

    Nothing the plan says about itself is trusted: fingerprints are computed from the keys, and the checksum is
    worked out again from the content.
    """
    raw = _parse_json(data, "plan")
    _refuse_secrets_anywhere(raw)
    if not isinstance(raw, dict):
        raise PlanProblem("A plan must be a JSON object.")
    mode = _mode(raw)
    expected = _PLAN_MEMBERS | ({"configuration"} if mode == FIRST_SETUP else set())
    _members(raw, expected, "plan")
    if (
        raw["format"] != PLAN_FORMAT
        or type(raw["version"]) is not int
        or raw["version"] != PLAN_VERSION
    ):
        raise PlanProblem("This is not a setup plan this portal can read.")
    claimed = raw["content_sha256"]
    if type(claimed) is not str or not _HEX64.fullmatch(claimed):
        raise PlanProblem("The plan's checksum is not 64 lowercase hexadecimal characters.")
    configuration = _configuration(raw["configuration"]) if mode == FIRST_SETUP else None
    issuers = [
        _issuer(item, n, "public_key_pem", _PLAN_ISSUER_MEMBERS)[0]
        for n, item in enumerate(_issuer_list(raw["issuers"]), start=1)
    ]
    _refuse_own_private_keys(issuers, _id_values(issuers, configuration, []))
    plan = _checked(mode, issuers, configuration)
    if plan.content() != {k: v for k, v in raw.items() if k != "content_sha256"}:
        raise PlanProblem(
            "A key in the plan is not written the way the portal writes it. Prepare the plan again.",
            "changed",
        )
    if not hmac.compare_digest(plan.content_sha256, claimed):
        raise PlanProblem(
            "The plan's content does not match its checksum: it was changed after it was prepared, or it is "
            "damaged. Nothing was done. Prepare it again.",
            "changed",
        )
    return plan


# ----------------------------------------------------------------------------- a request to prepare a plan


def _check_row(number: int, issuer: Issuer, typed: str) -> dict[str, Any]:
    """What the page is told about one issuer's fingerprint: whether the one typed matches the key, and nothing more.
    The fingerprint computed from the key is the value the administrator has to check with the issuer, so it is never
    part of the answer."""
    return {
        "number": number,
        "issuer": issuer.issuer,
        "key_id": issuer.key_id,
        "matches": fingerprints_match(typed, issuer.fingerprint),
    }


def read_request(data: bytes) -> tuple[Plan, list[dict[str, Any]]]:
    """Check what the prepare page sent and build the plan. Returns the plan and, for each issuer, whether the
    fingerprint that was typed matches the key. The computed fingerprint is never returned.

    Raises :class:`FingerprintMismatch` if any typed fingerprint does not match: no plan is made then.
    """
    raw = _parse_json(data, "request")
    _refuse_secrets_anywhere(raw)
    if not isinstance(raw, dict):
        raise PlanProblem("The request must be a JSON object.")
    mode = _mode(raw)
    expected = _REQUEST_MEMBERS | ({"configuration"} if mode == FIRST_SETUP else set())
    _members(raw, expected, "request")
    configuration = _configuration(raw["configuration"]) if mode == FIRST_SETUP else None
    issuers, checks, typed_values = [], [], []
    for number, item in enumerate(_issuer_list(raw["issuers"]), start=1):
        issuer, found = _issuer(item, number, "public_key", _REQUEST_ISSUER_MEMBERS)
        issuers.append(issuer)
        typed_values.append((f"issuer {number}, fingerprint", found["fingerprint"]))
    _refuse_own_private_keys(issuers, _id_values(issuers, configuration, typed_values))
    for number, (issuer, item) in enumerate(zip(issuers, raw["issuers"], strict=True), start=1):
        typed = typed_fingerprint(item["fingerprint"], f"issuer {number}, fingerprint")
        checks.append(_check_row(number, issuer, typed))
    if not all(check["matches"] for check in checks):
        raise FingerprintMismatch(
            "A fingerprint you typed does not match the public key it belongs to. No plan was made. Check the key "
            "and the fingerprint with the issuer, by a call or another route than the one the key came by.",
            checks,
        )
    return _checked(mode, issuers, configuration), checks


# ----------------------------------------------------------------------------- what a plan means, in words


# A maximum report age above this gets a notice. 30 days is the maximum age regaudit-fhe 0.2.1 applies on its own when
# replay checking is on and none is given (its DEFAULT_RETENTION), and the value this portal suggests.
LONG_AGE_DAYS = 30


def notices(plan: Plan) -> list[str]:
    """Plain warnings about settings that weaken what the portal checks. They come first, before anything else."""
    if plan.mode != FIRST_SETUP:
        return []
    found = []
    if plan.profile == "development":
        found.append(
            "Notice: the profile is development. It is for trying things out. Do not rely on its results: every "
            "result says so, and a report is not refused when the replay file cannot be used."
        )
    days = plan.max_age_days or 0
    if days > LONG_AGE_DAYS:
        found.append(
            f"Notice: the maximum report age is {days} days. That is longer than {LONG_AGE_DAYS} days, the age "
            "regaudit-fhe 0.2.1 applies on its own and the value this portal suggests, so an old report stays "
            "acceptable for longer."
        )
    if plan.replay_mode == "check":
        found.append(
            "Notice: the replay mode is check. Nothing is recorded, so a report shown twice is not refused as a "
            "repeat."
        )
    return found


def top_lines(plan: Plan) -> list[str]:
    """What must be read first: the notices, then the verifier id the reports must name."""
    lines = notices(plan)
    if plan.mode == FIRST_SETUP:
        lines.append(
            f"Verifier id: {quoted(plan.verifier_id or '')}. A report that names its recipients must name this id, "
            "and under high-assurance every report must. It should be your own organisation's id, the one issuers "
            "address their reports to."
        )
    return lines


def body_lines(plan: Plan) -> list[str]:
    """Everything else the plan does, worked out from its content alone. It shows no fingerprint on purpose."""
    lines: list[str] = []
    if plan.mode == FIRST_SETUP:
        lines.append(
            f"First setup: it creates {CONFIG_NAME} and {TRUST_LIST_NAME} in the portal's configuration folder. "
            "It refuses to replace either file if one is already there."
        )
        profile = explain(plan.profile or "")
        lines.append(f"Profile: {plan.profile}. {profile['summary']}")
        days = plan.max_age_days
        lines.append(f"Maximum report age: {days} day{'' if days == 1 else 's'}")
        lines.append(f"Replay mode: {replay_text(plan.replay_mode or '')}")
    else:
        lines.append(
            "Add issuers: it adds these issuers to the trust list that the existing configuration names. It "
            "removes, revokes and replaces nothing, and it does not change the configuration."
        )
    count = len(plan.issuers)
    lines.append(f"Issuers to enrol ({count}):")
    for number, issuer in enumerate(plan.issuers, start=1):
        lines.append(
            f"  {number}. {quoted(issuer.issuer)}, key id {issuer.key_id}, an Ed25519 public key"
        )
    lines.append(
        "No fingerprint is shown here, on purpose. To apply the plan you type, for each issuer, the fingerprint that "
        "issuer gave you by another route than this file, such as a call. It is applied only if every one matches "
        "the key in the plan."
    )
    return lines


def summary_lines(plan: Plan) -> list[str]:
    """A plain description of the plan: notices and the verifier id first, then the rest. No fingerprint."""
    return top_lines(plan) + body_lines(plan)


NEXT_STEPS = (
    "Save the plan file.",
    "Apply it outside the browser: in the application choose Administrator setup from the application's menu, or in "
    "Terminal run admin-describe and then admin-apply (the setup page shows both commands).",
    "When asked, type each issuer's fingerprint again from what the issuer gave you, not from this page. The plan is "
    "applied only if every fingerprint matches the key in the plan.",
    "Restart the portal afterwards, because it reads its configuration only when it starts. The application does "
    "this for you.",
)


def prepared(data: bytes) -> tuple[int, dict[str, Any]]:
    """The prepare route's answer: the plan and exactly what applying it would write, or why there is no plan.

    It is computed from the request alone. It reads no file and keeps nothing.
    """
    try:
        plan, checks = read_request(data)
    except FingerprintMismatch as exc:
        return 422, {"error": exc.code, "message": str(exc), "issuers": exc.checks}
    except PlanProblem as exc:
        status = 413 if exc.code == "too_large" else 422
        return status, {"error": exc.code, "message": exc.message, "where": exc.where}
    writes = []
    configuration = plan.configuration_text()
    if configuration is not None:
        writes.append({"file": CONFIG_NAME, "mode": "0600", "text": configuration})
        writes.append({"file": TRUST_LIST_NAME, "mode": "0600", "text": plan.trust_list_text()})
    else:
        writes.append(
            {
                "file": "the trust list the existing configuration names",
                "mode": "0600",
                "text": json.dumps(plan.new_entries(), indent=2) + "\n",
                "note": "These entries are added to it. Nothing already in it is changed.",
            }
        )
    return 200, {
        "ok": True,
        "plan_text": plan.text(),
        "plan_sha256": plan.content_sha256,
        "file_name": plan.file_name(),
        "issuers": checks,
        "writes": writes,
        "notices": notices(plan),
        "summary": summary_lines(plan),
        "next_steps": list(NEXT_STEPS),
    }
