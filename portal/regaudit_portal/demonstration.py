"""Recognising the portal's own demonstration keys and names, so that they never pass for real trust.

The bundled samples were signed with two throwaway keys whose fingerprints are pinned below. The same fingerprints are
also computed, every time, from the public keys in the bundled sample files, so a key that appears there is recognised
even if this list were out of date. ``demo-setup`` makes fresh keys each time it runs, so its keys cannot be pinned:
they are recognised by the issuer name and key ids it always writes. Names are a label, not a security property: the
fingerprints are what stops a demonstration key being enrolled.

This only reads the package's own sample files. It writes nothing.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import functools
from importlib import resources

from regaudit_fhe._keys import spki_fingerprint
from regaudit_fhe.canonical import CanonicalError, loads_strict

# SHA-256 of the SubjectPublicKeyInfo of each key that signed a bundled sample: the "DEMO-ONLY synthetic issuer" key
# that the demonstration trust list enrols, and the "DEMO-ONLY unenrolled signer" key of the untrusted-signer sample.
PINNED_FINGERPRINTS = frozenset(
    {
        "220618ae027e2cf3c634778f5f4708fc1ea53006973d379ef0d799d936e30df8",
        "31c7e0ea85af0752b9d95a01de395ceea6049757b5328fd5fdfee702fc2b923b",
    }
)
# What the bundled samples and ``demo-setup`` call their issuers and keys. Compared without regard to case.
_NAME_PREFIXES = ("demo-only",)
_NAMES = frozenset({"example synthetic issuer"})
_KEY_IDS = frozenset({"synthetic-issuer-key", "synthetic-outsider-key"})
_MAX_SAMPLE_BYTES = 1 << 20


def _sample_keys() -> set[str]:
    """Every public key in the bundled demonstration files: the trust list's entries and each report's signing key."""
    found: set[str] = set()
    folder = resources.files(__package__).joinpath("samples")

    def read(*parts: str) -> object:
        try:
            return loads_strict(folder.joinpath(*parts).read_bytes(), max_bytes=_MAX_SAMPLE_BYTES)
        except (OSError, CanonicalError, RecursionError, UnicodeDecodeError):
            return None

    manifest = read("index.json")
    if not isinstance(manifest, dict):
        return found
    trust_list = read(str(manifest.get("trust_list", "")))
    if isinstance(trust_list, dict) and isinstance(trust_list.get("entries"), dict):
        for entry in trust_list["entries"].values():
            if isinstance(entry, dict) and isinstance(entry.get("public_key_pem"), str):
                found.add(entry["public_key_pem"])
    for sample in manifest.get("samples", []) if isinstance(manifest.get("samples"), list) else []:
        name = sample.get("file") if isinstance(sample, dict) else None
        if not isinstance(name, str) or not name.startswith("reports/") or ".." in name:
            continue
        report = read(*name.split("/"))
        receipt = report.get("receipt") if isinstance(report, dict) else None
        if isinstance(receipt, dict) and isinstance(receipt.get("public_key_pem"), str):
            found.add(receipt["public_key_pem"])
    return found


@functools.lru_cache(maxsize=1)
def fingerprints() -> frozenset[str]:
    """The pinned fingerprints and those of every key in the bundled sample files. The package's files do not change
    while it runs, so this is worked out once."""
    computed = set()
    for pem in _sample_keys():
        try:
            computed.add(spki_fingerprint(pem))
        except ValueError:
            continue
    return PINNED_FINGERPRINTS | computed


def is_demonstration_key(fingerprint: str) -> bool:
    return fingerprint.lower() in fingerprints()


def is_demonstration_name(issuer: str) -> bool:
    folded = issuer.strip().casefold()
    return folded in _NAMES or folded.startswith(_NAME_PREFIXES)


def is_demonstration_key_id(key_id: str) -> bool:
    folded = key_id.strip().casefold()
    return folded in _KEY_IDS or folded.startswith(_NAME_PREFIXES)


def is_demonstration_entry(key_id: str, issuer: str | None, public_key_pem: str) -> bool:
    """Is this trust-list entry one of the portal's demonstration keys, by fingerprint, issuer name or key id?"""
    try:
        if is_demonstration_key(spki_fingerprint(public_key_pem)):
            return True
    except ValueError:
        pass
    return is_demonstration_key_id(key_id) or (issuer is not None and is_demonstration_name(issuer))
