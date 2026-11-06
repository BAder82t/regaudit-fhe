"""The administrator's configuration. It is read once at startup, and nothing in the browser can change it.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from regaudit_fhe.canonical import CanonicalError, loads_strict
from regaudit_fhe.replay import ReplayStateError, SqliteReplayCache
from regaudit_fhe.trust import TrustStore, TrustStoreError
from regaudit_fhe.verification import PolicyError, VerificationPolicy

from .demonstration import is_demonstration_entry
from .engine import REINSTALL, check_engine

MAX_CONFIG_BYTES = 64 * 1024
_MEMBERS = {
    "trust_store",
    "profile",
    "verifier_id",
    "max_age_days",
    "replay_mode",
    "replay_db",
    "allow_self_signed",
    "trust_mode",
}
_REQUIRED = {"trust_store", "profile", "verifier_id", "max_age_days"}
_PROFILES = ("confidential", "high-assurance", "development")
CUSTOMER = "customer"
DEMONSTRATION = "demonstration"
TRUST_MODES = (CUSTOMER, DEMONSTRATION)


class ConfigProblem(Exception):
    """The portal must not give verdicts until the administrator fixes this.

    ``kind`` says what sort of trouble it is, for the read-only setup page: ``missing`` (a file is not there),
    ``unsafe`` (who owns it or who can change it is wrong) or ``invalid`` (what it says is wrong).
    """

    def __init__(self, message: str, kind: str = "invalid") -> None:
        super().__init__(message)
        self.kind = kind


class EngineProblem(ConfigProblem):
    """The installed engine is not the recognised release. The text is for the administrator's terminal only."""

    def __init__(self, message: str) -> None:
        super().__init__(message, "engine")


@dataclass(frozen=True)
class Portal:
    policy: VerificationPolicy
    profile: str
    replay_mode: str
    approved_count: int
    engine: dict[str, Any]
    # Demonstration trust is kept apart from customer trust: see trust_mode_of.
    trust_mode: str = CUSTOMER
    trust_mode_reason: str = ""

    @property
    def demonstration(self) -> bool:
        return self.trust_mode == DEMONSTRATION


@dataclass(frozen=True)
class Settings:
    """What the configuration file says, once it has been read and found sound. Nothing here touches a trust list."""

    path: Path
    profile: str
    verifier_id: str
    max_age_days: int
    replay_mode: str
    allow_self_signed: bool
    store_path: Path
    replay_path: Path
    # Which kind of trust this configuration says it is: "customer", "demonstration" (demo-setup writes it), or ""
    # when it says nothing, which is customer trust. Chosen with the configuration when the portal starts, never later.
    trust_mode: str = ""


def _directory_problem(directory: Path, what: str) -> ConfigProblem | None:
    """The administrator's files must be theirs, and no other account may be able to change them."""
    if os.name != "posix" or not hasattr(os, "geteuid"):
        return ConfigProblem(
            f"{what}: this platform cannot establish who can change the file", "unsafe"
        )
    return _item_problem(directory, stat.S_ISDIR, "directory", what)


def _item_problem(path: Path, right_type: Any, kind: str, what: str) -> ConfigProblem | None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        missing = isinstance(exc, FileNotFoundError)
        return ConfigProblem(
            f"{what}: cannot read {path}: {exc.strerror}", "missing" if missing else "unsafe"
        )
    if not right_type(info.st_mode):
        return ConfigProblem(f"{what}: {path} is not a {kind}", "unsafe")
    if info.st_uid not in (os.geteuid(), 0):
        return ConfigProblem(f"{what}: {path} belongs to another account", "unsafe")
    if stat.S_IMODE(info.st_mode) & 0o022:
        return ConfigProblem(f"{what}: {path} can be changed by group or others", "unsafe")
    return None


def _owned_and_private_problem(path: Path, what: str) -> ConfigProblem | None:
    return _directory_problem(path.parent, what) or _item_problem(
        path, stat.S_ISREG, "regular file", what
    )


_KIND_WORDS = {int: "a whole number", str: "text", bool: "true or false"}


def approved_entries(count: int) -> str:
    """``1 approved issuer entry``, ``2 approved issuer entries``."""
    return f"{count} approved issuer {'entry' if count == 1 else 'entries'}"


def _member(raw: dict[str, Any], name: str, kind: type, default: Any = None) -> Any:
    value = raw.get(name, default)
    if type(value) is not kind and not (name not in raw and default is None):
        raise ConfigProblem(f"{name} must be {_KIND_WORDS.get(kind, kind.__name__)}")
    return value


def _create_replay_file(path: Path) -> None:
    """A new file is private from the start."""
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))
    except FileExistsError:
        return
    except OSError as exc:
        raise ConfigProblem(f"replay_db: cannot create {path}: {exc.strerror}", "unsafe") from exc


def read_settings(config_path: str | Path) -> Settings:
    """Read and check the configuration file. Read-only: it creates nothing and changes nothing."""
    path = Path(config_path).absolute()
    problem = _owned_and_private_problem(path, "configuration")
    if problem is not None:
        raise problem
    try:
        raw = loads_strict(path.read_bytes(), max_bytes=MAX_CONFIG_BYTES)
    except (OSError, CanonicalError, RecursionError, UnicodeDecodeError) as exc:
        raise ConfigProblem(f"configuration: {path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigProblem("configuration must be a JSON object")
    unknown = sorted(set(raw) - _MEMBERS)
    missing = sorted(_REQUIRED - set(raw))
    if unknown or missing:
        raise ConfigProblem(f"configuration: unknown members {unknown}, missing members {missing}")

    profile = _member(raw, "profile", str)
    if profile not in _PROFILES:
        raise ConfigProblem(f"profile must be one of {list(_PROFILES)}")
    verifier_id = _member(raw, "verifier_id", str)
    days = _member(raw, "max_age_days", int)
    if not verifier_id or days < 1 or days > 3650:
        raise ConfigProblem(
            "verifier_id must not be empty, and max_age_days must be from 1 to 3650"
        )
    replay_mode = _member(raw, "replay_mode", str, "check")
    if replay_mode not in ("check", "record"):
        raise ConfigProblem("replay_mode must be 'check' or 'record'")
    allow_self_signed = _member(raw, "allow_self_signed", bool, False)
    trust_mode = _member(raw, "trust_mode", str, "")
    if "trust_mode" in raw and trust_mode not in TRUST_MODES:
        raise ConfigProblem("trust_mode must be 'customer' or 'demonstration'")
    store_path = path.parent / _member(raw, "trust_store", str)
    replay_path = path.parent / _member(raw, "replay_db", str, "replay.db")
    return Settings(
        path,
        profile,
        verifier_id,
        days,
        replay_mode,
        allow_self_signed,
        store_path,
        replay_path,
        trust_mode,
    )


def trust_mode_of(settings: Settings, store: TrustStore) -> tuple[str, str]:
    """The kind of trust this is, and why: demonstration trust is kept apart from customer trust.

    It is a demonstration if the configuration says ``"trust_mode": "demonstration"`` (demo-setup writes it), or if
    the trust list holds one of the portal's bundled demonstration keys, recognised by exact fingerprint. A missing
    or ``"customer"`` setting cannot make a list with a bundled key into customer trust. Nothing else decides it: no
    issuer name or key id. A configuration without the setting and without a bundled key is customer trust.
    """
    if any(is_demonstration_entry(entry.public_key_pem) for entry in store.entries.values()):
        return DEMONSTRATION, "the trust list holds one of the portal's bundled demonstration keys"
    if settings.trust_mode == DEMONSTRATION:
        return DEMONSTRATION, 'the configuration says "trust_mode": "demonstration"'
    if settings.trust_mode == CUSTOMER:
        return CUSTOMER, 'the configuration says "trust_mode": "customer"'
    return (
        CUSTOMER,
        "the configuration does not say demonstration, and the trust list holds no bundled key",
    )


def is_demonstration_trust(settings: Settings, store: TrustStore) -> bool:
    return trust_mode_of(settings, store)[0] == DEMONSTRATION


def read_trust_store(settings: Settings) -> TrustStore:
    """Read and check the trust list the configuration names. Read-only."""
    problem = _owned_and_private_problem(settings.store_path, "trust_store")
    if problem is not None:
        raise problem
    try:
        store = TrustStore.from_json(settings.store_path)
    except TrustStoreError as exc:
        raise ConfigProblem(f"trust_store: {exc}") from exc
    if not store.keys or set(store.keys) != set(store.entries):
        raise ConfigProblem(
            "trust_store: it must use the 'entries' form, which states the issuer of each key. "
            "Build it with 'regaudit-fhe trust add'"
        )
    return store


def check_replay_location(settings: Settings) -> ConfigProblem | None:
    """Is the replay file's folder, and the file if it is already there, the administrator's own? Read-only.

    A file that is not there yet is not a problem: it is created, private, when the portal starts.
    """
    problem = _directory_problem(settings.replay_path.parent, "replay_db")
    if problem is not None:
        return problem
    if os.path.lexists(settings.replay_path):
        return _owned_and_private_problem(settings.replay_path, "replay_db")
    return None


def load_portal(config_path: str | Path) -> Portal:
    """Everything is checked before anything is accepted. Any doubt raises :class:`ConfigProblem`."""
    identity = check_engine()
    if not identity.ok or identity.engine is None:
        raise EngineProblem(
            f"engine: {identity.reason}: {identity.detail}. Reinstall with: {REINSTALL}"
        )
    engine = identity.engine
    settings = read_settings(config_path)
    store = read_trust_store(settings)
    problem = _directory_problem(settings.replay_path.parent, "replay_db")
    if problem is not None:
        raise problem
    _create_replay_file(settings.replay_path)
    problem = _owned_and_private_problem(settings.replay_path, "replay_db")
    if problem is not None:
        raise problem
    try:
        cache = SqliteReplayCache(settings.replay_path)
        policy = VerificationPolicy(
            profile=settings.profile,
            trust_store=store,
            allow_self_signed=settings.allow_self_signed,
            verifier_id=settings.verifier_id,
            max_age=timedelta(days=settings.max_age_days),
            replay_cache=cache,
            replay_mode=settings.replay_mode,
            check_provenance=True,
        )
    except (ReplayStateError, PolicyError) as exc:
        raise ConfigProblem(f"policy: {exc}") from exc
    mode, reason = trust_mode_of(settings, store)
    return Portal(
        policy, settings.profile, settings.replay_mode, len(store.keys), engine, mode, reason
    )
