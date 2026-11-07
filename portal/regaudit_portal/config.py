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
}
_REQUIRED = {"trust_store", "profile", "verifier_id", "max_age_days"}
_PROFILES = ("confidential", "high-assurance", "development")


class ConfigProblem(Exception):
    """The portal must not give verdicts until the administrator fixes this."""


class EngineProblem(ConfigProblem):
    """The installed engine is not the recognised release. The text is for the administrator's terminal only."""


@dataclass(frozen=True)
class Portal:
    policy: VerificationPolicy
    profile: str
    replay_mode: str
    approved_count: int
    engine: dict[str, Any]


def _directory_problem(directory: Path, what: str) -> str | None:
    """The administrator's files must be theirs, and no other account may be able to change them."""
    if os.name != "posix" or not hasattr(os, "geteuid"):
        return f"{what}: this platform cannot establish who can change the file"
    return _item_problem(directory, stat.S_ISDIR, "directory", what)


def _item_problem(path: Path, right_type: Any, kind: str, what: str) -> str | None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        return f"{what}: cannot read {path}: {exc.strerror}"
    if not right_type(info.st_mode):
        return f"{what}: {path} is not a {kind}"
    if info.st_uid not in (os.geteuid(), 0):
        return f"{what}: {path} belongs to another account"
    if stat.S_IMODE(info.st_mode) & 0o022:
        return f"{what}: {path} can be changed by group or others"
    return None


def _owned_and_private_problem(path: Path, what: str) -> str | None:
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
        raise ConfigProblem(f"replay_db: cannot create {path}: {exc.strerror}") from exc


def load_portal(config_path: str | Path) -> Portal:
    """Everything is checked before anything is accepted. Any doubt raises :class:`ConfigProblem`."""
    identity = check_engine()
    if not identity.ok or identity.engine is None:
        raise EngineProblem(
            f"engine: {identity.reason}: {identity.detail}. Reinstall with: {REINSTALL}"
        )
    engine = identity.engine
    path = Path(config_path).absolute()
    problem = _owned_and_private_problem(path, "configuration")
    if problem is not None:
        raise ConfigProblem(problem)
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

    store_path = path.parent / _member(raw, "trust_store", str)
    problem = _owned_and_private_problem(store_path, "trust_store")
    if problem is not None:
        raise ConfigProblem(problem)
    try:
        store = TrustStore.from_json(store_path)
    except TrustStoreError as exc:
        raise ConfigProblem(f"trust_store: {exc}") from exc
    if not store.keys or set(store.keys) != set(store.entries):
        raise ConfigProblem(
            "trust_store: it must use the 'entries' form, which states the issuer of each key. "
            "Build it with 'regaudit-fhe trust add'"
        )

    replay_path = path.parent / _member(raw, "replay_db", str, "replay.db")
    problem = _directory_problem(replay_path.parent, "replay_db")
    if problem is not None:
        raise ConfigProblem(problem)
    _create_replay_file(replay_path)
    problem = _owned_and_private_problem(replay_path, "replay_db")
    if problem is not None:
        raise ConfigProblem(problem)
    try:
        cache = SqliteReplayCache(replay_path)
        policy = VerificationPolicy(
            profile=profile,
            trust_store=store,
            allow_self_signed=allow_self_signed,
            verifier_id=verifier_id,
            max_age=timedelta(days=days),
            replay_cache=cache,
            replay_mode=replay_mode,
            check_provenance=True,
        )
    except (ReplayStateError, PolicyError) as exc:
        raise ConfigProblem(f"policy: {exc}") from exc
    return Portal(policy, profile, replay_mode, len(store.keys), engine)
