"""Issuer-side tooling for signed revocation data. EXPERIMENTAL.

It refuses inconsistent or hazardous actions **before signing**, because a verifier's protection against a bad list
is a contradiction latch that stops the whole issuer. A retired key stated as compromised after its retirement is
refused: the only form verifiers accept is a time at or before the retirement, and the operator has to state it. The
publisher persists a list before releasing it, so
that a crash cannot lead to a second, different list at the same epoch.

The signer here is a delegate of the enrolled pin and recovery anchor. There is no approver and no quorum.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from . import _revocation as rv
from ._keys import spki_fingerprint
from ._time import parse_rfc3339
from .canonical import CanonicalError, loads_strict
from .trust import TrustStore

MAX_LIST_VALIDITY = timedelta(days=30)
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")


class ActionRefused(ValueError):
    """The requested revocation action is inconsistent or hazardous. Nothing was signed."""


@dataclass(frozen=True)
class KeyAction:
    """One requested change to one report key."""

    key_id: str
    key_fingerprint: str
    status: str  # retired | replaced | compromised
    effective_from: str | None  # None only for compromised: unknown boundary
    successor: tuple[str, str] | None = None  # (key_id, fingerprint), required for replaced

    def entry(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "key_id": self.key_id,
            "key_fingerprint": self.key_fingerprint,
            "status": self.status,
            "effective_from": self.effective_from,
        }
        if self.successor is not None:
            out["successor"] = {"key_id": self.successor[0], "key_fingerprint": self.successor[1]}
        return out


@dataclass(frozen=True)
class NextList:
    document: dict[str, Any]
    digest: str


def _time_of(text: str, what: str) -> datetime:
    try:
        return parse_rfc3339(text)
    except ValueError as exc:
        raise ActionRefused(f"{what}: {exc}") from exc


def _check_action(action: KeyAction, now: datetime) -> None:
    if not action.key_id or len(action.key_id) > 256:
        raise ActionRefused("key_id must be 1..256 characters")
    if not _FINGERPRINT.fullmatch(action.key_fingerprint):
        raise ActionRefused(f"{action.key_id}: the fingerprint must be 64 lowercase hex characters")
    if action.status not in rv.STATUSES:
        raise ActionRefused(f"{action.key_id}: status must be one of {rv.STATUSES}")
    if action.effective_from is None:
        if action.status != "compromised":
            raise ActionRefused(f"{action.key_id}: only a compromise may have an unknown boundary")
    elif _time_of(action.effective_from, action.key_id) > now + rv.SKEW:
        raise ActionRefused(f"{action.key_id}: a future-dated action is refused")
    if action.status == "replaced" and action.successor is None:
        raise ActionRefused(f"{action.key_id}: replaced needs a successor")
    if action.successor is not None:
        if not _FINGERPRINT.fullmatch(action.successor[1]):
            raise ActionRefused(f"{action.key_id}: the successor fingerprint is malformed")
        if action.successor[1] == action.key_fingerprint or action.successor[0] == action.key_id:
            raise ActionRefused(f"{action.key_id}: a key cannot be its own successor")


def _merge(old: dict[str, Any] | None, action: KeyAction) -> dict[str, Any]:
    new = action.entry()
    if old is None:
        return new
    kid = action.key_id
    if old["key_fingerprint"] != action.key_fingerprint:
        raise ActionRefused(f"{kid}: this key_id is already bound to another fingerprint")
    if "successor" in old:
        if "successor" in new and new["successor"] != old["successor"]:
            raise ActionRefused(f"{kid}: the successor cannot change")
        new.setdefault("successor", old["successor"])
    was, eff = old["status"], old["effective_from"]
    if was == "compromised":
        if action.status != "compromised":
            raise ActionRefused(f"{kid}: a compromised key cannot move back to {action.status}")
        if eff is None and action.effective_from is not None:
            raise ActionRefused(f"{kid}: an unknown boundary cannot become known")
        if (
            eff is not None
            and action.effective_from is not None
            and parse_rfc3339(action.effective_from) > parse_rfc3339(eff)
        ):
            raise ActionRefused(f"{kid}: a compromise boundary can only move earlier")
        return new
    if action.status == "compromised":
        # Retired, then compromised after the retirement. Verifiers refuse the later boundary and latch the whole
        # issuer on it. Nothing the key signed at or after R is acceptable anyway, so the operator can state R, but
        # the tool does not rewrite a stated time: that is a decision about what is true.
        if action.effective_from is not None and parse_rfc3339(
            action.effective_from
        ) > parse_rfc3339(eff):
            raise ActionRefused(
                f"{kid}: compromise time {action.effective_from} is after the retirement at {eff}. Verifiers "
                f"would refuse this list and stop trusting every key of this issuer until a recovery. Nothing "
                f"signed at or after the retirement is acceptable anyway: state {eff} or earlier, or no time "
                "for an unknown boundary"
            )
        return new
    if action.effective_from != eff:
        raise ActionRefused(f"{kid}: a retirement date is fixed once published")
    return new


def next_list(
    *,
    issuer: str,
    authority: Any,
    generation: int,
    previous: dict[str, Any] | None,
    actions: list[KeyAction],
    now: datetime,
    valid_for: timedelta,
    trust_store: TrustStore | None = None,
    recovery_anchor_pem: str | None = None,
    allow_unknown_keys: bool = False,
    after_recovery: dict[str, Any] | None = None,
) -> NextList:
    """The next cumulative list, signed by ``authority`` (anything with ``sign``, ``key_id`` and
    ``public_key_pem``). With no actions this is a heartbeat. Raises :class:`ActionRefused` before signing.

    Lists are cumulative and an entry can never be withdrawn, so a mistake here is permanent. ``trust_store`` is the
    issuer's own inventory of report keys: with it, an action must name a key it holds, with the right fingerprint,
    unless ``allow_unknown_keys``. ``after_recovery`` is the statement that installed this signer, whose generation
    may be at or below the previous list's.
    """
    if now.tzinfo is None:
        raise ActionRefused("now must be timezone-aware")
    if not timedelta(0) < valid_for <= MAX_LIST_VALIDITY:
        raise ActionRefused("the list validity must be positive and at most 30 days")
    pem = authority.public_key_pem()
    fingerprint = spki_fingerprint(pem)
    if recovery_anchor_pem is not None and spki_fingerprint(recovery_anchor_pem) == fingerprint:
        raise ActionRefused("the list signer is the recovery anchor")
    if trust_store is not None and fingerprint in {
        spki_fingerprint(p) for p in trust_store.keys.values()
    }:
        raise ActionRefused("the list signer is a report key")
    current: dict[str, dict[str, Any]] = {}
    if previous is not None:
        if previous["issuer"] != issuer:
            raise ActionRefused("the previous list belongs to another issuer")
        was = previous["authority"]
        if after_recovery is not None:
            installed = after_recovery["new_authority"]
            if installed["key_fingerprint"] != fingerprint or installed["generation"] != generation:
                raise ActionRefused("this recovery statement does not install this signer at this generation")
        elif generation < was["generation"]:
            raise ActionRefused("the generation is below the previous list's")
        elif generation == was["generation"] and was["key_fingerprint"] != fingerprint:
            raise ActionRefused("another key at the same generation: rotate with a transition first")
        elif generation > was["generation"] and was["key_fingerprint"] == fingerprint:
            raise ActionRefused("the same key at a new generation: a rotation names a new key")
        if parse_rfc3339(previous["issued_at"]) > now + rv.SKEW:
            raise ActionRefused("the previous list is in the future: check this machine's clock")
        current = {e["key_id"]: e for e in previous["entries"]}
    seen: set[str] = set()
    for action in actions:
        _check_action(action, now)
        if action.key_id in seen:
            raise ActionRefused(f"{action.key_id}: two actions for one key in one list")
        seen.add(action.key_id)
        if action.key_fingerprint == fingerprint:
            raise ActionRefused("a list cannot name its own signer")
        current[action.key_id] = _merge(current.get(action.key_id), action)
    if len({e["key_fingerprint"] for e in current.values()}) != len(current):
        raise ActionRefused("one fingerprint would appear under two key_ids")
    if rv._successor_cycle(list(current.values())):
        raise ActionRefused("the successors would form a cycle")
    if trust_store is not None:
        conflict = rv._store_conflict(list(current.values()), issuer, trust_store)
        if conflict:
            raise ActionRefused(f"{conflict[0]}: {conflict[1]}: verifiers would refuse this list")
        held = {spki_fingerprint(p) for p in trust_store.keys.values()}
        for action in actions:
            if not allow_unknown_keys and action.key_fingerprint not in held:
                raise ActionRefused(
                    f"{action.key_id}: not in the inventory of report keys. An entry can never be "
                    "withdrawn: check the fingerprint, or say this is intended"
                )
    issued = max(now, parse_rfc3339(previous["issued_at"])) if previous is not None else now
    body = rv.build_body(
        issuer=issuer,
        authority_key_id=authority.key_id,
        authority_pem=pem,
        authority_generation=generation,
        epoch=previous["epoch"] + 1 if previous is not None else 1,
        prev_list_digest=rv.list_digest(previous) if previous is not None else None,
        issued_at=rv._z(issued),
        valid_until=rv._z(issued + valid_for),
        entries=list(current.values()),
    )
    document = rv.sign_list(body, authority)
    # The verifier's own rules, before anything leaves this function.
    try:
        rv.validate_shape(document)
    except rv.ShapeError as exc:
        raise ActionRefused(f"the list would be malformed: {exc}") from exc
    if len(json.dumps(document, indent=2, sort_keys=True).encode()) > rv.MAX_BYTES:
        raise ActionRefused(f"the list would exceed the {rv.MAX_BYTES}-byte size verifiers read")
    if previous is not None:
        problem = rv._monotone(
            {e["key_id"]: e for e in previous["entries"]},
            {e["key_id"]: e for e in document["entries"]},
        )
        if problem:
            raise ActionRefused(f"the list would not be monotone: {problem}")
    return NextList(document, rv.list_digest(document))


def sign_transition_statement(
    *,
    issuer: str,
    from_signer: Any,
    from_generation: int,
    to_signer: Any,
    now: datetime,
    valid_for: timedelta = timedelta(days=365),
    trust_store: TrustStore | None = None,
    recovery_anchor_pem: str | None = None,
) -> dict[str, Any]:
    """A routine rotation. Long validity by default: a verifier offline past it needs a ceremony."""
    if valid_for <= timedelta(0):
        raise ActionRefused("the validity must be positive")
    old_fp = spki_fingerprint(from_signer.public_key_pem())
    new_fp = spki_fingerprint(to_signer.public_key_pem())
    if old_fp == new_fp:
        raise ActionRefused("the new authority is the current authority")
    if recovery_anchor_pem is not None and spki_fingerprint(recovery_anchor_pem) == new_fp:
        raise ActionRefused("the new authority is the recovery anchor")
    if trust_store is not None and new_fp in {spki_fingerprint(p) for p in trust_store.keys.values()}:
        raise ActionRefused("the new authority is a report key")
    body = rv.build_transition_body(
        issuer=issuer,
        from_key_id=from_signer.key_id,
        from_pem=from_signer.public_key_pem(),
        from_generation=from_generation,
        to_key_id=to_signer.key_id,
        to_pem=to_signer.public_key_pem(),
        issued_at=rv._z(now),
        valid_until=rv._z(now + valid_for),
    )
    document = rv.sign_transition(body, from_signer, to_signer)
    rv.validate_transition_shape(document)
    return document


def sign_recovery_statement(
    *,
    issuer: str,
    anchor: Any,
    new_authority: Any,
    new_generation: int,
    recovery_epoch: int,
    declares: list[tuple[str, str | None]],
    now: datetime,
    previous: dict[str, Any] | None = None,
    rebase: dict[str, Any] | None = None,
    valid_for: timedelta = timedelta(days=365),
) -> dict[str, Any]:
    """Compromise recovery, signed by the recovery anchor. Declarations must be cumulative across statements,
    since a verifier that misses one statement would otherwise never learn what only that one said."""
    if valid_for <= timedelta(0):
        raise ActionRefused("the validity must be positive")
    anchor_fp = spki_fingerprint(anchor.public_key_pem())
    new_fp = spki_fingerprint(new_authority.public_key_pem())
    if anchor_fp == new_fp:
        raise ActionRefused("the new authority is the recovery anchor")
    if not declares:
        raise ActionRefused("a recovery must declare at least one key compromised")
    fingerprints = [fp for fp, _ in declares]
    if len(set(fingerprints)) != len(fingerprints):
        raise ActionRefused("a key is declared twice")
    if anchor_fp in fingerprints or new_fp in fingerprints:
        raise ActionRefused("a recovery cannot declare the anchor or its own new authority")
    for fp, boundary in declares:
        if not _FINGERPRINT.fullmatch(fp):
            raise ActionRefused("a declared fingerprint is malformed")
        if boundary is not None and _time_of(boundary, fp) > now + rv.SKEW:
            raise ActionRefused(f"{fp}: a future-dated compromise is refused")
    if previous is not None:
        if recovery_epoch <= previous["recovery_epoch"]:
            raise ActionRefused("recovery_epoch must be newer than the previous statement's")
        if new_generation <= previous["new_authority"]["generation"]:
            raise ActionRefused("the new generation must exceed the previous statement's")
        missing = {d["key_fingerprint"] for d in previous["declares_compromised"]} - set(fingerprints)
        if missing:
            raise ActionRefused(f"declarations must be cumulative; missing {sorted(missing)}")
        if new_fp == previous["new_authority"]["key_fingerprint"]:
            raise ActionRefused("the new authority must be a fresh key")
    body = rv.build_recovery_body(
        issuer=issuer,
        anchor_key_id=anchor.key_id,
        anchor_pem=anchor.public_key_pem(),
        recovery_epoch=recovery_epoch,
        declares=declares,
        new_key_id=new_authority.key_id,
        new_pem=new_authority.public_key_pem(),
        new_generation=new_generation,
        rebase=rebase,
        issued_at=rv._z(now),
        valid_until=rv._z(now + valid_for),
    )
    document = rv.sign_recovery(body, anchor, new_authority)
    rv.validate_recovery_shape(document)
    return document


# ----------------------------------------------------------------------------- the publisher's own state


def load_publisher_state(path: str | Path) -> dict[str, Any] | None:
    """The last list this publisher signed, or ``None`` if the file does not exist."""
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ActionRefused(f"cannot read the publisher state: {exc}") from exc
    try:
        doc = loads_strict(raw, max_bytes=rv.MAX_BYTES * 2)
    except (CanonicalError, RecursionError, UnicodeDecodeError) as exc:
        raise ActionRefused(f"the publisher state is unusable: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) != {"last_list"}:
        raise ActionRefused("the publisher state has an unexpected shape")
    last = doc["last_list"]
    try:
        rv.validate_shape(last)
    except rv.ShapeError as exc:
        raise ActionRefused(f"the publisher state holds a malformed list: {exc}") from exc
    return last  # type: ignore[no-any-return]


@contextlib.contextmanager
def publisher_lock(path: str | Path) -> Iterator[None]:
    """Serialise read, sign and persist across processes: two publishers at once would be a fork."""
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - supported platforms have it
        raise ActionRefused("this platform has no flock; refusing to publish") from exc
    lock_path = f"{path}.lock"
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as exc:
        raise ActionRefused(f"cannot lock the publisher state: {exc}") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def persist_before_release(path: str | Path, document: dict[str, Any]) -> None:
    """Durably record a signed list before anyone can see it, so that a crash leads to a gap and never to a fork."""
    target = Path(path)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".publisher-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"last_list": document}, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
        dir_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise ActionRefused(f"cannot persist the list; nothing released: {exc}") from exc
