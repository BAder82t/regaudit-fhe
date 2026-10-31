"""Local trust-store lifecycle edits: ``trust status`` / ``retire`` / ``revoke``.

Everything here works inside the EXISTING ``entries`` trust-store format
(``status``, ``retired_at``, ``compromised_from``, ``as_of``). It adds no schema
member, and it changes nothing about how a store is verified.

A local file is editable by anyone who can write it. This module makes honest
operator edits safe (validated, atomic, monotonic, never loosening); it cannot
make the file an independently protected revocation authority. See
``docs/TRUST_LIFECYCLE_PROPOSAL.md``.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ._keys import spki_fingerprint
from ._time import parse_rfc3339
from .canonical import MAX_INPUT_BYTES, CanonicalError, loads_strict
from .trust import TrustStore, TrustStoreError

__all__ = ["LifecycleRefused", "retire", "revoke", "status_rows"]

# A boundary this far past the operator's clock is refused as a typo or a replayed clock.
FUTURE_SKEW = timedelta(minutes=5)
BACKUP_SUFFIX = ".prev"


class LifecycleRefused(ValueError):
    """The requested change is refused; nothing was written."""


def _utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _read(path: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = Path(path).read_bytes()
        payload = loads_strict(raw, max_bytes=MAX_INPUT_BYTES)
    except FileNotFoundError as exc:
        raise TrustStoreError(f"trust-store {path!r} does not exist") from exc
    except (OSError, CanonicalError, RecursionError) as exc:
        raise TrustStoreError(f"trust-store {path!r} is unusable: {exc}") from exc
    if not isinstance(payload, dict) or "entries" not in payload:
        raise TrustStoreError(
            f"{path!r} is not an 'entries' trust store; refusing to convert or edit it "
            "(re-enrol the keys with 'trust add' into a new entries store)"
        )
    try:
        TrustStore.from_dict(payload)
    except TrustStoreError as exc:
        raise TrustStoreError(f"{path!r} does not validate: {exc}") from exc
    return raw, payload


def status_rows(path: str, key_id: str | None = None) -> dict[str, Any]:
    """Read-only summary. Works for both the entries form and the legacy form."""
    store = TrustStore.from_json(path)
    rows = []
    for kid in sorted(store.keys):
        if key_id is not None and kid != key_id:
            continue
        entry = store.entry(kid)
        assert entry is not None
        rows.append(
            {
                "key_id": kid,
                "issuer": entry.issuer,
                "status": entry.status,
                "not_before": _utc(entry.not_before) if entry.not_before else None,
                "retired_at": _utc(entry.retired_at) if entry.retired_at else None,
                "compromised_from": _utc(entry.compromised_from)
                if entry.compromised_from
                else None,
                "fingerprint_sha256": spki_fingerprint(store.keys[kid]),
            }
        )
    if key_id is not None and not rows:
        raise LifecycleRefused(f"key_id {key_id!r} is not in the trust store")
    return {
        "store_form": "entries" if store.entries else "legacy",
        "as_of": _utc(store.as_of) if store.as_of else None,
        "authenticated": False,
        "note": "local file; unauthenticated and not an independent revocation authority",
        "keys": rows,
    }


def _write_atomic(path: str, data: bytes, expected_old: bytes) -> None:
    """Back up the old bytes, then replace the store atomically and durably.

    Any failure before ``os.replace`` leaves the old store byte-identical. The
    store is re-read just before the replace; if it changed since this edit
    began, nothing is written (narrows, but does not close, a concurrent-writer race).
    """
    target = Path(path)
    directory = target.parent if str(target.parent) else Path(".")
    backup = target.with_name(target.name + BACKUP_SUFFIX)
    tmp_paths: list[str] = []

    def stage(dest_data: bytes, mode: int) -> str:
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".trust-", suffix=".tmp")
        tmp_paths.append(tmp)
        with os.fdopen(fd, "wb") as handle:
            handle.write(dest_data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        return tmp

    try:
        new_tmp = stage(data, 0o644)
        backup_tmp = stage(expected_old, 0o600)
        if target.read_bytes() != expected_old:
            raise LifecycleRefused("the trust store changed while this edit was prepared; retry")
        os.replace(backup_tmp, backup)
        os.replace(new_tmp, target)
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        for tmp in tmp_paths:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


def _mutate(
    path: str,
    key_id: str,
    now: datetime,
    change: Callable[[dict[str, Any], datetime], None],
) -> dict[str, Any]:
    if now.tzinfo is None:
        raise LifecycleRefused("the clock must be timezone-aware")
    raw, payload = _read(path)
    entries = payload["entries"]
    entry = entries.get(key_id)
    if entry is None:
        raise LifecycleRefused(f"key_id {key_id!r} is not in the trust store")
    before = {k: entry.get(k) for k in ("status", "retired_at", "compromised_from")}
    old_as_of = payload.get("as_of")
    if isinstance(old_as_of, str) and parse_rfc3339(old_as_of) > now + FUTURE_SKEW:
        raise LifecycleRefused(
            f"store as_of {old_as_of} is later than this machine's clock: possible clock "
            "rollback or a store from elsewhere; refusing to move as_of backwards"
        )
    change(entry, now)
    payload["as_of"] = _utc(now) if old_as_of is None else _utc(max(now, parse_rfc3339(old_as_of)))
    try:
        TrustStore.from_dict(payload)  # the validation verification will apply
    except TrustStoreError as exc:
        raise LifecycleRefused(f"refused, nothing written: {exc}") from exc
    data = (_dump(payload)).encode("utf-8")
    _write_atomic(path, data, raw)
    return {
        "key_id": key_id,
        "before": before,
        "after": {k: entry.get(k) for k in ("status", "retired_at", "compromised_from")},
        "as_of": payload["as_of"],
        "store": path,
        "backup": path + BACKUP_SUFFIX,
        "store_sha256": hashlib.sha256(data).hexdigest(),
    }


def _dump(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload, indent=2) + "\n"


def _boundary(text: str, now: datetime, what: str) -> datetime:
    try:
        moment = parse_rfc3339(text)
    except ValueError as exc:
        raise LifecycleRefused(f"{what}: {exc}") from exc
    if moment > now + FUTURE_SKEW:
        raise LifecycleRefused(f"{what} {text} is in the future; refusing")
    return moment


def retire(path: str, key_id: str, *, at: str | None, now: datetime) -> dict[str, Any]:
    """active -> retired. Planned rotation; never undone, never re-dated."""
    when = _boundary(at, now, "--at") if at is not None else now

    def change(entry: dict[str, Any], _now: datetime) -> None:
        if entry.get("status") != "active":
            raise LifecycleRefused(
                f"key_id {key_id!r} is {entry.get('status')!r}; only an active key can be "
                "retired (status changes are one-way and boundaries are never re-dated)"
            )
        nb = entry.get("not_before")
        if isinstance(nb, str) and when < parse_rfc3339(nb):
            raise LifecycleRefused("--at is earlier than the key's not_before")
        entry["status"] = "retired"
        entry["retired_at"] = _utc(when)

    return _mutate(path, key_id, now, change)


def revoke(
    path: str, key_id: str, *, compromised_from: str | None, now: datetime
) -> dict[str, Any]:
    """active|retired -> compromised. No boundary means "unknown": everything it signed is refused.

    Never loosens: a retired key's compromise boundary may not be later than its
    retired_at (that would re-open the interval retirement already closed).
    ``retired_at`` cannot coexist with ``compromised`` in this format; the old
    value stays in the ``.prev`` backup.
    """
    boundary = _boundary(compromised_from, now, "--compromised-from") if compromised_from else None

    def change(entry: dict[str, Any], _now: datetime) -> None:
        status = entry.get("status")
        if status == "compromised":
            raise LifecycleRefused(
                f"key_id {key_id!r} is already compromised; its boundary is never edited"
            )
        if status == "retired" and boundary is not None:
            retired_at = parse_rfc3339(entry["retired_at"])
            if boundary > retired_at:
                raise LifecycleRefused(
                    "--compromised-from is later than the key's retired_at; that would "
                    "accept reports retirement already refuses. Use an earlier boundary, "
                    "or omit it (unknown boundary refuses everything the key signed)"
                )
        entry["status"] = "compromised"
        entry.pop("retired_at", None)
        if boundary is not None:
            entry["compromised_from"] = _utc(boundary)

    return _mutate(path, key_id, now, change)
