"""Local replay caches for verifiers.

These provide **local** replay detection only. A cache records
``(key_id, audit_run_id)`` pairs so that a verifier it belongs to can refuse a
report it has already recorded. They do **not** provide global single-use
enforcement:

* :class:`InMemoryReplayCache` (``scope = "LOCAL_PROCESS"``) is lost on
  restart.
* :class:`SqliteReplayCache` (``scope = "LOCAL_PERSISTENT"``) survives restarts
  and is shared by processes that open the same file on one host.
* Independent verifiers that do not share a store can each accept the same
  report once. No distributed store is implemented.

Recording happens at verification time and is not coupled to any downstream
operation, so it is not a crash-safe exactly-once guarantee for such an
operation (see ``docs/TRUST_SPEC.md`` section 6.2).

Retention is never shortened to make room: when the cache is full it raises
:class:`ReplayStateError` (the verifier fails closed) instead of evicting a
live entry.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Protocol, runtime_checkable

SCOPE_LOCAL_PROCESS = "LOCAL_PROCESS"
SCOPE_LOCAL_PERSISTENT = "LOCAL_PERSISTENT"


class ReplayStateError(RuntimeError):
    """The replay store is unavailable, corrupt or full (or was given unusable input)."""


def _stamp(moment: datetime) -> float:
    """POSIX seconds for an aware datetime; anything else fails closed."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ReplayStateError("replay times must be timezone-aware")
    try:
        return moment.timestamp()
    except (OverflowError, OSError, ValueError) as exc:
        raise ReplayStateError(f"time out of range: {exc}") from exc


def _check_text(*values: str) -> None:
    for value in values:
        try:
            value.encode("utf-8")
        except (UnicodeEncodeError, AttributeError) as exc:
            raise ReplayStateError("identifier is not valid text") from exc


@runtime_checkable
class ReplayCache(Protocol):
    scope: str

    def seen(self, key_id: str, run_id: str, *, now: datetime) -> bool: ...

    def record(self, key_id: str, run_id: str, *, now: datetime, retain: timedelta) -> bool:
        """Atomically record the pair; ``True`` if newly recorded, ``False`` if present."""
        ...


class InMemoryReplayCache:
    scope = SCOPE_LOCAL_PROCESS

    def __init__(self, capacity: int = 100_000) -> None:
        self._capacity = capacity
        self._entries: dict[tuple[str, str], datetime] = {}
        self._lock = threading.Lock()

    def _purge(self, now: datetime) -> None:
        for key in [k for k, exp in self._entries.items() if exp <= now]:
            del self._entries[key]

    def seen(self, key_id: str, run_id: str, *, now: datetime) -> bool:
        _check_text(key_id, run_id)
        _stamp(now)
        with self._lock:
            self._purge(now)
            return (key_id, run_id) in self._entries

    def record(self, key_id: str, run_id: str, *, now: datetime, retain: timedelta) -> bool:
        _check_text(key_id, run_id)
        _stamp(now)
        try:
            expires = now + retain
        except OverflowError as exc:
            raise ReplayStateError("retention overflows the supported time range") from exc
        with self._lock:
            self._purge(now)
            if (key_id, run_id) in self._entries:
                return False
            if len(self._entries) >= self._capacity:
                raise ReplayStateError("replay cache is full; refusing to evict live entries")
            self._entries[(key_id, run_id)] = expires
            return True


class SqliteReplayCache:
    scope = SCOPE_LOCAL_PERSISTENT

    def __init__(self, path: str | Path, capacity: int = 1_000_000) -> None:
        self._path = str(path)
        self._capacity = capacity
        try:
            conn = self._connect()
            try:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS replay ("
                    "key_id TEXT NOT NULL, run_id TEXT NOT NULL, expires_at REAL NOT NULL, "
                    "PRIMARY KEY (key_id, run_id))"
                )
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            raise ReplayStateError(f"cannot open replay store {self._path!r}: {exc}") from exc

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        return conn

    def seen(self, key_id: str, run_id: str, *, now: datetime) -> bool:
        _check_text(key_id, run_id)
        stamp = _stamp(now)
        try:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT 1 FROM replay WHERE key_id = ? AND run_id = ? AND expires_at > ?",
                    (key_id, run_id, stamp),
                ).fetchone()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise ReplayStateError(f"replay store error: {exc}") from exc
        return row is not None

    def record(self, key_id: str, run_id: str, *, now: datetime, retain: timedelta) -> bool:
        _check_text(key_id, run_id)
        stamp = _stamp(now)
        try:
            expires = _stamp(now + retain)
        except OverflowError as exc:
            raise ReplayStateError("retention overflows the supported time range") from exc
        try:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute("DELETE FROM replay WHERE expires_at <= ?", (stamp,))
                    present = conn.execute(
                        "SELECT 1 FROM replay WHERE key_id = ? AND run_id = ?", (key_id, run_id)
                    ).fetchone()
                    if present is not None:
                        conn.execute("COMMIT")
                        return False
                    (count,) = conn.execute("SELECT COUNT(*) FROM replay").fetchone()
                    if count >= self._capacity:
                        conn.execute("ROLLBACK")
                        raise ReplayStateError(
                            "replay store is full; refusing to evict live entries"
                        )
                    conn.execute(
                        "INSERT INTO replay (key_id, run_id, expires_at) VALUES (?, ?, ?)",
                        (key_id, run_id, expires),
                    )
                    conn.execute("COMMIT")
                    return True
                except ReplayStateError:
                    raise
                except sqlite3.Error:
                    conn.execute("ROLLBACK")
                    raise
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise ReplayStateError(f"replay store error: {exc}") from exc
