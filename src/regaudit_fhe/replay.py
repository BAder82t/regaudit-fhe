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

**Policy floors.** Retention is decided when an identifier is recorded, so raising
``max_age`` between runs could let an identifier expire while its report is still
acceptable, and the same report would be accepted twice. Each shipped cache
therefore keeps a floor, :meth:`bind_max_age`: the smallest effective ``max_age`` it
has served. It only goes down, and a larger setting is not honoured against that
store. The sqlite store keeps a second floor for ``trust_history_max_age``. Both
survive restarts. Two policies sharing one store are held to the smaller value. A
third-party cache without the methods has no floor.

**Versioned files.** A sqlite file is at schema version 2 when it has a
``replay_meta`` row. A file written by a published version has none, and it does not
say what policy wrote it or what has been purged from it. Such a file is refused
(:class:`LegacyReplayFile`), never quietly adopted: the operator runs
:func:`migrate_replay_file`, stating the earlier ``max_age`` or stating that it is
unknown. Nothing is invented. See ``docs/DEPLOYMENT.md``.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import contextlib
import math
import sqlite3
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

SCOPE_LOCAL_PROCESS = "LOCAL_PROCESS"
SCOPE_LOCAL_PERSISTENT = "LOCAL_PERSISTENT"


class ReplayStateError(RuntimeError):
    """The replay store is unavailable, corrupt or full (or was given unusable input)."""


class LegacyReplayFile(ReplayStateError):
    """A file written by a published version: it must be migrated explicitly before use."""


class ReplayMigrationRefused(ReplayStateError):
    """Nothing was migrated: the state is ambiguous or malformed, or the request is."""


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
    # True only if a recorded identifier survives a process restart (is committed to
    # disk before ``record`` returns). Disclosed in every verification result.
    durable: bool

    def seen(self, key_id: str, run_id: str, *, now: datetime) -> bool:
        """Whether the pair is currently recorded (does not record)."""

    def record(self, key_id: str, run_id: str, *, now: datetime, retain: timedelta) -> bool:
        """Atomically record the pair; ``True`` if newly recorded, ``False`` if present."""


def _checked_requested(requested: timedelta) -> timedelta:
    if not isinstance(requested, timedelta) or requested <= timedelta(0):
        raise ReplayStateError("max_age must be a positive timedelta")
    return requested


class InMemoryReplayCache:
    scope = SCOPE_LOCAL_PROCESS
    durable = False  # lost when the process exits

    def __init__(self, capacity: int = 100_000) -> None:
        self._capacity = capacity
        self._entries: dict[tuple[str, str], datetime] = {}
        self._lock = threading.Lock()
        self._max_age_floor: timedelta | None = None

    def bind_max_age(self, requested: timedelta, *, persist: bool) -> timedelta:
        """The ``max_age`` to enforce: ``requested``, or the floor if that is smaller. See the module docstring."""
        _checked_requested(requested)
        with self._lock:
            floor = self._max_age_floor
            effective = requested if floor is None else min(floor, requested)
            if persist:
                self._max_age_floor = effective
            return effective

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


REPLAY_SCHEMA_VERSION = 2
_EMPTY, _LEGACY, _CURRENT = "empty", "legacy", "current"
_ORIGINS = ("new", "operator-attested", "history-unknown")
_CREATE_REPLAY = (
    "CREATE TABLE replay (key_id TEXT NOT NULL, run_id TEXT NOT NULL, expires_at REAL NOT NULL, "
    "PRIMARY KEY (key_id, run_id))"
)
_CREATE_META = (
    "CREATE TABLE replay_meta (id INTEGER PRIMARY KEY CHECK (id = 1), schema_version INTEGER NOT NULL, "
    "origin TEXT NOT NULL, max_age_us INTEGER, trust_history_max_age_us INTEGER, history_cutover REAL, "
    "migrated_at REAL)"
)
_INSERT_META = (
    "INSERT INTO replay_meta (id, schema_version, origin, max_age_us, trust_history_max_age_us, "
    "history_cutover, migrated_at) VALUES (1, ?, ?, ?, ?, ?, ?)"
)
_FLOOR_UPDATE = {
    "max_age_us": "UPDATE replay_meta SET max_age_us = ? WHERE id = 1",
    "trust_history_max_age_us": "UPDATE replay_meta SET trust_history_max_age_us = ? WHERE id = 1",
}
DEFAULT_TRUST_HISTORY_MAX_AGE = timedelta(hours=24)


def _legacy_message(path: str) -> str:
    return (
        f"replay store {path!r} was written by an earlier version and does not say what policy wrote it. "
        "Refusing to adopt it silently. Run: regaudit-fhe replay migrate --db FILE with "
        "--previous-max-age-seconds N or --previous-policy-unknown (see docs/DEPLOYMENT.md)"
    )


def _classify(conn: sqlite3.Connection) -> str:
    """What this file is. Anything but the three known shapes is ambiguous, and refused."""
    objects = conn.execute(
        "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    if any(kind != "table" for _, kind in objects):
        raise ReplayStateError("replay store has an unexpected view")
    tables = {name for name, _ in objects}
    if not tables:
        return _EMPTY
    if tables == {"replay"}:
        return _LEGACY
    if tables == {"replay", "replay_meta"}:
        return _CURRENT
    raise ReplayStateError(f"replay store has unexpected tables {sorted(tables)}")


def _refuse_if_not_current(conn: sqlite3.Connection, path: str) -> None:
    state = _classify(conn)
    if state == _LEGACY:  # for instance a backup restored under a running process
        raise LegacyReplayFile(_legacy_message(path))
    if state == _CURRENT:
        _read_meta(conn)


def _read_meta(conn: sqlite3.Connection) -> dict[str, Any]:
    state = _classify(conn)
    if state == _LEGACY:
        raise LegacyReplayFile("replay store is not at the current schema version")
    rows = conn.execute(
        "SELECT schema_version, origin, max_age_us, trust_history_max_age_us, history_cutover, migrated_at "
        "FROM replay_meta"
    ).fetchall()
    if len(rows) != 1:
        raise ReplayStateError("replay store policy record is missing or duplicated")
    version, origin, max_age, history, cutover, migrated = rows[0]
    if version != REPLAY_SCHEMA_VERSION or type(version) is not int:
        raise ReplayStateError(f"replay store has unsupported schema version {version!r}")
    if origin not in _ORIGINS:
        raise ReplayStateError("replay store policy record is corrupt")
    for floor in (max_age, history):
        if floor is not None and (type(floor) is not int or floor <= 0):
            raise ReplayStateError("replay store policy floor is corrupt")
    for moment in (cutover, migrated):
        if moment is not None and (
            not isinstance(moment, (int, float)) or not math.isfinite(moment)
        ):
            raise ReplayStateError("replay store policy record is corrupt")
    if origin == "history-unknown" and cutover is None:
        raise ReplayStateError("replay store policy record is corrupt")
    return {
        "schema_version": version,
        "origin": origin,
        "max_age_us": max_age,
        "trust_history_max_age_us": history,
        "history_cutover": cutover,
        "migrated_at": migrated,
    }


def replay_file_status(path: str | Path) -> dict[str, Any]:
    """Read-only description of a replay file, for operators. Writes nothing."""
    target = Path(path)
    if not target.is_file():
        raise ReplayStateError(f"{str(path)!r} is not a file")
    try:
        conn = sqlite3.connect(f"{target.resolve().as_uri()}?mode=ro", uri=True, timeout=5.0)
        try:
            state = _classify(conn)
            out: dict[str, Any] = {"path": str(path), "state": state}
            if state == _CURRENT:
                out.update(_read_meta(conn))
            if state != _EMPTY:
                (out["rows"],) = conn.execute("SELECT COUNT(*) FROM replay").fetchone()
            return out
        finally:
            conn.close()
    except sqlite3.Error as exc:
        raise ReplayStateError(f"cannot read replay store {str(path)!r}: {exc}") from exc


def _check_legacy_contents(conn: sqlite3.Connection) -> tuple[int, float | None]:
    """A published file has exactly one shape. Anything else is ambiguous, so nothing is guessed."""
    if conn.execute("PRAGMA integrity_check").fetchone() != ("ok",):
        raise ReplayMigrationRefused("the file fails sqlite's integrity check")
    columns = [(c[1], c[2].upper(), c[3], c[5]) for c in conn.execute("PRAGMA table_info(replay)")]
    if columns != [
        ("key_id", "TEXT", 1, 1),
        ("run_id", "TEXT", 1, 2),
        ("expires_at", "REAL", 1, 0),
    ]:
        raise ReplayMigrationRefused("the replay table does not have the published shape")
    (bad,) = conn.execute(
        "SELECT COUNT(*) FROM replay WHERE typeof(key_id) != 'text' OR typeof(run_id) != 'text' "
        "OR typeof(expires_at) NOT IN ('real', 'integer') OR abs(expires_at) > 1e15"
    ).fetchone()
    if bad:
        raise ReplayMigrationRefused(f"{bad} replay row(s) are malformed")
    (count, latest) = conn.execute("SELECT COUNT(*), MAX(expires_at) FROM replay").fetchone()
    return count, latest


def migrate_replay_file(
    path: str | Path,
    *,
    now: datetime,
    previous_max_age: timedelta | None = None,
    previous_policy_unknown: bool = False,
    previous_trust_history_max_age: timedelta = DEFAULT_TRUST_HISTORY_MAX_AGE,
    assumed_clock_skew: timedelta = timedelta(minutes=5),
    _fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Bring a published file to the current version in one transaction. Rows are not touched.

    The file never recorded its policy, so the operator says which of two things is true:

    * ``previous_max_age``: an **operator statement** of the largest ``max_age`` this file ever served. It becomes
      the floor, so verdicts are as before under that setting and a larger one is not honoured. If the statement is
      false, the guarantee is false; the file cannot show it, beyond refusing a value its rows contradict.
    * ``previous_policy_unknown``: every report issued up to now (plus the clock skew) is refused from here on
      (``REPLAY_HISTORY_UNKNOWN``), since it may have been recorded and purged. Only later reports are accepted.

    An interrupted migration leaves the file as it was, and it is refused until migrated.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ReplayMigrationRefused("now must be timezone-aware")
    if (previous_max_age is None) == (not previous_policy_unknown):
        raise ReplayMigrationRefused(
            "state exactly one of: the previous max_age, or that the previous policy is unknown"
        )
    for name, value in (
        ("previous_max_age", previous_max_age),
        ("previous_trust_history_max_age", previous_trust_history_max_age),
    ):
        if value is not None and (not isinstance(value, timedelta) or value <= timedelta(0)):
            raise ReplayMigrationRefused(f"{name} must be a positive timedelta")
    target = Path(path)
    if not target.is_file():
        raise ReplayMigrationRefused(f"{str(path)!r} is not a file; nothing to migrate")
    stamp = _stamp(now)
    try:
        conn = sqlite3.connect(str(target), timeout=5.0, isolation_level=None)
        try:
            conn.execute("BEGIN EXCLUSIVE")
            try:
                state = _classify(conn)
                if state == _CURRENT:
                    raise ReplayMigrationRefused("already at the current version")
                if state == _EMPTY:
                    raise ReplayMigrationRefused("no replay table: not a published replay file")
                count, latest = _check_legacy_contents(conn)
                floor = None
                origin = "history-unknown"
                cutover: float | None = stamp
                if previous_max_age is not None:
                    limit = stamp + (previous_max_age + 2 * assumed_clock_skew).total_seconds()
                    if latest is not None and latest > limit:
                        raise ReplayMigrationRefused(
                            "a row outlives the stated max_age, so the statement contradicts the file: "
                            "state a larger value, or that the previous policy is unknown"
                        )
                    floor = previous_max_age // timedelta(microseconds=1)
                    origin = "operator-attested"
                    cutover = None
                history = previous_trust_history_max_age // timedelta(microseconds=1)
                conn.execute(_CREATE_META)
                conn.execute(_INSERT_META, (REPLAY_SCHEMA_VERSION, origin, floor, history, cutover, stamp))
                if _fault is not None:
                    _fault("before-commit")
                conn.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()
    except sqlite3.Error as exc:
        raise ReplayMigrationRefused(f"cannot migrate {str(path)!r}: {exc}") from exc
    return {
        "path": str(path),
        "schema_version": REPLAY_SCHEMA_VERSION,
        "origin": origin,
        "rows_preserved": count,
        "max_age_floor_s": None if floor is None else floor / 1_000_000,
        "trust_history_max_age_floor_s": history / 1_000_000,
        "refuses_reports_issued_up_to": None if cutover is None else now.isoformat(),
    }


class SqliteReplayCache:
    scope = SCOPE_LOCAL_PERSISTENT
    durable = True  # committed to the sqlite file before record() returns

    def __init__(self, path: str | Path, capacity: int = 1_000_000) -> None:
        self._path = str(path)
        self._capacity = capacity
        self._lock = threading.Lock()
        self._lowest: dict[str, int] = {}
        try:
            conn = self._connect()
            try:
                state = _classify(conn)
                if state == _EMPTY:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        if _classify(conn) == _EMPTY:  # another process may have got here first
                            conn.execute(_CREATE_REPLAY)
                            conn.execute(_CREATE_META)
                            conn.execute(_INSERT_META, (REPLAY_SCHEMA_VERSION, "new", None, None, None, None))
                        conn.execute("COMMIT")
                    except sqlite3.Error:
                        conn.execute("ROLLBACK")
                        raise
                    state = _classify(conn)
                if state == _LEGACY:
                    raise LegacyReplayFile(_legacy_message(self._path))
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            raise ReplayStateError(f"cannot open replay store {self._path!r}: {exc}") from exc

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        return conn

    def _floor_memory(self, column: str, stored: int | None) -> None:
        """A floor only goes down, so one that went up while this object was alive means the file was replaced."""
        with self._lock:
            lowest = self._lowest.get(column)
            if lowest is not None and (stored is None or stored > lowest):
                raise ReplayStateError(
                    "replay store policy floor went up while in use: the file was restored or replaced"
                )
            if stored is not None:
                self._lowest[column] = stored if lowest is None else min(stored, lowest)

    def _bind_floor(self, column: str, requested: timedelta, *, persist: bool) -> timedelta:
        wanted = _checked_requested(requested) // timedelta(microseconds=1)
        try:
            conn = self._connect()
            try:
                if _classify(conn) == _EMPTY:  # ":memory:", or a file deleted under us: the record step reports it
                    return requested
                floor = _read_meta(conn)[column]
                self._floor_memory(column, floor)
                if floor is not None and floor <= wanted:
                    return timedelta(microseconds=floor)
                if not persist:
                    return requested
                conn.execute("BEGIN IMMEDIATE")
                try:
                    if _classify(conn) != _CURRENT:
                        raise ReplayStateError("replay store changed during use")
                    floor = _read_meta(conn)[column]
                    effective = wanted if floor is None else min(floor, wanted)
                    conn.execute(_FLOOR_UPDATE[column], (effective,))
                    conn.execute("COMMIT")
                except sqlite3.Error:
                    conn.execute("ROLLBACK")
                    raise
                self._floor_memory(column, effective)
                return timedelta(microseconds=effective)
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise ReplayStateError(f"replay store error: {exc}") from exc

    def bind_max_age(self, requested: timedelta, *, persist: bool) -> timedelta:
        """The ``max_age`` to enforce: ``requested``, or the floor if that is smaller. See the module docstring.

        ``persist`` false honours the floor without moving it, for a store that cannot be written. A normal call,
        with the setting unchanged, only reads.
        """
        return self._bind_floor("max_age_us", requested, persist=persist)

    def bind_trust_history_age(self, requested: timedelta, *, persist: bool) -> timedelta:
        """The same, for ``trust_history_max_age``."""
        return self._bind_floor("trust_history_max_age_us", requested, persist=persist)

    def _meta_or_none(self) -> dict[str, Any] | None:
        try:
            conn = self._connect()
            try:
                return None if _classify(conn) == _EMPTY else _read_meta(conn)
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise ReplayStateError(f"replay store error: {exc}") from exc

    def history_cutover(self) -> datetime | None:
        """Reports issued up to this time have an unknowable replay status: a migration said so."""
        meta = self._meta_or_none()
        if meta is None or meta["history_cutover"] is None:
            return None
        return datetime.fromtimestamp(meta["history_cutover"], tz=timezone.utc)

    def max_age_floor(self) -> timedelta | None:
        """The stored floor, for operators. ``None`` if this file has none yet."""
        meta = self._meta_or_none()
        floor = None if meta is None else meta["max_age_us"]
        return None if floor is None else timedelta(microseconds=floor)

    def trust_history_age_floor(self) -> timedelta | None:
        meta = self._meta_or_none()
        floor = None if meta is None else meta["trust_history_max_age_us"]
        return None if floor is None else timedelta(microseconds=floor)

    def seen(self, key_id: str, run_id: str, *, now: datetime) -> bool:
        _check_text(key_id, run_id)
        stamp = _stamp(now)
        try:
            conn = self._connect()
            try:
                _refuse_if_not_current(conn, self._path)
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
                    _refuse_if_not_current(conn, self._path)
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
