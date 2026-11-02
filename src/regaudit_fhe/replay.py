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

**Versioned files.** A sqlite file is at schema version 2 when it has exactly the
expected database objects and one ``replay_meta`` row. A file written by a published
version does not say what policy wrote it or what has been purged from it. It is
refused (:class:`LegacyReplayFile`), never quietly adopted. :func:`migrate_replay_file`
treats it as untrusted input: it accepts only the exact published shape, builds a
clean new file from the validated rows, checks it, and swaps it in, keeping the
original beside it. Nothing executable in a file survives, and any object in
``sqlite_master`` that is not expected, in any file at any time, is a refusal. A
writer of the file can still change plausible values: see ``docs/DEPLOYMENT.md``.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import sqlite3
import stat
import tempfile
import threading
from collections.abc import Callable, Iterator
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
        # Through its expiry instant, inclusive: a report is still fresh at exactly issued_at + max_age.
        for key in [k for k, exp in self._entries.items() if exp < now]:
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
_CEILING_US = 24 * 3600 * 1_000_000
_EMPTY, _LEGACY, _CURRENT = "empty", "legacy", "current"
_ORIGINS = ("new", "operator-attested", "history-unknown")
_CREATE_REPLAY = (
    "CREATE TABLE replay (key_id TEXT NOT NULL, run_id TEXT NOT NULL, expires_at REAL NOT NULL, "
    "PRIMARY KEY (key_id, run_id))"
)
_CREATE_META = (
    "CREATE TABLE replay_meta (id INTEGER PRIMARY KEY CHECK (id = 1), schema_version INTEGER NOT NULL, "
    "origin TEXT NOT NULL, max_age_us INTEGER, trust_history_max_age_us INTEGER, history_cutover REAL, "
    "trust_history_cutover REAL, migrated_at REAL)"
)
_INSERT_META = (
    "INSERT INTO replay_meta (id, schema_version, origin, max_age_us, trust_history_max_age_us, "
    "history_cutover, trust_history_cutover, migrated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?)"
)
_FLOOR_UPDATE = {
    "max_age_us": "UPDATE replay_meta SET max_age_us = ? WHERE id = 1",
    "trust_history_max_age_us": "UPDATE replay_meta SET trust_history_max_age_us = ? WHERE id = 1",
}
# The whole of sqlite_master, compared exactly. Not a list of what looks dangerous.
_LEGACY_OBJECTS = frozenset(
    {
        ("table", "replay", "replay", _CREATE_REPLAY),
        ("index", "sqlite_autoindex_replay_1", "replay", None),
    }
)
_CURRENT_OBJECTS = _LEGACY_OBJECTS | {("table", "replay_meta", "replay_meta", _CREATE_META)}
TRUST_HISTORY_CEILING = timedelta(microseconds=_CEILING_US)
_MIGRATING_PREFIX = ".replay-migrate-"
_SQLITE_HEADER = b"SQLite format 3\x00"


def _legacy_message(path: str) -> str:
    return (
        f"replay store {path!r} was written by an earlier version and does not say what policy wrote it. "
        "Refusing to adopt it silently. Run: regaudit-fhe replay migrate --db FILE with "
        "--previous-max-age-seconds N or --previous-policy-unknown (see docs/DEPLOYMENT.md)"
    )


def _classify(conn: sqlite3.Connection) -> str:
    """What this file is, from the whole of ``sqlite_master``. Anything but the three known shapes is refused."""
    objects = frozenset(
        tuple(row) for row in conn.execute("SELECT type, name, tbl_name, sql FROM sqlite_master")
    )
    if not objects:
        return _EMPTY
    if objects == _LEGACY_OBJECTS:
        return _LEGACY
    if objects == _CURRENT_OBJECTS:
        return _CURRENT
    unexpected = sorted(f"{o[0]} {o[1]}" for o in objects - _CURRENT_OBJECTS)
    raise ReplayStateError(
        f"replay store does not have the expected schema; refusing to use it (unexpected: {unexpected})"
    )


def _refuse_if_not_current(conn: sqlite3.Connection, path: str) -> None:
    state = _classify(conn)
    if state == _LEGACY:  # for instance a backup restored under a running process
        raise LegacyReplayFile(_legacy_message(path))
    if state == _CURRENT:
        _read_meta(conn)


def _read_meta(conn: sqlite3.Connection) -> dict[str, Any]:
    """The policy record, with its fields checked against each other. This catches damage and careless edits. It
    does not authenticate anything: a writer of the file can write a plausible record."""
    state = _classify(conn)
    if state == _LEGACY:
        raise LegacyReplayFile("replay store is not at the current schema version")
    rows = conn.execute(
        "SELECT schema_version, origin, max_age_us, trust_history_max_age_us, history_cutover, "
        "trust_history_cutover, migrated_at FROM replay_meta"
    ).fetchall()
    if len(rows) != 1:
        raise ReplayStateError("replay store policy record is missing or duplicated")
    version, origin, max_age, history, cutover, history_cut, migrated = rows[0]
    if version != REPLAY_SCHEMA_VERSION or type(version) is not int:
        raise ReplayStateError(f"replay store has unsupported schema version {version!r}")
    if origin not in _ORIGINS:
        raise ReplayStateError("replay store policy record is corrupt")
    for floor in (max_age, history):
        if floor is not None and (type(floor) is not int or floor <= 0):
            raise ReplayStateError("replay store policy floor is corrupt")
    if history is not None and history > _CEILING_US:
        raise ReplayStateError("replay store trust-history floor is above the ceiling")
    for moment in (cutover, history_cut, migrated):
        if moment is not None and (
            not isinstance(moment, (int, float)) or not math.isfinite(moment)
        ):
            raise ReplayStateError("replay store policy record is corrupt")
    consistent = {
        "new": migrated is None and cutover is None and history_cut is None,
        "operator-attested": migrated is not None and cutover is None,
        "history-unknown": migrated is not None and cutover is not None and history_cut is not None,
    }[origin]
    if not consistent:
        raise ReplayStateError("replay store policy record is corrupt")
    return {
        "schema_version": version,
        "origin": origin,
        "max_age_us": max_age,
        "trust_history_max_age_us": history,
        "history_cutover": cutover,
        "trust_history_cutover": history_cut,
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
            conn.execute("PRAGMA trusted_schema = OFF")
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


def _check_source_file(real: str) -> os.stat_result:
    """Before sqlite opens anything: a regular file, ours, in rollback-journal mode, with no sibling state."""
    info = os.stat(real)
    if not stat.S_ISREG(info.st_mode):
        raise ReplayMigrationRefused(f"{real!r} is not a regular file")
    if os.name == "posix" and info.st_uid != os.geteuid():
        raise ReplayMigrationRefused("run the migration as the owner of the file")
    for suffix in ("-journal", "-wal", "-shm"):
        if os.path.lexists(real + suffix):
            raise ReplayMigrationRefused(
                f"{real + suffix!r} exists: an interrupted or live writer. Stop every verifier using this file, "
                "and let a published version open it once if a journal remains"
            )
    with open(real, "rb") as handle:
        header = handle.read(100)
    if not header:
        raise ReplayMigrationRefused("the file is empty: not a published replay file")
    if not header.startswith(_SQLITE_HEADER) or len(header) < 100:
        raise ReplayMigrationRefused("not a sqlite database")
    if header[18:20] != b"\x01\x01":
        raise ReplayMigrationRefused("not in rollback-journal mode: not a published replay file")
    return info


def _read_legacy_rows(conn: sqlite3.Connection) -> Iterator[tuple[str, str, float]]:
    """Only values, one at a time, each checked. Nothing else from the file is ever carried over."""
    cursor = conn.execute("SELECT key_id, run_id, expires_at FROM replay ORDER BY key_id, run_id")
    for key_id, run_id, expires in cursor:
        if type(key_id) is not str or type(run_id) is not str:
            raise ReplayMigrationRefused("a replay row has a non-text identifier")
        if type(expires) not in (int, float) or not math.isfinite(expires) or abs(expires) > 1e15:
            raise ReplayMigrationRefused("a replay row has a malformed expiry")
        yield key_id, run_id, float(expires)


def _row_digest(digest: Any, row: tuple[str, str, float]) -> None:
    digest.update(json.dumps(row).encode())


def _build_destination(
    tmp: str, source: sqlite3.Connection, meta: tuple[Any, ...]
) -> tuple[int, float | None, str]:
    conn = sqlite3.connect(tmp, timeout=5.0, isolation_level=None)
    digest = hashlib.sha256()
    count = 0
    latest: float | None = None

    def rows() -> Iterator[tuple[str, str, float]]:
        nonlocal count, latest
        for row in _read_legacy_rows(source):
            count += 1
            latest = row[2] if latest is None else max(latest, row[2])
            _row_digest(digest, row)
            yield row

    try:
        conn.execute("PRAGMA trusted_schema = OFF")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(_CREATE_REPLAY)
        conn.execute(_CREATE_META)
        conn.executemany("INSERT INTO replay (key_id, run_id, expires_at) VALUES (?, ?, ?)", rows())
        conn.execute(_INSERT_META, meta)
        conn.execute("COMMIT")
    except sqlite3.Error as exc:
        raise ReplayMigrationRefused(f"the rows could not be copied: {exc}") from exc
    finally:
        conn.close()
    return count, latest, digest.hexdigest()


def _verify_destination(path: str, count: int, row_digest: str, meta: tuple[Any, ...]) -> None:
    """The file that will serve is read back: its objects, its policy record and every row."""
    conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True, timeout=5.0)
    try:
        conn.execute("PRAGMA trusted_schema = OFF")
        if _classify(conn) != _CURRENT:
            raise ReplayMigrationRefused("the new file does not have the current schema")
        if conn.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ReplayMigrationRefused("the new file fails sqlite's integrity check")
        record = _read_meta(conn)
        expected = dict(
            zip(
                (
                    "schema_version",
                    "origin",
                    "max_age_us",
                    "trust_history_max_age_us",
                    "history_cutover",
                    "trust_history_cutover",
                    "migrated_at",
                ),
                meta,
                strict=True,
            )
        )
        if record != expected:
            raise ReplayMigrationRefused("the new file's policy record is not what was written")
        digest = hashlib.sha256()
        seen = 0
        for row in conn.execute("SELECT key_id, run_id, expires_at FROM replay ORDER BY key_id, run_id"):
            seen += 1
            _row_digest(digest, tuple(row))
        if seen != count or digest.hexdigest() != row_digest:
            raise ReplayMigrationRefused("the new file's rows are not what was read")
    finally:
        conn.close()


def _fsync_path(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def migrate_replay_file(
    path: str | Path,
    *,
    now: datetime,
    previous_max_age: timedelta | None = None,
    previous_policy_unknown: bool = False,
    previous_trust_history_max_age: timedelta | None = None,
    assumed_clock_skew: timedelta = timedelta(minutes=5),
    _fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Bring a published file to the current version. The file is untrusted input.

    It must be exactly the published shape: one table, its automatic index, nothing else. Anything else is refused
    before a row is read. The validated rows go into a **new file**, which is read back and checked, and then swapped
    in. The original is kept at ``<path>.pre-migration``, unchanged and not used by anything. A kill at any step leaves
    ``path`` as either the whole original or the whole new file, and another run finishes or refuses cleanly.

    The file never recorded its policy, so the operator says which of two things is true:

    * ``previous_max_age``: an **operator statement** of the largest ``max_age`` this file ever served. It becomes the
      floor, so verdicts are as before under that setting and a larger one is not honoured. If the statement is false,
      the guarantee is false; the file cannot show it, beyond refusing a value its rows contradict.
    * ``previous_policy_unknown``: every report issued up to now (plus the clock skew) is refused from here on
      (``REPLAY_HISTORY_UNKNOWN``), since it may have been recorded and purged. Only later reports are accepted.

    Likewise ``previous_trust_history_max_age``: a statement, at most 24 hours. Without one, a history as of the
    migration or earlier is not fresh, because nothing says it was not already stale.
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
    if previous_trust_history_max_age is not None and (
        previous_trust_history_max_age > TRUST_HISTORY_CEILING
    ):
        raise ReplayMigrationRefused("previous_trust_history_max_age is capped at 24 hours")
    if not Path(path).is_file():
        raise ReplayMigrationRefused(f"{str(path)!r} is not a file; nothing to migrate")
    real = os.path.realpath(path)
    stamp = _stamp(now)

    def fault(point: str) -> None:
        if _fault is not None:
            _fault(point)

    tmp: str | None = None
    try:
        info = _check_source_file(real)
        keep = real + ".pre-migration"
        conn = sqlite3.connect(real, timeout=5.0, isolation_level=None)
        try:
            conn.execute("PRAGMA trusted_schema = OFF")
            # Held to the swap, so no writer can get in. Only SELECTs run on this connection.
            conn.execute("BEGIN EXCLUSIVE")
            try:
                state = _classify(conn)
            except ReplayStateError as exc:  # another shape: refused before any row is read
                raise ReplayMigrationRefused(str(exc)) from exc
            if state == _CURRENT:
                raise ReplayMigrationRefused("already at the current version")
            if state == _EMPTY:
                raise ReplayMigrationRefused("no replay table: not a published replay file")
            if conn.execute("PRAGMA user_version").fetchone() != (0,):
                raise ReplayMigrationRefused("the file has a user_version the published versions never set")
            if conn.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise ReplayMigrationRefused("the file fails sqlite's integrity check")
            if os.path.lexists(keep) and not os.path.samefile(keep, real):
                raise ReplayMigrationRefused(
                    f"{keep!r} exists and is another file. Move it away first; nothing is overwritten"
                )
            fault("after-validation")
            prefix = f"{_MIGRATING_PREFIX}{hashlib.sha256(real.encode()).hexdigest()[:16]}-"
            for leftover in Path(real).parent.glob(prefix + "*"):
                with contextlib.suppress(OSError):  # a killed migration's; the lock above says no other is live
                    leftover.unlink()
            floor: int | None = None
            origin = "history-unknown"
            cutover: float | None = stamp
            if previous_max_age is not None:
                floor = previous_max_age // timedelta(microseconds=1)
                origin = "operator-attested"
                cutover = None
            stated = previous_trust_history_max_age
            history = (stated or TRUST_HISTORY_CEILING) // timedelta(microseconds=1)
            history_cut = None if stated is not None else stamp
            meta = (REPLAY_SCHEMA_VERSION, origin, floor, history, cutover, history_cut, stamp)
            fd, tmp = tempfile.mkstemp(dir=Path(real).parent, prefix=prefix, suffix=".db")
            os.close(fd)
            count, latest, row_digest = _build_destination(tmp, conn, meta)
            fault("after-destination-built")
            if previous_max_age is not None and latest is not None:
                limit = stamp + (previous_max_age + 2 * assumed_clock_skew).total_seconds()
                if latest > limit:
                    raise ReplayMigrationRefused(
                        "a row outlives the stated max_age, so the statement contradicts the file: "
                        "state a larger value, or that the previous policy is unknown"
                    )
            _verify_destination(tmp, count, row_digest, meta)
            if os.path.lexists(tmp + "-journal"):
                raise ReplayMigrationRefused("the new file left a journal behind")
            os.chmod(tmp, stat.S_IMODE(info.st_mode))
            if os.name == "posix" and os.stat(tmp).st_gid != info.st_gid:
                os.chown(tmp, -1, info.st_gid)
            _fsync_path(tmp)
            fault("before-keeping-original")
            if not os.path.lexists(keep):
                os.link(real, keep)
            _fsync_path(str(Path(real).parent))
            fault("before-swap")
            os.replace(tmp, real)
            tmp = None
            fault("after-swap")
            _fsync_path(str(Path(real).parent))
            fault("after-directory-sync")
        finally:
            conn.close()
        _verify_destination(real, count, row_digest, meta)
    except (sqlite3.Error, OSError) as exc:
        raise ReplayMigrationRefused(f"cannot migrate {str(path)!r}: {exc}") from exc
    finally:
        if tmp is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            with contextlib.suppress(OSError):
                os.unlink(tmp + "-journal")
    mode = stat.S_IMODE(info.st_mode)
    return {
        "path": str(path),
        "schema_version": REPLAY_SCHEMA_VERSION,
        "origin": origin,
        "rows_preserved": count,
        "max_age_floor_s": None if floor is None else floor / 1_000_000,
        "trust_history_max_age_floor_s": history / 1_000_000,
        "trust_history_policy": "stated" if stated is not None else "unknown",
        "refuses_reports_issued_up_to": None if cutover is None else now.isoformat(),
        "original_kept_at": keep,
        "warnings": [f"mode {mode:04o} lets others write this file"] if mode & 0o022 else [],
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
                            conn.execute(_INSERT_META, (REPLAY_SCHEMA_VERSION, "new", None, None, None, None, None))
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
        conn.execute("PRAGMA trusted_schema = OFF")
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

    def trust_history_cutover(self) -> datetime | None:
        """A history as of this time or earlier is not fresh: a migration could not say it was not already stale."""
        meta = self._meta_or_none()
        if meta is None or meta["trust_history_cutover"] is None:
            return None
        return datetime.fromtimestamp(meta["trust_history_cutover"], tz=timezone.utc)

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
                    "SELECT 1 FROM replay WHERE key_id = ? AND run_id = ? AND expires_at >= ?",
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
                    # Through its expiry instant, inclusive: a report is still fresh at exactly issued_at + max_age.
                    conn.execute("DELETE FROM replay WHERE expires_at < ?", (stamp,))
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
