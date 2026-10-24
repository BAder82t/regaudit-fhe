"""Local replay caches: atomic record-if-absent, retention, fail-closed capacity."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from regaudit_fhe.replay import (
    InMemoryReplayCache,
    ReplayStateError,
    SqliteReplayCache,
)

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
RETAIN = timedelta(hours=1)


@pytest.fixture(params=["memory", "sqlite"])
def cache(request, tmp_path: Path):
    if request.param == "memory":
        return InMemoryReplayCache()
    return SqliteReplayCache(tmp_path / "replay.db")


def test_scopes_are_declared_honestly(tmp_path: Path):
    assert InMemoryReplayCache().scope == "LOCAL_PROCESS"
    assert SqliteReplayCache(tmp_path / "r.db").scope == "LOCAL_PERSISTENT"


def test_record_if_absent(cache):
    assert not cache.seen("k", "r1", now=NOW)
    assert cache.record("k", "r1", now=NOW, retain=RETAIN) is True
    assert cache.seen("k", "r1", now=NOW)
    assert cache.record("k", "r1", now=NOW, retain=RETAIN) is False


def test_seen_does_not_record(cache):
    assert not cache.seen("k", "r1", now=NOW)
    assert not cache.seen("k", "r1", now=NOW)
    assert cache.record("k", "r1", now=NOW, retain=RETAIN) is True


def test_identifiers_are_scoped_by_key_id(cache):
    assert cache.record("k1", "r", now=NOW, retain=RETAIN)
    assert cache.record("k2", "r", now=NOW, retain=RETAIN)
    assert not cache.record("k1", "r", now=NOW, retain=RETAIN)


def test_entries_are_kept_for_the_full_retention_then_expire(cache):
    assert cache.record("k", "r", now=NOW, retain=RETAIN)
    just_before = NOW + RETAIN - timedelta(seconds=1)
    assert cache.seen("k", "r", now=just_before)
    assert cache.record("k", "r", now=just_before, retain=RETAIN) is False
    after = NOW + RETAIN + timedelta(seconds=1)
    assert not cache.seen("k", "r", now=after)
    assert cache.record("k", "r", now=after, retain=RETAIN) is True


def test_capacity_exhaustion_fails_closed_and_never_evicts_live_entries(tmp_path: Path):
    for c in (InMemoryReplayCache(capacity=2), SqliteReplayCache(tmp_path / "c.db", capacity=2)):
        assert c.record("k", "a", now=NOW, retain=RETAIN)
        assert c.record("k", "b", now=NOW, retain=RETAIN)
        with pytest.raises(ReplayStateError):
            c.record("k", "c", now=NOW, retain=RETAIN)
        # the earlier entries survive: nothing was evicted to make room
        assert c.seen("k", "a", now=NOW) and c.seen("k", "b", now=NOW)
        # expired entries are reclaimed, which frees capacity
        later = NOW + RETAIN + timedelta(seconds=1)
        assert c.record("k", "c", now=later, retain=RETAIN)


def test_concurrent_records_of_one_id_admit_exactly_one(cache):
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        won = cache.record("k", "same", now=NOW, retain=RETAIN)
        with lock:
            results.append(won)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1 and results.count(False) == 15


def test_sqlite_state_survives_a_restart(tmp_path: Path):
    path = tmp_path / "persist.db"
    first = SqliteReplayCache(path)
    assert first.record("k", "r", now=NOW, retain=RETAIN)
    restarted = SqliteReplayCache(path)
    assert restarted.seen("k", "r", now=NOW)
    assert restarted.record("k", "r", now=NOW, retain=RETAIN) is False


def test_memory_state_does_not_survive_a_new_instance():
    a = InMemoryReplayCache()
    assert a.record("k", "r", now=NOW, retain=RETAIN)
    assert InMemoryReplayCache().record("k", "r", now=NOW, retain=RETAIN) is True


def test_unusable_sqlite_store_raises_replay_state_error(tmp_path: Path):
    with pytest.raises(ReplayStateError):
        SqliteReplayCache(tmp_path)  # a directory
    bad = tmp_path / "corrupt.db"
    bad.write_bytes(b"this is not a sqlite database" * 50)
    with pytest.raises(ReplayStateError):
        SqliteReplayCache(bad).seen("k", "r", now=NOW)


def test_naive_or_out_of_range_times_fail_closed_as_replay_state_errors(cache):
    naive = datetime(2026, 10, 10, 12, 0)
    with pytest.raises(ReplayStateError):
        cache.seen("k", "r", now=naive)
    with pytest.raises(ReplayStateError):
        cache.record("k", "r", now=naive, retain=RETAIN)
    huge = datetime(9999, 12, 31, tzinfo=timezone.utc)
    with pytest.raises(ReplayStateError):
        cache.record("k", "r", now=huge, retain=timedelta(days=365))


def test_unencodable_identifiers_fail_closed_as_replay_state_errors(cache):
    with pytest.raises(ReplayStateError):
        cache.record("k\ud800", "r", now=NOW, retain=RETAIN)
    with pytest.raises(ReplayStateError):
        cache.seen("k", "r\ud800", now=NOW)


def test_sqlite_constructor_does_not_leak_connections(tmp_path: Path):
    import gc
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        for _ in range(20):
            SqliteReplayCache(tmp_path / "leak.db")
        gc.collect()
