"""F-12: raising trust_history_max_age must not make a history acceptable that was already stale.

Above 24 hours a setting is never honoured, whatever a cache says about itself. Below that, the shipped sqlite store holds a
floor. If the floor cannot be used, no history counts. What remains is stated in the tests named limit. Real files and new
processes. The history itself is caller-supplied: the library produces none.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.replay import (
    InMemoryReplayCache,
    ReplayMigrationRefused,
    SqliteReplayCache,
    migrate_replay_file,
    replay_file_status,
)
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.verification import TimestampEvidence, TrustHistory, VerificationPolicy, verify

from .test_replay_migration import (
    DAY,
    ENTRY,
    HOUR,
    RUN,
    SIGNER,
    STORE,
    T0,
    published_file,
    report,
)


def _retired_history_case(*, setting, as_of, cache=None, mode=None):
    """A retired key, a verified timestamp before retirement, a caller-supplied authenticated history."""
    store = rf.TrustStore.from_dict(
        {"entries": {"k": {**ENTRY, "status": "retired", "retired_at": "2026-10-20T00:00:00Z"}}}
    )
    signed = datetime(2026, 10, 1, tzinfo=timezone.utc)
    env = envelope_v2(
        "drift",
        rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])),
        signer=SIGNER,
        deployment_id="p",
        issued_at=T0 - HOUR,
        audit_run_id=RUN + "10",
    )
    env = env.with_timestamp(issuer="t", token=b"ok:" + env.sealed_digest(), issued_at=signed)

    def verifier(digest, token):
        return TimestampEvidence(signed, timedelta(0)) if token == b"ok:" + digest else None

    pol = VerificationPolicy(
        trust_store=store,
        now=lambda: T0,
        timestamp_verifier=verifier,
        trust_history=TrustHistory(as_of=as_of, authenticated=True),
        trust_history_max_age=setting,
        replay_mode=mode or ("check" if cache is not None else "off"),
        replay_cache=cache,
    )
    return verify(env, pol)


class _SelfDeclared:
    """C7-07: says it is durable, and its binder returns what it is asked."""

    scope = "LOCAL_PERSISTENT"
    durable = True

    def seen(self, key_id, run_id, *, now):
        return False

    def record(self, key_id, run_id, *, now, retain):
        return True

    def bind_max_age(self, requested, *, persist):
        return requested

    def bind_trust_history_age(self, requested, *, persist):
        return requested


class _RaisingBinder(_SelfDeclared):
    """C7-08."""

    def bind_trust_history_age(self, requested, *, persist):
        raise RuntimeError("floor unusable")


class _SqliteSubclass(SqliteReplayCache):
    def bind_trust_history_age(self, requested, *, persist):
        return timedelta(days=30)


THREE_DAYS = T0 - 3 * DAY
THIRTY_DAYS = 30 * DAY


@pytest.fixture
def db(tmp_path):
    return tmp_path / "replay.db"


@pytest.mark.parametrize(
    "make",
    [
        lambda db: None,
        lambda db: InMemoryReplayCache(),
        lambda db: _SelfDeclared(),
        lambda db: _RaisingBinder(),
        lambda db: _SqliteSubclass(db),
        lambda db: SqliteReplayCache(db),  # a brand-new file: no earlier setting known
    ],
    ids=["no-cache", "in-memory", "self-declared-durable", "raising-binder", "subclass", "new-sqlite-file"],
)
def test_no_cache_can_get_a_window_above_the_ceiling(db, make):
    res = _retired_history_case(setting=THIRTY_DAYS, as_of=THREE_DAYS, cache=make(db))
    assert not res.accepted and res.trust_history == "STALE"
    assert "TRUST_STORE_FRESHNESS_UNPROVEN" in res.blocking_reasons
    assert "TRUST_HISTORY_FLOOR_APPLIED" in res.reasons


def test_control_under_the_ceiling_a_history_still_counts(db):
    assert _retired_history_case(setting=DAY, as_of=T0 - 23 * HOUR).accepted
    assert _retired_history_case(
        setting=DAY, as_of=T0 - 23 * HOUR, cache=SqliteReplayCache(db)
    ).accepted


def test_a_broken_floor_does_not_widen_the_window_it_closes_it_real_sqlite(db, tmp_path):
    """C7-08 with the real store: its file swapped for a published one, in the development profile."""
    cache = SqliteReplayCache(db)
    good = _retired_history_case(setting=DAY, as_of=T0 - HOUR, cache=cache)
    assert good.accepted
    legacy = tmp_path / "legacy.db"
    published_file(legacy)
    shutil.copy(legacy, db)
    res = _retired_history_case(setting=THIRTY_DAYS, as_of=T0 - HOUR, cache=cache)
    assert res.trust_history == "UNPROVEN" and not res.accepted
    assert "TRUST_STORE_FRESHNESS_UNPROVEN" in res.blocking_reasons
    assert "TRUST_HISTORY_FLOOR_APPLIED" in res.reasons


def test_raising_trust_history_max_age_does_not_revive_stale_history(db):
    as_of = T0 - 2 * HOUR
    assert _retired_history_case(setting=3 * HOUR, as_of=as_of, cache=SqliteReplayCache(db)).accepted
    stale_as_of = T0 - 4 * HOUR
    refused = _retired_history_case(setting=3 * HOUR, as_of=stale_as_of, cache=SqliteReplayCache(db))
    assert refused.trust_history == "STALE"
    assert "TRUST_STORE_FRESHNESS_UNPROVEN" in refused.blocking_reasons
    raised = _retired_history_case(setting=7 * HOUR, as_of=stale_as_of, cache=SqliteReplayCache(db))
    assert raised.trust_history == "STALE" and not raised.accepted
    assert "TRUST_HISTORY_FLOOR_APPLIED" in raised.reasons
    assert SqliteReplayCache(db).trust_history_age_floor() == 3 * HOUR


def test_the_history_floor_survives_a_real_new_process(db):
    _retired_history_case(setting=3 * HOUR, as_of=T0 - HOUR, cache=SqliteReplayCache(db))
    code = (
        "import sys; from regaudit_fhe.replay import SqliteReplayCache as C; "
        "print(C(sys.argv[1]).trust_history_age_floor().total_seconds())"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code, str(db)], capture_output=True, text=True, check=True, timeout=120
    )
    assert float(out.stdout) == 3 * 3600


def test_control_unchanged_trust_history_setting_has_no_new_code(db):
    res = _retired_history_case(setting=3 * HOUR, as_of=T0 - HOUR, cache=SqliteReplayCache(db))
    assert res.accepted and "TRUST_HISTORY_FLOOR_APPLIED" not in res.reasons


def test_limit_a_raise_below_the_ceiling_without_the_shipped_store_cannot_be_seen():
    stale = _retired_history_case(setting=HOUR, as_of=T0 - 2 * HOUR)
    assert stale.trust_history == "STALE"
    assert _retired_history_case(setting=3 * HOUR, as_of=T0 - 2 * HOUR).accepted  # at most 24 hours


def test_limit_a_new_file_or_a_restored_backup_forgets_a_floor_below_the_ceiling(db, tmp_path):
    backup = tmp_path / "backup.db"
    SqliteReplayCache(db).bind_trust_history_age(DAY, persist=True)
    shutil.copy(db, backup)
    SqliteReplayCache(db).bind_trust_history_age(HOUR, persist=True)
    shutil.copy(backup, db)
    assert SqliteReplayCache(db).trust_history_age_floor() == DAY  # undetected by a new process, bounded by the ceiling
    assert _retired_history_case(setting=2 * DAY, as_of=T0 - 25 * HOUR, cache=SqliteReplayCache(db)).trust_history == (
        "STALE"
    )


def test_a_running_object_catches_a_restored_history_floor(db, tmp_path):
    running = SqliteReplayCache(db)
    running.bind_trust_history_age(DAY, persist=True)
    backup = tmp_path / "b.db"
    shutil.copy(db, backup)
    running.bind_trust_history_age(HOUR, persist=True)
    shutil.copy(backup, db)
    res = _retired_history_case(setting=DAY, as_of=T0 - 2 * HOUR, cache=running)
    assert res.trust_history == "UNPROVEN" and not res.accepted


def test_a_legacy_file_with_no_history_statement_does_not_count_older_history(db):
    published_file(db)
    at = T0 - HOUR
    migrate_replay_file(db, now=at, previous_max_age=30 * DAY)
    assert SqliteReplayCache(db).trust_history_cutover() == at
    before = _retired_history_case(setting=DAY, as_of=at - timedelta(seconds=1), cache=SqliteReplayCache(db))
    assert before.trust_history == "STALE" and not before.accepted
    equal = _retired_history_case(setting=DAY, as_of=at, cache=SqliteReplayCache(db))
    assert equal.trust_history == "STALE"
    after = _retired_history_case(setting=DAY, as_of=at + timedelta(seconds=1), cache=SqliteReplayCache(db))
    assert after.trust_history == "FRESH" and after.accepted


def test_a_stated_history_policy_is_the_floor_and_a_false_one_is_bounded(db, tmp_path):
    published_file(db)
    migrate_replay_file(db, now=T0, previous_max_age=30 * DAY, previous_trust_history_max_age=HOUR)
    cache = SqliteReplayCache(db)
    assert cache.trust_history_cutover() is None and cache.trust_history_age_floor() == HOUR
    assert _retired_history_case(setting=DAY, as_of=T0 - 2 * HOUR, cache=cache).trust_history == "STALE"
    other = tmp_path / "o.db"
    published_file(other)
    with pytest.raises(ReplayMigrationRefused, match="capped"):
        migrate_replay_file(other, now=T0, previous_max_age=DAY, previous_trust_history_max_age=2 * DAY)
    assert replay_file_status(other)["state"] == "legacy"


def test_the_history_rules_do_not_touch_the_default(db):
    pol = VerificationPolicy(trust_store=STORE, now=lambda: T0)
    res = verify(report(T0 - HOUR), pol)
    assert res.accepted and res.reasons == () and res.trust_history == "UNPROVEN"
