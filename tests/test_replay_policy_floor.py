"""F-07: raising ``max_age`` must not make the same report acceptable twice, or stale evidence acceptable again.

Reproduced on the published 0.2.1. Control: record under max_age=1h, verify at +2h under max_age=1d gave TRUSTED twice,
because the entry had expired under the retention of the policy in force when it was recorded. The replay store now
keeps a floor: the smallest effective max_age it has served. It only goes down and survives restarts. Files written by
published versions are covered in test_replay_migration.py.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.replay import InMemoryReplayCache, ReplayStateError, SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.verification import VerificationPolicy, verify

UTC = timezone.utc
T0 = datetime(2026, 11, 1, 12, tzinfo=UTC)
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
SIGNER = rf.Signer.generate(issuer="acme", key_id="k")
STORE = rf.TrustStore.from_dict(
    {"entries": {"k": {"issuer": "acme", "public_key_pem": SIGNER.public_key_pem(), "status": "active"}}}
)
FLOOR_CODE = "REPLAY_POLICY_FLOOR_APPLIED"


def report(issued_at: datetime = T0, run: str = "3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e601"):
    return envelope_v2(
        "drift",
        rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])),
        signer=SIGNER,
        deployment_id="p",
        audience=["reg"],
        issued_at=issued_at,
        audit_run_id=run,
    )


def check(cache, max_age, at, env=None, mode="record"):
    pol = VerificationPolicy(
        profile="confidential",
        trust_store=STORE,
        max_age=max_age,
        replay_mode=mode,
        replay_cache=cache,
        verifier_id="reg",
        now=lambda: at,
    )
    return verify(env or report(), pol)


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "replay.db"


def test_the_finding_raising_max_age_no_longer_accepts_a_report_twice(db):
    first = check(SqliteReplayCache(db), HOUR, T0 + timedelta(minutes=1))
    assert first.accepted and first.consumption == "RECORDED_LOCAL"
    later = T0 + 2 * HOUR
    again = check(SqliteReplayCache(db), DAY, later)  # a new instance: as after a restart
    assert not again.accepted
    assert again.blocking_reasons == ("REPORT_TOO_OLD",)
    assert FLOOR_CODE in again.reasons


def test_control_unchanged_max_age_is_the_normal_replay_path(db):
    cache = SqliteReplayCache(db)
    assert check(cache, DAY, T0 + timedelta(minutes=1)).accepted
    again = check(cache, DAY, T0 + 2 * HOUR)
    assert again.blocking_reasons == ("REPLAY_DETECTED",) and FLOOR_CODE not in again.reasons


def test_control_unchanged_max_age_output_has_no_new_code(db):
    res = check(SqliteReplayCache(db), DAY, T0 + timedelta(minutes=1))
    assert res.reasons == () and res.accepted


def test_a_report_refused_as_stale_stays_refused_when_the_setting_is_raised(db):
    env = report(T0)
    refused = check(SqliteReplayCache(db), HOUR, T0 + 2 * HOUR, env)
    assert refused.blocking_reasons == ("REPORT_TOO_OLD",)
    raised = check(SqliteReplayCache(db), DAY, T0 + 2 * HOUR, env)
    assert not raised.accepted and raised.blocking_reasons == ("REPORT_TOO_OLD",)


def test_a_fresh_report_is_still_accepted_under_a_raised_setting(db):
    check(SqliteReplayCache(db), HOUR, T0)
    fresh = report(T0 + 2 * HOUR, run="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e602")
    res = check(SqliteReplayCache(db), DAY, T0 + 2 * HOUR + timedelta(minutes=1), fresh)
    assert res.accepted and FLOOR_CODE in res.reasons


def test_lowering_is_honoured_and_raising_back_is_not(db):
    check(SqliteReplayCache(db), DAY, T0)
    other = report(T0, run="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e603")
    low = check(SqliteReplayCache(db), HOUR, T0 + 2 * HOUR, other)
    assert low.blocking_reasons == ("REPORT_TOO_OLD",) and FLOOR_CODE not in low.reasons
    back = check(SqliteReplayCache(db), DAY, T0 + 2 * HOUR, other)
    assert back.blocking_reasons == ("REPORT_TOO_OLD",) and FLOOR_CODE in back.reasons
    assert SqliteReplayCache(db).max_age_floor() == HOUR


def test_the_floor_survives_a_real_new_process(db):
    check(SqliteReplayCache(db), HOUR, T0)
    code = (
        "import sys; from regaudit_fhe.replay import SqliteReplayCache as C; "
        "print(C(sys.argv[1]).max_age_floor().total_seconds())"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code, str(db)], capture_output=True, text=True, check=True, timeout=120
    )
    assert float(out.stdout) == 3600.0


def test_retention_follows_the_effective_max_age(db):
    cache = SqliteReplayCache(db)
    check(cache, HOUR, T0)
    other = report(T0 + timedelta(minutes=5), run="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e604")
    check(cache, DAY, T0 + timedelta(minutes=5), other)
    conn = sqlite3.connect(db)
    try:
        (expires,) = conn.execute(
            "SELECT expires_at FROM replay WHERE run_id = ?", (other.audit_run_id,)
        ).fetchone()
    finally:
        conn.close()
    assert expires == (T0 + timedelta(minutes=5) + HOUR + 2 * timedelta(minutes=5)).timestamp()


def test_check_mode_is_held_to_the_floor_as_well(db):
    check(SqliteReplayCache(db), DAY, T0)
    env = report(T0, run="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e605")
    res = check(SqliteReplayCache(db), 2 * DAY, T0 + 36 * HOUR, env, mode="check")
    assert res.blocking_reasons == ("REPORT_TOO_OLD",) and FLOOR_CODE in res.reasons
    low = check(SqliteReplayCache(db), HOUR, T0 + 2 * HOUR, env, mode="check")
    assert low.blocking_reasons == ("REPORT_TOO_OLD",)
    assert SqliteReplayCache(db).max_age_floor() == HOUR


def test_a_corrupt_floor_fails_closed_with_the_existing_code(db):
    check(SqliteReplayCache(db), DAY, T0)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE replay_meta SET max_age_us = -5")
    conn.commit()
    conn.close()
    other = report(T0, run="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e606")
    res = check(SqliteReplayCache(db), DAY, T0 + HOUR, other)
    assert not res.accepted and "REPLAY_STATE_UNAVAILABLE" in res.blocking_reasons


def test_an_earlier_refusal_keeps_its_exit_path_when_the_floor_is_broken(db):
    """The store failure is reported at the replay step, as before: a refused report stays a policy refusal."""
    check(SqliteReplayCache(db), DAY, T0)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE replay_meta SET max_age_us = -5")
    conn.commit()
    conn.close()
    res = check(SqliteReplayCache(db), DAY, T0 + 3 * DAY)
    assert res.blocking_reasons == ("REPORT_TOO_OLD",)


def test_the_memory_path_behaves_as_it_did(tmp_path):
    """sqlite ':memory:' is a new database per connection, so it has always failed closed at the first record."""
    cache = SqliteReplayCache(":memory:")
    res = check(cache, DAY, T0 + HOUR)
    assert not res.accepted and res.blocking_reasons == ("REPLAY_STATE_UNAVAILABLE",)


def test_in_memory_cache_holds_the_floor_for_its_lifetime():
    cache = InMemoryReplayCache()
    assert cache.bind_max_age(HOUR, persist=True) == HOUR
    assert cache.bind_max_age(DAY, persist=True) == HOUR
    assert cache.bind_max_age(timedelta(minutes=1), persist=False) == timedelta(minutes=1)
    assert cache.bind_max_age(DAY, persist=False) == HOUR


class _ThirdParty:
    """A cache written against the published protocol: no floor method."""

    scope = "LOCAL_PERSISTENT"
    durable = True

    def __init__(self) -> None:
        self.seen_ids: set[tuple[str, str]] = set()

    def seen(self, key_id, run_id, *, now):
        return (key_id, run_id) in self.seen_ids

    def record(self, key_id, run_id, *, now, retain):
        if (key_id, run_id) in self.seen_ids:
            return False
        self.seen_ids.add((key_id, run_id))
        return True


def test_a_third_party_cache_without_the_method_still_works_and_has_no_floor():
    cache = _ThirdParty()
    assert check(cache, HOUR, T0).accepted
    res = check(cache, DAY, T0 + 2 * HOUR)
    assert res.blocking_reasons == ("REPLAY_DETECTED",) and FLOOR_CODE not in res.reasons


def test_bind_refuses_nonsense():
    with pytest.raises(ReplayStateError):
        InMemoryReplayCache().bind_max_age(timedelta(0), persist=True)
