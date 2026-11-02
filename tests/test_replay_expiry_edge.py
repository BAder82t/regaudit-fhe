"""An identifier must outlive the last instant its report is fresh, which is inclusive.

Reproduced on the published 0.2.1: with clock_skew=0, first presented at exactly T and again at exactly T+max_age, a report
was accepted twice. Purge used <= and freshness uses >. Only the library can set clock_skew; the CLI and the server use the
default. Injected clocks: this edge cannot be hit deliberately with a real one.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from regaudit_fhe.replay import InMemoryReplayCache, SqliteReplayCache
from regaudit_fhe.verification import VerificationPolicy, verify

from .test_replay_migration import (
    HOUR,
    RUN,
    STORE,
    T0,
    _signed_cli_report,
    cli,
    report,
)


def _edge_policy(cache, at, *, skew=timedelta(0), mode="record"):
    return VerificationPolicy(
        trust_store=STORE,
        max_age=HOUR,
        clock_skew=skew,
        replay_mode=mode,
        replay_cache=cache,
        now=lambda: at,
    )


@pytest.fixture
def db(tmp_path):
    return tmp_path / "replay.db"


@pytest.mark.parametrize("kind", ["sqlite", "memory"])
def test_a_report_is_not_accepted_twice_at_exactly_issued_at_plus_max_age(db, kind):
    """clock_skew=0: an identifier must outlive the last instant its report is fresh, which is inclusive."""
    cache = SqliteReplayCache(db) if kind == "sqlite" else InMemoryReplayCache()
    env = report(T0, RUN + "30")
    assert verify(env, _edge_policy(cache, T0)).accepted
    edge = verify(env, _edge_policy(cache, T0 + HOUR))
    assert not edge.accepted and edge.blocking_reasons == ("REPLAY_DETECTED",)
    assert verify(env, _edge_policy(cache, T0 + HOUR, mode="check")).blocking_reasons == (
        "REPLAY_DETECTED",
    )
    past = verify(env, _edge_policy(cache, T0 + HOUR + timedelta(microseconds=1)))
    assert past.blocking_reasons == ("REPORT_TOO_OLD",)


@pytest.mark.parametrize("kind", ["sqlite", "memory"])
def test_control_the_entry_goes_once_it_can_no_longer_matter(db, kind):
    cache = SqliteReplayCache(db) if kind == "sqlite" else InMemoryReplayCache()
    assert cache.record("k", "r", now=T0, retain=HOUR)
    assert cache.seen("k", "r", now=T0 + HOUR)
    assert not cache.seen("k", "r", now=T0 + HOUR + timedelta(microseconds=1))
    assert cache.record("k", "r", now=T0 + HOUR + timedelta(microseconds=1), retain=HOUR)


@pytest.mark.parametrize("kind", ["sqlite", "memory"])
@pytest.mark.parametrize("skew", [timedelta(microseconds=1), timedelta(seconds=1), timedelta(minutes=5)])
def test_positive_skew_controls_at_the_same_boundary(db, kind, skew):
    """The defect is at skew 0 only. With any positive skew the entry already outlived the freshness window."""
    cache = SqliteReplayCache(db) if kind == "sqlite" else InMemoryReplayCache()
    env = report(T0, RUN + "32")
    assert verify(env, _edge_policy(cache, T0, skew=skew)).accepted
    for at in (T0 + timedelta(microseconds=1), T0 + HOUR - timedelta(microseconds=1), T0 + HOUR):
        assert verify(env, _edge_policy(cache, at, skew=skew)).blocking_reasons == ("REPLAY_DETECTED",)
    past = verify(env, _edge_policy(cache, T0 + HOUR + timedelta(microseconds=1), skew=skew))
    assert past.blocking_reasons == ("REPORT_TOO_OLD",)


def test_policy_retention_covers_every_acceptable_presentation():
    """TRUST_SPEC 6.1, for a range of skews and presentation times, on the engine with a real cache."""
    for skew in (timedelta(0), timedelta(microseconds=1), timedelta(minutes=5)):
        for first_after in (timedelta(0), timedelta(seconds=1), HOUR):
            cache = InMemoryReplayCache()
            env = report(T0, RUN + "31")
            assert verify(env, _edge_policy(cache, T0 + first_after, skew=skew)).accepted
            for later in (timedelta(0), timedelta(seconds=1), HOUR - first_after):
                again = verify(env, _edge_policy(cache, T0 + first_after + later, skew=skew))
                assert not again.accepted, (skew, first_after, later)


def test_the_default_skew_through_the_real_cli(tmp_path):
    """The CLI and the server have no clock_skew option: they always use the default 5 minutes, away from the edge."""
    _signed_cli_report(tmp_path, issued_at=datetime.now(timezone.utc))
    args = (
        "verify", "-i", "r.json", "--trusted-keys", "t.json", "--replay-mode", "record", "--replay-db", "e.db",
        "--max-age-seconds", "3600",
    )  # fmt: skip
    assert cli(*args, cwd=tmp_path).returncode == 0
    second = cli(*args, cwd=tmp_path)
    assert second.returncode == 1 and "REPLAY_DETECTED" in second.stdout
    assert "clock-skew" not in cli("verify", "--help", cwd=tmp_path).stdout
