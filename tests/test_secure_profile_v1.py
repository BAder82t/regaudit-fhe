"""The secure-v1 profile's fixed trust-history window (F-12).

24 hours on a new store, an existing store and with no store state at all. A caller cannot make it larger or smaller inside the
profile. What a shorter setting already refused on a store stays refused. Existing profiles keep their own rules and make no such
claim. Real files, and a new object for every restart. The history itself is caller-supplied: the library produces none.
"""

from __future__ import annotations

import dataclasses
import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.replay import (
    SCOPE_LOCAL_PERSISTENT,
    InMemoryReplayCache,
    SqliteReplayCache,
    migrate_replay_file,
    replay_file_status,
)
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.verification import (
    PROFILES,
    SECURE_PROFILE_V1,
    PolicyError,
    TimestampEvidence,
    TrustHistory,
    VerificationPolicy,
    verify,
)

T0 = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
US = timedelta(microseconds=1)
SIGNER = rf.Signer.generate(issuer="acme", key_id="k")
ENTRY = {"issuer": "acme", "public_key_pem": SIGNER.public_key_pem(), "status": "active"}
ACTIVE = rf.TrustStore.from_dict({"entries": {"k": ENTRY}})
RETIRED = rf.TrustStore.from_dict(
    {"entries": {"k": {**ENTRY, "status": "retired", "retired_at": "2026-10-20T00:00:00Z"}}}
)
SIGNED = datetime(2026, 10, 1, tzinfo=timezone.utc)
RESULT = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
_RUN = [0]


def _env(now=T0):
    _RUN[0] += 1
    env = envelope_v2(
        "drift", RESULT, signer=SIGNER, deployment_id="p", issued_at=now - timedelta(minutes=1),
        audit_run_id=f"3f2b1c4e-5a6d-4e7f-8091-{_RUN[0]:012x}",
    )  # fmt: skip
    return env.with_timestamp(issuer="t", token=b"ok:" + env.sealed_digest(), issued_at=SIGNED)


def _verifier(digest, token):
    return TimestampEvidence(SIGNED, timedelta(0)) if token == b"ok:" + digest else None


def case(cache, *, as_of, profile=SECURE_PROFILE_V1, now=T0, mode="record", **kw):
    """A retired key, a verified timestamp before retirement: acceptance depends on the history, so the window decides."""
    pol = VerificationPolicy(
        profile=profile,
        trust_store=RETIRED,
        now=lambda: now,
        timestamp_verifier=_verifier,
        trust_history=TrustHistory(as_of=as_of, authenticated=True),
        max_age=DAY,
        replay_mode=mode,
        replay_cache=cache,
        **kw,
    )
    return verify(_env(now), pol)


def fresh(res):
    return res.accepted and res.trust_history == "FRESH"


def stale(res):
    # the window itself decided: the rest of the report is fine
    return (
        not res.accepted
        and res.trust_history == "STALE"
        and res.blocking_reasons == ("TRUST_STORE_FRESHNESS_UNPROVEN",)
    )


class ThirdParty:
    """A persistent replay cache of someone else's: no floors, and nothing it says is believed about history."""

    scope = SCOPE_LOCAL_PERSISTENT
    durable = True

    def __init__(self):
        self.ids = set()

    def seen(self, key_id, run_id, *, now):
        return (key_id, run_id) in self.ids

    def record(self, key_id, run_id, *, now, retain):
        if (key_id, run_id) in self.ids:
            return False
        self.ids.add((key_id, run_id))
        return True


def caches(tmp_path):
    return {
        "new sqlite": SqliteReplayCache(tmp_path / "new.db"),
        "third party": ThirdParty(),
    }


# ------------------------------------------------------------------ the profile


def test_it_is_a_distinct_versioned_profile():
    assert SECURE_PROFILE_V1 == "secure-v1" and SECURE_PROFILE_V1 in PROFILES
    pol = VerificationPolicy(
        profile="secure-v1", trust_store=ACTIVE, max_age=HOUR, replay_mode="record", replay_cache=ThirdParty()
    )
    assert pol.policy_id == "regaudit-fhe/secure-v1/v1"


@pytest.mark.parametrize("setting", [US, HOUR, 23 * HOUR, DAY + US, 2 * DAY, 30 * DAY])
def test_a_caller_cannot_set_the_window_larger_or_smaller(setting):
    with pytest.raises(PolicyError, match="fixed trust-history window"):
        VerificationPolicy(
            profile="secure-v1", trust_store=ACTIVE, max_age=HOUR, replay_mode="record", replay_cache=ThirdParty(),
            trust_history_max_age=setting,
        )  # fmt: skip


def test_replace_cannot_set_it_either():
    pol = VerificationPolicy(
        profile="secure-v1", trust_store=ACTIVE, max_age=HOUR, replay_mode="record", replay_cache=ThirdParty()
    )
    with pytest.raises(PolicyError, match="fixed trust-history window"):
        dataclasses.replace(pol, trust_history_max_age=30 * DAY)


def test_a_longer_policy_cannot_be_moved_into_the_profile():
    pol = VerificationPolicy(
        profile="confidential", trust_store=ACTIVE, max_age=HOUR, replay_mode="record", replay_cache=ThirdParty(),
        trust_history_max_age=HOUR,
    )  # fmt: skip
    with pytest.raises(PolicyError, match="fixed trust-history window"):
        dataclasses.replace(pol, profile="secure-v1")


@pytest.mark.parametrize(
    "kw",
    [
        {"max_age": None, "replay_mode": "record", "replay_cache": ThirdParty()},
        {"max_age": HOUR, "replay_mode": "off"},
        {"max_age": HOUR, "replay_mode": "record", "replay_cache": InMemoryReplayCache()},
    ],
)
def test_it_is_at_least_as_strict_as_confidential(kw):
    with pytest.raises(PolicyError):
        VerificationPolicy(profile="secure-v1", trust_store=ACTIVE, **kw)


def test_it_refuses_a_v1_report_as_confidential_does(tmp_path):
    env = rf.envelope("drift", RESULT, signer=SIGNER)
    pol = VerificationPolicy(
        profile="secure-v1", trust_store=ACTIVE, max_age=HOUR, replay_mode="record",
        replay_cache=SqliteReplayCache(tmp_path / "v1.db"),
    )  # fmt: skip
    assert verify(env, pol).blocking_reasons == ("REPLAY_ID_MISSING",)


# ------------------------------------------------------------------ the same window everywhere


@pytest.mark.parametrize("which", ["new sqlite", "third party"])
def test_the_edges_of_the_window_with_the_setting_omitted(which, tmp_path):
    cache = caches(tmp_path)[which]
    assert fresh(case(cache, as_of=T0 - DAY))
    assert stale(case(cache, as_of=T0 - DAY - US))


def test_a_fresh_file_records_the_window_and_no_cutover(tmp_path):
    db = tmp_path / "f.db"
    assert fresh(case(SqliteReplayCache(db), as_of=T0 - HOUR))
    status = replay_file_status(db)
    assert status["trust_history_max_age_us"] == DAY // US
    assert status["trust_history_cutover"] is None and status["origin"] == "new"


def test_no_state_is_read_with_a_third_party_cache():
    class Trap(ThirdParty):
        def __getattr__(self, name):
            assert "trust_history" not in name, f"the window read {name} from the cache"
            raise AttributeError(name)

    assert fresh(case(Trap(), as_of=T0 - HOUR))


def test_an_existing_file_at_the_window_gets_the_same_window(tmp_path):
    db = tmp_path / "e.db"
    assert fresh(case(SqliteReplayCache(db), profile="confidential", as_of=T0 - HOUR))
    before = replay_file_status(db)
    assert before["trust_history_max_age_us"] == DAY // US
    assert fresh(case(SqliteReplayCache(db), as_of=T0 - DAY))
    assert stale(case(SqliteReplayCache(db), as_of=T0 - DAY - US))
    assert replay_file_status(db)["origin"] == before["origin"]  # nothing was adopted


def test_it_survives_a_restart(tmp_path):
    db = tmp_path / "r.db"
    assert fresh(case(SqliteReplayCache(db), as_of=T0 - DAY))
    assert stale(case(SqliteReplayCache(db), as_of=T0 - DAY - US))
    code = (
        "import sys;from regaudit_fhe.replay import SqliteReplayCache as C;"
        "print(C(sys.argv[1]).trust_history_age_floor())"
    )
    out = subprocess.run([sys.executable, "-c", code, str(db)], capture_output=True, text=True, check=True, timeout=60)  # noqa: S603
    assert out.stdout.strip() == "1 day, 0:00:00"


def test_check_mode_gets_the_same_window(tmp_path):
    db = tmp_path / "c.db"
    assert fresh(case(SqliteReplayCache(db), mode="check", as_of=T0 - DAY))
    assert stale(case(SqliteReplayCache(db), mode="check", as_of=T0 - DAY - US))


# ------------------------------------------------------------------ expired stays expired


def test_an_increase_from_a_shorter_value_does_not_revive_anything(tmp_path):
    db = tmp_path / "up.db"
    two_hours_old = T0 - 2 * HOUR
    first = case(SqliteReplayCache(db), profile="confidential", trust_history_max_age=HOUR, as_of=two_hours_old)
    assert stale(first)
    assert replay_file_status(db)["trust_history_max_age_us"] == HOUR // US
    # moved to the profile, whose window would otherwise cover it
    second = case(SqliteReplayCache(db), as_of=two_hours_old)
    assert stale(second)
    status = replay_file_status(db)
    assert status["origin"] == "fixed-window-adopted"
    assert status["trust_history_max_age_us"] == DAY // US


def test_after_the_increase_the_window_is_the_same_24_hours(tmp_path):
    db = tmp_path / "w.db"
    assert stale(case(SqliteReplayCache(db), profile="confidential", trust_history_max_age=HOUR, as_of=T0 - 2 * HOUR))
    assert stale(case(SqliteReplayCache(db), as_of=T0 - 2 * HOUR))
    later = T0 + 3 * HOUR
    assert fresh(case(SqliteReplayCache(db), as_of=T0 + HOUR, now=later))  # 2 hours old and after the takeover
    assert stale(case(SqliteReplayCache(db), as_of=T0 - 2 * HOUR, now=later))  # still refused, after a restart
    edge = T0 + HOUR
    assert fresh(case(SqliteReplayCache(db), as_of=edge, now=edge + DAY))
    assert stale(case(SqliteReplayCache(db), as_of=edge, now=edge + DAY + US))


def test_going_back_and_forth_does_not_revive_anything(tmp_path):
    db = tmp_path / "ff.db"
    assert fresh(case(SqliteReplayCache(db), as_of=T0 - HOUR))
    later = T0 + 4 * HOUR
    as_of = T0 + HOUR  # three hours old at the time below
    assert stale(
        case(SqliteReplayCache(db), profile="confidential", trust_history_max_age=HOUR, as_of=as_of, now=later)
    )
    assert stale(case(SqliteReplayCache(db), as_of=as_of, now=later))
    assert stale(case(SqliteReplayCache(db), as_of=as_of, now=later + HOUR))


def test_the_longer_setting_gets_nothing_back_from_the_takeover(tmp_path):
    db = tmp_path / "back.db"
    as_of = T0 - 2 * HOUR
    assert stale(case(SqliteReplayCache(db), profile="confidential", trust_history_max_age=HOUR, as_of=as_of))
    assert stale(case(SqliteReplayCache(db), as_of=as_of))
    assert stale(case(SqliteReplayCache(db), profile="confidential", as_of=as_of))


@pytest.mark.parametrize("profile", ["confidential", "secure-v1"])
def test_older_than_the_window_is_expired_on_a_new_file_after_any_reconfiguration(profile, tmp_path):
    as_of = T0 - DAY - HOUR
    assert stale(case(SqliteReplayCache(tmp_path / "a.db"), as_of=as_of))
    assert stale(case(SqliteReplayCache(tmp_path / "b.db"), profile=profile, as_of=as_of))
    assert stale(case(ThirdParty(), profile=profile, as_of=as_of))


def test_a_legacy_file_with_no_history_statement_keeps_its_cutover(tmp_path):
    from .test_replay_migration import published_file

    db = tmp_path / "pub.db"
    published_file(db, ("k", "old", T0.timestamp() + 60))
    migrate_replay_file(db, now=T0, previous_policy_unknown=True)
    later = T0 + 2 * HOUR
    assert stale(case(SqliteReplayCache(db), as_of=T0, now=later))
    assert fresh(case(SqliteReplayCache(db), as_of=T0 + HOUR, now=later))


def test_a_stated_shorter_history_on_a_migrated_file_is_taken_over(tmp_path):
    from .test_replay_migration import published_file

    db = tmp_path / "pub.db"
    published_file(db, ("k", "old", T0.timestamp() + 60))
    migrate_replay_file(db, now=T0, previous_max_age=HOUR, previous_trust_history_max_age=HOUR)
    assert stale(case(SqliteReplayCache(db), as_of=T0 + HOUR, now=T0 + 3 * HOUR))
    assert fresh(case(SqliteReplayCache(db), as_of=T0 + 4 * HOUR, now=T0 + 5 * HOUR))


def test_a_floor_that_cannot_be_moved_counts_no_history(tmp_path):
    db = tmp_path / "ro.db"
    assert stale(case(SqliteReplayCache(db), profile="confidential", trust_history_max_age=HOUR, as_of=T0 - 2 * HOUR))
    os.chmod(db, stat.S_IRUSR)
    try:
        res = case(SqliteReplayCache(db), mode="check", as_of=T0 - HOUR)
    finally:
        os.chmod(db, stat.S_IRUSR | stat.S_IWUSR)
    assert not res.accepted and res.trust_history == "UNPROVEN"
    assert res.blocking_reasons == ("TRUST_STORE_FRESHNESS_UNPROVEN",)


def test_a_corrupt_policy_record_counts_no_history(tmp_path):
    import sqlite3

    db = tmp_path / "bad.db"
    assert fresh(case(SqliteReplayCache(db), as_of=T0 - HOUR))
    conn = sqlite3.connect(db)
    conn.execute("UPDATE replay_meta SET origin = 'made-up'")
    conn.commit()
    conn.close()
    res = case(SqliteReplayCache(db), as_of=T0 - HOUR)
    assert not res.accepted and res.trust_history == "UNPROVEN"


def test_a_running_object_that_remembers_a_lower_floor_counts_no_history_until_restarted(tmp_path):
    """A stated limit. It reads as a replaced file, and it fails closed for history only."""
    db = tmp_path / "run.db"
    running = SqliteReplayCache(db)
    assert stale(case(running, profile="confidential", trust_history_max_age=HOUR, as_of=T0 - 2 * HOUR))
    assert stale(case(SqliteReplayCache(db), as_of=T0 - 2 * HOUR))  # another process takes the file over
    later = T0 + 2 * HOUR
    res = case(running, profile="confidential", trust_history_max_age=HOUR, as_of=later - timedelta(minutes=1), now=later)
    assert not res.accepted and res.trust_history == "UNPROVEN"
    fresh_object = case(
        SqliteReplayCache(db), profile="confidential", trust_history_max_age=HOUR, as_of=later - timedelta(minutes=1), now=later
    )
    assert fresh(fresh_object)


# ------------------------------------------------------------------ the other profiles


def test_existing_profiles_keep_their_own_rules(tmp_path):
    cache = SqliteReplayCache(tmp_path / "x.db")
    assert stale(case(cache, profile="confidential", trust_history_max_age=HOUR, as_of=T0 - 2 * HOUR))
    res = case(cache, profile="confidential", trust_history_max_age=HOUR, as_of=T0 - HOUR)
    assert res.accepted and res.policy_id == "regaudit-fhe/confidential/v1"
    assert replay_file_status(tmp_path / "x.db")["origin"] == "new"


def test_required_under_high_assurance_stays_refused():
    from regaudit_fhe import _revocation_gate as gate
    from regaudit_fhe import _revocation_state as st

    ctx = gate.RevocationContext("required", st.FileStateStore(Path("/nonexistent-state")), {})
    pol = VerificationPolicy(
        profile="high-assurance", trust_store=ACTIVE, max_age=HOUR, verifier_id="reg", replay_mode="record",
        replay_cache=ThirdParty(),
    )  # fmt: skip
    with pytest.raises(PolicyError, match="REVOCATION_HIGH_ASSURANCE_UNAVAILABLE"):
        gate.verify_with_revocation(_env(), pol, ctx)


# ------------------------------------------------------------------ the CLI


def test_the_real_cli_has_the_profile(tmp_path):
    env = envelope_v2(
        "drift", RESULT, signer=SIGNER, deployment_id="p", issued_at=datetime.now(timezone.utc),
        audit_run_id="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6ee",
    )  # fmt: skip
    (tmp_path / "r.json").write_text(json.dumps(env.to_dict()))
    (tmp_path / "t.json").write_text(json.dumps({"entries": {"k": ENTRY}}))
    out = subprocess.run(
        [sys.executable, "-m", "regaudit_fhe.cli", "verify", "-i", "r.json", "--trusted-keys", "t.json",
         "--profile", "secure-v1", "--max-age-seconds", "3600", "--replay-mode", "record", "--replay-db", "x.db"],
        capture_output=True, text=True, timeout=120, cwd=tmp_path, check=False,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["policy_id"] == "regaudit-fhe/secure-v1/v1"
