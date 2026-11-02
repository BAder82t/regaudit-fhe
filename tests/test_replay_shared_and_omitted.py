"""F-07 by routes where nobody raises anything: two services on one file, and a later run that omits max_age.

Both gave a double acceptance on the published 0.2.1 wheel (TRUSTED, TRUSTED). Every step here reopens the real file.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.verification import VerificationPolicy, verify

T = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
SIGNER = rf.Signer.generate(issuer="acme", key_id="k")
ENTRIES = {"entries": {"k": {"issuer": "acme", "public_key_pem": SIGNER.public_key_pem(), "status": "active"}}}
STORE = rf.TrustStore.from_dict(ENTRIES)
RESULT = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))


def report(at: datetime = T):
    return envelope_v2(
        "drift", RESULT, signer=SIGNER, deployment_id="p", issued_at=at, audit_run_id=str(uuid.uuid4())
    )


def run(env, path: Path, at: datetime, max_age: timedelta | None):
    return verify(
        env,
        VerificationPolicy(
            trust_store=STORE, max_age=max_age, replay_mode="record", replay_cache=SqliteReplayCache(path), now=lambda: at
        ),
    )


def test_two_services_on_one_file_do_not_accept_a_report_twice(tmp_path):
    env, db = report(), tmp_path / "shared.db"
    assert run(env, db, T, HOUR).accepted
    second = run(env, db, T + 2 * HOUR, DAY)
    assert not second.accepted
    assert second.blocking_reasons == ("REPORT_TOO_OLD",)
    assert "REPLAY_POLICY_FLOOR_APPLIED" in second.reasons  # the floor decided it, not the 24 hour setting
    assert SqliteReplayCache(db).max_age_floor() == HOUR


def test_the_order_of_the_two_services_does_not_matter(tmp_path):
    env, db = report(), tmp_path / "shared.db"
    assert run(env, db, T, DAY).accepted
    assert run(report(), db, T, HOUR).accepted  # the 1 hour service arrives and lowers the floor
    assert SqliteReplayCache(db).max_age_floor() == HOUR
    # env's row was written for 24 hours. A new report past the floor is held to it as well.
    stale = report()
    second = run(stale, db, T + 2 * HOUR, DAY)
    assert second.blocking_reasons == ("REPORT_TOO_OLD",) and "REPLAY_POLICY_FLOOR_APPLIED" in second.reasons


def test_limit_the_longer_service_is_held_to_the_shorter_one(tmp_path):
    """The stated cost: an unseen report within the 24 hour service's own window is refused once a 1 hour service shares
    the file. Each service needs its own file to keep its own window, and then they do not share replay memory."""
    db = tmp_path / "shared.db"
    assert run(report(), db, T, HOUR).accepted
    unseen = report(T + timedelta(hours=1))
    res = run(unseen, db, T + 3 * HOUR, DAY)
    assert not res.accepted and res.blocking_reasons == ("REPORT_TOO_OLD",)


def test_control_two_files_keep_two_windows(tmp_path):
    env = report()
    assert run(env, tmp_path / "a.db", T, HOUR).accepted
    # No shared memory, and that is what separate files mean: this is the configured behaviour, not a replay of one store.
    assert run(env, tmp_path / "b.db", T + 2 * HOUR, DAY).accepted


def test_a_later_run_that_omits_max_age_does_not_get_thirty_days(tmp_path):
    env, db = report(), tmp_path / "omit.db"
    assert run(env, db, T, HOUR).accepted
    second = run(env, db, T + 2 * HOUR, None)
    assert not second.accepted and second.blocking_reasons == ("REPORT_TOO_OLD",)
    assert "REPLAY_POLICY_FLOOR_APPLIED" in second.reasons


def test_control_omitting_max_age_from_the_start_is_the_default_window(tmp_path):
    env, db = report(), tmp_path / "default.db"
    assert run(env, db, T + 2 * HOUR, None).accepted
    assert SqliteReplayCache(db).max_age_floor() == timedelta(days=30)
    assert run(env, db, T + 3 * HOUR, None).blocking_reasons == ("REPLAY_DETECTED",)


def _cli(tmp: Path, name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", "verify", "-i", name, "--trusted-keys", "t.json",
         "--replay-mode", "record", "--replay-db", "cli.db", *args],
        capture_output=True, text=True, timeout=120, cwd=tmp, check=False,
    )  # fmt: skip


def test_the_real_cli_with_the_flag_dropped(tmp_path):
    now = datetime.now(timezone.utc)
    (tmp_path / "t.json").write_text(json.dumps(ENTRIES))
    (tmp_path / "fresh.json").write_text(json.dumps(report(now).to_dict()))
    (tmp_path / "old.json").write_text(json.dumps(report(now - 2 * HOUR).to_dict()))
    assert _cli(tmp_path, "fresh.json", "--max-age-seconds", "3600").returncode == 0
    out = _cli(tmp_path, "old.json")  # the flag dropped: 30 days without the floor
    assert out.returncode == 1, out.stderr
    body = json.loads(out.stdout)
    assert body["blocking_reasons"] == ["REPORT_TOO_OLD"] and "REPLAY_POLICY_FLOOR_APPLIED" in body["reasons"]


def _bind(path: str, seconds: int, q) -> None:
    res = run(report(), Path(path), T, timedelta(seconds=seconds))
    q.put(res.accepted)


def test_processes_racing_with_different_settings_leave_the_smallest(tmp_path):
    db = tmp_path / "race.db"
    # The largest binds first, so the floor has to come down whichever process wins each step.
    assert run(report(), db, T, 9 * HOUR).accepted
    assert SqliteReplayCache(db).max_age_floor() == 9 * HOUR
    ctx = mp.get_context("fork")
    q = ctx.Queue()
    seconds = [3600 * (i + 1) for i in reversed(range(8))]
    procs = [ctx.Process(target=_bind, args=(str(db), s, q)) for s in seconds]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    assert [q.get() for _ in procs] == [True] * 8
    assert SqliteReplayCache(db).max_age_floor() == HOUR


@pytest.mark.parametrize("first", [HOUR, DAY])
def test_the_floor_survives_a_restart_and_only_goes_down(tmp_path, first):
    db = tmp_path / "restart.db"
    assert run(report(), db, T, first).accepted
    assert run(report(), db, T, 2 * first).accepted
    assert SqliteReplayCache(db).max_age_floor() == first
