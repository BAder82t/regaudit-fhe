"""Replay files written by published versions, and trust_history_max_age.

REAL: new processes for restarts, a process killed with SIGKILL inside the migration transaction, the CLI and ``serve`` as
processes. The published files here are created with the same SQL the published versions run; the same sequence against a
file written by the real 0.2.1 wheel is run outside the suite. SIMULATED or absent: power loss.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.replay import (
    InMemoryReplayCache,
    LegacyReplayFile,
    ReplayMigrationRefused,
    ReplayStateError,
    SqliteReplayCache,
    migrate_replay_file,
    replay_file_status,
)
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.verification import TimestampEvidence, TrustHistory, VerificationPolicy, verify

T0 = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
SIGNER = rf.Signer.generate(issuer="acme", key_id="k")
ENTRY = {"issuer": "acme", "public_key_pem": SIGNER.public_key_pem(), "status": "active"}
STORE = rf.TrustStore.from_dict({"entries": {"k": ENTRY}})
RUN = "3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6"
PACKAGE_PARENT = str(Path(rf.__file__).resolve().parents[1])


def report(issued_at=T0, run=RUN + "01"):
    return envelope_v2(
        "drift",
        rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])),
        signer=SIGNER,
        deployment_id="p",
        audience=["reg"],
        issued_at=issued_at,
        audit_run_id=run,
    )


def published_file(db: Path, *rows: tuple[str, str, float]) -> None:
    """What published versions create: one table, with no policy recorded anywhere."""
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS replay (key_id TEXT NOT NULL, run_id TEXT NOT NULL, "
        "expires_at REAL NOT NULL, PRIMARY KEY (key_id, run_id))"
    )
    conn.executemany("INSERT INTO replay VALUES (?, ?, ?)", rows)
    conn.commit()
    conn.close()


def published_record_of(env, recorded_at=T0 + timedelta(minutes=1), max_age=HOUR, skew=timedelta(minutes=5)):
    """The row a published version wrote for this report, under this policy."""
    return ("k", env.audit_run_id, (recorded_at + max_age + 2 * skew).timestamp())


def check(db, max_age, at, env=None, mode="record"):
    pol = VerificationPolicy(
        profile="confidential",
        trust_store=STORE,
        max_age=max_age,
        replay_mode=mode,
        replay_cache=SqliteReplayCache(db),
        verifier_id="reg",
        now=lambda: at,
    )
    return verify(env or report(), pol)


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "replay.db"


# ------------------------------------------------------------------ not migrated


def test_a_published_file_is_refused_until_migrated(db):
    published_file(db, published_record_of(report()))
    with pytest.raises(LegacyReplayFile, match="replay migrate"):
        SqliteReplayCache(db)
    assert replay_file_status(db)["state"] == "legacy"  # reading the status writes nothing
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [("replay",)]
    conn.close()


def test_an_empty_published_file_is_refused_too(db):
    """Empty does not mean unused: rows are purged."""
    published_file(db)
    with pytest.raises(LegacyReplayFile):
        SqliteReplayCache(db)


def test_a_new_file_needs_no_migration(db):
    SqliteReplayCache(db)
    assert replay_file_status(db)["state"] == "current"
    assert replay_file_status(db)["origin"] == "new"


def cli(*args: str, cwd: Path, env=None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=cwd,
        check=False,
        env=env,
    )


def _signed_cli_report(cwd: Path) -> None:
    (cwd / "r.json").write_text(report().to_json())
    (cwd / "t.json").write_text(json.dumps({"entries": {"k": ENTRY}}))


def test_cli_verify_on_a_published_file_exits_3_and_says_how_to_migrate(tmp_path):
    _signed_cli_report(tmp_path)
    published_file(tmp_path / "replay.db")
    out = cli(
        "verify", "-i", "r.json", "--trusted-keys", "t.json", "--replay-mode", "check", "--replay-db", "replay.db",
        cwd=tmp_path,
    )  # fmt: skip
    assert out.returncode == 3 and "replay migrate" in out.stderr and out.stdout == ""


def test_serve_refuses_to_start_on_a_published_file(tmp_path):
    pytest.importorskip("uvicorn")
    published_file(tmp_path / "replay.db")
    env = {
        **os.environ,
        "REGAUDIT_FHE_REPLAY_DB": str(tmp_path / "replay.db"),
        "REGAUDIT_FHE_REPLAY_MODE": "record",
        "REGAUDIT_FHE_DEV_MODE": "1",
    }
    out = cli("serve", "--host", "127.0.0.1", "--port", "1", cwd=tmp_path, env=env)
    assert out.returncode == 2 and "replay migrate" in out.stderr


def test_a_file_swapped_for_a_published_one_under_a_running_process_is_refused(db, tmp_path):
    cache = SqliteReplayCache(db)
    legacy = tmp_path / "legacy.db"
    published_file(legacy)
    shutil.copy(legacy, db)
    with pytest.raises(LegacyReplayFile):
        cache.seen("k", "r", now=T0)
    with pytest.raises(LegacyReplayFile):
        cache.record("k", "r", now=T0, retain=HOUR)
    with pytest.raises(ReplayStateError):
        cache.bind_max_age(HOUR, persist=True)


# ------------------------------------------------------------------ the finding: first-contact increase


def test_first_contact_increase_after_an_attested_migration_is_not_accepted_twice(db):
    env = report()
    published_file(db, published_record_of(env))  # recorded under one hour, row now expired
    report_out = migrate_replay_file(db, now=T0 + 2 * HOUR, previous_max_age=HOUR)
    assert report_out["origin"] == "operator-attested" and report_out["rows_preserved"] == 1
    res = check(db, DAY, T0 + 2 * HOUR, env)  # max_age raised at first contact
    assert not res.accepted and res.blocking_reasons == ("REPORT_TOO_OLD",)
    assert "REPLAY_POLICY_FLOOR_APPLIED" in res.reasons


def test_first_contact_increase_after_an_unknown_migration_is_refused(db):
    env = report()
    published_file(db, published_record_of(env))
    migrate_replay_file(db, now=T0 + 2 * HOUR, previous_policy_unknown=True)
    res = check(db, DAY, T0 + 2 * HOUR, env)
    assert not res.accepted and res.blocking_reasons == ("REPLAY_HISTORY_UNKNOWN",)


def test_replay_after_migration_preserves_recorded_decisions(db):
    env = report()
    published_file(db, published_record_of(env, max_age=DAY))
    migrate_replay_file(db, now=T0 + HOUR, previous_max_age=DAY)
    res = check(db, DAY, T0 + 2 * HOUR, env)
    assert res.blocking_reasons == ("REPLAY_DETECTED",)
    assert res.reasons == ("REPLAY_DETECTED",)


def test_attested_migration_with_the_same_max_age_keeps_verdicts(db):
    published_file(db)
    migrate_replay_file(db, now=T0, previous_max_age=DAY)
    env = report(T0 + HOUR, run=RUN + "02")
    first = check(db, DAY, T0 + 2 * HOUR, env)
    assert first.accepted and first.reasons == () and first.consumption == "RECORDED_LOCAL"
    assert check(db, DAY, T0 + 3 * HOUR, env).blocking_reasons == ("REPLAY_DETECTED",)
    too_old = report(T0 - 2 * DAY, run=RUN + "03")
    assert check(db, DAY, T0 + 2 * HOUR, too_old).blocking_reasons == ("REPORT_TOO_OLD",)


def test_unknown_migration_refuses_older_reports_and_accepts_later_ones(db):
    published_file(db)
    migrate_replay_file(db, now=T0, previous_policy_unknown=True)
    skew = timedelta(minutes=5)
    assert check(db, DAY, T0 + HOUR, report(T0 - HOUR, RUN + "04")).blocking_reasons == (
        "REPLAY_HISTORY_UNKNOWN",
    )
    assert check(db, DAY, T0 + HOUR, report(T0 + skew, RUN + "05")).blocking_reasons == (
        "REPLAY_HISTORY_UNKNOWN",
    )
    later = check(db, DAY, T0 + HOUR, report(T0 + skew + timedelta(seconds=1), RUN + "06"))
    assert later.accepted and later.reasons == ()
    # the floor is then the policy in force, and holds
    assert SqliteReplayCache(db).max_age_floor() == DAY


def test_unknown_migration_survives_a_restart(db):
    published_file(db)
    migrate_replay_file(db, now=T0, previous_policy_unknown=True)
    code = (
        "import sys; from regaudit_fhe.replay import SqliteReplayCache as C; "
        "print(C(sys.argv[1]).history_cutover().isoformat())"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code, str(db)], capture_output=True, text=True, check=True, timeout=120
    )
    assert out.stdout.strip() == T0.isoformat()


def test_cli_migrate_end_to_end(tmp_path):
    _signed_cli_report(tmp_path)
    published_file(tmp_path / "replay.db")
    status = json.loads(cli("replay", "status", "--db", "replay.db", cwd=tmp_path).stdout)
    assert status["state"] == "legacy" and status["rows"] == 0
    neither = cli("replay", "migrate", "--db", "replay.db", cwd=tmp_path)
    assert neither.returncode == 2 and "exactly one" in neither.stderr
    both = cli(
        "replay", "migrate", "--db", "replay.db", "--previous-max-age-seconds", "60", "--previous-policy-unknown",
        cwd=tmp_path,
    )  # fmt: skip
    assert both.returncode == 2
    for bad in ("0", "-1", "nan", "inf", "1e300"):
        out = cli("replay", "migrate", "--db", "replay.db", f"--previous-max-age-seconds={bad}", cwd=tmp_path)
        assert out.returncode == 2, bad
    ok = cli("replay", "migrate", "--db", "replay.db", "--previous-max-age-seconds", "3600", cwd=tmp_path)
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["max_age_floor_s"] == 3600
    again = cli("replay", "migrate", "--db", "replay.db", "--previous-max-age-seconds", "3600", cwd=tmp_path)
    assert again.returncode == 2 and "already" in again.stderr
    assert cli(
        "verify", "-i", "r.json", "--trusted-keys", "t.json", "--replay-mode", "check", "--replay-db", "replay.db",
        cwd=tmp_path,
    ).returncode in (0, 1)  # fmt: skip
    assert cli("replay", "migrate", "--db", "missing.db", "--previous-policy-unknown", cwd=tmp_path).returncode == 2


# ------------------------------------------------------------------ refusing what cannot be read


def _bad_files():
    def extra_table(c):
        c.execute("CREATE TABLE other (x)")

    def extra_column(c):
        c.execute("ALTER TABLE replay ADD COLUMN note TEXT")

    def view(c):
        c.execute("CREATE VIEW v AS SELECT 1")

    def text_expiry(c):
        c.execute("INSERT INTO replay VALUES ('k', 'r', 'soon')")

    def blob_key(c):
        c.execute("INSERT INTO replay VALUES (x'00', 'r', 1.0)")

    def huge_expiry(c):
        c.execute("INSERT INTO replay VALUES ('k', 'r', 9e300)")

    return [extra_table, extra_column, view, text_expiry, blob_key, huge_expiry]


@pytest.mark.parametrize("damage", _bad_files(), ids=lambda f: f.__name__)
def test_ambiguous_or_malformed_files_are_refused_unchanged(db, damage):
    published_file(db)
    conn = sqlite3.connect(db)
    damage(conn)
    conn.commit()
    conn.close()
    before = db.read_bytes()
    with pytest.raises(ReplayStateError):
        migrate_replay_file(db, now=T0, previous_policy_unknown=True)
    assert db.read_bytes() == before


def test_other_table_shape_is_refused(db):
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE replay (a, b, c)")
    conn.commit()
    conn.close()
    with pytest.raises(ReplayMigrationRefused, match="published shape"):
        migrate_replay_file(db, now=T0, previous_policy_unknown=True)


def test_a_non_database_file_is_refused_unchanged(db):
    db.write_bytes(b"not a database, not at all, not even close" * 20)
    before = db.read_bytes()
    with pytest.raises(ReplayMigrationRefused):
        migrate_replay_file(db, now=T0, previous_policy_unknown=True)
    assert db.read_bytes() == before


def test_nothing_to_migrate_is_refused(db, tmp_path):
    with pytest.raises(ReplayMigrationRefused, match="nothing to migrate"):
        migrate_replay_file(tmp_path / "absent.db", now=T0, previous_policy_unknown=True)
    db.write_bytes(b"")
    with pytest.raises(ReplayMigrationRefused, match="not a published"):
        migrate_replay_file(db, now=T0, previous_policy_unknown=True)
    assert db.read_bytes() == b""


@pytest.mark.parametrize("kw", [{}, {"previous_max_age": HOUR, "previous_policy_unknown": True}])
def test_exactly_one_statement_is_required(db, kw):
    published_file(db)
    with pytest.raises(ReplayMigrationRefused, match="exactly one"):
        migrate_replay_file(db, now=T0, **kw)


def test_a_statement_the_rows_contradict_is_refused(db):
    published_file(db, ("k", "r", (T0 + 3 * DAY).timestamp()))
    with pytest.raises(ReplayMigrationRefused, match="outlives"):
        migrate_replay_file(db, now=T0, previous_max_age=DAY)
    assert replay_file_status(db)["state"] == "legacy"
    migrate_replay_file(db, now=T0, previous_max_age=4 * DAY)


@pytest.mark.parametrize(
    "tamper",
    [
        "UPDATE replay_meta SET schema_version = 99",
        "UPDATE replay_meta SET origin = 'made-up'",
        "UPDATE replay_meta SET max_age_us = -1",
        "UPDATE replay_meta SET max_age_us = 'lots'",
        "UPDATE replay_meta SET origin = 'history-unknown', history_cutover = NULL",
        "DELETE FROM replay_meta",
        "CREATE TABLE extra (x)",
    ],
)
def test_a_damaged_policy_record_fails_closed(db, tamper):
    published_file(db)
    migrate_replay_file(db, now=T0, previous_max_age=DAY)
    conn = sqlite3.connect(db)
    conn.execute(tamper)
    conn.commit()
    conn.close()
    with pytest.raises(ReplayStateError):
        cache = SqliteReplayCache(db)
        cache.seen("k", "r", now=T0)


def test_dropping_the_policy_table_returns_the_file_to_refused(db):
    published_file(db)
    migrate_replay_file(db, now=T0, previous_max_age=DAY)
    conn = sqlite3.connect(db)
    conn.execute("DROP TABLE replay_meta")
    conn.commit()
    conn.close()
    with pytest.raises(LegacyReplayFile):
        SqliteReplayCache(db)


# ------------------------------------------------------------------ interrupted, rolled back


CHILD = textwrap.dedent(
    """
    import os, signal, sys
    from datetime import datetime, timedelta
    sys.path.insert(0, sys.argv[1])
    from regaudit_fhe.replay import migrate_replay_file

    def die(point):
        os.kill(os.getpid(), signal.SIGKILL)

    migrate_replay_file(
        sys.argv[2], now=datetime.fromisoformat(sys.argv[3]), previous_max_age=timedelta(days=1), _fault=die
    )
    """
)


def test_real_process_killed_during_migration_leaves_a_legacy_file(db):
    row = ("k", "r", (T0 + HOUR).timestamp())
    published_file(db, row)
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", CHILD, PACKAGE_PARENT, str(db), T0.isoformat()],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == -signal.SIGKILL, proc.stderr  # it really died inside the transaction
    assert replay_file_status(db)["state"] == "legacy"
    with pytest.raises(LegacyReplayFile):
        SqliteReplayCache(db)
    report_out = migrate_replay_file(db, now=T0, previous_max_age=DAY)
    assert report_out["rows_preserved"] == 1
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT * FROM replay").fetchall() == [row]
    conn.close()


def test_a_restored_premigration_backup_is_refused_again(db, tmp_path):
    published_file(db)
    backup = tmp_path / "backup.db"
    shutil.copy(db, backup)
    migrate_replay_file(db, now=T0, previous_max_age=HOUR)
    running = SqliteReplayCache(db)
    assert running.bind_max_age(DAY, persist=True) == HOUR
    shutil.copy(backup, db)
    with pytest.raises(ReplayStateError):
        running.bind_max_age(DAY, persist=True)
    code = "import sys; from regaudit_fhe.replay import SqliteReplayCache as C; C(sys.argv[1])"
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code, str(db)], capture_output=True, text=True, check=False, timeout=120
    )
    assert out.returncode != 0 and "LegacyReplayFile" in out.stderr


def test_limit_a_restored_later_backup(db, tmp_path):
    """A migrated backup with a higher floor. An object that remembers refuses it; a new process cannot tell."""
    SqliteReplayCache(db).bind_max_age(DAY, persist=True)
    backup = tmp_path / "backup.db"
    shutil.copy(db, backup)
    running = SqliteReplayCache(db)
    assert running.bind_max_age(HOUR, persist=True) == HOUR
    shutil.copy(backup, db)
    with pytest.raises(ReplayStateError, match="went up"):
        running.bind_max_age(HOUR, persist=True)
    assert SqliteReplayCache(db).max_age_floor() == DAY  # the stated limit: replay state is a local file


# ------------------------------------------------------------------ trust_history_max_age (F-12)


def _retired_history_case(db, *, setting, as_of, cache=None):
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
        replay_mode="check" if cache is not None else "off",
        replay_cache=cache,
    )
    return verify(env, pol)


def test_raising_trust_history_max_age_does_not_revive_stale_history(db):
    as_of = T0 - 2 * HOUR
    assert _retired_history_case(db, setting=3 * HOUR, as_of=as_of, cache=SqliteReplayCache(db)).accepted
    stale_as_of = T0 - 4 * HOUR
    refused = _retired_history_case(db, setting=3 * HOUR, as_of=stale_as_of, cache=SqliteReplayCache(db))
    assert refused.trust_history == "STALE"
    assert "TRUST_STORE_FRESHNESS_UNPROVEN" in refused.blocking_reasons
    raised = _retired_history_case(db, setting=7 * HOUR, as_of=stale_as_of, cache=SqliteReplayCache(db))
    assert raised.trust_history == "STALE" and not raised.accepted
    assert "TRUST_HISTORY_FLOOR_APPLIED" in raised.reasons
    assert SqliteReplayCache(db).trust_history_age_floor() == 3 * HOUR


def test_control_unchanged_trust_history_setting_has_no_new_code(db):
    res = _retired_history_case(db, setting=3 * HOUR, as_of=T0 - HOUR, cache=SqliteReplayCache(db))
    assert res.accepted and "TRUST_HISTORY_FLOOR_APPLIED" not in res.reasons


def test_without_a_durable_store_a_fixed_ceiling_applies(db):
    """Nothing can remember the earlier setting, so a raise above 24 hours is not honoured at all."""
    for cache in (None, InMemoryReplayCache()):
        at_ceiling = _retired_history_case(db, setting=DAY, as_of=T0 - 23 * HOUR, cache=cache)
        assert at_ceiling.accepted
        raised = _retired_history_case(db, setting=2 * DAY, as_of=T0 - 25 * HOUR, cache=cache)
        assert raised.trust_history == "STALE" and not raised.accepted
        assert "TRUST_HISTORY_FLOOR_APPLIED" in raised.reasons


def test_limit_a_raise_below_the_ceiling_without_a_store_cannot_be_seen(db):
    stale = _retired_history_case(db, setting=HOUR, as_of=T0 - 2 * HOUR)
    assert stale.trust_history == "STALE"
    assert _retired_history_case(db, setting=3 * HOUR, as_of=T0 - 2 * HOUR).accepted


def test_a_durable_store_may_serve_more_than_the_ceiling_from_the_start(db):
    res = _retired_history_case(db, setting=2 * DAY, as_of=T0 - 25 * HOUR, cache=SqliteReplayCache(db))
    assert res.accepted
    assert SqliteReplayCache(db).trust_history_age_floor() == 2 * DAY


def test_migration_records_a_history_floor_at_the_stated_or_default_value(db, tmp_path):
    published_file(db)
    migrate_replay_file(db, now=T0, previous_policy_unknown=True)
    assert SqliteReplayCache(db).trust_history_age_floor() == DAY
    other = tmp_path / "o.db"
    published_file(other)
    migrate_replay_file(other, now=T0, previous_max_age=DAY, previous_trust_history_max_age=HOUR)
    assert SqliteReplayCache(other).trust_history_age_floor() == HOUR
