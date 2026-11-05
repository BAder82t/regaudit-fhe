"""Replay files written by published versions, and trust_history_max_age.

REAL: new processes for restarts, a process killed with SIGKILL inside the migration transaction, the CLI and ``serve`` as
processes. ``published_file`` makes a file with the SQL the published versions run. The ``real_file`` fixture is a file
really written by the published 0.2.1 wheel, from PyPI with its hash checked; a harness outside the suite also runs the
real 0.2.1 CLI. SIMULATED or absent: power loss.
"""

from __future__ import annotations

import base64
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
    LegacyReplayFile,
    ReplayMigrationRefused,
    ReplayStateError,
    SqliteReplayCache,
    migrate_replay_file,
    replay_file_status,
)
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.verification import VerificationPolicy, verify

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


def published_record_of(
    env, recorded_at=T0 + timedelta(minutes=1), max_age=HOUR, skew=timedelta(minutes=5)
):
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
    assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [
        ("replay",)
    ]
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


def _signed_cli_report(cwd: Path, issued_at=None) -> None:
    (cwd / "r.json").write_text(report(issued_at or T0).to_json())
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
        [sys.executable, "-c", code, str(db)],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
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
        out = cli(
            "replay",
            "migrate",
            "--db",
            "replay.db",
            f"--previous-max-age-seconds={bad}",
            cwd=tmp_path,
        )
        assert out.returncode == 2, bad
    ok = cli(
        "replay", "migrate", "--db", "replay.db", "--previous-max-age-seconds", "3600", cwd=tmp_path
    )
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["max_age_floor_s"] == 3600
    again = cli(
        "replay", "migrate", "--db", "replay.db", "--previous-max-age-seconds", "3600", cwd=tmp_path
    )
    assert again.returncode == 2 and "already" in again.stderr
    assert cli(
        "verify", "-i", "r.json", "--trusted-keys", "t.json", "--replay-mode", "check", "--replay-db", "replay.db",
        cwd=tmp_path,
    ).returncode in (0, 1)  # fmt: skip
    assert (
        cli(
            "replay", "migrate", "--db", "missing.db", "--previous-policy-unknown", cwd=tmp_path
        ).returncode
        == 2
    )


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
    with pytest.raises(ReplayMigrationRefused, match="expected schema"):
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
        if point == sys.argv[4]:
            os.kill(os.getpid(), signal.SIGKILL)

    migrate_replay_file(
        sys.argv[2], now=datetime.fromisoformat(sys.argv[3]), previous_max_age=timedelta(days=1), _fault=die
    )
    """
)


@pytest.mark.parametrize(
    ("point", "swapped"),
    [
        ("after-validation", False),
        ("after-destination-built", False),
        ("before-keeping-original", False),
        ("before-swap", False),
        ("after-swap", True),
        ("after-directory-sync", True),
    ],
)
def test_real_process_killed_at_every_step_of_migration(db, point, swapped):
    row = ("k", "r", (T0 + HOUR).timestamp())
    published_file(db, row)
    original = db.read_bytes()
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", CHILD, PACKAGE_PARENT, str(db), T0.isoformat(), point],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == -signal.SIGKILL, proc.stderr  # it really died there
    assert not db.with_name(db.name + "-journal").exists()
    if swapped:
        assert replay_file_status(db)["state"] == "current"
        assert db.with_name(db.name + ".pre-migration").read_bytes() == original
        with pytest.raises(ReplayMigrationRefused, match="already"):
            migrate_replay_file(db, now=T0, previous_max_age=DAY)
    else:
        assert db.read_bytes() == original  # the whole original, not a byte changed
        with pytest.raises(LegacyReplayFile):
            SqliteReplayCache(db)
        report_out = migrate_replay_file(
            db, now=T0, previous_max_age=DAY
        )  # a second run finishes it
        assert report_out["rows_preserved"] == 1
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT * FROM replay").fetchall() == [row]
    conn.close()
    assert not [p for p in db.parent.iterdir() if p.name.startswith(".replay-migrate-")]


def test_a_killed_migration_leaves_no_temp_behind_after_the_next_run(db):
    published_file(db)
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            sys.executable,
            "-c",
            CHILD,
            PACKAGE_PARENT,
            str(db),
            T0.isoformat(),
            "after-destination-built",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == -signal.SIGKILL
    assert [p for p in db.parent.iterdir() if p.name.startswith(".replay-migrate-")]
    migrate_replay_file(db, now=T0, previous_max_age=DAY)
    assert not [p for p in db.parent.iterdir() if p.name.startswith(".replay-migrate-")]


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
        [sys.executable, "-c", code, str(db)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
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
    assert (
        SqliteReplayCache(db).max_age_floor() == DAY
    )  # the stated limit: replay state is a local file


# ------------------------------------------------------------------ the clean destination


def test_the_original_is_kept_unchanged_and_the_new_file_has_only_what_was_validated(db):
    published_file(db, ("k", "r", (T0 + HOUR).timestamp()))
    original = db.read_bytes()
    out = migrate_replay_file(db, now=T0, previous_max_age=DAY)
    keep = db.with_name(db.name + ".pre-migration")
    assert out["original_kept_at"] == str(keep.resolve()) and keep.read_bytes() == original
    conn = sqlite3.connect(db)
    names = sorted(row[0] for row in conn.execute("SELECT name FROM sqlite_master"))
    conn.close()
    assert names == ["replay", "replay_meta", "sqlite_autoindex_replay_1"]
    assert db.read_bytes() != original


def test_permissions_are_kept(db):
    published_file(db)
    os.chmod(db, 0o640)
    assert migrate_replay_file(db, now=T0, previous_max_age=DAY)["warnings"] == []
    assert db.stat().st_mode & 0o777 == 0o640


def test_a_group_writable_file_keeps_its_mode_and_says_so(db):
    published_file(db)
    os.chmod(db, 0o660)
    out = migrate_replay_file(db, now=T0, previous_max_age=DAY)
    assert db.stat().st_mode & 0o777 == 0o660 and "lets others write" in out["warnings"][0]


def test_a_symlinked_path_migrates_the_real_file_and_keeps_the_link(db, tmp_path):
    published_file(db)
    link = tmp_path / "link.db"
    link.symlink_to(db)
    migrate_replay_file(link, now=T0, previous_max_age=DAY)
    assert link.is_symlink() and replay_file_status(db)["state"] == "current"
    assert db.with_name(db.name + ".pre-migration").exists()


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_journal_or_wal_siblings_are_refused(db, suffix):
    published_file(db)
    sibling = db.with_name(db.name + suffix)
    sibling.write_bytes(b"x")
    before = db.read_bytes()
    with pytest.raises(ReplayMigrationRefused, match="interrupted or live"):
        migrate_replay_file(db, now=T0, previous_policy_unknown=True)
    assert db.read_bytes() == before and sibling.read_bytes() == b"x"


def test_a_wal_mode_file_is_refused(db):
    published_file(db)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.close()
    with pytest.raises(ReplayMigrationRefused, match="rollback-journal"):
        migrate_replay_file(db, now=T0, previous_policy_unknown=True)


def test_an_existing_other_backup_is_not_overwritten(db):
    published_file(db)
    keep = db.with_name(db.name + ".pre-migration")
    keep.write_bytes(b"something else")
    with pytest.raises(ReplayMigrationRefused, match="another file"):
        migrate_replay_file(db, now=T0, previous_max_age=DAY)
    assert keep.read_bytes() == b"something else"
    assert replay_file_status(db)["state"] == "legacy"


def test_a_user_version_the_published_code_never_set_is_refused(db):
    published_file(db)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA user_version = 7")
    conn.close()
    with pytest.raises(ReplayMigrationRefused, match="user_version"):
        migrate_replay_file(db, now=T0, previous_max_age=DAY)


# ------------------------------------------------------------------ the planted objects, in a real published file


def _plant(kind):
    return {
        "trigger": "CREATE TRIGGER forget AFTER INSERT ON replay BEGIN DELETE FROM replay; END",
        "trigger-before": "CREATE TRIGGER forget BEFORE DELETE ON replay BEGIN SELECT 1; END",
        "extra-table": "CREATE TABLE other (x)",
        "view": "CREATE VIEW seen AS SELECT * FROM replay",
        "index": "CREATE INDEX odd ON replay (expires_at)",
    }[kind]


PLANTED = ["trigger", "trigger-before", "extra-table", "view", "index"]


@pytest.fixture
def real_file(tmp_path: Path) -> tuple[Path, dict]:
    """A file really written by the published 0.2.1 wheel. See tests/vectors/published_replay_files/generate.py."""
    fixture = json.loads(
        (Path(__file__).parent / "vectors/published_replay_files/by_0.2.1.json").read_text()
    )
    assert fixture["written_by"] == "0.2.1"
    db = tmp_path / "published.db"
    db.write_bytes(base64.b64decode(fixture["file_b64"]))
    return db, fixture


def test_clean_control_a_file_really_written_by_0_2_1_migrates(real_file):
    db, _ = real_file
    assert replay_file_status(db) == {"path": str(db), "state": "legacy", "rows": 1}
    out = migrate_replay_file(db, now=T0, previous_max_age=DAY)
    assert out["rows_preserved"] == 1 and replay_file_status(db)["state"] == "current"


@pytest.mark.parametrize("kind", PLANTED)
def test_planted_objects_in_a_real_published_file_are_refused_unchanged(real_file, kind):
    db, _ = real_file
    conn = sqlite3.connect(db)
    conn.execute(_plant(kind))
    conn.commit()
    conn.close()
    before = db.read_bytes()
    with pytest.raises(ReplayMigrationRefused, match="expected schema"):
        migrate_replay_file(db, now=T0, previous_max_age=DAY)
    assert db.read_bytes() == before
    assert not db.with_name(db.name + ".pre-migration").exists()
    with pytest.raises(ReplayStateError):
        SqliteReplayCache(db)


def test_an_analyze_table_is_refused_too(real_file):
    db, _ = real_file
    conn = sqlite3.connect(db)
    conn.execute("ANALYZE")
    conn.commit()
    conn.close()
    with pytest.raises(ReplayMigrationRefused, match="expected schema"):
        migrate_replay_file(db, now=T0, previous_max_age=DAY)


@pytest.mark.parametrize("kind", PLANTED)
def test_an_object_planted_after_migration_is_refused_in_every_operation(real_file, kind):
    db, _ = real_file
    migrate_replay_file(db, now=T0, previous_max_age=DAY)
    running = SqliteReplayCache(db)
    conn = sqlite3.connect(db)
    conn.execute(_plant(kind))
    conn.commit()
    conn.close()
    for operation in (
        lambda: running.seen("k", "r", now=T0),
        lambda: running.record("k", "r", now=T0, retain=HOUR),
        lambda: running.bind_max_age(HOUR, persist=True),
        lambda: running.max_age_floor(),
        lambda: SqliteReplayCache(db),
        lambda: replay_file_status(db),
    ):
        with pytest.raises(ReplayStateError, match="expected schema"):
            operation()


CHECK_CHILD = textwrap.dedent(
    """
    import json, sys
    from datetime import datetime, timedelta
    sys.path.insert(0, sys.argv[1])
    from regaudit_fhe.replay import SqliteReplayCache
    from regaudit_fhe.report_v2 import parse_envelope_strict
    from regaudit_fhe.trust import TrustStore
    from regaudit_fhe.verification import VerificationPolicy, verify
    fx = json.load(open(sys.argv[2]))
    store = TrustStore.from_dict({"entries": {fx["key_id"]: {
        "issuer": fx["issuer"], "public_key_pem": fx["public_key_pem"], "status": "active"}}})
    now = datetime.fromisoformat(sys.argv[4])
    res = verify(parse_envelope_strict(json.dumps(fx["report"])), VerificationPolicy(
        profile="confidential", trust_store=store, max_age=timedelta(seconds=float(sys.argv[5])), replay_mode="record",
        replay_cache=SqliteReplayCache(sys.argv[3]), verifier_id="reg", now=lambda: now))
    print(json.dumps([res.trust_status, list(res.blocking_reasons), list(res.reasons)]))
    """
)


def _new_process(fixture_path: Path, db: Path, now: datetime, max_age: timedelta) -> list:
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            sys.executable, "-c", CHECK_CHILD, PACKAGE_PARENT, str(fixture_path), str(db), now.isoformat(),
            str(max_age.total_seconds()),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )  # fmt: skip
    return json.loads(out.stdout)


FIXTURE_PATH = Path(__file__).parent / "vectors/published_replay_files/by_0.2.1.json"
FIXTURE_T = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)


def test_replay_stays_enforced_after_migration_across_real_new_processes(real_file):
    db, _ = real_file
    at = FIXTURE_T + 2 * HOUR
    migrate_replay_file(db, now=at, previous_max_age=DAY)
    for _ in range(3):
        status, blocking, _ = _new_process(FIXTURE_PATH, db, at, DAY)
        assert status == "INVALID" and blocking == ["REPLAY_DETECTED"]
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM replay").fetchone() == (1,)  # still there
    conn.close()


def test_first_contact_increase_on_a_real_file_across_new_processes(real_file):
    db, _ = real_file
    at = FIXTURE_T + 3 * DAY  # the row, written under one day, has expired
    migrate_replay_file(db, now=at, previous_max_age=DAY)
    for _ in range(2):
        status, blocking, reasons = _new_process(FIXTURE_PATH, db, at, 10 * DAY)
        assert status == "INVALID" and blocking == ["REPORT_TOO_OLD"]
        assert "REPLAY_POLICY_FLOOR_APPLIED" in reasons


def test_first_contact_increase_on_a_real_file_with_unknown_policy(real_file):
    db, _ = real_file
    at = FIXTURE_T + 3 * DAY
    migrate_replay_file(db, now=at, previous_policy_unknown=True)
    status, blocking, _ = _new_process(FIXTURE_PATH, db, at, 10 * DAY)
    assert status == "INVALID" and blocking == ["REPLAY_HISTORY_UNKNOWN"]


def test_the_planted_trigger_case_end_to_end_through_the_cli(real_file, tmp_path):
    """The finding: trigger planted, migrate exit 0, then the same report TRUSTED twice. Now refused at migrate."""
    db, _ = real_file
    _signed_cli_report(tmp_path)
    conn = sqlite3.connect(db)
    conn.execute(_plant("trigger"))
    conn.commit()
    conn.close()
    before = db.read_bytes()
    out = cli(
        "replay", "migrate", "--db", str(db), "--previous-max-age-seconds", "86400", cwd=tmp_path
    )
    assert out.returncode == 2 and "forget" in out.stderr and db.read_bytes() == before
    verify_args = (
        "verify", "-i", "r.json", "--trusted-keys", "t.json", "--replay-mode", "record", "--replay-db", str(db),
    )  # fmt: skip
    assert cli(*verify_args, cwd=tmp_path).returncode == 3


def test_clean_control_end_to_end_through_the_cli_replay_is_detected_in_new_processes(
    real_file, tmp_path
):
    db, _ = real_file
    _signed_cli_report(tmp_path, issued_at=datetime.now(timezone.utc))
    out = cli(
        "replay", "migrate", "--db", str(db), "--previous-max-age-seconds", "86400", cwd=tmp_path
    )
    assert out.returncode == 0, out.stderr
    verify_args = (
        "verify", "-i", "r.json", "--trusted-keys", "t.json", "--replay-mode", "record", "--replay-db", str(db),
        "--max-age-seconds", "86400",
    )  # fmt: skip
    first = cli(*verify_args, cwd=tmp_path)
    assert first.returncode == 0, first.stdout + first.stderr
    second = cli(*verify_args, cwd=tmp_path)
    assert second.returncode == 1 and "REPLAY_DETECTED" in second.stdout


def test_a_trigger_planted_after_migration_stops_the_cli(real_file, tmp_path):
    db, _ = real_file
    _signed_cli_report(tmp_path, issued_at=datetime.now(timezone.utc))
    migrate_replay_file(db, now=datetime.now(timezone.utc), previous_max_age=DAY)
    conn = sqlite3.connect(db)
    conn.execute(_plant("trigger"))
    conn.commit()
    conn.close()
    verify_args = (
        "verify", "-i", "r.json", "--trusted-keys", "t.json", "--replay-mode", "record", "--replay-db", str(db),
    )  # fmt: skip
    out = cli(*verify_args, cwd=tmp_path)
    assert out.returncode == 3 and "expected schema" in out.stderr


# ------------------------------------------------------------------ plausible edits


@pytest.mark.parametrize(
    "tamper",
    [
        "UPDATE replay_meta SET history_cutover = NULL WHERE origin = 'history-unknown'",
        "UPDATE replay_meta SET origin = 'new'",
        "UPDATE replay_meta SET origin = 'operator-attested'",
        "UPDATE replay_meta SET migrated_at = NULL",
        "UPDATE replay_meta SET trust_history_max_age_us = 999999999999",
    ],
)
def test_incoherent_edits_to_the_policy_record_are_refused(db, tamper):
    published_file(db)
    migrate_replay_file(db, now=T0, previous_policy_unknown=True)
    conn = sqlite3.connect(db)
    conn.execute(tamper)
    conn.commit()
    conn.close()
    if tamper.endswith("'operator-attested'"):  # coherent only with the cutover gone
        with pytest.raises(ReplayStateError):
            SqliteReplayCache(db).history_cutover()
        return
    with pytest.raises(ReplayStateError):
        SqliteReplayCache(db).max_age_floor()


def test_limit_a_plausible_edit_by_someone_who_can_write_the_file_is_not_detected(db):
    """Nothing here is authenticated. This is why replay state is local, and why a writer of it is out of scope."""
    env = report(T0 + HOUR, RUN + "20")
    SqliteReplayCache(db)
    assert check(db, HOUR, T0 + HOUR, env).accepted
    conn = sqlite3.connect(db)
    conn.execute("UPDATE replay_meta SET max_age_us = ?", (DAY // timedelta(microseconds=1),))
    conn.execute("DELETE FROM replay")
    conn.commit()
    conn.close()
    assert check(db, DAY, T0 + 2 * HOUR, env).accepted  # accepted twice
