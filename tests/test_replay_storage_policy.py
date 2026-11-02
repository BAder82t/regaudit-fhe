"""C3-04: a strict profile accepts a replay file only if other accounts cannot change it.

The real CLI and server paths are used where they exist. The limit tests at the end pin down what this does not do: a
change made under the same account still goes undetected.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe import replay as replay_module
from regaudit_fhe.replay import (
    InMemoryReplayCache,
    ReplayStateError,
    ReplayStorageUnsafe,
    SqliteReplayCache,
)
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.verification import PolicyError, VerificationPolicy, verify

from .test_revocation_tooling_and_cli import cli, op  # noqa: F401

STRICT = ["confidential", "high-assurance", "secure-v1"]
UTC = timezone.utc
T0 = datetime.now(UTC)
HOUR = timedelta(hours=1)
SIGNER = rf.Signer.generate(issuer="acme", key_id="k")
STORE = rf.TrustStore.from_dict(
    {
        "entries": {
            "k": {"issuer": "acme", "public_key_pem": SIGNER.public_key_pem(), "status": "active"}
        }
    }
)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def verify_cli(cwd: Path, db: str = "replay.db", profile: str = "confidential"):
    out = cli(
        "verify", "-i", str(cwd / "r.json"), "--trusted-keys", str(cwd / "t.json"), "--profile", profile,
        "--max-age-seconds", "3600", "--replay-mode", "record", "--replay-db", db, "--verifier-id", "reg",
        cwd=cwd,
    )  # fmt: skip
    return out, (json.loads(out.stdout) if out.stdout.strip() else None)


@pytest.fixture
def world(op):  # noqa: F811
    cwd, _ = op
    os.chmod(cwd, 0o700)
    return cwd


def seeded(path: Path, file_mode: int = 0o600) -> bytes:
    """A real replay file holding no record of the report, with the mode it should have for the test."""
    SqliteReplayCache(path)
    os.chmod(path, file_mode)
    return path.read_bytes()


def envelope():
    return envelope_v2(
        "drift",
        rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])),
        signer=SIGNER,
        deployment_id="p",
        audience=["reg"],
        issued_at=T0,
        audit_run_id="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e601",
    )


def policy(cache, profile="confidential"):
    return VerificationPolicy(
        profile=profile,
        trust_store=STORE,
        verifier_id="reg",
        max_age=HOUR,
        replay_cache=cache,
        replay_mode="record",
    )


# ----------------------------------------------------------------------------- positive controls


@pytest.mark.parametrize("profile", STRICT)
def test_a_new_file_works_and_a_replay_is_still_detected(world, profile):
    out, first = verify_cli(world, profile=profile)
    assert out.returncode == 0, out.stderr
    assert first["trust_status"] == "TRUSTED" and first["replay_durable"] is True
    assert mode(world / "replay.db") == 0o600
    out, second = verify_cli(world, profile=profile)
    assert out.returncode == 1 and "REPLAY_DETECTED" in second["blocking_reasons"]


@pytest.mark.parametrize("file_mode", [0o600, 0o640, 0o644, 0o400], ids=oct)
def test_an_existing_file_nobody_else_can_write_is_accepted_and_keeps_its_mode(world, file_mode):
    seeded(world / "replay.db", file_mode)
    out, verdict = verify_cli(world)
    if file_mode == 0o400:  # a record cannot be written: unavailable, for that reason alone
        assert out.returncode == 3 and "replay store" in out.stderr
    else:
        assert out.returncode == 0, out.stderr
        assert verdict["replay_durable"] is True
    assert mode(world / "replay.db") == file_mode


@pytest.mark.parametrize("dir_mode", [0o700, 0o750, 0o755], ids=oct)
def test_a_parent_directory_nobody_else_can_write_is_accepted(world, dir_mode):
    box = world / "box"
    box.mkdir()
    os.chmod(box, dir_mode)
    out, verdict = verify_cli(world, str(box / "replay.db"))
    assert out.returncode == 0, out.stderr
    assert verdict["trust_status"] == "TRUSTED"


def test_a_sticky_directory_above_a_private_parent_is_accepted(tmp_path):
    above = tmp_path / "shared"
    above.mkdir()
    os.chmod(above, 0o1777)  # noqa: S103 - the point of the test
    box = above / "box"
    box.mkdir(mode=0o700)
    cache = SqliteReplayCache(box / "replay.db", private_storage=True)
    assert cache.durable and cache.record("k", "r", now=T0, retain=HOUR)


def test_a_symlinked_directory_of_ours_is_accepted(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    (tmp_path / "link").symlink_to(real)
    cache = SqliteReplayCache(tmp_path / "link" / "replay.db", private_storage=True)
    assert cache.durable and cache.record("k", "r", now=T0, retain=HOUR)


@pytest.mark.parametrize("umask", [0o000, 0o002, 0o022, 0o077], ids=oct)
@pytest.mark.parametrize("private", [False, True], ids=["unchecked", "strict"])
def test_a_new_file_is_0600_whatever_the_umask(tmp_path, umask, private):
    previous = os.umask(umask)
    try:
        SqliteReplayCache(tmp_path / "replay.db", private_storage=private)
    finally:
        os.umask(previous)
    assert mode(tmp_path / "replay.db") == 0o600


# ----------------------------------------------------------------------------- refusals through the real CLI


@pytest.mark.parametrize("profile", STRICT)
@pytest.mark.parametrize("file_mode", [0o666, 0o660, 0o620, 0o602], ids=oct)
def test_a_file_others_can_write_is_refused_and_left_alone(world, profile, file_mode):
    before = seeded(world / "replay.db", file_mode)
    out, verdict = verify_cli(world, profile=profile)
    assert out.returncode == 3 and verdict is None, out.stdout + out.stderr
    assert "lets group or others write" in out.stderr
    assert mode(world / "replay.db") == file_mode and (world / "replay.db").read_bytes() == before


@pytest.mark.parametrize("profile", STRICT)
@pytest.mark.parametrize("dir_mode", [0o777, 0o770, 0o1777], ids=oct)
def test_a_parent_directory_others_can_write_is_refused_before_anything_is_created(
    world, profile, dir_mode
):
    box = world / "box"
    box.mkdir()
    os.chmod(box, dir_mode)
    out, verdict = verify_cli(world, str(box / "replay.db"), profile=profile)
    assert out.returncode == 3 and verdict is None
    assert "writable by group or others" in out.stderr
    assert not list(box.iterdir()) and mode(box) == dir_mode


def test_an_existing_safe_file_in_a_directory_others_can_write_is_refused(world):
    box = world / "box"
    box.mkdir()
    before = seeded(box / "replay.db")
    os.chmod(box, 0o777)  # noqa: S103 - the point of the test
    out, _ = verify_cli(world, str(box / "replay.db"))
    assert out.returncode == 3 and "writable by group or others" in out.stderr
    assert (box / "replay.db").read_bytes() == before


def test_a_directory_higher_up_that_others_can_write_is_refused(world):
    high = world / "high"
    high.mkdir()
    os.chmod(high, 0o777)  # noqa: S103 - the point of the test
    box = high / "box"
    box.mkdir(mode=0o700)
    out, _ = verify_cli(world, str(box / "replay.db"))
    assert out.returncode == 3 and "high" in out.stderr and not list(box.iterdir())


@pytest.mark.parametrize("profile", STRICT)
def test_a_symlink_at_the_path_is_refused_and_the_target_untouched(world, profile):
    target = world / "target.db"
    before = seeded(target)
    (world / "replay.db").symlink_to(target)
    out, verdict = verify_cli(world, profile=profile)
    assert out.returncode == 3 and verdict is None
    assert target.read_bytes() == before


def test_a_dangling_symlink_at_the_path_is_refused_and_creates_nothing(world):
    (world / "replay.db").symlink_to(world / "elsewhere.db")
    out, _ = verify_cli(world)
    assert out.returncode == 3 and not (world / "elsewhere.db").exists()


def test_a_symlinked_directory_in_a_directory_others_can_write_is_refused(world):
    shared = world / "shared"
    shared.mkdir()
    real = world / "real"
    real.mkdir(mode=0o700)
    (shared / "link").symlink_to(real)
    os.chmod(shared, 0o777)  # noqa: S103 - the point of the test
    out, _ = verify_cli(world, str(shared / "link" / "replay.db"))
    assert out.returncode == 3 and "shared" in out.stderr and not list(real.iterdir())


def test_a_fifo_is_refused_without_hanging(world):
    os.mkfifo(world / "replay.db", 0o600)
    out, _ = verify_cli(world)
    assert out.returncode == 3 and "not a regular file" in out.stderr


def test_a_directory_at_the_path_is_refused(world):
    (world / "replay.db").mkdir(mode=0o700)
    out, _ = verify_cli(world)
    assert out.returncode == 3 and "replay store" in out.stderr


def test_a_file_with_a_second_name_is_refused(world):
    seeded(world / "replay.db")
    os.link(world / "replay.db", world / "other.db")
    out, _ = verify_cli(world)
    assert out.returncode == 3 and "more than one name" in out.stderr


def test_a_missing_parent_directory_is_refused_and_not_created(world):
    out, _ = verify_cli(world, str(world / "absent" / "replay.db"))
    assert out.returncode == 3 and not (world / "absent").exists()


# ----------------------------------------------------------------------------- ownership and platform


def test_a_file_of_another_account_is_refused(tmp_path, monkeypatch):
    seeded(tmp_path / "replay.db")
    real = os.geteuid()
    cache = SqliteReplayCache(tmp_path / "replay.db")
    monkeypatch.setattr(replay_module, "directory_problem", lambda directory: None)
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    with pytest.raises(ReplayStorageUnsafe, match="another account"):
        cache.enforce_private_storage()
    assert not cache.durable


def test_a_directory_of_another_account_is_refused(tmp_path, monkeypatch):
    real = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    with pytest.raises(ReplayStorageUnsafe, match="another account"):
        SqliteReplayCache(tmp_path / "replay.db", private_storage=True)
    assert not (tmp_path / "replay.db").exists()


@pytest.mark.parametrize("missing", ["geteuid", "O_NOFOLLOW"])
def test_a_platform_that_cannot_establish_it_is_refused(tmp_path, monkeypatch, missing):
    monkeypatch.delattr(os, missing)
    with pytest.raises(ReplayStorageUnsafe, match="this platform cannot establish"):
        SqliteReplayCache(tmp_path / "replay.db", private_storage=True)


def test_an_unknown_platform_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "freebsd14")
    with pytest.raises(ReplayStorageUnsafe, match="this platform cannot establish"):
        SqliteReplayCache(tmp_path / "replay.db", private_storage=True)


macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACLs")


def set_acl(path: Path, entry: str) -> None:
    subprocess.run(["/bin/chmod", "+a", entry, str(path)], check=True, capture_output=True)  # noqa: S603


@macos
@pytest.mark.parametrize("right", ["write", "append", "delete", "writesecurity"])
def test_an_acl_letting_others_change_the_file_is_refused_and_not_called_durable(world, right):
    seeded(world / "replay.db")
    set_acl(world / "replay.db", f"group:everyone allow {right}")
    out, verdict = verify_cli(world)
    assert out.returncode == 3 and verdict is None and "ACL" in out.stderr
    assert not SqliteReplayCache(world / "replay.db").durable


@macos
def test_an_acl_letting_others_change_the_parent_directory_is_refused(world):
    box = world / "box"
    box.mkdir(mode=0o700)
    set_acl(box, "group:everyone allow add_file")
    out, _ = verify_cli(world, str(box / "replay.db"))
    assert out.returncode == 3 and "ACL" in out.stderr and not list(box.iterdir())


@macos
def test_an_acl_added_while_in_use_fails_closed(tmp_path):
    db = tmp_path / "replay.db"
    env = envelope()
    active = policy(SqliteReplayCache(db, private_storage=True))
    assert verify(env, active).accepted
    set_acl(db, "group:everyone allow write")
    res = verify(env, active)
    assert not res.accepted and res.blocking_reasons == ("REPLAY_STATE_UNAVAILABLE",)


@macos
def test_a_deny_only_acl_is_accepted(world):
    seeded(world / "replay.db")
    set_acl(world / "replay.db", "group:everyone deny delete")
    out, verdict = verify_cli(world)
    assert out.returncode == 0 and verdict["trust_status"] == "TRUSTED", out.stderr


# ----------------------------------------------------------------------------- the file opened, not the path checked


def test_a_file_replaced_while_in_use_fails_closed(tmp_path):
    db = tmp_path / "replay.db"
    env = envelope()
    active = policy(SqliteReplayCache(db, private_storage=True))
    assert verify(env, active).accepted
    swap = tmp_path / "swap.db"
    shutil.copyfile(db, swap)
    os.chmod(swap, 0o600)
    conn = sqlite3.connect(swap, isolation_level=None)
    conn.execute("DELETE FROM replay")
    conn.close()
    # Safe by itself, and the same policy floors, so only the file's identity can tell: ours, 0600, no record of this report.
    os.replace(swap, db)
    res = verify(env, active)
    assert not res.accepted and res.blocking_reasons == ("REPLAY_STATE_UNAVAILABLE",)


def test_a_file_deleted_while_in_use_fails_closed_and_is_not_recreated(tmp_path):
    db = tmp_path / "replay.db"
    env = envelope()
    active = policy(SqliteReplayCache(db, private_storage=True))
    assert verify(env, active).accepted
    db.unlink()
    res = verify(env, active)
    assert not res.accepted and res.blocking_reasons == ("REPLAY_STATE_UNAVAILABLE",)
    assert not db.exists()


def test_a_mode_loosened_while_in_use_fails_closed(tmp_path):
    db = tmp_path / "replay.db"
    env = envelope()
    active = policy(SqliteReplayCache(db, private_storage=True))
    assert verify(env, active).accepted
    os.chmod(db, 0o666)  # noqa: S103 - the point of the test
    res = verify(env, active)
    assert not res.accepted and res.blocking_reasons == ("REPLAY_STATE_UNAVAILABLE",)
    assert mode(db) == 0o666


def test_a_file_swapped_between_the_check_and_sqlite_opening_it_is_refused(tmp_path, monkeypatch):
    db = tmp_path / "replay.db"
    cache = SqliteReplayCache(db, private_storage=True)
    swap = tmp_path / "swap.db"
    seeded(swap)
    real_connect = sqlite3.connect

    def swapping(*args, **kwargs):
        os.replace(swap, db)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(replay_module.sqlite3, "connect", swapping)
    with pytest.raises(ReplayStorageUnsafe, match="replaced while it was opened"):
        cache.seen("k", "r", now=T0)


# ----------------------------------------------------------------------------- the library path and durability


@pytest.mark.parametrize("profile", STRICT)
def test_a_cache_built_without_the_flag_is_still_refused_by_a_strict_policy(tmp_path, profile):
    db = tmp_path / "replay.db"
    cache = SqliteReplayCache(db)
    os.chmod(db, 0o666)  # noqa: S103 - the point of the test
    with pytest.raises(PolicyError, match="lets group or others write"):
        policy(cache, profile)
    assert mode(db) == 0o666


def test_the_memory_path_still_fails_closed_at_the_record_step_and_is_not_durable():
    for cache in (
        SqliteReplayCache(":memory:"),
        SqliteReplayCache(":memory:", private_storage=True),
    ):
        res = verify(envelope(), policy(cache))
        assert not res.accepted and res.blocking_reasons == ("REPLAY_STATE_UNAVAILABLE",)
        assert not cache.durable


def test_development_keeps_working_but_does_not_call_an_unsafe_file_durable(world):
    seeded(world / "replay.db", 0o666)
    out, verdict = verify_cli(world, profile="development")
    assert out.returncode == 0, out.stderr
    assert verdict["trust_status"] == "TRUSTED" and verdict["replay_durable"] is False
    assert mode(world / "replay.db") == 0o666


def test_development_calls_a_safe_file_durable(world):
    out, verdict = verify_cli(world, profile="development")
    assert out.returncode == 0 and verdict["replay_durable"] is True


def test_memory_is_not_durable():
    assert not SqliteReplayCache(":memory:").durable
    assert not InMemoryReplayCache().durable


def test_the_refusal_is_a_replay_state_error():
    assert issubclass(ReplayStorageUnsafe, ReplayStateError)


# ----------------------------------------------------------------------------- the real server path


def serve(cwd: Path, db: Path, profile: str = "confidential") -> subprocess.CompletedProcess[str]:
    env = dict(
        os.environ,
        REGAUDIT_FHE_REPLAY_DB=str(db),
        REGAUDIT_FHE_REPLAY_MODE="record",
        REGAUDIT_FHE_PROFILE=profile,
        REGAUDIT_FHE_TRUST_STORE=str(cwd / "t.json"),
        REGAUDIT_FHE_VERIFIER_ID="reg",
        REGAUDIT_FHE_MAX_AGE_S="3600",
    )
    code = (
        "from regaudit_fhe.server import load_config_from_env\n"
        "config = load_config_from_env()\n"
        "print(type(config.replay_cache).__name__, config.replay_cache.durable)\n"
    )
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.mark.parametrize("profile", STRICT)
def test_the_server_refuses_to_start_on_an_unsafe_file(world, profile):
    seeded(world / "replay.db", 0o666)
    out = serve(world, world / "replay.db", profile)
    assert out.returncode != 0 and "ReplayStorageUnsafe" in out.stderr
    assert mode(world / "replay.db") == 0o666


def test_the_server_creates_nothing_in_a_directory_others_can_write(world):
    box = world / "box"
    box.mkdir()
    os.chmod(box, 0o777)  # noqa: S103 - the point of the test
    out = serve(world, box / "replay.db")
    assert out.returncode != 0 and "writable by group or others" in out.stderr
    assert not list(box.iterdir())


def test_the_server_starts_on_a_safe_file(world):
    out = serve(world, world / "replay.db")
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["SqliteReplayCache", "True"]
    assert mode(world / "replay.db") == 0o600


def test_the_server_command_exits_2_on_an_unsafe_file(world):
    seeded(world / "replay.db", 0o666)
    env = dict(
        os.environ,
        REGAUDIT_FHE_REPLAY_DB=str(world / "replay.db"),
        REGAUDIT_FHE_REPLAY_MODE="record",
        REGAUDIT_FHE_PROFILE="confidential",
        REGAUDIT_FHE_TRUST_STORE=str(world / "t.json"),
        REGAUDIT_FHE_VERIFIER_ID="reg",
        REGAUDIT_FHE_MAX_AGE_S="3600",
    )
    out = subprocess.run(
        [sys.executable, "-m", "regaudit_fhe.cli", "serve"],
        cwd=world, env=env, capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert out.returncode == 2 and "lets group or others write" in out.stderr


def test_a_running_server_answers_503_when_the_file_becomes_unsafe(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from regaudit_fhe.server import ServerConfig, build_app

    from ._asgi import client_for

    db = tmp_path / "replay.db"
    config = ServerConfig(
        api_keys={},
        dev_mode=True,
        max_body_bytes=1 << 20,
        rate_limit_per_min=1000,
        request_timeout_s=30.0,
        cors_origins=(),
        trust_store=STORE,
        profile="confidential",
        verifier_id="reg",
        max_age_s=3600.0,
        replay_cache=SqliteReplayCache(db, private_storage=True),
        replay_mode="record",
    )
    client = client_for(build_app(config=config), base_url="http://127.0.0.1")
    body = {"envelope": envelope().to_dict()}
    first = client.post("/v1/verify", json=body)
    assert first.status_code == 200, first.text
    assert first.json()["replay_durable"] is True
    os.chmod(db, 0o666)  # noqa: S103 - the point of the test
    assert client.post("/v1/verify", json=body).status_code == 503


# ----------------------------------------------------------------------------- what this does not protect against


def test_limit_the_same_account_can_still_erase_the_records_and_nothing_notices(world):
    """Not a guarantee: a statement of the limit. If this ever fails, the documented limit needs updating."""
    out, _ = verify_cli(world)
    assert out.returncode == 0
    assert verify_cli(world)[0].returncode == 1
    conn = sqlite3.connect(world / "replay.db", isolation_level=None)
    conn.execute("DELETE FROM replay")
    conn.close()
    out, again = verify_cli(world)
    assert out.returncode == 0 and again["trust_status"] == "TRUSTED"


def test_limit_a_new_process_cannot_tell_a_deleted_file_from_a_first_use(world):
    """Not a guarantee. An empty file is an explicit decision to forget: docs/DEPLOYMENT.md says so."""
    assert verify_cli(world)[0].returncode == 0
    (world / "replay.db").unlink()
    out, again = verify_cli(world)
    assert out.returncode == 0 and again["trust_status"] == "TRUSTED"
