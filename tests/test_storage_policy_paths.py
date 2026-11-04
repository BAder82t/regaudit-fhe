"""Findings from independent verification: paths that dodged the directory check, and ways to launder an unsafe store.

Another process stands in for another account, and ownership is simulated where noted. See the module docstring of
test_trust_store_storage_policy.py for what these checks do not protect against.
"""

from __future__ import annotations

import ctypes
import dataclasses
import errno
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import regaudit_fhe as rf
from regaudit_fhe import _storage_policy as policy_module
from regaudit_fhe import trust as trust_module
from regaudit_fhe.replay import ReplayStorageUnsafe, SqliteReplayCache
from regaudit_fhe.trust import TrustStoreError
from regaudit_fhe.verification import PolicyError, VerificationPolicy

from .test_replay_migration import published_file
from .test_revocation_tooling_and_cli import cli
from .test_trust_store_storage_policy import add_outsider, make_world, mode, verify_cli

STRICT = ["confidential", "high-assurance", "secure-v1"]
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACLs")


@pytest.fixture
def world(tmp_path: Path) -> Path:
    return make_world(tmp_path)


def set_acl(path: Path, entry: str) -> None:
    subprocess.run(["/bin/chmod", "+a", entry, str(path)], check=True, capture_output=True)  # noqa: S603


# ----------------------------------------------------------------------------- F1: a path written with ..


def _evil_layout(world: Path) -> Path:
    evil = world / "evil"
    (evil / "sub").mkdir(parents=True)
    shutil.copy(world / "t.json", evil / "t.json")
    safe = world / "safe"
    safe.mkdir()
    (safe / "link").symlink_to(evil / "sub")
    os.chmod(evil, 0o777)  # noqa: S103 - the point of the test
    return safe


@pytest.mark.parametrize("profile", STRICT)
def test_dotdot_after_a_link_is_checked_where_it_really_leads(world, profile):
    _evil_layout(world)
    out, verdict = verify_cli(world, "trusted.json", store="safe/link/../t.json", profile=profile)
    assert out.returncode == 3 and verdict is None, out.stdout + out.stderr
    assert "evil" in out.stderr and "writable by group or others" in out.stderr


def test_dotdot_after_a_link_is_recorded_for_a_store_loaded_without_the_flag(world):
    safe = _evil_layout(world)
    store = rf.TrustStore.from_json(safe / "link" / ".." / "t.json")
    assert store.storage_problem is not None
    with pytest.raises(PolicyError, match="another account could change"):
        VerificationPolicy(profile="confidential", trust_store=store)


def test_a_rolled_back_store_is_not_reached_through_dotdot(world):
    """The outcome: a key marked compromised must not come back through a directory others can write."""
    _evil_layout(world)
    assert verify_cli(world, "trusted.json", store="safe/link/../t.json")[0].returncode == 3


def test_dotdot_in_a_safe_tree_still_works(world):
    (world / "plain" / "sub").mkdir(parents=True)
    shutil.copy(world / "t.json", world / "plain" / "t.json")
    out, verdict = verify_cli(world, "trusted.json", store="plain/sub/../t.json")
    assert out.returncode == 0 and verdict["trust_status"] == "TRUSTED", out.stderr


def test_a_store_path_ending_in_dotdot_is_refused(world):
    with pytest.raises(TrustStoreError):
        rf.TrustStore.from_json(world / "..", private_storage=True)


# ----------------------------------------------------------------------------- F2: a link in the middle of a chain


def _chain(world: Path) -> tuple[Path, Path]:
    real = world / "real"
    real.mkdir(mode=0o700)
    mid = world / "mid"
    mid.mkdir()
    (mid / "l2").symlink_to(real)
    a = world / "a"
    a.mkdir(mode=0o700)
    (a / "l1").symlink_to(mid / "l2")
    os.chmod(mid, 0o777)  # noqa: S103 - the point of the test
    return a / "l1", real


@pytest.mark.parametrize("profile", STRICT)
def test_the_directory_holding_a_middle_link_is_checked_for_a_store(world, profile):
    path, real = _chain(world)
    shutil.copy(world / "t.json", real / "t.json")
    out, verdict = verify_cli(world, "trusted.json", store=str(path / "t.json"), profile=profile)
    assert out.returncode == 3 and verdict is None and "mid" in out.stderr, out.stderr


def test_the_directory_holding_a_middle_link_is_checked_for_a_replay_file(world):
    path, real = _chain(world)
    assert "mid" in (policy_module.directory_problem(str(path)) or "")
    with pytest.raises(Exception, match="mid"):
        SqliteReplayCache(path / "replay.db", private_storage=True)
    assert not list(real.iterdir())


def test_a_chain_of_links_in_safe_directories_still_works(world):
    real = world / "real"
    real.mkdir(mode=0o700)
    shutil.copy(world / "t.json", real / "t.json")
    (world / "l2").symlink_to(real)
    (world / "l1").symlink_to("l2")
    out, verdict = verify_cli(world, "trusted.json", store="l1/t.json")
    assert out.returncode == 0 and verdict["trust_status"] == "TRUSTED", out.stderr


def test_a_link_owned_by_another_account_is_refused(world, monkeypatch):
    (world / "real").mkdir(mode=0o700)
    (world / "link").symlink_to(world / "real")
    real_lstat = os.lstat

    def foreign_link(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if str(path).endswith("/link"):
            fields = list(info)
            fields[stat.ST_UID] = os.geteuid() + 1
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(policy_module.os, "lstat", foreign_link)
    assert "another account" in policy_module.directory_problem(str(world / "link"))


def test_a_link_loop_is_refused_without_hanging(world):
    """In its own process with a time limit, so that a loop with no limit fails here instead of hanging the run."""
    (world / "x").symlink_to(world / "y")
    (world / "y").symlink_to(world / "x")
    code = "import sys\nfrom regaudit_fhe import _storage_policy as p\nprint(p.directory_problem(sys.argv[1]))\n"
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code, str(world / "x")],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert "too many symbolic links" in out.stdout, out.stderr


def test_the_resolved_directory_is_what_gets_opened(world):
    (world / "real").mkdir(mode=0o700)
    (world / "link").symlink_to(world / "real")
    problem, directory = policy_module.resolve_directory(str(world / "link"))
    assert problem is None and directory == os.path.realpath(world / "real")


# ----------------------------------------------------------------------------- F4: trust add and friends


def _trust_add(world: Path, store: str = "t.json"):
    return cli(
        "trust", "add", "--store", store, "--key-id", "outsider", "--issuer", "acme", "--public-key", "outsider.pub",
        "--fingerprint", (world / "outsider.fp").read_text(), cwd=world,
    )  # fmt: skip


def test_trust_add_will_not_launder_a_store_another_process_changed(world):
    add_outsider(world / "t.json", world)
    before = (world / "t.json").read_bytes()
    os.chmod(world / "t.json", 0o666)  # noqa: S103 - the point of the test
    out = _trust_add(world)
    assert out.returncode == 3 and "another account could have changed" in out.stderr
    assert (world / "t.json").read_bytes() == before and mode(world / "t.json") == 0o666
    assert verify_cli(world, "outsider.json")[0].returncode == 3


@pytest.mark.parametrize("dir_mode", [0o777, 0o775, 0o1777], ids=oct)
def test_trust_add_refuses_a_directory_others_can_write(world, dir_mode):
    """A key planted there during the add would be kept, and become trusted once the directory was fixed."""
    box = world / "box"
    box.mkdir()
    os.chmod(box, dir_mode)
    out = _trust_add(world, "box/new.json")
    assert out.returncode == 3 and "writable by group or others" in out.stderr, out.stderr
    assert not list(box.iterdir())


def test_trust_add_does_not_keep_a_key_planted_while_it_runs(world):
    """In a directory others can write it never reaches the read, so a planted file has nothing to join."""
    box = world / "box"
    box.mkdir()
    shutil.copy(world / "t.json", box / "t.json")
    add_outsider(box / "t.json", world)
    before = (box / "t.json").read_bytes()
    os.chmod(box, 0o777)  # noqa: S103 - the point of the test
    assert _trust_add(world, "box/t.json").returncode == 3
    assert (box / "t.json").read_bytes() == before


def test_trust_add_refuses_a_store_with_a_second_name(world):
    os.link(world / "t.json", world / "other.json")
    before = (world / "t.json").read_bytes()
    out = _trust_add(world)
    assert out.returncode == 3 and "more than one name" in out.stderr
    assert (world / "t.json").read_bytes() == before


def test_trust_add_refuses_a_symlink_rather_than_replace_it_with_a_file(world):
    (world / "link.json").symlink_to(world / "t.json")
    out = _trust_add(world, "link.json")
    assert out.returncode == 3 and "symbolic link" in out.stderr
    assert (world / "link.json").is_symlink()


def test_trust_add_on_a_fifo_is_refused_without_hanging(world):
    os.mkfifo(world / "fifo.json", 0o600)
    out = _trust_add(world, "fifo.json")
    assert out.returncode == 3 and "not a regular file" in out.stderr


@pytest.mark.parametrize("file_mode", [0o600, 0o640, 0o644], ids=oct)
def test_trust_add_keeps_the_mode_of_a_safe_store(world, file_mode):
    os.chmod(world / "t.json", file_mode)
    out = _trust_add(world)
    assert out.returncode == 0, out.stderr
    assert mode(world / "t.json") == file_mode


def test_trust_add_still_creates_a_new_store_as_0644(world):
    out = _trust_add(world, "new.json")
    assert out.returncode == 0, out.stderr
    assert mode(world / "new.json") == 0o644


def test_trust_list_warns_about_an_unsafe_store(world):
    os.chmod(world / "t.json", 0o666)  # noqa: S103 - the point of the test
    out = cli("trust", "list", "--store", "t.json", cwd=world)
    assert out.returncode == 0 and "another account could change" in out.stderr


def test_trust_status_warns_about_a_directory_others_can_write(world):
    box = world / "box"
    box.mkdir()
    shutil.copy(world / "t.json", box / "t.json")
    os.chmod(box, 0o777)  # noqa: S103 - the point of the test
    out = cli("trust", "status", "--store", "box/t.json", cwd=world)
    assert out.returncode == 0 and "strict profiles refuse this store" in out.stdout + out.stderr


def test_serve_under_development_warns(world):
    pytest.importorskip("uvicorn")
    os.chmod(world / "t.json", 0o666)  # noqa: S103 - the point of the test
    env = dict(os.environ, REGAUDIT_FHE_PROFILE="development", REGAUDIT_FHE_HOST_REFUSE="1")
    process = subprocess.Popen(
        [sys.executable, "-m", "regaudit_fhe.cli", "serve", "--trust-store", "t.json", "--port", "0"],
        cwd=world, env=env, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True,
    )  # fmt: skip
    try:
        line = process.stderr.readline()
    finally:
        process.terminate()
        process.wait(timeout=30)
        process.stderr.close()
    assert "another account could change which keys this server trusts" in line


def test_a_development_result_carries_the_reason(world):
    os.chmod(world / "t.json", 0o666)  # noqa: S103 - the point of the test
    _, verdict = verify_cli(world, "trusted.json", profile="development")
    assert (
        verdict["trust_status"] == "TRUSTED" and "TRUST_STORE_STORAGE_UNSAFE" in verdict["reasons"]
    )


def test_a_safe_result_does_not_carry_the_reason(world):
    _, verdict = verify_cli(world, "trusted.json", profile="development")
    assert "TRUST_STORE_STORAGE_UNSAFE" not in verdict["reasons"]


# ----------------------------------------------------------------------------- F5: a copy of the object


@pytest.mark.parametrize("profile", STRICT)
def test_a_copy_of_an_unsafe_store_is_still_refused(world, profile):
    os.chmod(world / "t.json", 0o666)  # noqa: S103 - the point of the test
    store = rf.TrustStore.from_json(world / "t.json")
    copied = dataclasses.replace(store)
    assert copied.storage_problem == store.storage_problem is not None
    with pytest.raises(PolicyError, match="another account could change"):
        VerificationPolicy(profile=profile, trust_store=copied)


# ----------------------------------------------------------------------------- F8: real ACL text


@pytest.mark.parametrize(
    ("text", "bad"),
    [
        ("!#acl 1\ngroup:AA:everyone:12:allow,inherited:read\n", False),
        ("!#acl 1\ngroup:AA:everyone:12:deny,inherited:delete\n", False),
        ("!#acl 1\ngroup:AA:everyone:12:allow,file_inherit:read\n", False),
        ("!#acl 1\ngroup:AA:everyone:12:allow,inherited:write\n", True),
        ("!#acl 1\ngroup:AA:everyone:12:allow,only_inherit:write\n", True),
    ],
)
def test_real_acl_flags_are_understood(text, bad):
    assert (policy_module._acl_text_problem(text, "x") is not None) is bad


def test_an_unknown_acl_flag_fails_closed():
    text = "!#acl 1\ngroup:AA:everyone:12:allow,brand_new:read\n"
    assert "cannot be read reliably" in policy_module._acl_text_problem(text, "x")


@macos
@pytest.mark.parametrize(
    ("entry", "accepted"),
    [
        ("group:everyone allow read,file_inherit", True),
        ("group:everyone deny delete,file_inherit", True),
        ("group:everyone allow write,file_inherit", False),
    ],
)
def test_an_inherited_acl_is_judged_by_its_rights(world, entry, accepted):
    box = world / "box"
    box.mkdir(mode=0o700)
    set_acl(box, entry)
    shutil.copy(world / "t.json", box / "t.json")
    out, verdict = verify_cli(world, "trusted.json", store="box/t.json")
    if accepted:
        assert out.returncode == 0 and verdict["trust_status"] == "TRUSTED", out.stderr
    else:
        assert out.returncode == 3 and verdict is None and "ACL" in out.stderr


@macos
def test_a_write_acl_for_a_group_is_refused_even_a_group_this_user_is_in(world):
    set_acl(world / "t.json", "group:wheel allow write")
    assert verify_cli(world, "trusted.json")[0].returncode == 3


def _fake_libc(world_fd_result=1, *, errno_value=None, text_result=1):
    def get_fd(_fd, _kind):
        if errno_value is not None:
            ctypes.set_errno(errno_value)
        return world_fd_result

    return SimpleNamespace(
        acl_get_fd_np=get_fd,
        acl_get_link_np=lambda _path, _kind: (ctypes.set_errno(errno.ENOENT), 0)[1],
        acl_to_text=lambda _acl, _size: text_result,
        acl_free=lambda _pointer: 0,
    )


def _with_functions_settable(fake):
    for name in ("acl_get_fd_np", "acl_get_link_np", "acl_to_text", "acl_free"):
        function = getattr(fake, name)
        wrapper = lambda *a, _f=function: _f(*a)  # noqa: E731
        setattr(fake, name, wrapper)
    return fake


@macos
@pytest.mark.parametrize(
    ("fake", "patch_text"),
    [
        (dict(world_fd_result=0, errno_value=errno.EIO), False),
        (dict(text_result=0), False),
        (dict(), True),
    ],
    ids=["read-error", "no-text", "undecodable"],
)
def test_an_acl_that_cannot_be_read_fails_closed(world, monkeypatch, fake, patch_text):
    """The acl calls are faked: this host cannot produce these failures for real."""
    library = _with_functions_settable(_fake_libc(**fake))
    monkeypatch.setattr(policy_module.ctypes, "CDLL", lambda *_a, **_k: library)
    if patch_text:
        monkeypatch.setattr(policy_module.ctypes, "string_at", lambda *_a: b"\xff\xfe")
    assert "cannot be read" in policy_module.acl_problem("x", fd=0)


@macos
def test_no_acl_is_not_a_problem(world):
    fd = os.open(world / "t.json", os.O_RDONLY)
    try:
        assert policy_module.acl_problem("x", fd=fd) is None
    finally:
        os.close(fd)


# ----------------------------------------------------------------------------- F10 and other routes


def test_a_fifo_in_development_reads_as_it_did_and_is_recorded(world):
    os.mkfifo(world / "fifo.json", 0o600)
    body = (world / "t.json").read_bytes()

    def writer():
        with open(world / "fifo.json", "wb") as handle:
            handle.write(body)

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    store = rf.TrustStore.from_json(world / "fifo.json")
    thread.join(timeout=30)
    assert list(store.keys) == ["issuer"] and "not a regular file" in store.storage_problem


def test_a_symlinked_store_loaded_without_the_flag_is_refused_by_a_strict_policy(world):
    (world / "link.json").symlink_to(world / "t.json")
    store = rf.TrustStore.from_json(world / "link.json")
    assert "symbolic link" in store.storage_problem
    with pytest.raises(PolicyError, match="another account could change"):
        VerificationPolicy(profile="confidential", trust_store=store)


def test_a_real_root_owned_file_passes_the_storage_check():
    """A file root really owns. It fails later, at parsing, for being no store."""
    target = "/etc/hosts"
    if not os.path.isfile(target) or os.stat(target).st_uid != 0 or os.geteuid() == 0:
        pytest.skip("needs a root-owned file and a non-root user")
    with pytest.raises(TrustStoreError) as caught:
        rf.TrustStore.from_json(target, private_storage=True)
    assert "not safe to use" not in str(caught.value)


def test_a_file_removed_right_after_it_is_read_is_refused(world, monkeypatch):
    real_lstat = os.lstat
    monkeypatch.setattr(trust_module, "_store_location", lambda path: (None, str(path)))

    def gone(path, *args, **kwargs):
        if str(path).endswith("t.json"):
            raise FileNotFoundError(path)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(trust_module.os, "lstat", gone)
    with pytest.raises(TrustStoreError, match="replaced while it was read"):
        rf.TrustStore.from_json(world / "t.json", private_storage=True)


def test_a_replay_cache_built_without_the_flag_is_refused_by_a_strict_policy_for_its_directory(
    world, tmp_path
):
    box = tmp_path / "box"
    box.mkdir(mode=0o700)
    cache = SqliteReplayCache(box / "replay.db")
    os.chmod(box, 0o777)  # noqa: S103 - the point of the test
    store = rf.TrustStore.from_json(world / "t.json", private_storage=True)
    with pytest.raises(PolicyError, match="writable by group or others"):
        VerificationPolicy(
            profile="confidential",
            trust_store=store,
            verifier_id="reg",
            max_age=__import__("datetime").timedelta(hours=1),
            replay_cache=cache,
            replay_mode="record",
        )


# ----------------------------------------------------------------------------- N1: retire and revoke


@pytest.mark.parametrize("command", ["retire", "revoke"])
def test_a_lifecycle_edit_will_not_clear_a_second_name(world, command):
    add_outsider(world / "t.json", world)
    os.link(world / "t.json", world / "other.json")
    before = (world / "t.json").read_bytes()
    out = cli("trust", command, "--store", "t.json", "--key-id", "issuer", cwd=world)
    assert out.returncode != 0 and "more than one name" in out.stdout + out.stderr
    assert (world / "t.json").read_bytes() == before
    assert (world / "t.json").stat().st_nlink == 2
    assert verify_cli(world, "outsider.json")[0].returncode == 3


@macos
@pytest.mark.parametrize("command", ["retire", "revoke"])
def test_a_lifecycle_edit_will_not_clear_an_acl_and_the_outsider_stays_refused(world, command):
    add_outsider(world / "t.json", world)
    set_acl(world / "t.json", "group:everyone allow write")
    before = (world / "t.json").read_bytes()
    out = cli("trust", command, "--store", "t.json", "--key-id", "issuer", cwd=world)
    assert out.returncode != 0 and "ACL" in out.stdout + out.stderr
    assert (world / "t.json").read_bytes() == before
    assert verify_cli(world, "outsider.json")[0].returncode == 3


def test_a_rewrite_problem_reports_another_owner(world):
    real = os.geteuid()
    fd = os.open(world / "t.json", os.O_RDONLY)
    try:
        info = list(os.fstat(fd))
    finally:
        os.close(fd)
    info[stat.ST_UID] = real + 1
    assert "another account" in trust_module._rewrite_problem(os.stat_result(info), -1)


def test_a_lifecycle_edit_of_a_safe_store_still_works(world):
    out = cli("trust", "retire", "--store", "t.json", "--key-id", "issuer", cwd=world)
    assert out.returncode == 0, out.stdout + out.stderr


def test_a_lifecycle_edit_of_a_world_writable_store_keeps_the_mode_so_strict_still_refuses(world):
    os.chmod(world / "t.json", 0o666)  # noqa: S103 - the point of the test
    out = cli("trust", "retire", "--store", "t.json", "--key-id", "issuer", cwd=world)
    assert out.returncode == 0, out.stdout + out.stderr
    assert mode(world / "t.json") == 0o666
    assert verify_cli(world, "trusted.json")[0].returncode == 3


# ----------------------------------------------------------------------------- N2: the path must lead to the file read


@pytest.mark.skipif(not os.path.exists("/dev/fd"), reason="needs /dev/fd")
def test_a_descriptor_path_is_recorded_and_refused_by_a_strict_policy(world):
    box = world / "box"
    box.mkdir()
    shutil.copy(world / "t.json", box / "t.json")
    os.chmod(box, 0o777)  # noqa: S103 - the point of the test
    fd = os.open(box / "t.json", os.O_RDONLY)
    try:
        path = f"/dev/fd/{fd}"
        assert trust_module.store_storage_problem(path) is not None
        store = rf.TrustStore.from_json(path)
    finally:
        os.close(fd)
    assert store.storage_problem is not None
    with pytest.raises(PolicyError, match="another account could change"):
        VerificationPolicy(profile="confidential", trust_store=store)


def test_what_is_opened_is_the_directory_the_walk_ended_in(world, monkeypatch):
    """A link flipped after the walk must not change what is read."""
    safe = world / "safe"
    safe.mkdir(mode=0o700)
    shutil.copy(world / "t.json", safe / "t.json")
    elsewhere = world / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    shutil.copy(world / "t.json", elsewhere / "t.json")
    add_outsider(elsewhere / "t.json", world)
    monkeypatch.setattr(trust_module, "resolve_directory", lambda _directory: (None, str(safe)))
    store = rf.TrustStore.from_json(elsewhere / "t.json", private_storage=True)
    assert "outsider" not in store.keys


def test_the_root_directory_is_checked(world, monkeypatch):
    """Simulated: a real root directory cannot be loosened here."""
    real_lstat = os.lstat

    def loose_root(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if str(path) == "/":
            fields = list(info)
            fields[stat.ST_MODE] = stat.S_IFDIR | 0o777
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(policy_module.os, "lstat", loose_root)
    assert "writable by group or others" in policy_module.directory_problem(str(world))


# ----------------------------------------------------------------------------- N4: a working directory that is gone


def test_a_deleted_working_directory_is_an_unusable_store_not_a_refused_report(world):
    code = (
        "import os, sys\n"
        "from regaudit_fhe.cli import main\n"
        "os.mkdir(sys.argv[1]); os.chdir(sys.argv[1]); os.rmdir(sys.argv[1])\n"
        "sys.exit(main(['verify', '-i', sys.argv[2], '--trusted-keys', 't.json', '--profile', 'confidential',\n"
        "    '--max-age-seconds', '3600', '--replay-mode', 'record', '--replay-db', sys.argv[3], '--verifier-id', 'reg']))\n"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code, str(world / "gone"), str(world / "trusted.json"), str(world / "r.db")],
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert out.returncode == 3 and "Traceback" not in out.stderr, out.stderr


# ----------------------------------------------------------------------------- N5: replay, the path as written


def test_a_replay_path_with_dotdot_checks_and_uses_the_real_directory(world):
    safe = _evil_layout(world)
    path = safe / "link" / ".." / "r2.db"
    cache = SqliteReplayCache(path)
    assert not cache.durable, "it lives in a directory others can write"
    assert (world / "evil" / "r2.db").exists() and not (safe / "r2.db").exists()


def test_a_replay_path_with_dotdot_in_a_safe_tree_is_durable(world):
    (world / "plain" / "sub").mkdir(parents=True)
    cache = SqliteReplayCache(world / "plain" / "sub" / ".." / "r.db", private_storage=True)
    assert cache.durable and (world / "plain" / "r.db").exists()


# ----------------------------------------------------------------------------- N6: other platforms keep working


def test_trust_add_does_not_stop_on_a_platform_that_cannot_be_checked(world, monkeypatch):
    monkeypatch.setattr(sys, "platform", "freebsd14")
    assert trust_module.store_file_problem(world / "t.json") is None
    assert "this platform cannot establish" in trust_module.store_storage_problem(world / "t.json")


def test_a_rewrite_is_not_stopped_on_a_platform_that_cannot_be_checked(world, monkeypatch):
    monkeypatch.setattr(sys, "platform", "freebsd14")
    assert trust_module.store_rewrite_problem(world / "t.json") is None


@pytest.mark.parametrize("command", ["retire", "revoke"])
def test_a_lifecycle_edit_refuses_a_directory_others_can_write(world, command):
    box = world / "box"
    box.mkdir()
    shutil.copy(world / "t.json", box / "t.json")
    before = (box / "t.json").read_bytes()
    os.chmod(box, 0o777)  # noqa: S103 - the point of the test
    out = cli("trust", command, "--store", "box/t.json", "--key-id", "issuer", cwd=world)
    assert out.returncode != 0 and "writable by group or others" in out.stdout + out.stderr
    assert (box / "t.json").read_bytes() == before


def test_a_lifecycle_refusal_does_not_repeat_itself(world):
    os.link(world / "t.json", world / "other.json")
    out = cli("trust", "retire", "--store", "t.json", "--key-id", "issuer", cwd=world)
    text = out.stdout + out.stderr
    assert text.count("nothing written") == 1, text


# ----------------------------------------------------------------------------- R1: replay migrate


def _legacy_replay(world: Path) -> Path:
    db = world / "legacy.db"
    published_file(db)
    os.chmod(db, 0o600)
    return db


def _migrate(world: Path):
    return cli("replay", "migrate", "--db", "legacy.db", "--previous-policy-unknown", cwd=world)


def test_replay_migrate_refuses_a_second_name(world):
    db = _legacy_replay(world)
    os.link(db, world / "other.db")
    before = db.read_bytes()
    out = _migrate(world)
    assert out.returncode != 0 and "more than one name" in out.stdout + out.stderr
    assert db.read_bytes() == before and db.stat().st_nlink == 2


@macos
def test_replay_migrate_refuses_an_acl(world):
    db = _legacy_replay(world)
    set_acl(db, "group:everyone allow write")
    before = db.read_bytes()
    out = _migrate(world)
    assert out.returncode != 0 and "ACL" in out.stdout + out.stderr
    assert db.read_bytes() == before


def test_replay_migrate_refuses_a_third_name_even_with_its_own_backup(world):
    db = _legacy_replay(world)
    os.link(db, world / "legacy.db.pre-migration")
    os.link(db, world / "other.db")
    out = _migrate(world)
    assert out.returncode != 0 and "more than one name" in out.stdout + out.stderr


@pytest.mark.parametrize("dir_mode", [0o777, 0o775, 0o1777], ids=oct)
def test_replay_migrate_refuses_a_directory_others_can_write(world, dir_mode):
    box = world / "box"
    box.mkdir()
    db = box / "legacy.db"
    published_file(db)
    os.chmod(db, 0o600)
    before = db.read_bytes()
    os.chmod(box, dir_mode)
    out = cli("replay", "migrate", "--db", "box/legacy.db", "--previous-policy-unknown", cwd=world)
    assert out.returncode != 0 and "writable by group or others" in out.stdout + out.stderr
    assert db.read_bytes() == before and sorted(p.name for p in box.iterdir()) == ["legacy.db"]


def test_replay_migrate_refuses_a_link_through_a_directory_others_can_write(world):
    real = world / "real"
    real.mkdir(mode=0o700)
    published_file(real / "legacy.db")
    os.chmod(real / "legacy.db", 0o600)
    shared = world / "shared"
    shared.mkdir()
    (shared / "link").symlink_to(real)
    os.chmod(shared, 0o777)  # noqa: S103 - the point of the test
    out = cli(
        "replay", "migrate", "--db", "shared/link/legacy.db", "--previous-policy-unknown", cwd=world
    )
    assert out.returncode != 0 and "shared" in out.stdout + out.stderr


def test_replay_migrate_of_a_safe_file_still_works(world):
    _legacy_replay(world)
    out = _migrate(world)
    assert out.returncode == 0, out.stdout + out.stderr


def test_a_relative_replay_path_with_a_deleted_working_directory_is_unusable(world):
    code = (
        "import os, sys\n"
        "from regaudit_fhe.cli import main\n"
        "os.mkdir(sys.argv[1]); os.chdir(sys.argv[1]); os.rmdir(sys.argv[1])\n"
        "sys.exit(main(['verify', '-i', sys.argv[2], '--trusted-keys', sys.argv[3], '--profile', 'confidential',\n"
        "    '--max-age-seconds', '3600', '--replay-mode', 'record', '--replay-db', 'r.db', '--verifier-id', 'reg']))\n"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code, str(world / "gone"), str(world / "trusted.json"), str(world / "t.json")],
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert out.returncode == 3 and "Traceback" not in out.stderr, out.stderr


@pytest.mark.parametrize("command", ["retire", "revoke"])
def test_a_lifecycle_edit_refuses_a_link_through_a_directory_others_can_write(world, command):
    path, real = _chain(world)
    shutil.copy(world / "t.json", real / "t.json")
    before = (real / "t.json").read_bytes()
    out = cli("trust", command, "--store", str(path / "t.json"), "--key-id", "issuer", cwd=world)
    assert out.returncode != 0 and "mid" in out.stdout + out.stderr
    assert (real / "t.json").read_bytes() == before


def test_a_lifecycle_edit_through_a_final_link_in_a_safe_directory_still_works(world):
    (world / "link.json").symlink_to(world / "t.json")
    out = cli("trust", "retire", "--store", "link.json", "--key-id", "issuer", cwd=world)
    assert out.returncode == 0 and (world / "link.json").is_symlink(), out.stdout + out.stderr


# ----------------------------------------------------------------------------- a chain of final links


def _link_chain(
    world: Path, name: str, *, through_a_directory_link: bool = False
) -> tuple[Path, Path]:
    """safe/link -> ../shared/... -> ../real/name. Neither the path as written nor the real path shows ``shared``."""
    safe, shared, real = world / "safe", world / "shared", world / "real"
    for directory in (safe, shared, real):
        directory.mkdir(mode=0o700)
    if through_a_directory_link:
        (shared / "hop").symlink_to("../real")
        (safe / "link").symlink_to(f"../shared/hop/{name}")
    else:
        (shared / "hop").symlink_to(f"../real/{name}")
        (safe / "link").symlink_to("../shared/hop")
    os.chmod(shared, 0o777)  # noqa: S103 - the point of the test
    return safe / "link", real / name


@pytest.mark.parametrize(
    "through_a_directory_link", [False, True], ids=["file-hop", "directory-hop"]
)
@pytest.mark.parametrize("command", ["retire", "revoke"])
def test_a_lifecycle_edit_refuses_a_chain_of_links_through_a_directory_others_can_write(
    world, command, through_a_directory_link
):
    link, store = _link_chain(world, "t.json", through_a_directory_link=through_a_directory_link)
    shutil.copy(world / "t.json", store)
    before = store.read_bytes()
    out = cli("trust", command, "--store", str(link), "--key-id", "issuer", cwd=world)
    assert out.returncode != 0 and "writable by group or others" in out.stdout + out.stderr
    assert store.read_bytes() == before and sorted(p.name for p in store.parent.iterdir()) == [
        "t.json"
    ]


def test_a_revocation_cannot_be_diverted_to_another_file_through_a_chain_of_links(world):
    """Whoever can write the hop's directory could send the revocation to an old copy and leave the key trusted."""
    link, store = _link_chain(world, "t.json")
    shutil.copy(world / "t.json", store)
    copy = store.with_name("t.json.prev")
    shutil.copy(store, copy)
    hop = world / "shared" / "hop"
    hop.unlink()
    hop.symlink_to("../real/t.json.prev")
    before = copy.read_bytes()
    out = cli("trust", "revoke", "--store", str(link), "--key-id", "issuer", cwd=world)
    assert out.returncode != 0 and "writable by group or others" in out.stdout + out.stderr
    assert copy.read_bytes() == before


def test_a_lifecycle_edit_through_a_chain_of_links_in_safe_directories_still_works(world):
    link, store = _link_chain(world, "t.json")
    os.chmod(world / "shared", 0o700)
    shutil.copy(world / "t.json", store)
    out = cli("trust", "retire", "--store", str(link), "--key-id", "issuer", cwd=world)
    assert out.returncode == 0, out.stdout + out.stderr
    assert link.is_symlink() and (world / "shared" / "hop").is_symlink() and not store.is_symlink()
    assert json.loads(store.read_text())["entries"]["issuer"]["status"] == "retired"


@pytest.mark.parametrize(
    "through_a_directory_link", [False, True], ids=["file-hop", "directory-hop"]
)
def test_replay_migrate_refuses_a_chain_of_links_through_a_directory_others_can_write(
    world, through_a_directory_link
):
    link, db = _link_chain(world, "legacy.db", through_a_directory_link=through_a_directory_link)
    published_file(db)
    os.chmod(db, 0o600)
    before = db.read_bytes()
    out = cli("replay", "migrate", "--db", str(link), "--previous-policy-unknown", cwd=world)
    assert out.returncode != 0 and "writable by group or others" in out.stdout + out.stderr
    assert db.read_bytes() == before and sorted(p.name for p in db.parent.iterdir()) == [
        "legacy.db"
    ]


def test_replay_migrate_refuses_a_file_in_a_directory_others_can_write_reached_from_a_safe_link(
    world,
):
    safe, unsafe = world / "safe", world / "unsafe"
    safe.mkdir(mode=0o700)
    unsafe.mkdir(mode=0o700)
    published_file(unsafe / "legacy.db")
    os.chmod(unsafe / "legacy.db", 0o600)
    (safe / "link").symlink_to("../unsafe/legacy.db")
    os.chmod(unsafe, 0o777)  # noqa: S103 - the point of the test
    before = (unsafe / "legacy.db").read_bytes()
    out = cli("replay", "migrate", "--db", "safe/link", "--previous-policy-unknown", cwd=world)
    assert out.returncode != 0 and "writable by group or others" in out.stdout + out.stderr
    assert (unsafe / "legacy.db").read_bytes() == before


def test_replay_migrate_through_a_chain_of_links_in_safe_directories_still_works(world):
    link, db = _link_chain(world, "legacy.db")
    os.chmod(world / "shared", 0o700)
    published_file(db)
    os.chmod(db, 0o600)
    out = cli("replay", "migrate", "--db", str(link), "--previous-policy-unknown", cwd=world)
    assert out.returncode == 0, out.stdout + out.stderr
    assert link.is_symlink() and db.with_name("legacy.db.pre-migration").exists()


def test_replay_migrate_keeps_a_mode_others_can_write_so_a_strict_profile_keeps_refusing(world):
    box = world / "box"
    box.mkdir(mode=0o700)
    db = box / "legacy.db"
    published_file(db)
    os.chmod(db, 0o666)  # noqa: S103 - the point of the test
    out = cli("replay", "migrate", "--db", "box/legacy.db", "--previous-policy-unknown", cwd=world)
    assert out.returncode == 0, out.stdout + out.stderr
    assert mode(db) == 0o666
    with pytest.raises(ReplayStorageUnsafe, match="group or others"):
        SqliteReplayCache(db, private_storage=True)


def test_a_final_link_owned_by_another_account_is_refused(world, monkeypatch):
    """Ownership is simulated, since a test run has one account."""
    (world / "link.json").symlink_to(world / "t.json")
    real_lstat = os.lstat

    def as_another_account(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if str(path).endswith("link.json"):
            fields = list(info)
            fields[stat.ST_UID] = os.geteuid() + 1
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(policy_module.os, "lstat", as_another_account)
    problem, _ = policy_module.resolve_file(str(world / "link.json"))
    assert "belongs to another account" in problem


def test_a_loop_of_final_links_is_refused(world):
    (world / "a").symlink_to("b")
    (world / "b").symlink_to("a")
    problem, _ = policy_module.resolve_file(str(world / "a"))
    assert "too many symbolic links" in problem


def test_resolve_file_ends_at_the_real_file_or_where_a_missing_one_would_be(world):
    (world / "link.json").symlink_to("t.json")
    assert policy_module.resolve_file(str(world / "link.json")) == (None, str(world / "t.json"))
    assert policy_module.resolve_file(str(world / "t.json")) == (None, str(world / "t.json"))
    assert policy_module.resolve_file(str(world / "missing")) == (None, str(world / "missing"))


# ----------------------------------------------------------------------------- which platform reads an ACL


def test_only_macos_reads_an_acl_and_it_decides(monkeypatch):
    monkeypatch.setattr(
        policy_module, "_macos_acl_problem", lambda what, fd, path: f"refused {what}"
    )
    monkeypatch.setattr(sys, "platform", "darwin")
    assert policy_module.acl_problem("the file", fd=1) == "refused the file"
    monkeypatch.setattr(sys, "platform", "linux")
    assert policy_module.acl_problem("the file", fd=1) is None


def test_a_failure_to_read_a_macos_acl_is_a_problem_through_the_public_check(monkeypatch):
    def unreadable(what, fd, path):
        return f"the ACL on {what} cannot be read reliably"

    monkeypatch.setattr(policy_module, "_macos_acl_problem", unreadable)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert "cannot be read" in policy_module.acl_problem("the file", path="/x")
