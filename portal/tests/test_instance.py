"""F-022: one running portal for each account and configuration folder.

The lock is an operating-system lock (flock), so these tests use real processes: two starts at the same moment, a holder killed
with SIGKILL, a second ``serve`` that must be refused without touching the first, and separate configuration folders that must
still run side by side. The folder and the lock file must be private, ours, and not links.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.request
from pathlib import Path

import pytest
from regaudit_portal import instance

PORTAL = Path(__file__).resolve().parents[1]


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    place = tmp_path / "locks"
    place.mkdir(mode=0o700)
    return place


# ----------------------------------------------------------------------------- the lock itself, in one process


def test_a_second_take_of_the_same_folder_is_refused_and_names_the_holder(folder, tmp_path):
    first = instance.acquire(tmp_path / "config", folder=folder)
    first.publish("http://127.0.0.1:4242/")
    with pytest.raises(instance.AlreadyRunning) as refused:
        instance.acquire(tmp_path / "config", folder=folder)
    assert refused.value.pid == os.getpid() and refused.value.url == "http://127.0.0.1:4242/"
    text = str(refused.value)
    assert "already running" in text and "Nothing was stopped" in text
    first.close()


def test_closing_the_lock_lets_the_next_start_take_it(folder, tmp_path):
    instance.acquire(tmp_path / "config", folder=folder).close()
    instance.acquire(tmp_path / "config", folder=folder).close()


def test_other_configuration_folders_run_side_by_side(folder, tmp_path):
    held = [instance.acquire(tmp_path / f"config-{n}", folder=folder) for n in range(5)]
    for lock in held:
        lock.close()


def test_the_same_folder_by_any_spelling_is_one_instance(folder, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real, target_is_directory=True)
    held = instance.acquire(real, folder=folder)
    for spelling in (str(real) + "/", tmp_path / "link", tmp_path / "real" / "."):
        with pytest.raises(instance.AlreadyRunning):
            instance.acquire(spelling, folder=folder)
    held.close()


def test_a_start_waits_for_a_portal_that_is_being_replaced(folder, tmp_path):
    held = instance.acquire(tmp_path / "config", folder=folder)
    threading.Timer(0.4, held.close).start()
    started = time.monotonic()
    again = instance.acquire(tmp_path / "config", folder=folder, wait=5)
    assert 0.3 < time.monotonic() - started < 4
    again.close()


def test_a_start_that_does_not_wait_does_not_wait(folder, tmp_path):
    held = instance.acquire(tmp_path / "config", folder=folder)
    started = time.monotonic()
    with pytest.raises(instance.AlreadyRunning):
        instance.acquire(tmp_path / "config", folder=folder)
    assert time.monotonic() - started < 1
    held.close()


# ----------------------------------------------------------------------------- the place for the lock must be safe


def test_the_folder_and_lock_file_are_made_private(tmp_path):
    place = tmp_path / "made-here"
    lock = instance.acquire(tmp_path / "config", folder=place)
    assert stat.S_IMODE(place.stat().st_mode) == 0o700
    (file,) = list(place.iterdir())
    assert stat.S_IMODE(file.stat().st_mode) == 0o600 and file.name.endswith(".lock")
    lock.close()


def test_a_folder_others_can_use_is_refused(tmp_path):
    place = tmp_path / "open"
    place.mkdir()
    os.chmod(place, 0o755)  # noqa: S103
    with pytest.raises(instance.InstanceProblem, match="group or others"):
        instance.acquire(tmp_path / "config", folder=place)


def test_a_link_in_place_of_the_folder_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(instance.InstanceProblem, match="link"):
        instance.acquire(tmp_path / "config", folder=link)
    assert list(real.iterdir()) == []


def test_a_link_in_place_of_the_lock_file_is_refused_and_the_target_is_untouched(folder, tmp_path):
    target = tmp_path / "victim"
    target.write_text("keep me")
    (folder / (instance.root_key(tmp_path / "config") + ".lock")).symlink_to(target)
    with pytest.raises(instance.InstanceProblem, match="link"):
        instance.acquire(tmp_path / "config", folder=folder)
    assert target.read_text() == "keep me"


def test_a_lock_file_with_another_hard_link_is_refused(folder, tmp_path):
    name = folder / (instance.root_key(tmp_path / "config") + ".lock")
    name.write_text("")
    os.chmod(name, 0o600)
    os.link(name, tmp_path / "second-name")
    with pytest.raises(instance.InstanceProblem, match="private regular file"):
        instance.acquire(tmp_path / "config", folder=folder)


def test_a_lock_file_others_can_read_is_refused(folder, tmp_path):
    name = folder / (instance.root_key(tmp_path / "config") + ".lock")
    name.write_text("")
    os.chmod(name, 0o644)
    with pytest.raises(instance.InstanceProblem, match="private regular file"):
        instance.acquire(tmp_path / "config", folder=folder)


def test_a_folder_that_belongs_to_another_account_is_refused(folder, tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(instance.InstanceProblem, match="another account"):
        instance.acquire(tmp_path / "config", folder=folder)


def test_a_hostile_holder_note_cannot_put_anything_but_a_local_address_in_a_message(
    folder, tmp_path
):
    lock = instance.acquire(tmp_path / "config", folder=folder)
    name = folder / (instance.root_key(tmp_path / "config") + ".lock")
    name.write_text(json.dumps({"pid": True, "url": "https://evil.example/\nrun this"}))
    with pytest.raises(instance.AlreadyRunning) as refused:
        instance.acquire(tmp_path / "config", folder=folder)
    assert refused.value.pid is None and refused.value.url is None
    assert "evil" not in str(refused.value)
    lock.close()


# ----------------------------------------------------------------------------- real processes

_HOLDER = textwrap.dedent(
    """
    import os, sys, time
    sys.path.insert(0, {portal!r})
    from regaudit_portal import instance
    start_at = float(sys.argv[3])
    while time.time() < start_at:
        time.sleep(0.001)
    try:
        lock = instance.acquire(sys.argv[1], folder=__import__("pathlib").Path(sys.argv[2]))
    except instance.AlreadyRunning:
        print("NO", flush=True)
        sys.exit(0)
    print("YES", flush=True)
    time.sleep(float(sys.argv[4]))
    """
).format(portal=str(PORTAL))


def _holder(root: Path, folder: Path, start_at: float, hold: float) -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", _HOLDER, str(root), str(folder), str(start_at), str(hold)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def test_many_starts_at_the_same_moment_give_exactly_one_winner(folder, tmp_path):
    start_at = time.time() + 2.0
    children = [_holder(tmp_path / "config", folder, start_at, 3.0) for _ in range(10)]
    answers = [c.communicate(timeout=60)[0].strip() for c in children]
    assert sorted(answers) == ["NO"] * 9 + ["YES"], answers


def test_a_holder_killed_with_sigkill_does_not_block_the_next_start(folder, tmp_path):
    child = _holder(tmp_path / "config", folder, 0.0, 60.0)
    assert child.stdout.readline().strip() == "YES"
    with pytest.raises(instance.AlreadyRunning):
        instance.acquire(tmp_path / "config", folder=folder)
    child.send_signal(signal.SIGKILL)
    child.wait(timeout=30)
    instance.acquire(
        tmp_path / "config", folder=folder
    ).close()  # no stale file, no waiting, no manual cleanup


def test_the_lock_is_not_inherited_by_a_child_process(folder, tmp_path):
    lock = instance.acquire(tmp_path / "config", folder=folder)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        lock.close()
        instance.acquire(
            tmp_path / "config", folder=folder
        ).close()  # the child does not keep it held
    finally:
        child.kill()
        child.wait()


# ----------------------------------------------------------------------------- the portal command


def _env(home: Path, tmp: Path | None = None, **more: str) -> dict[str, str]:
    env = {**os.environ, "HOME": str(home), "PYTHONPATH": str(PORTAL)}
    for key in ("XDG_RUNTIME_DIR",):
        env.pop(key, None)
    if tmp is not None:
        env["TMPDIR"] = str(tmp)
    env.update(more)
    return env


def _account() -> tuple[Path, Path, Path]:
    work = Path(tempfile.mkdtemp(prefix="portal-instance-")).resolve()
    os.chmod(work, 0o700)
    home, tmp = work / "home", work / "tmp"
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    return work, home, tmp


def _serve(home: Path, tmp: Path, *extra: str, **env: str) -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "regaudit_portal", "serve", "--port", "0", *extra],
        env=_env(home, tmp, **env),
        cwd=PORTAL,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def _url(proc: subprocess.Popen[str]) -> str:
    end = time.time() + 60
    while time.time() < end:
        line = proc.stdout.readline()
        if line.startswith("portal-listening"):
            return line.split("url=")[1].split()[0]
        if proc.poll() is not None:
            break
    raise AssertionError("the portal did not start")


def _answers(url: str) -> bool:
    try:
        with urllib.request.urlopen(url + "api/status", timeout=10) as reply:  # noqa: S310
            return reply.status == 200
    except OSError:
        return False


def _stop(proc: subprocess.Popen[str]) -> str:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
    try:
        return proc.communicate(timeout=30)[0]
    finally:
        if proc.poll() is None:
            proc.kill()


@pytest.fixture
def account():
    work, home, tmp = _account()
    running: list[subprocess.Popen[str]] = []
    yield home, tmp, running
    for proc in running:
        _stop(proc)
    shutil.rmtree(work, ignore_errors=True)


def test_a_second_serve_is_refused_with_a_clear_status_and_leaves_the_first_alone(account):
    home, tmp, running = account
    first = _serve(home, tmp)
    running.append(first)
    url = _url(first)
    second = _serve(home, tmp)
    out = second.communicate(timeout=60)[0]
    assert second.returncode == instance.ALREADY_RUNNING_STATUS == 75, out
    assert "already running" in out and url in out and "Nothing was stopped" in out
    assert first.poll() is None and _answers(url), (
        "the first portal must be left running and answering"
    )


def test_a_second_serve_for_the_same_configuration_file_is_refused(account):
    home, tmp, running = account
    work = home.parent
    demo = work / "demo"
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "regaudit_portal", "demo-setup", str(demo)],
        env=_env(home, tmp),
        cwd=PORTAL,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    config = str(demo / "portal-config.json")
    first = _serve(home, tmp, "--config", config)
    running.append(first)
    _url(first)
    second = _serve(home, tmp, "--config", config)
    out = second.communicate(timeout=60)[0]
    assert second.returncode == 75 and "already running" in out, out
    # and a different configuration folder, same account, runs alongside
    other = work / "other"
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "regaudit_portal", "demo-setup", str(other)],
        env=_env(home, tmp),
        cwd=PORTAL,
        capture_output=True,
        timeout=120,
        check=True,
    )
    third = _serve(home, tmp, "--config", str(other / "portal-config.json"))
    running.append(third)
    assert _answers(_url(third))


def test_separate_accounts_or_test_instances_run_in_parallel(account):
    home, tmp, running = account
    work2, home2, tmp2 = _account()
    try:
        a = _serve(home, tmp)
        b = _serve(home2, tmp2)
        running += [a, b]
        assert _answers(_url(a)) and _answers(_url(b))
    finally:
        shutil.rmtree(work2, ignore_errors=True)


def test_the_commands_that_do_not_serve_still_work_while_a_portal_runs(account):
    home, tmp, running = account
    first = _serve(home, tmp)
    running.append(first)
    _url(first)
    check = subprocess.run(
        [sys.executable, "-m", "regaudit_portal", "check-config"],
        env=_env(home, tmp),
        cwd=PORTAL,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert check.returncode == 3 and "already running" not in check.stderr, check.stderr
    made = home.parent / "demo"
    demo = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "regaudit_portal", "demo-setup", str(made)],
        env=_env(home, tmp),
        cwd=PORTAL,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert demo.returncode == 0 and (made / "portal-config.json").exists(), demo.stderr
    plan = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "regaudit_portal",
            "admin-describe",
            "--",
            str(made / "nothing.json"),
        ],
        env=_env(home, tmp),
        cwd=PORTAL,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert plan.returncode != 75, plan.stderr


def test_killing_the_portal_with_sigkill_lets_the_next_serve_start(account):
    home, tmp, running = account
    first = _serve(home, tmp)
    _url(first)
    first.send_signal(signal.SIGKILL)
    first.wait(timeout=30)
    second = _serve(home, tmp)
    running.append(second)
    assert _answers(_url(second))


def test_a_restart_waits_for_the_old_portal_to_release_its_lock(account):
    home, tmp, running = account
    first = _serve(home, tmp)
    _url(first)
    threading.Timer(1.0, lambda: first.send_signal(signal.SIGTERM)).start()
    second = _serve(home, tmp, "--wait-for-instance", "20")
    running.append(second)
    assert _answers(_url(second))
    first.communicate(timeout=30)


def test_changing_tmpdir_does_not_get_round_the_lock(account):
    """No environment variable moves the lock folder: a second start from a shell with another TMPDIR is still refused."""
    home, tmp, running = account
    first = _serve(home, tmp)
    running.append(first)
    _url(first)
    elsewhere = home.parent / "other-tmp"
    elsewhere.mkdir(mode=0o700)
    second = _serve(home, elsewhere)
    out = second.communicate(timeout=60)[0]
    assert second.returncode == 75 and "already running" in out, out


def test_a_start_where_the_lock_cannot_be_made_safe_refuses_to_run(monkeypatch, capsys):
    from regaudit_portal import __main__ as entry

    def unsafe(*_a, **_k):
        raise instance.InstanceProblem("/x can be used by group or others")

    monkeypatch.setattr(instance, "acquire", unsafe)
    args = entry.argparse.Namespace(config=None, wait_for_instance=0.0)
    assert entry._take_instance(args) == 1
    assert "does not run without its instance lock" in capsys.readouterr().err


def test_the_lock_folder_is_not_moved_by_any_environment_variable(monkeypatch, tmp_path):
    before = instance.instance_folder()
    for name in ("TMPDIR", "TMP", "TEMP", "XDG_RUNTIME_DIR", "HOME"):
        monkeypatch.setenv(name, str(tmp_path / name))
    assert instance.instance_folder() == before
