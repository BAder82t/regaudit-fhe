"""A launcher can make the portal stop when the launcher goes away, even if the launcher is killed."""

import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

PORTAL = Path(__file__).resolve().parents[1]


def _start(extra, stdin):
    work = Path(tempfile.mkdtemp(prefix="portal-pipe-"))
    os.chmod(work, 0o700)
    home, tmp = work / "home", work / "tmp"
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    env = {**os.environ, "HOME": str(home), "TMPDIR": str(tmp), "PYTHONPATH": str(PORTAL)}
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_portal", "serve", "--port", "0", *extra],
        env=env,
        cwd=PORTAL,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc, tmp


def _wait_listening(proc):
    end = time.time() + 60
    while time.time() < end:
        line = proc.stdout.readline()
        if line.startswith("portal-listening"):
            return line
        if proc.poll() is not None:
            break
    raise AssertionError("the portal did not start")


def test_closing_standard_input_stops_the_portal_cleanly():
    proc, tmp = _start(["--exit-when-input-closes"], subprocess.PIPE)
    try:
        _wait_listening(proc)
        assert len(list(tmp.glob("regaudit-portal-pyc-*"))) == 1
        proc.stdin.close()  # what the kernel does when a launcher dies, even by SIGKILL
        proc.stdin = None
        out = proc.communicate(timeout=30)[0]
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode == 0, out
    assert "the portal has stopped." in out
    assert list(tmp.glob("regaudit-portal-pyc-*")) == [], (
        "the private bytecode folder must be removed"
    )


def test_without_the_option_an_open_or_closed_input_changes_nothing():
    proc, _tmp = _start([], subprocess.PIPE)
    try:
        _wait_listening(proc)
        proc.stdin.close()
        proc.stdin = None
        time.sleep(2)
        assert proc.poll() is None, "the portal must keep running when the option is not given"
    finally:
        proc.terminate()
        proc.communicate(timeout=30)


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_a_signal_while_the_portal_watches_its_input_is_a_clean_stop(sig):
    """The watcher must not leave the interpreter aborting when it shuts down with the watcher still waiting."""
    proc, tmp = _start(
        ["--exit-when-input-closes"], subprocess.PIPE
    )  # the pipe stays open, as a live launcher's does
    try:
        _wait_listening(proc)
        proc.send_signal(sig)
        out = proc.communicate(timeout=30)[0]
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode == 0, f"exit {proc.returncode}: {out[-400:]}"
    assert "Fatal Python error" not in out and "Traceback" not in out, out[-400:]
    assert "the portal has stopped." in out
    assert list(tmp.glob("regaudit-portal-pyc-*")) == []


def test_the_watcher_reads_the_descriptor_and_never_the_buffered_standard_input():
    """Waiting inside sys.stdin's buffered reader makes Python abort at shutdown, intermittently. Check it by construction."""
    import inspect

    from regaudit_portal import __main__ as entry

    source = inspect.getsource(entry._stop_when_input_closes)
    code = "\n".join(line for line in source.splitlines() if not line.strip().startswith("#"))
    assert "os.read(0" in code
    assert "sys.stdin" not in code and ".buffer" not in code
