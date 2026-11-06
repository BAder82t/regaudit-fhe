"""Stopping the portal at any moment must be quiet and must leave nothing behind.

A stop request (SIGTERM, what a launcher sends when the application quits; SIGINT; or the launcher's standard input
closing) can arrive while the portal is still starting, a moment after it started, or while an upload is still coming
in. In every case the portal has to exit with status 0 and say that it stopped, with no traceback, no death by signal
and no private bytecode folder left in the temporary directory. A hard kill cannot be handled by any program and is not
covered here.
"""

import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

PORTAL = Path(__file__).resolve().parents[1]
STOPPED = "the portal has stopped."
FOLDER = "regaudit-portal-pyc-*"


def _default_signals() -> None:
    """The macOS launcher starts the portal with the default signal behaviour. A test run from a background job
    (nohup, a trailing &) would otherwise hand its own "ignore" on to the portal and test nothing."""
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(sig, signal.SIG_DFL)


def _env(tmp: Path, home: Path) -> dict:
    return {**os.environ, "HOME": str(home), "TMPDIR": str(tmp), "PYTHONPATH": str(PORTAL)}


def _start(extra, stdin=subprocess.PIPE, config=None):
    work = Path(tempfile.mkdtemp(prefix="portal-early-"))
    os.chmod(work, 0o700)
    home, tmp = work / "home", work / "tmp"
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    argv = [sys.executable, "-m", "regaudit_portal", "serve", "--port", "0", *extra]
    if config is not None:
        argv += ["--config", str(config)]
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        argv,
        env=_env(tmp, home),
        cwd=PORTAL,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=_default_signals,
    )
    return proc, tmp


def _wait_for_folder(tmp: Path, proc) -> None:
    """The private bytecode folder is made when the package is first imported, after the early stop handler is in."""
    end = time.time() + 30
    while time.time() < end:
        if list(tmp.glob(FOLDER)):
            return
        if proc.poll() is not None:
            break
        time.sleep(0.005)
    pytest.fail("the portal never made its private folder")


def _wait_listening(proc) -> str:
    end = time.time() + 60
    while time.time() < end:
        line = proc.stdout.readline()
        if line.startswith("portal-listening"):
            return line
        if proc.poll() is not None:
            break
    pytest.fail("the portal did not start")


def _assert_quiet_stop(proc, out: str, tmp: Path) -> None:
    assert proc.returncode == 0, f"exit {proc.returncode}: {out[-500:]}"
    assert "Traceback" not in out and "Fatal Python error" not in out, out[-500:]
    assert STOPPED in out, out[-500:]
    assert list(tmp.glob(FOLDER)) == [], "the private bytecode folder must be removed"


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
@pytest.mark.parametrize("extra", [[], ["--exit-when-input-closes"]])
@pytest.mark.parametrize("wait", [0.0, 0.2, 0.6, 1.2])
def test_a_stop_while_the_portal_is_starting_is_quiet(sig, extra, wait):
    proc, tmp = _start(extra)
    try:
        _wait_for_folder(tmp, proc)
        time.sleep(wait)
        proc.send_signal(sig)
        out = proc.communicate(timeout=30)[0]
    finally:
        if proc.poll() is None:
            proc.kill()
    _assert_quiet_stop(proc, out, tmp)


@pytest.mark.parametrize("wait", [0.0, 0.2, 0.6, 1.2])
def test_the_launchers_input_closing_while_the_portal_is_starting_is_quiet(wait):
    proc, tmp = _start(["--exit-when-input-closes"])
    try:
        _wait_for_folder(tmp, proc)
        time.sleep(wait)
        proc.stdin.close()  # what the kernel does when a launcher dies, even by SIGKILL
        proc.stdin = None
        out = proc.communicate(timeout=30)[0]
    finally:
        if proc.poll() is None:
            proc.kill()
    _assert_quiet_stop(proc, out, tmp)


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
@pytest.mark.parametrize("extra", [[], ["--exit-when-input-closes"]])
def test_a_stop_right_after_the_portal_started_is_quiet(sig, extra):
    proc, tmp = _start(extra)
    try:
        _wait_listening(proc)
        proc.send_signal(sig)
        out = proc.communicate(timeout=30)[0]
    finally:
        if proc.poll() is None:
            proc.kill()
    _assert_quiet_stop(proc, out, tmp)


@pytest.mark.parametrize("sig", ["SIGTERM", "SIGINT"])
def test_the_earliest_stop_handler_removes_the_folder_and_leaves_quietly(sig, tmp_path):
    """A stop that lands as soon as the package has made its folder, before the portal sets up anything of its own.

    The program is started as ``python -m`` does (the first argument is ``-m`` while the package is imported), the
    package is imported, and the process signals itself. Nothing else of the portal has run.
    """
    home, tmp = tmp_path / "home", tmp_path / "tmp"
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    code = (
        "import sys; sys.argv[:] = ['-m', 'serve']\n"
        "import regaudit_portal, os, signal, time\n"
        f"os.kill(os.getpid(), signal.{sig})\n"
        "time.sleep(20)\n"
        "print('NOT STOPPED')\n"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-B", "-c", code],
        env=_env(tmp, home),
        cwd=PORTAL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        preexec_fn=_default_signals,
    )
    out = done.stdout + done.stderr
    assert done.returncode == 0, f"exit {done.returncode}: {out[-400:]}"
    assert "NOT STOPPED" not in out and "Traceback" not in out, out[-400:]
    assert STOPPED in out
    assert list(tmp.glob(FOLDER)) == []


def test_importing_the_package_as_a_library_does_not_take_over_the_signals():
    """Only the program itself installs the early handler: a test runner or another program importing it keeps its own."""
    code = (
        "import signal\n"
        "before = (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))\n"
        "import regaudit_portal\n"
        "after = (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))\n"
        "print('UNCHANGED' if before == after else 'CHANGED')\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-B", "-c", code],
            env={**os.environ, "TMPDIR": tmp, "PYTHONPATH": str(PORTAL)},
            cwd=PORTAL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    assert done.stdout.strip() == "UNCHANGED", done.stdout + done.stderr


def test_a_stop_during_a_slow_upload_does_not_outlast_the_launchers_wait(demo):
    """The macOS launcher waits six seconds after SIGTERM and then kills. A slow upload must not make it get there."""
    proc, tmp = _start(["--exit-when-input-closes"], config=demo / "portal-config.json")
    sock = None
    try:
        line = _wait_listening(proc)
        port = int(line.split("127.0.0.1:")[1].split("/")[0].split()[0])
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        head = (
            "POST /api/verify HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {1 << 20}\r\n\r\n"
        )
        sock.sendall(head.encode() + b'{"report": ')  # the rest never comes
        time.sleep(1.0)
        started = time.time()
        proc.send_signal(signal.SIGTERM)
        out = proc.communicate(timeout=20)[0]
        waited = time.time() - started
    finally:
        if sock is not None:
            sock.close()
        if proc.poll() is None:
            proc.kill()
    _assert_quiet_stop(proc, out, tmp)
    assert waited < 5.0, f"stopping took {waited:.1f} s; the launcher gives up at 6 s"


def test_a_stop_while_only_part_of_the_request_headers_arrived_is_quiet():
    proc, tmp = _start(["--exit-when-input-closes"])
    sock = None
    try:
        line = _wait_listening(proc)
        port = int(line.split("127.0.0.1:")[1].split("/")[0].split()[0])
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        sock.sendall(b"POST /api/verify HTTP/1.1\r\nHost: 127.0.0")
        time.sleep(0.5)
        proc.send_signal(signal.SIGTERM)
        out = proc.communicate(timeout=20)[0]
    finally:
        if sock is not None:
            sock.close()
        if proc.poll() is None:
            proc.kill()
    _assert_quiet_stop(proc, out, tmp)


@pytest.mark.parametrize("first", [signal.SIGTERM, signal.SIGINT])
def test_a_second_stop_request_while_the_portal_is_stopping_changes_nothing(first):
    """A signal and then the launcher's input closing, back to back. The second must not interrupt the clean-up."""
    for _ in range(6):
        proc, tmp = _start(["--exit-when-input-closes"])
        try:
            _wait_listening(proc)
            proc.send_signal(first)
            proc.stdin.close()
            proc.stdin = None
            out = proc.communicate(timeout=30)[0]
        finally:
            if proc.poll() is None:
                proc.kill()
        _assert_quiet_stop(proc, out, tmp)


def test_importing_the_package_keeps_a_stop_request_that_was_being_held():
    """A command that holds a stop request while its libraries load must still be holding it after the import."""
    code = (
        "import signal\n"
        "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})\n"
        "import regaudit_portal\n"
        "held = signal.pthread_sigmask(signal.SIG_BLOCK, set())\n"
        "print('HELD' if signal.SIGTERM in held else 'RELEASED')\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-B", "-c", code],
            env={**os.environ, "TMPDIR": tmp, "PYTHONPATH": str(PORTAL)},
            cwd=PORTAL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    assert done.stdout.strip() == "HELD", done.stdout + done.stderr


@pytest.mark.parametrize("command", ["admin-apply", "admin-describe", "check-config", "demo-setup"])
def test_the_earliest_stop_of_another_command_says_nothing_changed_and_is_not_success(
    command, tmp_path
):
    """Before such a command has done anything, a stop ends it with status 1, never 0: a script must not take it for success."""
    home, tmp = tmp_path / "home", tmp_path / "tmp"
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    code = (
        f"import sys; sys.argv[:] = ['-m', {command!r}, 'x']\n"
        "import regaudit_portal, os, signal, time\n"
        "os.kill(os.getpid(), signal.SIGTERM)\n"
        "time.sleep(20)\n"
        "print('NOT STOPPED')\n"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-B", "-c", code],
        env=_env(tmp, home),
        cwd=PORTAL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    out = done.stdout + done.stderr
    assert done.returncode == 1, f"exit {done.returncode}: {out[-300:]}"
    assert "stopped: Nothing was changed." in out and "NOT STOPPED" not in out
    assert list(tmp.glob(FOLDER)) == []


_SCRIPT = "import sys\nfrom regaudit_portal.__main__ import main\nsys.exit(main())\n"


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
@pytest.mark.parametrize("wait", [0.0, 0.4, 1.0])
def test_the_console_script_is_covered_as_well(sig, wait, tmp_path):
    """README tells people to run ``regaudit-portal serve``: a script, not ``python -m``. The argument list then starts
    with the script's path, and the early handler must be in place there too."""
    work = tmp_path / "w"
    home, tmp, bin_dir = work / "home", work / "tmp", work / "bin"
    for folder in (home, tmp, bin_dir):
        folder.mkdir(parents=True, mode=0o700)
    script = bin_dir / "regaudit-portal"
    script.write_text(_SCRIPT)
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(script), "serve", "--port", "0"],
        env=_env(tmp, home),
        cwd=PORTAL,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=_default_signals,
    )
    try:
        _wait_for_folder(tmp, proc)
        time.sleep(wait)
        proc.send_signal(sig)
        out = proc.communicate(timeout=30)[0]
    finally:
        if proc.poll() is None:
            proc.kill()
    _assert_quiet_stop(proc, out, tmp)


def test_a_stop_that_something_swallows_still_ends_the_portal(tmp_path):
    """A library can catch the interrupt that a stop raises (pydantic turned it into a SchemaError, and the portal
    carried on). The portal must end anyway, by its own deadline."""
    home, tmp = tmp_path / "home", tmp_path / "tmp"
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    code = (
        "import sys; sys.argv[:] = ['-m', 'serve']\n"
        "import regaudit_portal\n"
        "from regaudit_portal import __main__ as entry\n"
        "entry.STOP_DEADLINE_SECONDS = 1.0\n"
        "entry._hand_over_from_the_early_stop(True)\n"
        "import os, signal, time\n"
        "sent = False\n"
        "while True:\n"
        "    try:\n"
        "        if not sent:\n"
        "            sent = True\n"
        "            os.kill(os.getpid(), signal.SIGTERM)\n"
        "        time.sleep(0.1)\n"
        "    except KeyboardInterrupt:\n"
        "        pass  # whatever swallowed the stop\n"
    )
    started = time.time()
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-B", "-c", code],
        env=_env(tmp, home),
        cwd=PORTAL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        preexec_fn=_default_signals,
    )
    out = done.stdout + done.stderr
    assert done.returncode == 0, f"exit {done.returncode}: {out[-400:]}"
    assert STOPPED in out and "Traceback" not in out, out[-400:]
    assert time.time() - started < 10
    assert list(tmp.glob(FOLDER)) == []


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
@pytest.mark.parametrize("wait", [0.0, 0.3])
def test_demo_setup_stopped_early_leaves_nothing_and_is_not_success(sig, wait, tmp_path):
    work = tmp_path / "w"
    home, tmp = work / "home", work / "tmp"
    for folder in (home, tmp):
        folder.mkdir(parents=True, mode=0o700)
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_portal", "demo-setup", str(work / "demo")],
        env=_env(tmp, home),
        cwd=PORTAL,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=_default_signals,
    )
    try:
        _wait_for_folder(tmp, proc)
        time.sleep(wait)
        proc.send_signal(sig)
        out = proc.communicate(timeout=30)[0]
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode == 1, f"exit {proc.returncode}: {out[-400:]}"
    assert "Traceback" not in out and STOPPED not in out, out[-400:]
    assert "stopped" in out
    assert list(tmp.glob(FOLDER)) == []
