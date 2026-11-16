"""F-022 in the macOS launcher: a second launcher for the same account and configuration folder says so and quits, and leaves the
running one alone. The source checks run everywhere; the native runs need swiftc on macOS and start the real compiled launcher,
directly (not through Launch Services), with a throw-away account folder each.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest

PORTAL = Path(__file__).resolve().parents[1]
SWIFT = PORTAL / "installer" / "macos" / "launcher" / "main.swift"
NATIVE = pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("swiftc") is None, reason="needs swiftc on macOS"
)


def test_the_launcher_reports_status_75_as_already_running_and_never_stops_the_running_one():
    source = SWIFT.read_text()
    assert "let alreadyRunningStatus: Int32 = 75" in source
    assert "if status == alreadyRunningStatus { return alreadyRunning(detail) }" in source
    body = source[source.index("func alreadyRunning(") : source.index("func fail(")]
    # it shows what is running and quits itself; it signals no other process and starts no portal
    for forbidden in ("terminate()", "kill(", "SIGKILL", "SIGTERM", "startPortal", "Process("):
        assert forbidden not in body.replace("NSApp.terminate(nil)", ""), forbidden
    assert "NSWorkspace.shared.open(target)" in body and "exit(alreadyRunningStatus)" in body


def test_a_restart_after_administrator_setup_waits_for_the_old_portal_to_release_its_lock():
    source = SWIFT.read_text()
    assert "func startPortal(replacing: Bool = false)" in source
    assert '(replacing ? ["--wait-for-instance", "8"] : [])' in source
    assert source.count("self.startPortal(replacing: true)") == 1
    assert source.count("startPortal()") >= 1  # the first start does not wait


def _launcher_bundle(root: Path) -> Path:
    """A bundle laid out like the real one: the compiled launcher, and a ``python3`` that runs this checkout's portal."""
    app = root / "Evidence Verification Portal.app" / "Contents"
    (app / "MacOS").mkdir(parents=True)
    python = app / "Resources" / "python" / "bin"
    python.mkdir(parents=True)
    wrapper = python / "python3"
    # The launcher starts `python3 -I -B -m regaudit_portal ...`; -I would ignore PYTHONPATH, so it is dropped here.
    wrapper.write_text(f'#!/bin/sh\nshift\nPYTHONPATH={PORTAL} exec {sys.executable} -B "$@"\n')
    wrapper.chmod(stat.S_IRWXU)
    # What Launch Services needs to start the bundle as an application.
    (app / "Info.plist").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>'
        "<key>CFBundleExecutable</key><string>launcher</string>"
        f"<key>CFBundleIdentifier</key><string>test.regaudit.portal.launcher.{os.getpid()}</string>"
        "<key>CFBundleName</key><string>Evidence Verification Portal (test)</string>"
        "<key>CFBundlePackageType</key><string>APPL</string>"
        "<key>LSMinimumSystemVersion</key><string>14.0</string>"
        "</dict></plist>\n"
    )
    done = subprocess.run(  # noqa: S603 - the Swift compiler
        [shutil.which("swiftc") or "swiftc", "-swift-version", "5", "-target", "arm64-apple-macos14", str(SWIFT), "-o", str(app / "MacOS" / "launcher")],
        capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-3000:]
    return app / "MacOS" / "launcher"


@pytest.fixture(scope="module")
def launcher(tmp_path_factory):
    return _launcher_bundle(tmp_path_factory.mktemp("bundle"))


def _account():
    work = Path(tempfile.mkdtemp(prefix="portal-launch-")).resolve()
    os.chmod(work, 0o700)
    home, tmp = work / "home", work / "tmp"
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    return work, home, tmp


def _start(launcher: Path, home: Path, tmp: Path, *extra: str) -> subprocess.Popen[str]:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp), "LANG": "en_US.UTF-8"}
    return subprocess.Popen(  # noqa: S603 - the compiled launcher, fixed argv
        [str(launcher), "--no-browser", "--print-url", *extra],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _url(proc: subprocess.Popen[str], seconds: float = 90) -> str:
    end = time.time() + seconds
    while time.time() < end:
        line = proc.stdout.readline()
        if line.startswith("PORTAL_URL="):
            return line.strip().split("=", 1)[1]
        if proc.poll() is not None:
            break
    raise AssertionError(
        "the launcher did not print a portal address: "
        + (proc.stderr.read() if proc.poll() is not None else "")
    )


def _answers(url: str) -> bool:
    try:
        with urllib.request.urlopen(url + "api/status", timeout=10) as reply:  # noqa: S310 - 127.0.0.1 only
            return reply.status == 200
    except OSError:
        return False


def _quit(*procs: subprocess.Popen[str]) -> None:
    for proc in procs:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
    for proc in procs:
        try:
            proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()


@NATIVE
def test_a_second_launcher_says_so_and_leaves_the_first_running(launcher):
    work, home, tmp = _account()
    first = second = None
    try:
        first = _start(launcher, home, tmp)
        url = _url(first)
        second = _start(launcher, home, tmp)
        out, err = second.communicate(timeout=90)
        assert second.returncode == 75, (out, err)
        assert f"LAUNCHER_ERROR=ALREADY_RUNNING {url}" in err, err
        assert first.poll() is None and _answers(url), "the running portal must not be touched"
    finally:
        _quit(*[p for p in (first, second) if p is not None])
        shutil.rmtree(work, ignore_errors=True)


@NATIVE
def test_two_launchers_started_at_the_same_moment_give_one_portal(launcher):
    work, home, tmp = _account()
    procs = [_start(launcher, home, tmp) for _ in range(4)]
    try:
        end = time.time() + 120
        while time.time() < end and sum(p.poll() is not None for p in procs) < 3:
            time.sleep(0.2)
        finished = [p for p in procs if p.poll() is not None]
        running = [p for p in procs if p.poll() is None]
        assert len(running) == 1 and all(p.returncode == 75 for p in finished), [
            p.returncode for p in procs
        ]
        assert _answers(_url(running[0]))
    finally:
        _quit(*procs)
        shutil.rmtree(work, ignore_errors=True)


@NATIVE
def test_a_launcher_killed_with_sigkill_does_not_block_the_next_one(launcher):
    work, home, tmp = _account()
    first = third = None
    try:
        first = _start(launcher, home, tmp)
        url = _url(first)
        first.send_signal(signal.SIGKILL)
        first.communicate(timeout=30)
        # the portal notices that its launcher is gone and stops; the next launcher may need a moment for that
        end = time.time() + 60
        while time.time() < end:
            third = _start(launcher, home, tmp)
            try:
                new = _url(third, seconds=30)
                break
            except AssertionError:
                third = None
                time.sleep(0.5)
        assert third is not None and _answers(new) and new != url
    finally:
        _quit(*[p for p in (first, third) if p is not None])
        shutil.rmtree(work, ignore_errors=True)


@NATIVE
def test_separate_accounts_run_their_own_launchers_in_parallel(launcher):
    first_work, first_home, first_tmp = _account()
    second_work, second_home, second_tmp = _account()
    a = b = None
    try:
        a = _start(launcher, first_home, first_tmp)
        b = _start(launcher, second_home, second_tmp)
        assert _answers(_url(a)) and _answers(_url(b))
    finally:
        _quit(*[p for p in (a, b) if p is not None])
        shutil.rmtree(first_work, ignore_errors=True)
        shutil.rmtree(second_work, ignore_errors=True)


@NATIVE
def test_two_configuration_folders_of_one_account_run_side_by_side_and_each_excludes_its_own_second_start(
    launcher,
):
    work, home, tmp = _account()
    a = b = again = None
    try:
        other = (
            work / "other-config"
        )  # no file there: the portal serves its "needs attention" page, which is enough
        a = _start(launcher, home, tmp)
        b = _start(launcher, home, tmp, "--", "--config", str(other / "portal-config.json"))
        assert _answers(_url(a)) and _answers(_url(b))
        again = _start(launcher, home, tmp, "--", "--config", str(other / "portal-config.json"))
        out, err = again.communicate(timeout=90)
        assert again.returncode == 75 and "ALREADY_RUNNING" in err, (out, err)
        assert a.poll() is None and b.poll() is None
    finally:
        _quit(*[p for p in (a, b, again) if p is not None])
        shutil.rmtree(work, ignore_errors=True)


def _pids(bundle_launcher: Path) -> list[int]:
    done = subprocess.run(  # noqa: S603 - fixed argv
        ["/usr/bin/pgrep", "-f", str(bundle_launcher)], capture_output=True, text=True, check=False
    )
    return [int(n) for n in done.stdout.split() if n.isdigit() and int(n) != os.getpid()]


def _open(app: Path, home: Path, tmp: Path, out: Path, err: Path, *flags: str) -> None:
    subprocess.run(  # noqa: S603 - Launch Services, fixed argv
        [
            "/usr/bin/open", *flags, "--env", f"HOME={home}", "--env", f"TMPDIR={tmp}",
            "--stdout", str(out), "--stderr", str(err), "-a", str(app), "--args", "--no-browser", "--print-url",
        ],
        check=True, timeout=60,
    )  # fmt: skip


@NATIVE
def test_through_launch_services_a_second_start_does_not_make_a_second_portal(launcher):
    """``open`` of a running application brings it forward; ``open -n`` forces another process, which must say so and quit."""
    app = launcher.parent.parent.parent  # .../X.app
    work, home, tmp = _account()
    out1, err1, out2, err2 = (work / n for n in ("out1", "err1", "out2", "err2"))
    first_pids: list[int] = []
    try:
        _open(app, home, tmp, out1, err1)
        end = time.time() + 90
        while time.time() < end and "PORTAL_URL=" not in (
            out1.read_text() if out1.exists() else ""
        ):
            time.sleep(0.3)
        url = out1.read_text().strip().split("PORTAL_URL=", 1)[1].split()[0]
        first_pids = _pids(launcher)
        assert len(first_pids) == 1 and _answers(url)
        _open(
            app, home, tmp, out2, err2
        )  # a plain second open: the running application is brought forward
        time.sleep(4)
        assert _pids(launcher) == first_pids and _answers(url)
        _open(app, home, tmp, out2, err2, "-n")  # a forced new process
        end = time.time() + 60
        while time.time() < end and "ALREADY_RUNNING" not in (
            err2.read_text() if err2.exists() else ""
        ):
            time.sleep(0.3)
        assert f"ALREADY_RUNNING {url}" in err2.read_text(), err2.read_text()
        time.sleep(3)
        assert _pids(launcher) == first_pids and _answers(url), (
            "one launcher, the first, still running"
        )
    finally:
        for pid in _pids(launcher):
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGTERM)
        time.sleep(3)
        shutil.rmtree(work, ignore_errors=True)
