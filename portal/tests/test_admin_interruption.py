"""An interrupted or half-heard apply: the exit status and the words always match what is on the disk.

A stop is sent at every step that writes or flushes, before and after it. Whatever happens, an apply never says
"Nothing was changed." when files were changed, never reports success without the change being in place, flushed and
read back by the portal's own readers, and leaves no temporary folder behind. With standard output or standard error
closed when it starts, it completes, and the status and the words that can still be written say so.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from helpers import issuer_signer, prepare_plan, snapshot
from regaudit_portal import admin
from regaudit_portal.__main__ import main
from regaudit_portal.config import read_settings, read_trust_store
from regaudit_portal.paths import default_config_folder
from test_admin import _env, _expect, _first_setup, _plan_file, _private_folder

# Every test here sends a stop to a child process; see the fixture for why the children must start with default signals.
pytestmark = pytest.mark.usefixtures("children_start_with_default_stop_signals")

PORTAL = Path(__file__).resolve().parents[1]
UNCHANGED = "Nothing was changed."


def _state(folder: Path) -> dict:
    if not folder.exists():
        return {}
    return {name: found for name, found in snapshot(folder).items() if name != "."}


def _leftovers(folder: Path) -> list[str]:
    places = [folder, folder.parent]
    return [
        p.name
        for place in places
        if place.exists()
        for p in place.iterdir()
        if p.name.startswith(".regaudit-admin-")
    ]


def _prepare(case: str, tmp_path, run, signer) -> tuple[Path, list[str]]:
    """The plan to apply and its arguments, for: no folder yet, an empty private folder, or adding to a setup."""
    later = issuer_signer("Later Ltd", "later-1")
    if case == "fresh":
        return _plan_file(tmp_path, prepare_plan([signer])), _expect(signer)
    if case == "empty-folder":
        _private_folder(default_config_folder())
        return _plan_file(tmp_path, prepare_plan([signer])), _expect(signer)
    _first_setup(tmp_path, run, signer)
    return _plan_file(tmp_path, prepare_plan([later], mode="add-issuers"), "add.json"), _expect(
        later
    )


STEPS = [
    (name, n)
    for name, count in (("_sync", 6), ("rename", 2), ("link", 2))
    for n in range(1, count + 1)
]


@pytest.mark.parametrize("case", ["fresh", "empty-folder", "add"])
@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize("step, nth", STEPS)
def test_a_stop_at_any_writing_step_is_reported_exactly_as_the_disk_is(
    home, tmp_path, run, northwind, monkeypatch, case, when, step, nth
):
    plan, expect = _prepare(case, tmp_path, run, northwind)
    folder = default_config_folder()
    before = _state(folder)
    owner, name = (admin, "_sync") if step == "_sync" else (os, step)
    real, calls = getattr(owner, name), []

    def hooked(*args, **kwargs):
        calls.append(1)
        if len(calls) == nth and when == "before":
            os.kill(os.getpid(), signal.SIGTERM)
        done = real(*args, **kwargs)
        if len(calls) == nth and when == "after":
            os.kill(os.getpid(), signal.SIGTERM)
        return done

    monkeypatch.setattr(owner, name, hooked)
    code, out, err = run("admin-apply", plan, *expect)
    monkeypatch.undo()
    after = _state(folder)
    said = out + err
    assert "Traceback" not in said and _leftovers(folder) == [], (code, said)
    if after != before:  # something was committed: never "nothing changed", never plain failure
        assert UNCHANGED not in said, (code, said)
        assert code in (0, 4), (code, said)
        assert sorted(after) == ["portal-config.json", "trust-store.json"]
        read_trust_store(read_settings(folder / "portal-config.json"))
    else:
        assert code in (1, 2) and UNCHANGED in said, (code, said)
    if code == 0:  # success only with the change in place and read back
        assert "Applied setup plan" in out and after != before
    if code == 4:
        assert "The change is complete" in err or "The new files are in place" in err, err


def test_a_stop_while_the_committed_change_is_flushed_waits_for_the_flush(
    home, tmp_path, run, northwind, monkeypatch
):
    """The stop is taken only once the folder holding the new files is on the disk itself."""
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    real, events = admin._sync, []

    def flush(fd):
        if os.path.exists(default_config_folder() / "portal-config.json") and "stop" not in events:
            events.append("stop")
            os.kill(os.getpid(), signal.SIGTERM)  # arrives during the flush of the committed change
        real(fd)
        events.append("flushed")

    monkeypatch.setattr(admin, "_sync", flush)
    code, _, err = run("admin-apply", plan, *_expect(northwind))
    assert code == 4 and "stopped: The change is complete" in err, err
    assert events[events.index("stop") + 1] == "flushed", events


def test_guard_off_without_holding_the_stop_the_flush_of_the_committed_change_is_cut_short(
    home, tmp_path, run, northwind, monkeypatch
):
    """The control: if stops were not held over the flush, the stop would land before it finished."""
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    real, events = admin._sync, []

    @contextlib.contextmanager
    def not_held():
        yield

    def flush(fd):
        if os.path.exists(default_config_folder() / "portal-config.json") and "stop" not in events:
            events.append("stop")
            os.kill(os.getpid(), signal.SIGTERM)
        real(fd)
        events.append("flushed")

    monkeypatch.setattr(admin, "_held_signals", not_held)
    monkeypatch.setattr(admin, "_sync", flush)
    code, _, _err = run("admin-apply", plan, *_expect(northwind))
    assert code == 4 and events[-1] == "stop", events


def test_a_failed_flush_after_the_change_says_the_files_are_in_place_and_may_not_survive_a_power_cut(
    home, tmp_path, run, northwind, monkeypatch
):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    real = admin._sync

    def flush(fd):
        if os.path.exists(default_config_folder() / "portal-config.json"):
            raise OSError(5, "Input/output error")
        real(fd)

    monkeypatch.setattr(admin, "_sync", flush)
    code, out, err = run("admin-apply", plan, *_expect(northwind))
    assert code == 4 and UNCHANGED not in out + err
    assert (
        "failed: The new files are in place, but flushing them to the disk failed (Input/output error)"
        in err
    )
    assert sorted(p.name for p in default_config_folder().iterdir()) == [
        "portal-config.json",
        "trust-store.json",
    ]


# ----------------------------------------------------------------------------- standard output or error closed


def _closed(account: Path, which: str, *argv: str) -> subprocess.CompletedProcess:
    """Run the command with standard output (1), standard error (2) or both closed before it starts."""
    closing = {"1": ">&-", "2": "2>&-", "both": ">&- 2>&-"}[which]
    shell = f'exec "$@" {closing}'
    return subprocess.run(  # noqa: S603 - /bin/sh with a fixed script, this interpreter, fixed arguments
        ["/bin/sh", "-c", shell, "sh", sys.executable, "-m", "regaudit_portal", *argv],
        env=_env(account), cwd=PORTAL, capture_output=which != "both", text=True, timeout=120, check=False,
        stdin=subprocess.DEVNULL,
    )  # fmt: skip


def _complete(folder: Path) -> None:
    assert sorted(p.name for p in folder.iterdir()) == ["portal-config.json", "trust-store.json"]
    read_trust_store(read_settings(folder / "portal-config.json"))


def test_with_standard_output_closed_the_apply_completes_and_says_so_on_standard_error(
    home, tmp_path, northwind
):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    done = _closed(home, "1", "admin-apply", str(plan), *_expect(northwind))
    assert done.returncode == 0, done.stderr
    assert "Traceback" not in done.stderr and UNCHANGED not in done.stderr
    assert (
        done.stderr.startswith("Applied setup plan ")
        and "Standard output could not be written" in done.stderr
    )
    _complete(default_config_folder())


def test_with_standard_error_closed_the_apply_completes_and_prints_everything_on_standard_output(
    home, tmp_path, northwind
):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    done = _closed(home, "2", "admin-apply", str(plan), *_expect(northwind))
    assert done.returncode == 0 and done.stdout.startswith("Applied setup plan ")
    assert "Wrote trust-store.json" in done.stdout and "Enrolled:" in done.stdout
    _complete(default_config_folder())


def test_with_both_closed_the_status_alone_tells_and_matches_the_disk(home, tmp_path, northwind):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    assert _closed(home, "both", "admin-describe", str(plan)).returncode == 0
    assert _closed(home, "both", "admin-apply", str(plan), *_expect(northwind)).returncode == 0
    _complete(default_config_folder())
    before = _state(default_config_folder())
    assert (
        _closed(home, "both", "admin-apply", str(plan), *_expect(northwind)).returncode == 2
    )  # already set up
    assert _state(default_config_folder()) == before


def test_with_standard_output_closed_a_refusal_is_still_said_on_standard_error(
    home, tmp_path, northwind
):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    wrong = ["--expect-fingerprint", f"{northwind.key_id}={'ab' * 32}"]
    done = _closed(home, "1", "admin-apply", str(plan), *wrong)
    assert done.returncode == 2 and done.stderr.startswith("refused: ") and UNCHANGED in done.stderr
    assert not default_config_folder().exists()


def test_guard_off_the_earlier_output_crashed_after_the_change_was_complete(
    home, tmp_path, northwind, monkeypatch
):
    """The control: printing as before, with standard output closed (Python's None), the command raised after the
    files were in place, so its status said failure while the disk said success."""

    def earlier(text, err=False):
        target = sys.stderr if err else sys.stdout
        target.write(text + "\n")
        target.flush()
        return True

    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    monkeypatch.setattr(admin, "_out", earlier)
    monkeypatch.setattr(sys, "stdout", None)
    with pytest.raises(AttributeError):
        main(["admin-apply", str(plan), *_expect(northwind)])
    _complete(default_config_folder())


def test_now_with_standard_output_none_the_apply_returns_success(
    home, tmp_path, northwind, monkeypatch, capsys
):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    monkeypatch.setattr(sys, "stdout", None)
    assert main(["admin-apply", str(plan), *_expect(northwind)]) == 0
    assert "Standard output could not be written" in capsys.readouterr().err
    _complete(default_config_folder())


_RESERVE = """
import os, sys
from regaudit_portal import admin
if sys.argv[1] == "reserve":
    admin._reserve_standard_descriptors()
fd = os.open(os.devnull, os.O_RDONLY)
print(fd, file=open(sys.argv[2], "w"))
"""


@pytest.mark.parametrize(
    "reserve, expected", [("reserve", lambda fd: fd > 2), ("off", lambda fd: fd == 2)]
)
def test_a_closed_standard_error_is_never_reused_by_a_file_the_command_opens(
    tmp_path, reserve, expected
):
    """With the reservation, the first file opened does not get number 2; with it off (the control), it does, and a
    library writing to standard error would write into it."""
    told = tmp_path / "fd.txt"
    subprocess.run(  # noqa: S603 - /bin/sh with a fixed script, this interpreter, fixed arguments
        ["/bin/sh", "-c", 'exec "$@" 2>&-', "sh", sys.executable, "-c", _RESERVE, reserve, str(told)],
        env={**os.environ, "PYTHONPATH": str(PORTAL)}, timeout=60, check=True, stdin=subprocess.DEVNULL,
    )  # fmt: skip
    assert expected(int(told.read_text()))


# ----------------------------------------------------------------------------- a stop in the first and last moments


_STOP_RIGHT_AFTER_THE_PACKAGE_STARTS = """
import os, signal, sys
which = sys.argv[1]
sys.argv = ["-m", *sys.argv[2:]]  # what "python -m regaudit_portal" sets while the package is imported
import regaudit_portal  # its first lines: the early stop handling and the private bytecode folder
os.kill(os.getpid(), getattr(signal, which))  # a stop now, before the command itself has started
from regaudit_portal.__main__ import main
sys.exit(main(sys.argv[1:]))
"""


def _pyc_folders(account: Path) -> list[str]:
    return [
        p.name
        for p in (account.parent / "tmp").iterdir()
        if p.name.startswith("regaudit-portal-pyc-")
    ]


def _start_and_stop(
    account: Path, script: str, sig: str, *argv: str, env: dict | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-c", script, sig, *argv],
        env={**_env(account), **(env or {})}, cwd=PORTAL, capture_output=True, text=True, timeout=120, check=False,
        stdin=subprocess.DEVNULL,
    )  # fmt: skip


def _plain_stop(done: subprocess.CompletedProcess, account: Path) -> None:
    said = done.stdout + done.stderr
    assert done.returncode == 1, (done.returncode, said[-400:])
    assert (
        "Traceback" not in said and said.strip().splitlines()[-1] == "stopped: Nothing was changed."
    )
    assert not default_config_folder().exists() and _pyc_folders(account) == []


@pytest.mark.parametrize("sig", ["SIGTERM", "SIGINT"])
@pytest.mark.parametrize("command", ["admin-apply", "admin-describe"])
def test_a_stop_right_after_the_package_starts_ends_plainly(
    home, tmp_path, northwind, sig, command
):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    extra = _expect(northwind) if command == "admin-apply" else []
    _plain_stop(
        _start_and_stop(
            home, _STOP_RIGHT_AFTER_THE_PACKAGE_STARTS, sig, command, str(plan), *extra
        ),
        home,
    )


@pytest.mark.parametrize("command", ["admin-apply", "admin-describe"])
def test_a_hang_up_right_after_the_package_starts_ends_plainly(home, tmp_path, northwind, command):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    extra = _expect(northwind) if command == "admin-apply" else []
    _plain_stop(
        _start_and_stop(
            home, _STOP_RIGHT_AFTER_THE_PACKAGE_STARTS, "SIGHUP", command, str(plan), *extra
        ),
        home,
    )


@pytest.mark.parametrize("sig", ["SIGHUP", "SIGTERM", "SIGINT"])
def test_a_stop_in_the_first_moments_never_changes_anything_and_ends_plainly_or_by_the_signal(
    home, tmp_path, northwind, sig
):
    """Sent at real delays after the start. Before the package's first lines run, nothing of ours can take the stop,
    and the process ends by the signal itself. After them it is a plain stop. Nothing is ever written."""
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    for delay in (0.0, 0.02, 0.05, 0.1, 0.2, 0.3):
        proc = subprocess.Popen(  # noqa: S603 - this interpreter, fixed arguments
            [sys.executable, "-m", "regaudit_portal", "admin-apply", str(plan), *_expect(northwind)],
            env=_env(home), cwd=PORTAL, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )  # fmt: skip
        time.sleep(delay)
        proc.send_signal(getattr(signal, sig))
        out, err = proc.communicate(timeout=120)
        assert not default_config_folder().exists(), delay
        if proc.returncode == 1 and "Fatal Python error: init_import_site" in err:
            # The stop landed while CPython itself was still starting up (importing its own ``site`` module), before any
            # of our code. CPython reports that as a fatal error with status 1. Measured: about 1 run in 4 at a 20 ms delay,
            # on the admin branch alone as well, and never after 100 ms. The Portal cannot take a stop it has not started to
            # run for. What must still hold is checked above: nothing was written.
            assert delay <= 0.1, (delay, err[-300:])
        elif proc.returncode == 1:
            assert (out + err).strip().splitlines()[-1] == "stopped: Nothing was changed.", delay
        else:
            assert proc.returncode == -getattr(signal, sig), (delay, proc.returncode, err[-300:])
        if (
            sig != "SIGINT"
        ):  # Python itself reports a Ctrl-C that comes before any of our code has run
            assert "Traceback" not in err, (delay, err[-300:])
        for left in (
            home.parent / "tmp"
        ).iterdir():  # what a death by the signal leaves, cleared for the next delay
            shutil.rmtree(left)


_STOP_AFTER_THE_COMMAND_FINISHED = """
import os, signal, sys
which = sys.argv[1]
sys.argv = ["/usr/local/bin/regaudit-portal", *sys.argv[2:]]  # as the installed command
from regaudit_portal import admin
from regaudit_portal.__main__ import main
if os.environ.get("GUARD_OFF"):
    admin._leave_the_result_as_it_is = lambda: None
real = admin.run
def run_then_stop(args):
    code = real(args)
    os.kill(os.getpid(), getattr(signal, which))  # after the command finished, before the process ends
    return code
admin.run = run_then_stop
sys.exit(main(sys.argv[1:]))
"""


@pytest.mark.parametrize("sig", ["SIGHUP", "SIGTERM", "SIGINT"])
def test_a_stop_after_the_apply_finished_leaves_its_status_and_words_as_they_are(
    home, tmp_path, northwind, sig
):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    done = _start_and_stop(
        home, _STOP_AFTER_THE_COMMAND_FINISHED, sig, "admin-apply", str(plan), *_expect(northwind)
    )
    assert done.returncode == 0, (done.returncode, done.stderr[-400:])
    assert "stopped" not in done.stdout + done.stderr and done.stdout.startswith(
        "Applied setup plan "
    )
    _complete(default_config_folder())


@pytest.mark.parametrize("sig", ["SIGHUP", "SIGTERM", "SIGINT"])
def test_guard_off_a_stop_after_the_apply_finished_turned_success_into_a_stop_or_a_death(
    home, tmp_path, northwind, sig
):
    """The control: without ignoring stops once the result is final, the entry point's own handlers take the late
    stop: a "stopped." with status 1, or a death by SIGHUP, after an apply that had completed."""
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    done = _start_and_stop(
        home,
        _STOP_AFTER_THE_COMMAND_FINISHED,
        sig,
        "admin-apply",
        str(plan),
        *_expect(northwind),
        env={"GUARD_OFF": "1"},
    )
    assert done.returncode in (1, -signal.SIGHUP) and done.returncode != 0
    _complete(default_config_folder())


def test_a_stop_after_the_files_are_checked_is_not_taken(
    home, tmp_path, run, northwind, monkeypatch
):
    """Once the files are in place, flushed and read back, the result stands: a stop while the summary is printed
    changes no word and no status. Before that point (the control) the same stop is taken and reported."""
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    real = admin._out

    def stop_then_print(text, err=False):
        if text.startswith("Applied setup plan "):
            os.kill(os.getpid(), signal.SIGTERM)
        return real(text, err)

    monkeypatch.setattr(admin, "_out", stop_then_print)
    code, out, err = run("admin-apply", plan, *_expect(northwind))
    assert code == 0 and out.startswith("Applied setup plan ") and "stopped" not in err


def test_guard_off_a_stop_while_the_files_are_read_back_is_still_taken(
    home, tmp_path, run, northwind, monkeypatch
):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    real = admin._final_check

    def stop_then_check(folder, plan):
        os.kill(os.getpid(), signal.SIGTERM)
        real(folder, plan)

    monkeypatch.setattr(admin, "_final_check", stop_then_check)
    code, out, err = run("admin-apply", plan, *_expect(northwind))
    assert code == 4 and "stopped: The change is complete" in err and out == ""
