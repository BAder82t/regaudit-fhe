"""Three outcomes of a trust-store write: failed (old store), written but not confirmed durable, durable.

Fault injection at each step of ``trust add``, repeated attempts after an unconfirmed write, the lock refusing instead of
failing open, and a SIGKILLed writer. Local filesystem only; no claim about the same account, an administrator or a network
filesystem.
"""

from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from regaudit_fhe import cli
from regaudit_fhe import trust as trust_module

from .test_trust_add_storage import _add, _ids, _keys

posix = pytest.mark.skipif(
    not sys.platform.startswith(("linux", "darwin")), reason="POSIX permission bits and flock"
)

NOT_DURABLE = "NOT confirmed durable"


@pytest.fixture
def keys(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    made = _keys(tmp_path, 3)
    capsys.readouterr()
    return made


def _tmps(directory: Path) -> list[str]:
    return [p.name for p in directory.iterdir() if p.name.startswith(".trust-")]


def _is_dir(fd: int) -> bool:
    return stat.S_ISDIR(os.fstat(fd).st_mode)


def _seed(tmp_path: Path, keys: list[dict[str, Any]]) -> tuple[Path, bytes]:
    store = tmp_path / "store.json"
    assert _add(store, keys[0]) == 0
    return store, store.read_bytes()


# ---- outcome 1: failed write -------------------------------------------------------------------------------------


@posix
@pytest.mark.parametrize("step", ["file_fsync", "chmod", "replace"])
def test_outcome1_failed_write_keeps_old_store(tmp_path, keys, monkeypatch, capsys, step):
    store, before = _seed(tmp_path, keys)
    capsys.readouterr()
    real_fsync = os.fsync

    def file_fsync(fd: int) -> None:
        if not _is_dir(fd):
            raise OSError(28, "injected: no space left on device")
        real_fsync(fd)

    def boom(*_a: Any, **_k: Any) -> None:
        raise OSError(5, f"injected {step}")

    if step == "file_fsync":
        monkeypatch.setattr(os, "fsync", file_fsync)
    elif step == "chmod":
        monkeypatch.setattr(os, "chmod", boom)
    else:
        monkeypatch.setattr(os, "replace", boom)
    assert _add(store, keys[1]) == 2
    err = capsys.readouterr()
    monkeypatch.undo()
    assert "cannot write" in err.err and NOT_DURABLE not in err.err and "enrolled" not in err.out
    assert store.read_bytes() == before
    assert _tmps(tmp_path) == []


# ---- outcome 2: written, durability not confirmed ----------------------------------------------------------------


def _fail_dir_fsync(monkeypatch: pytest.MonkeyPatch) -> None:
    real = os.fsync

    def failing(fd: int) -> None:
        if _is_dir(fd):
            raise OSError(5, "injected dir fsync")
        real(fd)

    monkeypatch.setattr(os, "fsync", failing)


def _fail_dir_open_after_replace(monkeypatch: pytest.MonkeyPatch) -> None:
    real_open, real_replace = os.open, os.replace
    state = {"replaced": False}

    def replace(src: Any, dst: Any) -> None:
        real_replace(src, dst)
        state["replaced"] = True

    def opener(path: Any, flags: int, *a: Any, **k: Any) -> int:
        if state["replaced"] and os.path.isdir(path):
            raise OSError(13, "injected dir open")
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(os, "open", opener)


@posix
@pytest.mark.parametrize("inject", [_fail_dir_fsync, _fail_dir_open_after_replace])
def test_outcome2_written_but_not_confirmed(tmp_path, keys, monkeypatch, capsys, inject):
    store, before = _seed(tmp_path, keys)
    capsys.readouterr()
    inject(monkeypatch)
    assert (
        _add(store, keys[1]) == 3
    )  # distinct from the failed write (2), within the existing 0/1/2/3 scheme
    out = capsys.readouterr()
    monkeypatch.undo()
    assert NOT_DURABLE in out.err
    assert "trust add" in out.err and "trust status" in out.err and "idempotent" in out.err
    assert "cannot write" not in out.err and "nothing written" not in out.err
    assert out.out == ""  # no success JSON
    assert _ids(store) == {"k-0", "k-1"}  # the new content is in place and visible
    assert store.read_bytes() != before
    assert _tmps(tmp_path) == []


@posix
def test_repeat_after_unconfirmed_write_is_idempotent_and_recovers(
    tmp_path, keys, monkeypatch, capsys
):
    store, _ = _seed(tmp_path, keys)
    _fail_dir_fsync(monkeypatch)
    assert _add(store, keys[1]) == 3
    # still failing: the repeat does not claim success either, and does not change the store
    written = store.read_bytes()
    assert _add(store, keys[1]) == 3
    assert store.read_bytes() == written
    monkeypatch.undo()
    capsys.readouterr()
    # the disk recovers: the same command now confirms durability and succeeds, with no manual edit
    assert _add(store, keys[1]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["enrolled"] == "k-1" and out["already_enrolled"] is True
    assert store.read_bytes() == written and _ids(store) == {"k-0", "k-1"}
    assert _tmps(tmp_path) == []


@posix
def test_same_key_id_with_a_different_key_is_still_refused(tmp_path, keys, capsys):
    store, _ = _seed(tmp_path, keys)
    other = dict(keys[1], id="k-0")
    before = store.read_bytes()
    assert _add(store, other) == 2
    assert "already enrolled" in capsys.readouterr().err
    assert store.read_bytes() == before


@posix
def test_unconfirmed_write_is_not_reported_by_lifecycle_as_nothing_written(
    tmp_path, keys, monkeypatch, capsys
):
    store, _ = _seed(tmp_path, keys)
    capsys.readouterr()
    _fail_dir_fsync(monkeypatch)
    rc = cli.main(["trust", "retire", "--store", str(store), "--key-id", "k-0"])
    err = capsys.readouterr().err
    monkeypatch.undo()
    assert rc == 3 and NOT_DURABLE in err and "trust status" in err
    assert json.loads(store.read_text())["entries"]["k-0"]["status"] == "retired"


# ---- outcome 3 --------------------------------------------------------------------------------------------------


@posix
def test_outcome3_durable_write_exits_zero(tmp_path, keys, capsys):
    store, _ = _seed(tmp_path, keys)
    capsys.readouterr()
    assert _add(store, keys[1]) == 0
    assert json.loads(capsys.readouterr().out)["enrolled"] == "k-1"


# ---- lock: S4, S5, S2, S3 ----------------------------------------------------------------------------------------


def test_no_flock_platform_refuses_instead_of_running_unlocked(tmp_path, keys, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "fcntl", None)  # `import fcntl` raises ImportError
    store = tmp_path / "store.json"
    assert _add(store, keys[0]) == 3
    err = capsys.readouterr().err
    assert "cannot lock" in err and "no flock" in err
    assert not store.exists() and _tmps(tmp_path) == []


@posix
def test_only_lock_errors_are_labelled_cannot_lock(tmp_path, keys, monkeypatch, capsys):
    def boom(*_a: Any, **_k: Any) -> int:
        raise OSError(5, "injected unrelated I/O error")

    monkeypatch.setattr(cli, "_trust_add_locked", boom)
    assert _add(tmp_path / "store.json", keys[0]) == 3
    err = capsys.readouterr().err
    assert "cannot lock" not in err and "injected unrelated" in err


@posix
@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
def test_directory_without_read_permission_is_refused_not_locked_around(tmp_path, keys, capsys):
    """S2: documented limitation. The lock needs a readable directory; falling back to the file would not be a lock."""
    d = tmp_path / "d"
    d.mkdir()
    store = d / "s.json"
    assert _add(store, keys[0]) == 0
    before = store.read_bytes()
    os.chmod(d, 0o300)
    try:
        assert _add(store, keys[1]) == 3
        assert "cannot lock" in capsys.readouterr().err
    finally:
        os.chmod(d, 0o700)
    assert store.read_bytes() == before


@posix
def test_retire_waits_for_the_trust_add_lock(tmp_path, keys, monkeypatch):
    """S3: an add that has read the store and a retire must not lose each other's change."""
    store, _ = _seed(tmp_path, keys)
    reached, release = threading.Event(), threading.Event()
    real = trust_module.TrustStore.from_dict.__func__  # type: ignore[attr-defined]

    def pause(cls: Any, payload: Any) -> Any:
        if "k-1" in payload.get("entries", {}) and not reached.is_set():
            reached.set()
            release.wait(10)
        return real(cls, payload)

    monkeypatch.setattr(trust_module.TrustStore, "from_dict", classmethod(pause))
    rcs: dict[str, int] = {}
    adder = threading.Thread(target=lambda: rcs.__setitem__("add", _add(store, keys[1])))
    adder.start()
    assert reached.wait(10)
    retirer = threading.Thread(
        target=lambda: rcs.__setitem__(
            "retire", cli.main(["trust", "retire", "--store", str(store), "--key-id", "k-0"])
        )
    )
    retirer.start()
    time.sleep(1.0)
    release.set()
    adder.join(30)
    retirer.join(30)
    monkeypatch.undo()
    entries = json.loads(store.read_text())["entries"]
    assert rcs == {"add": 0, "retire": 0}
    assert set(entries) == {"k-0", "k-1"} and entries["k-0"]["status"] == "retired"


# ---- interrupted writer ------------------------------------------------------------------------------------------

CHILD = """
import os, sys, time
from regaudit_fhe import cli
point, marker = sys.argv[1], sys.argv[2]
real_replace, real_fsync = os.replace, os.fsync
def pause():
    open(marker, "w").write("ready"); sys.stdout.flush()
    time.sleep(60)
if point == "before_replace":
    def replace(a, b):
        pause()
    os.replace = replace
elif point == "after_replace":
    def replace(a, b):
        real_replace(a, b); pause()
    os.replace = replace
sys.exit(cli.main(sys.argv[3:]))
"""


@posix
@pytest.mark.parametrize("point", ["before_replace", "after_replace"])
def test_sigkill_during_write_leaves_old_or_new_never_torn(tmp_path, keys, point):
    store, before = _seed(tmp_path, keys)
    marker = tmp_path / "ready"
    k = keys[1]
    argv = [
        "trust", "add", "--store", str(store), "--key-id", k["id"], "--issuer", "acme",
        "--public-key", k["pub"], "--fingerprint", k["fp"],
    ]  # fmt: skip
    env = dict(os.environ)
    proc = subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, "-c", CHILD, point, str(marker), *argv], env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    deadline = time.time() + 60
    while not marker.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert marker.exists(), "child never reached the pause point"
    proc.send_signal(signal.SIGKILL)
    proc.wait(30)
    data = store.read_bytes()
    assert json.loads(data)  # whole JSON, not torn
    assert _ids(store) == ({"k-0"} if point == "before_replace" else {"k-0", "k-1"})
    if point == "before_replace":
        assert data == before
    # the repeat succeeds without editing anything; a SIGKILL may leave one stray .trust-*.tmp (never read as the store)
    assert _add(store, k) == 0
    assert _ids(store) == {"k-0", "k-1"}
