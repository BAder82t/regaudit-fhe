"""``trust add`` storage behaviour: creation mode, durability, concurrent adds, failure mid-write.

Local filesystem only. These do not claim protection from the same account, an administrator or a restored backup.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from regaudit_fhe import cli
from regaudit_fhe import trust as trust_module

posix = pytest.mark.skipif(
    not sys.platform.startswith(("linux", "darwin")), reason="POSIX permission bits and flock"
)


def _keys(tmp_path: Path, count: int) -> list[dict[str, Any]]:
    keys = []
    for i in range(count):
        priv, pub = tmp_path / f"k{i}.pem", tmp_path / f"k{i}.pub"
        assert (
            cli.main(
                [
                    "keygen",
                    "--key-id",
                    f"k-{i}",
                    "--issuer",
                    "acme",
                    "--private-key",
                    str(priv),
                    "--public-key",
                    str(pub),
                ]
            )
            == 0
        )
        from regaudit_fhe._keys import spki_fingerprint

        keys.append({"id": f"k-{i}", "pub": str(pub), "fp": spki_fingerprint(pub.read_text())})
    return keys


def _add(store: Path, key: dict[str, Any]) -> int:
    return cli.main(
        [
            "trust",
            "add",
            "--store",
            str(store),
            "--key-id",
            key["id"],
            "--issuer",
            "acme",
            "--public-key",
            key["pub"],
            "--fingerprint",
            key["fp"],
        ]
    )


def _ids(store: Path) -> set[str]:
    return set(json.loads(store.read_text())["entries"])


@pytest.fixture
def keys(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    made = _keys(tmp_path, 3)
    capsys.readouterr()
    return made


@posix
def test_new_store_is_created_owner_only_whatever_the_umask(tmp_path, keys, capsys):
    old = os.umask(0o022)
    try:
        store = tmp_path / "store.json"
        assert _add(store, keys[0]) == 0
    finally:
        os.umask(old)
    assert stat.S_IMODE(store.stat().st_mode) == 0o600


@posix
def test_existing_store_mode_is_kept_not_tightened(tmp_path, keys):
    store = tmp_path / "store.json"
    assert _add(store, keys[0]) == 0
    os.chmod(store, 0o400)
    assert _add(store, keys[1]) == 0
    assert stat.S_IMODE(store.stat().st_mode) == 0o400
    assert _ids(store) == {"k-0", "k-1"}


@posix
def test_trust_add_syncs_the_file_and_the_directory(tmp_path, keys, monkeypatch):
    synced: list[bool] = []
    real_fsync = os.fsync

    def spy(fd: int) -> None:
        synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)
    assert _add(tmp_path / "store.json", keys[0]) == 0
    assert False in synced, "the new file was not fsynced"
    assert True in synced, "the directory was not fsynced after the replace"


@posix
def test_failure_at_the_swap_leaves_the_old_store_and_no_temp_file(tmp_path, keys, monkeypatch):
    store = tmp_path / "store.json"
    assert _add(store, keys[0]) == 0
    before = store.read_bytes()

    def boom(src: Any, dst: Any) -> None:
        raise OSError(5, "injected I/O error")

    monkeypatch.setattr(os, "replace", boom)
    assert _add(store, keys[1]) == 2
    monkeypatch.undo()
    assert store.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".trust-")] == []


@posix
def test_failure_while_writing_leaves_the_old_store_and_no_temp_file(tmp_path, keys, monkeypatch):
    store = tmp_path / "store.json"
    assert _add(store, keys[0]) == 0
    before = store.read_bytes()
    real_fsync = os.fsync

    def failing(fd: int) -> None:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(28, "injected: no space left on device")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", failing)
    assert _add(store, keys[1]) == 2
    monkeypatch.undo()
    assert store.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".trust-")] == []


@posix
def test_two_adds_that_overlap_both_land(tmp_path, keys, monkeypatch):
    """Both adds read the store, then both reach validation before either writes. A lock makes the second wait."""
    store = tmp_path / "store.json"
    assert _add(store, keys[0]) == 0
    barrier = threading.Barrier(2)
    real = trust_module.TrustStore.from_dict.__func__  # type: ignore[attr-defined]

    def meet(cls: Any, payload: Any) -> Any:
        # With a lock the other thread never gets here, so the wait times out and is ignored.
        with contextlib.suppress(threading.BrokenBarrierError):
            barrier.wait(timeout=1.5)
        return real(cls, payload)

    monkeypatch.setattr(trust_module.TrustStore, "from_dict", classmethod(meet))
    results: dict[str, int] = {}

    def run(key: dict[str, Any]) -> None:
        results[key["id"]] = _add(store, key)

    threads = [threading.Thread(target=run, args=(k,)) for k in keys[1:]]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    monkeypatch.undo()
    assert results == {"k-1": 0, "k-2": 0}
    assert _ids(store) == {"k-0", "k-1", "k-2"}


@posix
def test_adds_from_separate_processes_all_land(tmp_path, keys):
    store = tmp_path / "store.json"
    procs = [
        subprocess.Popen(  # noqa: S603 - fixed argv
            [
                sys.executable,
                "-m",
                "regaudit_fhe.cli",
                "trust",
                "add",
                "--store",
                str(store),
                "--key-id",
                k["id"],
                "--issuer",
                "acme",
                "--public-key",
                k["pub"],
                "--fingerprint",
                k["fp"],
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        for k in keys
    ]
    codes = [p.wait(120) for p in procs]
    assert codes == [0, 0, 0]
    assert _ids(store) == {"k-0", "k-1", "k-2"}


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("setfacl") is None,
    reason="needs Linux POSIX ACLs and setfacl",
)
def test_linux_acl_that_lets_another_user_write_shows_in_the_group_bits_and_is_refused(
    tmp_path, keys
):
    """A POSIX ACL write entry raises the mask, which stat reports as the group bits, so the mode check refuses it."""
    from regaudit_fhe.trust import store_file_problem

    store = tmp_path / "store.json"
    assert _add(store, keys[0]) == 0
    setfacl = shutil.which("setfacl")
    assert setfacl is not None
    subprocess.run([setfacl, "-m", "u:nobody:rw", str(store)], check=True)  # noqa: S603
    assert store_file_problem(str(store)) is not None
