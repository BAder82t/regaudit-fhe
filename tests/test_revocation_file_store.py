"""The real single-host file store, under real processes.

REAL here: processes killed with SIGKILL at each commit point, concurrent processes contending on flock, new processes
after a restart, files damaged or restored on disk. SIMULATED or absent: power loss (nothing here cuts power, so
whether fsync reached the medium is not shown), and a torn write (made by truncating the file, since rename does not
tear). Everything runs through the public gate under a lower profile, on the shipped store.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import textwrap
from datetime import timedelta
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe import _revocation as rv
from regaudit_fhe import _revocation_gate as gate
from regaudit_fhe import _revocation_state as st
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.verification import VerificationPolicy

from .experimental_revocation.gen_fixtures import NOW, dump, make_world

pytestmark = pytest.mark.skipif(os.name != "posix", reason="flock and SIGKILL")

# Children import the same package this process is testing, wherever it is installed.
PACKAGE_PARENT = str(Path(rv.__file__).resolve().parents[1])
W = make_world()
STORE = W.store(W.old, W.new, W.third)
STALE = NOW + timedelta(hours=22)


@pytest.fixture
def box(tmp_path: Path) -> Path:
    d = tmp_path / "state"
    d.mkdir(mode=0o700)
    return d


def pin() -> st.Pin:
    return st.Pin(
        W.issuer,
        W.rev.public_key_pem(),
        "enr-1",
        recovery_pem=W.recovery.public_key_pem(),
        baseline_epoch=0,
    )


def chain(n: int) -> list[dict]:
    docs = [W.signed(1, [])]
    for epoch in range(2, n + 1):
        docs.append(W.signed(epoch, [], prev=rv.list_digest(docs[-1])))
    return docs


def enrolled(box: Path) -> st.FileStateStore:
    fs = st.FileStateStore(box)
    st.enroll(fs, pin(), STORE, now=NOW - timedelta(days=30))
    return fs


def report():
    return envelope_v2(
        "drift",
        rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])),
        signer=W.old,
        deployment_id="p",
        audience=["reg"],
        issued_at=NOW - timedelta(hours=1),
    )


def decide(fs, tmp_path: Path, now=NOW, ctx=None):
    pol = VerificationPolicy(
        profile="confidential",
        trust_store=STORE,
        now=lambda: now,
        max_age=timedelta(days=90),
        replay_mode="check",
        replay_cache=SqliteReplayCache(tmp_path / "replay.db"),
        verifier_id="reg",
    )
    context = ctx or gate.RevocationContext(gate.MODE_REQUIRED, fs, {W.issuer: pin()})
    return gate.verify_with_revocation(report(), pol, context)


# Child processes: the same operations, through the product, in a separate interpreter.
CHILD = textwrap.dedent(
    """
    import json, os, signal, sys
    from datetime import datetime
    sys.path.insert(0, sys.argv[1])
    from regaudit_fhe import _revocation_state as st
    from regaudit_fhe.trust import TrustStore
    args = json.loads(sys.argv[2])

    class Killed(st.FileStateStore):
        def _fault(self, point):
            if point == args.get("kill_at"):
                os.kill(os.getpid(), signal.SIGKILL)

    pin = st.Pin(**args["pin"])
    store = TrustStore.from_dict(args["trust"])
    now = datetime.fromisoformat(args["now"])
    out = st.ingest_list(Killed(args["dir"]), pin, args["doc"], store, now)
    print(json.dumps({"accepted": out.accepted, "code": out.code, "seq": out.seq}))
    """
)


def child_args(box: Path, doc: dict, **extra) -> str:
    payload = {
        "dir": str(box),
        "pin": pin().to_dict(),
        "trust": {
            "entries": {
                s.key_id: {
                    "issuer": W.issuer,
                    "public_key_pem": s.public_key_pem(),
                    "status": "active",
                }
                for s in (W.old, W.new, W.third)
            }
        },
        "doc": dump(doc),
        "now": NOW.isoformat(),
        **extra,
    }
    return json.dumps(payload)


def spawn(box: Path, doc: dict, **extra) -> subprocess.Popen:
    return subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", CHILD, PACKAGE_PARENT, child_args(box, doc, **extra)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


@pytest.mark.parametrize(
    ("point", "epoch_after"),
    [
        ("mid-write", 1),
        ("partial-temp", 1),
        ("before-rename", 1),
        ("after-rename", 2),
        ("after-directory-sync", 2),
    ],
)
def test_real_process_killed_at_each_commit_point(box, tmp_path, point, epoch_after):
    fs = enrolled(box)
    docs = chain(2)
    assert st.ingest_list(fs, pin(), dump(docs[0]), STORE, NOW).accepted
    proc = spawn(box, docs[1], kill_at=point)
    proc.communicate(timeout=120)
    assert proc.returncode == -signal.SIGKILL, point  # it really died there
    rec, _ = st.load(fs, pin())  # whole, not torn
    assert rec.state.get(W.issuer).epoch == epoch_after
    assert decide(fs, tmp_path).result.accepted
    retry = st.ingest_list(fs, pin(), dump(docs[1]), STORE, NOW)  # re-delivery converges
    assert retry.accepted and st.load(fs, pin())[0].state.get(W.issuer).epoch == 2
    assert not list(
        box.glob(".state-*.tmp")
    )  # a dead writer's temp file does not outlive the next commit


def test_a_temp_file_from_a_killed_writer_is_never_read(box):
    fs = enrolled(box)
    proc = spawn(box, chain(1)[0], kill_at="before-rename")
    proc.communicate(timeout=120)
    assert proc.returncode == -signal.SIGKILL
    assert list(box.glob(".state-*.tmp"))
    assert st.load(fs, pin())[0].state.get(W.issuer) is None


def test_real_concurrent_processes_end_at_the_highest_epoch(box):
    fs = enrolled(box)
    docs = chain(8)
    procs = [spawn(box, d) for d in reversed(docs)]
    results = []
    for proc in procs:
        out, err = proc.communicate(timeout=180)
        assert proc.returncode == 0, err
        results.append(json.loads(out))
    rec, _ = st.load(fs, pin())
    assert rec.state.get(W.issuer).epoch == 8
    allowed = {None, "REVOCATION_ROLLBACK", "REVOCATION_STATE_CONFLICT"}
    assert {r["code"] for r in results} <= allowed, results
    assert (
        sum(1 for r in results if r["accepted"]) + 1 == rec.seq
    )  # one write per acceptance, none lost


def test_a_new_process_sees_the_state_after_a_restart(box):
    fs = enrolled(box)
    assert st.ingest_list(fs, pin(), dump(chain(1)[0]), STORE, NOW).accepted
    code = textwrap.dedent(
        """
        import json, sys
        sys.path.insert(0, sys.argv[1])
        from regaudit_fhe import _revocation_state as st
        args = json.loads(sys.argv[2])
        rec, _ = st.load(st.FileStateStore(args["dir"]), st.Pin(**args["pin"]))
        print(rec.state.get(args["pin"]["issuer"]).epoch, rec.seq)
        """
    )
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code, PACKAGE_PARENT, child_args(box, chain(1)[0])],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    assert out.stdout.split() == ["1", "2"]


@pytest.mark.parametrize(
    "damage",
    [
        "truncate",
        "empty",
        "flip-byte",
        "valid-json-wrong-digest",
        "replace-with-directory",
        "symlink",
    ],
)
def test_a_damaged_record_fails_closed_never_as_empty(box, tmp_path, damage):
    fs = enrolled(box)
    assert st.ingest_list(fs, pin(), dump(chain(1)[0]), STORE, NOW).accepted
    path = fs.path(W.issuer)
    raw = path.read_bytes()
    if damage == "truncate":  # simulates a torn write: rename itself does not tear
        path.write_bytes(raw[: len(raw) // 2])
    elif damage == "empty":
        path.write_bytes(b"")
    elif damage == "flip-byte":
        path.write_bytes(raw[:60] + bytes([raw[60] ^ 1]) + raw[61:])
    elif damage == "valid-json-wrong-digest":
        doc = json.loads(raw)
        doc["record"]["seq"] += 7
        path.write_text(json.dumps(doc))
    elif damage == "replace-with-directory":
        path.unlink()
        path.mkdir()
    else:
        other = tmp_path / "elsewhere"
        other.write_bytes(raw)
        path.unlink()
        path.symlink_to(other)
    d = decide(fs, tmp_path)
    assert not d.result.accepted and "REVOCATION_STATE_UNAVAILABLE" in d.result.blocking_reasons
    assert st.ingest_list(fs, pin(), dump(chain(2)[1]), STORE, NOW).code == (
        "REVOCATION_STATE_UNAVAILABLE"
    )


def test_a_deleted_record_with_a_surviving_pin_is_lost_not_first_use(box, tmp_path):
    fs = enrolled(box)
    assert st.ingest_list(fs, pin(), dump(chain(1)[0]), STORE, NOW).accepted
    fs.path(W.issuer).unlink()
    d = decide(fs, tmp_path)
    assert not d.result.accepted and "REVOCATION_STATE_LOST" in d.result.blocking_reasons


def test_an_unusable_directory_fails_closed(box, tmp_path):
    fs = enrolled(box)
    assert st.ingest_list(fs, pin(), dump(chain(1)[0]), STORE, NOW).accepted
    os.chmod(box, 0o777)  # noqa: S103 - the point of the test
    try:
        d = decide(fs, tmp_path)
        assert "REVOCATION_STATE_UNAVAILABLE" in d.result.blocking_reasons
    finally:
        os.chmod(box, 0o700)
    moved = box.with_name("moved")
    box.rename(moved)
    box.symlink_to(moved)
    d = decide(fs, tmp_path)
    assert "REVOCATION_STATE_UNAVAILABLE" in d.result.blocking_reasons


def test_a_restored_backup_is_caught_by_a_process_that_remembers(box, tmp_path):
    fs = enrolled(box)
    docs = chain(2)
    assert st.ingest_list(fs, pin(), dump(docs[0]), STORE, NOW).accepted
    backup = tmp_path / "backup"
    shutil.copy2(fs.path(W.issuer), backup)
    assert st.ingest_list(fs, pin(), dump(docs[1]), STORE, NOW).accepted
    ctx = gate.RevocationContext(gate.MODE_REQUIRED, fs, {W.issuer: pin()})
    assert decide(fs, tmp_path, ctx=ctx).result.accepted
    shutil.copy2(backup, fs.path(W.issuer))
    d = decide(fs, tmp_path, ctx=ctx)
    assert "REVOCATION_STATE_ROLLBACK" in d.result.blocking_reasons and not d.result.accepted


def test_limit_a_restored_backup_is_not_caught_by_a_new_process_and_the_bound_is_the_deadline(
    box, tmp_path
):
    """No independent store exists. This is the reason high-assurance refuses this store."""
    fs = enrolled(box)
    first, second = chain(2)
    revoked = W.signed(3, [W.entry(W.old, "compromised", None)], prev=rv.list_digest(second))
    assert st.ingest_list(fs, pin(), dump(first), STORE, NOW).accepted
    backup = tmp_path / "backup"
    shutil.copy2(fs.path(W.issuer), backup)
    assert st.ingest_list(fs, pin(), dump(second), STORE, NOW).accepted
    assert st.ingest_list(fs, pin(), dump(revoked), STORE, NOW).accepted
    assert not decide(fs, tmp_path).result.accepted
    shutil.copy2(backup, fs.path(W.issuer))
    assert decide(fs, tmp_path).result.accepted  # forgotten: undetected in a new context
    assert "REVOCATION_DATA_STALE" in decide(fs, tmp_path, now=STALE).result.blocking_reasons


def test_files_are_private(box):
    fs = enrolled(box)
    assert stat.S_IMODE(fs.path(W.issuer).stat().st_mode) == 0o600


def test_pin_file_refuses_a_group_writable_file_and_malformed_content(tmp_path):
    path = tmp_path / "pins.json"
    st.save_pin(path, pin())
    assert st.load_pins(path)[W.issuer] == pin()
    os.chmod(path, 0o660)
    with pytest.raises(st.PinStoreError, match="writable"):
        st.load_pins(path)
    os.chmod(path, 0o600)
    path.write_text('{"pins": {"acme": {"issuer": "acme"}}}')
    with pytest.raises(st.PinStoreError):
        st.load_pins(path)
    path.write_text("{")
    with pytest.raises(st.PinStoreError):
        st.load_pins(path)
    path.unlink()
    with pytest.raises(st.PinStoreError):
        st.load_pins(path)
