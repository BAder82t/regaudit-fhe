"""Local trust-store lifecycle edits (status / retire / revoke) on the existing format.

Synthetic keys only. The store is an unauthenticated local file; these tests pin what
the edits do (validated, atomic, one-way, never loosening) and that nothing about how
an existing store verifies has changed.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from regaudit_fhe import _trust_lifecycle as lc
from regaudit_fhe.trust import TrustStore

NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


def _pem() -> str:
    return (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def _store(tmp_path: Path, **extra: dict) -> Path:
    entries = {
        "a-1": {"issuer": "acme", "public_key_pem": _pem(), "status": "active"},
        "b-1": {"issuer": "acme", "public_key_pem": _pem(), "status": "active"},
    }
    for k, v in extra.items():
        entries[k.replace("_", "-")].update(v)
    path = tmp_path / "store.json"
    path.write_text(json.dumps({"entries": entries}, indent=2) + "\n")
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _entry(path: Path, key_id: str) -> dict:
    return json.loads(path.read_text())["entries"][key_id]


# ----------------------------------------------------------------------------- status


def test_status_is_read_only_and_reports_unauthenticated(tmp_path):
    path = _store(tmp_path)
    before = _sha(path)
    out = lc.status_rows(str(path))
    assert _sha(path) == before and not Path(str(path) + ".prev").exists()
    assert out["authenticated"] is False and out["store_form"] == "entries"
    assert [r["key_id"] for r in out["keys"]] == ["a-1", "b-1"]
    assert lc.status_rows(str(path), "a-1")["keys"][0]["status"] == "active"


def test_status_unknown_key_refused(tmp_path):
    with pytest.raises(lc.LifecycleRefused):
        lc.status_rows(str(_store(tmp_path)), "nope")


def test_status_reads_legacy_store_without_editing(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"keys": {"k": _pem()}, "revoked": []}))
    before = _sha(path)
    out = lc.status_rows(str(path))
    assert out["store_form"] == "legacy" and out["keys"][0]["status"] == "active"
    assert _sha(path) == before


# ----------------------------------------------------------------------------- retire


def test_retire_sets_only_status_retired_at_and_as_of(tmp_path):
    path = _store(tmp_path)
    old = json.loads(path.read_text())
    res = lc.retire(str(path), "a-1", at="2026-10-01T00:00:00Z", now=NOW)
    new = json.loads(path.read_text())
    assert new["entries"]["a-1"]["status"] == "retired"
    assert new["entries"]["a-1"]["retired_at"] == "2026-10-01T00:00:00Z"
    assert new["entries"]["b-1"] == old["entries"]["b-1"]  # other keys untouched
    assert new["entries"]["a-1"]["public_key_pem"] == old["entries"]["a-1"]["public_key_pem"]
    assert new["as_of"] == "2026-10-31T12:00:00Z"
    assert set(new) == {"entries", "as_of"}  # no new schema member
    assert res["before"]["status"] == "active"
    assert TrustStore.from_json(str(path)).entry("a-1").status == "retired"


def test_retire_default_is_now(tmp_path):
    path = _store(tmp_path)
    lc.retire(str(path), "a-1", at=None, now=NOW)
    assert _entry(path, "a-1")["retired_at"] == "2026-10-31T12:00:00Z"


@pytest.mark.parametrize(
    "bad", ["2026-10-31", "not-a-time", "2027-01-01T00:00:00Z", "2026-10-01T00:00:00"]
)
def test_retire_bad_or_future_time_refused_store_untouched(tmp_path, bad):
    path = _store(tmp_path)
    before = _sha(path)
    with pytest.raises(lc.LifecycleRefused):
        lc.retire(str(path), "a-1", at=bad, now=NOW)
    assert _sha(path) == before


def test_retire_unknown_key_refused(tmp_path):
    path = _store(tmp_path)
    before = _sha(path)
    with pytest.raises(lc.LifecycleRefused):
        lc.retire(str(path), "zzz", at=None, now=NOW)
    assert _sha(path) == before


def test_retire_is_one_way_and_never_redated(tmp_path):
    path = _store(tmp_path)
    lc.retire(str(path), "a-1", at="2026-10-01T00:00:00Z", now=NOW)
    before = _sha(path)
    with pytest.raises(lc.LifecycleRefused):
        lc.retire(str(path), "a-1", at="2026-09-01T00:00:00Z", now=NOW)
    assert _sha(path) == before


def test_retire_before_not_before_refused(tmp_path):
    path = _store(tmp_path, a_1={"not_before": "2026-06-01T00:00:00Z"})
    with pytest.raises(lc.LifecycleRefused):
        lc.retire(str(path), "a-1", at="2026-01-01T00:00:00Z", now=NOW)


def test_retire_refuses_legacy_store(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"keys": {"k": _pem()}}))
    before = _sha(path)
    with pytest.raises(Exception, match="entries"):
        lc.retire(str(path), "k", at=None, now=NOW)
    assert _sha(path) == before


# ----------------------------------------------------------------------------- revoke


def test_revoke_without_boundary_is_unknown_boundary(tmp_path):
    path = _store(tmp_path)
    lc.revoke(str(path), "a-1", compromised_from=None, now=NOW)
    e = _entry(path, "a-1")
    assert e["status"] == "compromised" and "compromised_from" not in e
    assert TrustStore.from_json(str(path)).entry("a-1").compromised_from is None


def test_revoke_with_boundary(tmp_path):
    path = _store(tmp_path)
    lc.revoke(str(path), "a-1", compromised_from="2026-09-01T00:00:00Z", now=NOW)
    assert _entry(path, "a-1")["compromised_from"] == "2026-09-01T00:00:00Z"


def test_revoke_retired_key_drops_retired_at_but_backup_keeps_it(tmp_path):
    path = _store(tmp_path)
    lc.retire(str(path), "a-1", at="2026-10-01T00:00:00Z", now=NOW)
    lc.revoke(str(path), "a-1", compromised_from="2026-09-15T00:00:00Z", now=NOW)
    assert "retired_at" not in _entry(path, "a-1")
    prev = json.loads(Path(str(path) + ".prev").read_text())
    assert prev["entries"]["a-1"]["retired_at"] == "2026-10-01T00:00:00Z"


def test_revoke_never_loosens_retirement(tmp_path):
    path = _store(tmp_path)
    lc.retire(str(path), "a-1", at="2026-10-01T00:00:00Z", now=NOW)
    before = _sha(path)
    with pytest.raises(lc.LifecycleRefused, match="later than"):
        lc.revoke(str(path), "a-1", compromised_from="2026-10-15T00:00:00Z", now=NOW)
    assert _sha(path) == before


def test_revoke_twice_refused(tmp_path):
    path = _store(tmp_path)
    lc.revoke(str(path), "a-1", compromised_from=None, now=NOW)
    before = _sha(path)
    with pytest.raises(lc.LifecycleRefused):
        lc.revoke(str(path), "a-1", compromised_from="2026-01-01T00:00:00Z", now=NOW)
    assert _sha(path) == before


def test_compromised_cannot_be_retired_back(tmp_path):
    path = _store(tmp_path)
    lc.revoke(str(path), "a-1", compromised_from=None, now=NOW)
    with pytest.raises(lc.LifecycleRefused):
        lc.retire(str(path), "a-1", at=None, now=NOW)


def test_revoke_unknown_key_refused(tmp_path):
    with pytest.raises(lc.LifecycleRefused):
        lc.revoke(str(_store(tmp_path)), "zzz", compromised_from=None, now=NOW)


# ----------------------------------------------------------------------------- as_of / rollback


def test_as_of_never_moves_backwards(tmp_path):
    path = _store(tmp_path)
    lc.retire(str(path), "a-1", at=None, now=NOW)
    later = datetime(2026, 11, 5, tzinfo=timezone.utc)
    lc.revoke(str(path), "b-1", compromised_from=None, now=later)
    assert json.loads(path.read_text())["as_of"] == "2026-11-05T00:00:00Z"


def test_store_from_the_future_of_this_clock_is_refused(tmp_path):
    path = _store(tmp_path)
    lc.retire(str(path), "a-1", at=None, now=datetime(2027, 1, 1, tzinfo=timezone.utc))
    before = _sha(path)
    with pytest.raises(lc.LifecycleRefused, match="as_of"):
        lc.revoke(str(path), "b-1", compromised_from=None, now=NOW)
    assert _sha(path) == before


# ----------------------------------------------------------------------------- durability


def test_failure_before_replace_leaves_old_store_and_no_temp_files(tmp_path, monkeypatch):
    path = _store(tmp_path)
    before = path.read_bytes()

    def boom(*_a, **_k):
        raise OSError("disk gone")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        lc.retire(str(path), "a-1", at=None, now=NOW)
    assert path.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["store.json"]


def test_failure_during_fsync_leaves_old_store(tmp_path, monkeypatch):
    path = _store(tmp_path)
    before = path.read_bytes()
    monkeypatch.setattr(os, "fsync", lambda *_a: (_ for _ in ()).throw(OSError("fsync")))
    with pytest.raises(OSError):
        lc.revoke(str(path), "a-1", compromised_from=None, now=NOW)
    assert path.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["store.json"]


def test_concurrent_change_is_detected_and_not_overwritten(tmp_path, monkeypatch):
    path = _store(tmp_path)
    real = lc._write_atomic

    def racing(p, data, expected_old):
        Path(p).write_text(Path(p).read_text() + " ")  # another writer lands first
        return real(p, data, expected_old)

    monkeypatch.setattr(lc, "_write_atomic", racing)
    with pytest.raises(lc.LifecycleRefused, match="changed"):
        lc.retire(str(path), "a-1", at=None, now=NOW)
    assert _entry(path, "a-1")["status"] == "active"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["store.json"]


def test_backup_holds_previous_bytes(tmp_path):
    path = _store(tmp_path)
    before = path.read_bytes()
    lc.retire(str(path), "a-1", at=None, now=NOW)
    assert Path(str(path) + ".prev").read_bytes() == before


# ----------------------------------------------------------------------------- CLI and verdicts


def _cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=cwd,
        check=False,
    )


@pytest.fixture
def issued(tmp_path):
    """A v2 report signed by acme-2026 plus a store enrolling it (and an unrelated key)."""
    (tmp_path / "in.json").write_text(json.dumps({"p": [0.2, 0.3, 0.5], "q": [0.25, 0.25, 0.5]}))
    kg = _cli("keygen", "--key-id", "acme-2026", "--issuer", "acme", "--private-key", "k.pem",
              "--public-key", "k.pub", cwd=tmp_path)  # fmt: skip
    assert kg.returncode == 0, kg.stderr
    info = json.loads(kg.stdout)
    sg = _cli("audit", "drift", "-i", "in.json", "-o", "report.json", "--signing-key", "k.pem",
              "--key-id", "acme-2026", "--issuer", "acme", "--deployment-id", "prod-1",
              cwd=tmp_path)  # fmt: skip
    assert sg.returncode == 0, sg.stderr
    add = _cli("trust", "add", "--store", "s.json", "--key-id", "acme-2026", "--issuer", "acme",
               "--public-key", "k.pub", "--fingerprint", info["fingerprint_sha256"], cwd=tmp_path)  # fmt: skip
    assert add.returncode == 0, add.stderr
    return tmp_path


def _verify(work: Path) -> subprocess.CompletedProcess[str]:
    return _cli("verify", "-i", "report.json", "--trusted-keys", "s.json", cwd=work)


def test_cli_status_retire_revoke_flow_changes_verdicts(issued):
    ok = _verify(issued)
    assert ok.returncode == 0 and json.loads(ok.stdout)["trust_status"] == "TRUSTED"

    st = _cli("trust", "status", "--store", "s.json", cwd=issued)
    assert st.returncode == 0 and json.loads(st.stdout)["keys"][0]["status"] == "active"
    assert _verify(issued).stdout == ok.stdout  # status is read-only: verdict bytes identical

    rt = _cli("trust", "retire", "--store", "s.json", "--key-id", "acme-2026", cwd=issued)
    assert rt.returncode == 0, rt.stderr
    after_retire = _verify(issued)
    assert after_retire.returncode == 1  # no authenticated chronology -> refused, not trusted
    assert json.loads(after_retire.stdout)["trust_status"] == "INVALID"

    rv = _cli("trust", "revoke", "--store", "s.json", "--key-id", "acme-2026", cwd=issued)
    assert rv.returncode == 0, rv.stderr
    after_revoke = _verify(issued)
    assert after_revoke.returncode == 1
    assert json.loads(after_revoke.stdout)["key_status"] == "compromised"


def test_cli_exit_codes(issued):
    assert (
        _cli("trust", "retire", "--store", "s.json", "--key-id", "nope", cwd=issued).returncode == 2
    )
    assert (
        _cli("trust", "retire", "--store", "missing.json", "--key-id", "x", cwd=issued).returncode
        == 3
    )
    (issued / "bad.json").write_text("{not json")
    assert _cli("trust", "status", "--store", "bad.json", cwd=issued).returncode == 3
    assert (
        _cli("trust", "revoke", "--store", "s.json", "--key-id", "acme-2026",
             "--compromised-from", "garbage", cwd=issued).returncode == 2
    )  # fmt: skip


def test_editing_one_key_does_not_change_verdict_for_another(issued):
    """Compat control: verdict JSON for an untouched key is byte-identical after unrelated edits."""
    store = json.loads((issued / "s.json").read_text())
    store["entries"]["other-1"] = {"issuer": "x", "public_key_pem": _pem(), "status": "active"}
    (issued / "s.json").write_text(json.dumps(store, indent=2))
    before = _verify(issued)
    lc.retire(str(issued / "s.json"), "other-1", at=None, now=datetime.now(timezone.utc))
    after = _verify(issued)
    assert before.returncode == after.returncode == 0
    drop = lambda o: {k: v for k, v in json.loads(o).items() if k != "trust_store_as_of"}  # noqa: E731
    assert drop(before.stdout) == drop(after.stdout)


def test_store_edited_by_lifecycle_loads_identically_for_unchanged_entries(tmp_path):
    path = _store(tmp_path)
    old = TrustStore.from_json(str(path))
    lc.retire(str(path), "a-1", at=None, now=NOW)
    new = TrustStore.from_json(str(path))
    assert new.entry("b-1") == old.entry("b-1")
    assert new.keys == old.keys  # the lifecycle never touches key material


def test_as_of_is_monotonic_within_the_clock_skew_allowance(tmp_path):
    path = _store(tmp_path)
    lc.retire(str(path), "a-1", at=None, now=datetime(2026, 10, 31, 12, 2, tzinfo=timezone.utc))
    lc.revoke(str(path), "b-1", compromised_from=None, now=NOW)  # clock 2 minutes behind
    assert json.loads(path.read_text())["as_of"] == "2026-10-31T12:02:00Z"
