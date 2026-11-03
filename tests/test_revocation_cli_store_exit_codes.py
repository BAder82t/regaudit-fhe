"""An unusable trust store is an infrastructure failure: exit 3 from ``revocation enroll`` and ``rebaseline``, nothing changed.

``TrustStoreError`` is a ``ValueError``, so it has to be caught before the handler for a refusal.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from regaudit_fhe import _revocation_cli as revocation_cli
from regaudit_fhe import _revocation_state as st
from regaudit_fhe.trust import ISSUER_PROVENANCE_SUFFIX, MAX_TRUST_STORE_BYTES

from .test_revocation_tooling_and_cli import cli, op, verify_cli  # noqa: F401


def _missing(path: Path) -> None:
    assert not path.exists()


def _directory(path: Path) -> None:
    path.mkdir()


def _malformed(path: Path) -> None:
    path.write_text("{")


def _not_utf8(path: Path) -> None:
    path.write_bytes(b"\xff\xfe{}")


def _duplicate_key(path: Path) -> None:
    path.write_text('{"keys": {}, "keys": {}}')


def _not_an_object(path: Path) -> None:
    path.write_text("[]")


def _oversized(path: Path) -> None:
    path.write_bytes(b" " * (MAX_TRUST_STORE_BYTES + 1))


def _leftover_record(path: Path) -> None:
    path.write_bytes((path.parent / "t.json").read_bytes())
    path.with_name(path.name + ISSUER_PROVENANCE_SUFFIX).write_text("{}")


UNUSABLE = [
    pytest.param(_missing, "unreadable", id="missing"),
    pytest.param(_directory, "unreadable", id="directory"),
    pytest.param(_malformed, "not valid JSON", id="malformed"),
    pytest.param(_not_utf8, "unreadable", id="not-utf8"),
    pytest.param(_duplicate_key, "not valid JSON", id="duplicate-key"),
    pytest.param(_not_an_object, "must be a JSON object", id="not-an-object"),
    pytest.param(_oversized, "exceeds", id="oversized"),
    pytest.param(_leftover_record, "migrat", id="leftover-provenance-record"),
]


def snapshot(root: Path) -> dict[str, tuple[int, bytes | None]]:
    """Every path under ``root`` with its mode and, for a file, its bytes."""
    out = {}
    for path in sorted(root.rglob("*")):
        info = path.stat()
        out[path.relative_to(root).as_posix()] = (
            info.st_mode,
            path.read_bytes() if path.is_file() else None,
        )
    return out


def _pin_args(
    fps: dict[str, str], pins: str, state: str, authority: str = "authority"
) -> tuple[str, ...]:
    return (
        "--pins", pins, "--state", state, "--issuer", "acme",
        "--authority-key", f"{authority}.pub", "--authority-fingerprint", fps[authority],
        "--anchor-key", "anchor.pub", "--anchor-fingerprint", fps["anchor"], "--baseline-epoch", "0",
    )  # fmt: skip


def enroll(
    cwd: Path,
    fps: dict[str, str],
    store: str = "t.json",
    pins: str = "new-pins.json",
    authority: str = "authority",
):
    return cli(
        "revocation",
        "enroll",
        *_pin_args(fps, pins, "new-state", authority),
        "--trusted-keys",
        store,
        cwd=cwd,
    )


def rebaseline(cwd: Path, fps: dict[str, str], store: str = "t.json", authority: str = "authority"):
    return cli(
        "revocation",
        "rebaseline",
        *_pin_args(fps, "pins.json", "state", authority),
        "--trusted-keys",
        store,
        cwd=cwd,
    )


@pytest.fixture
def world(op):  # noqa: F811
    """An enrolled verifier that has written replay state, so a snapshot covers pins, enrollment and replay."""
    cwd, fps = op
    assert (
        verify_cli(cwd).returncode == 1
    )  # no list yet: refused by policy, after opening the replay file
    assert (cwd / "replay.db").is_file()
    assert (cwd / "pins.json").is_file() and any((cwd / "state").iterdir())
    return cwd, fps


@pytest.mark.parametrize(("make", "says"), UNUSABLE)
def test_enroll_exits_3_on_an_unusable_store_and_changes_nothing(world, make, says):
    cwd, fps = world
    make(cwd / "bad.json")
    before = snapshot(cwd)
    out = enroll(cwd, fps, "bad.json")
    assert out.returncode == 3, out.stderr
    assert says in out.stderr and "refused" not in out.stderr and "Traceback" not in out.stderr
    assert snapshot(cwd) == before


@pytest.mark.parametrize(("make", "says"), UNUSABLE)
def test_rebaseline_exits_3_on_an_unusable_store_and_changes_nothing(world, make, says):
    cwd, fps = world
    make(cwd / "bad.json")
    before = snapshot(cwd)
    out = rebaseline(cwd, fps, "bad.json")
    assert out.returncode == 3, out.stderr
    assert says in out.stderr and "refused" not in out.stderr and "Traceback" not in out.stderr
    assert snapshot(cwd) == before


def test_enroll_with_a_usable_store_succeeds(world):
    cwd, fps = world
    out = enroll(cwd, fps)
    assert out.returncode == 0, out.stderr
    assert (cwd / "new-pins.json").is_file() and any((cwd / "new-state").iterdir())


def test_rebaseline_with_a_usable_store_succeeds(world):
    cwd, fps = world
    pins = json.loads((cwd / "pins.json").read_text())
    out = rebaseline(cwd, fps)
    assert out.returncode == 0, out.stderr
    assert json.loads((cwd / "pins.json").read_text()) != pins


def test_enroll_exits_3_on_malformed_pins_and_changes_nothing(world):
    cwd, fps = world
    (cwd / "new-pins.json").write_text("{")
    before = snapshot(cwd)
    out = enroll(cwd, fps)
    assert out.returncode == 3, out.stderr
    assert "pin file" in out.stderr and "refused" not in out.stderr
    assert snapshot(cwd) == before


def test_rebaseline_exits_3_on_malformed_pins(world):
    cwd, fps = world
    (cwd / "pins.json").write_text("{")
    out = rebaseline(cwd, fps)
    assert out.returncode == 3, out.stderr
    assert "pin file" in out.stderr and "refused" not in out.stderr


def test_rebaseline_on_malformed_pins_changes_nothing(world):
    cwd, fps = world
    (cwd / "pins.json").write_text("{")
    before = snapshot(cwd)
    assert rebaseline(cwd, fps).returncode == 3
    assert snapshot(cwd) == before


def test_rebaseline_that_failed_on_malformed_pins_leaves_verification_as_it_was(world):
    cwd, fps = world
    pins = (cwd / "pins.json").read_bytes()
    (cwd / "pins.json").write_text("{")
    assert rebaseline(cwd, fps).returncode == 3
    (cwd / "pins.json").write_bytes(pins)
    assert verify_cli(cwd).returncode == 1  # no list yet: refused by policy, as before the failure
    assert rebaseline(cwd, fps).returncode == 0
    assert verify_cli(cwd).returncode == 1


@pytest.mark.parametrize("flag", ["--clear-key-actions", "--reset-policy-floor", "--accept-loss"])
def test_rebaseline_flags_change_nothing_when_the_pins_are_malformed(world, flag):
    cwd, fps = world
    (cwd / "pins.json").write_text("{")
    before = snapshot(cwd)
    args = _pin_args(fps, "pins.json", "state")
    assert (
        cli("revocation", "rebaseline", *args, "--trusted-keys", "t.json", flag, cwd=cwd).returncode
        == 3
    )
    assert snapshot(cwd) == before


def test_rebaseline_on_a_group_writable_pin_file_changes_nothing(world):
    cwd, fps = world
    (cwd / "pins.json").chmod(0o660)
    before = snapshot(cwd)
    assert rebaseline(cwd, fps).returncode == 3
    assert snapshot(cwd) == before


def test_rebaseline_with_a_pin_directory_it_cannot_write_changes_nothing(world, tmp_path_factory):
    cwd, fps = world
    box = tmp_path_factory.mktemp("pins")
    (box / "pins.json").write_bytes((cwd / "pins.json").read_bytes())
    (box / "pins.json").chmod(0o600)
    box.chmod(0o500)
    before = snapshot(cwd)
    try:
        args = _pin_args(fps, str(box / "pins.json"), "state")
        assert (
            cli("revocation", "rebaseline", *args, "--trusted-keys", "t.json", cwd=cwd).returncode
            == 3
        )
        assert snapshot(cwd) == before
    finally:
        box.chmod(0o700)


def test_rebaseline_on_malformed_pins_does_not_create_a_state_directory(world):
    cwd, fps = world
    (cwd / "other-pins.json").write_text("{")
    args = _pin_args(fps, "other-pins.json", "other-state")
    out = cli(
        "revocation", "rebaseline", *args, "--trusted-keys", "t.json", "--accept-loss", cwd=cwd
    )
    assert out.returncode == 3 and not (cwd / "other-state").exists()


class _Args:
    """What the parser gives ``_cmd_rebaseline``, for the failures only an in-process fault can reach."""

    def __init__(
        self, cwd: Path, fps: dict[str, str], state: str = "state", accept_loss: bool = False
    ):
        self.pins, self.state, self.issuer = str(cwd / "pins.json"), str(cwd / state), "acme"
        self.authority_key, self.authority_fingerprint = (
            str(cwd / "authority.pub"),
            fps["authority"],
        )
        self.anchor_key, self.anchor_fingerprint = str(cwd / "anchor.pub"), fps["anchor"]
        self.first_use, self.baseline_epoch, self.baseline_digest = False, 0, None
        self.authority_generation, self.recovery_epoch, self.recovery_digest = 1, 0, None
        self.trusted_keys = str(cwd / "t.json")
        self.clear_key_actions, self.accept_loss, self.reset_policy_floor = (
            False,
            accept_loss,
            False,
        )


def _save_fails(*_args, **_kwargs):
    raise st.PinStoreError("the disk filled up")


def test_a_save_that_fails_after_the_checks_puts_the_record_back(world, monkeypatch, capsys):
    cwd, fps = world
    before = snapshot(cwd)
    monkeypatch.setattr(st, "save_pin", _save_fails)
    assert revocation_cli._cmd_rebaseline(_Args(cwd, fps)) == 3
    assert "the disk filled up" in capsys.readouterr().err
    assert snapshot(cwd) == before


def test_a_save_that_fails_removes_a_record_that_did_not_exist_before(world, monkeypatch):
    cwd, fps = world
    monkeypatch.setattr(st, "save_pin", _save_fails)
    assert revocation_cli._cmd_rebaseline(_Args(cwd, fps, "empty-state", accept_loss=True)) == 3
    assert not [p for p in (cwd / "empty-state").iterdir() if p.name != ".lock"]


def test_rebaseline_checks_the_pin_directory_before_it_touches_the_record(
    world, tmp_path_factory, monkeypatch
):
    cwd, fps = world
    box = tmp_path_factory.mktemp("pins")
    box.chmod(0o500)

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("the record was touched before the pin directory was checked")

    monkeypatch.setattr(st, "rebaseline", must_not_run)
    args = _Args(cwd, fps)
    args.pins = str(box / "pins.json")
    try:
        assert revocation_cli._cmd_rebaseline(args) == 3
    finally:
        box.chmod(0o700)


def test_a_record_changed_during_the_ceremony_is_not_overwritten_by_the_undo(
    world, monkeypatch, capsys
):
    cwd, fps = world
    store = st.FileStateStore(cwd / "state")
    newer = []

    def someone_else_writes(_path, pin):
        current = store.read(pin.issuer)
        newer.append(current + b" ")
        assert store.cas(pin.issuer, current, newer[0])
        raise st.PinStoreError("the disk filled up")

    monkeypatch.setattr(st, "save_pin", someone_else_writes)
    assert revocation_cli._cmd_rebaseline(_Args(cwd, fps)) == 3
    assert "repeat the ceremony" in capsys.readouterr().err
    assert store.read("acme") == newer[0]


# ----------------------------------------------------------------------------- C3-08: enrollment


def _enroll_args(
    cwd: Path, fps: dict[str, str], authority: str = "authority", pins: str = "new-pins.json"
):
    args = _Args(cwd, fps, "new-state")
    args.pins = str(cwd / pins)
    args.authority_key, args.authority_fingerprint = str(cwd / f"{authority}.pub"), fps[authority]
    return args


def _state_records(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.glob("*.state"))


def test_enroll_with_a_pin_directory_it_cannot_write_writes_nothing_and_can_be_retried(
    world, tmp_path_factory
):
    cwd, fps = world
    box = tmp_path_factory.mktemp("pins")
    box.chmod(0o500)
    args = _pin_args(fps, str(box / "pins.json"), "new-state")
    before = snapshot(cwd)
    try:
        out = cli("revocation", "enroll", *args, "--trusted-keys", "t.json", cwd=cwd)
        assert out.returncode == 3, out.stderr
        assert snapshot(cwd) == before and not (cwd / "new-state").exists()
    finally:
        box.chmod(0o700)
    out = cli("revocation", "enroll", *args, "--trusted-keys", "t.json", cwd=cwd)
    assert out.returncode == 0, out.stderr
    assert json.loads((box / "pins.json").read_text())["pins"]["acme"]


def test_enroll_checks_the_pin_directory_before_it_writes_a_record(
    world, tmp_path_factory, monkeypatch
):
    cwd, fps = world
    box = tmp_path_factory.mktemp("pins")
    box.chmod(0o500)

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("the record was written before the pin directory was checked")

    monkeypatch.setattr(st, "enroll", must_not_run)
    args = _enroll_args(cwd, fps)
    args.pins = str(box / "pins.json")
    try:
        assert revocation_cli._cmd_enroll(args) == 3
    finally:
        box.chmod(0o700)


def test_a_failed_pin_write_during_enroll_removes_the_record_and_a_retry_succeeds(
    world, monkeypatch, capsys
):
    cwd, fps = world
    with monkeypatch.context() as during:
        during.setattr(st, "save_pin", _save_fails)
        assert revocation_cli._cmd_enroll(_enroll_args(cwd, fps)) == 3
    assert "the disk filled up" in capsys.readouterr().err
    assert _state_records(cwd / "new-state") == [] and not (cwd / "new-pins.json").exists()
    assert revocation_cli._cmd_enroll(_enroll_args(cwd, fps)) == 0
    assert len(_state_records(cwd / "new-state")) == 1
    pins = json.loads((cwd / "new-pins.json").read_text())["pins"]
    assert list(pins) == ["acme"]
    record = (cwd / "new-state" / _state_records(cwd / "new-state")[0]).read_text()
    assert pins["acme"]["enrollment_id"] in record


def test_a_record_changed_during_a_failed_enroll_is_not_removed(world, monkeypatch, capsys):
    cwd, fps = world
    store = st.FileStateStore(cwd / "new-state")
    newer = []

    def someone_else_writes(_path, pin):
        current = store.read(pin.issuer)
        newer.append(current + b" ")
        assert store.cas(pin.issuer, current, newer[0])
        raise st.PinStoreError("the disk filled up")

    monkeypatch.setattr(st, "save_pin", someone_else_writes)
    assert revocation_cli._cmd_enroll(_enroll_args(cwd, fps)) == 3
    assert "repeat the ceremony" in capsys.readouterr().err
    assert store.read("acme") == newer[0]


def test_enroll_after_a_good_save_is_unchanged(world):
    cwd, fps = world
    assert enroll(cwd, fps).returncode == 0
    before = snapshot(cwd)
    out = enroll(cwd, fps)
    assert out.returncode == 2 and "already enrolled" in out.stderr
    assert snapshot(cwd) == before


def _crash_at(point: str, cwd: Path, argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    """A real process that dies at a real write, with no cleanup: ``os._exit`` runs no handler."""
    code = f"""
import os, sys
from regaudit_fhe import _revocation_state as st
from regaudit_fhe.cli import main
def die(*_a, **_k):
    os._exit(9)
{point}
sys.exit(main(sys.argv[1:]))
"""
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code, *argv],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_a_crash_before_the_record_is_written_leaves_nothing(world):
    cwd, fps = world
    args = (
        "revocation",
        "enroll",
        *_pin_args(fps, "new-pins.json", "new-state"),
        "--trusted-keys",
        "t.json",
    )
    before = snapshot(cwd)
    assert _crash_at("st.enroll = die", cwd, args).returncode == 9
    after = snapshot(cwd)
    after.pop("new-state", None)
    assert after == before
    assert enroll(cwd, fps).returncode == 0


def test_a_crash_after_the_record_and_before_the_pin_fails_closed_and_is_recoverable(world):
    """No journal: the record stays. It grants nothing without a pin, a retry says so, and rebaseline recovers it."""
    cwd, fps = world
    enroll_args = (
        "revocation",
        "enroll",
        *_pin_args(fps, "new-pins.json", "new-state"),
        "--trusted-keys",
        "t.json",
    )
    assert _crash_at("st.save_pin = die", cwd, enroll_args).returncode == 9
    assert len(_state_records(cwd / "new-state")) == 1 and not (cwd / "new-pins.json").exists()
    record = (cwd / "new-state" / _state_records(cwd / "new-state")[0]).read_bytes()

    no_pin = verify_cli(
        cwd,
        "--revocation-pins",
        "new-pins.json",
        "--revocation-state",
        "new-state",
        mode="required",
    )
    assert no_pin.returncode == 3, no_pin.stdout + no_pin.stderr

    # a retry changes nothing and names the way out, and a different authority cannot get in that way
    for authority in ("authority", "authority2"):
        again = enroll(cwd, fps, authority=authority)
        assert again.returncode == 2 and "re-baselining" in again.stderr
        assert (cwd / "new-state" / _state_records(cwd / "new-state")[0]).read_bytes() == record
        assert not (cwd / "new-pins.json").exists()

    args = _pin_args(fps, "new-pins.json", "new-state")
    out = cli("revocation", "rebaseline", *args, "--trusted-keys", "t.json", cwd=cwd)
    assert out.returncode == 0, out.stderr
    assert len(_state_records(cwd / "new-state")) == 1
    pins = json.loads((cwd / "new-pins.json").read_text())["pins"]
    assert list(pins) == ["acme"]
    assert (
        pins["acme"]["enrollment_id"]
        in (cwd / "new-state" / _state_records(cwd / "new-state")[0]).read_text()
    )


def test_a_crash_after_the_pin_is_saved_is_a_complete_enrollment(world):
    cwd, fps = world
    code_args = (
        "revocation",
        "enroll",
        *_pin_args(fps, "new-pins.json", "new-state"),
        "--trusted-keys",
        "t.json",
    )
    point = (
        "real = st.save_pin\n"
        "def save_then_die(*a, **k):\n"
        "    real(*a, **k)\n"
        "    os._exit(9)\n"
        "st.save_pin = save_then_die"
    )
    assert _crash_at(point.replace("\\n", "\n"), cwd, code_args).returncode == 9
    pins = json.loads((cwd / "new-pins.json").read_text())["pins"]
    assert (
        pins["acme"]["enrollment_id"]
        in (cwd / "new-state" / _state_records(cwd / "new-state")[0]).read_text()
    )
    again = enroll(cwd, fps)
    assert again.returncode == 2 and "already enrolled" in again.stderr


# ----------------------------------------------------------------------------- review findings


macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACLs")


def _set_acl(path: Path, entry: str) -> None:
    subprocess.run(["/bin/chmod", "+a", entry, str(path)], check=True, capture_output=True)  # noqa: S603


def _state_record(cwd: Path) -> Path:
    return next((cwd / "state").glob("*.state"))


@macos
def test_a_write_acl_on_the_state_record_stops_verification(world):
    cwd, _ = world
    assert verify_cli(cwd).returncode == 1
    _set_acl(_state_record(cwd), "group:everyone allow write")
    refused = verify_cli(cwd)
    assert refused.returncode == 3, refused.stdout + refused.stderr


@macos
def test_a_write_acl_on_the_pin_file_stops_verification(world):
    cwd, _ = world
    _set_acl(cwd / "pins.json", "group:everyone allow write")
    assert verify_cli(cwd).returncode == 3
    assert (
        cli(
            "revocation",
            "status",
            "--pins",
            "pins.json",
            "--state",
            "state",
            "--issuer",
            "acme",
            cwd=cwd,
        ).returncode
        != 0
    )


@macos
def test_a_write_acl_on_the_state_directory_stops_verification(world):
    cwd, _ = world
    _set_acl(cwd / "state", "group:everyone allow add_file")
    assert verify_cli(cwd).returncode == 3


def _move_under_a_writable_parent(cwd: Path) -> None:
    """The state and pin files move below a directory others can write, and the tree is otherwise safe."""
    box = cwd / "box"
    box.mkdir()
    (cwd / "state").rename(box / "state")
    (cwd / "pins.json").rename(box / "pins.json")
    (box).chmod(0o777)


def test_a_parent_directory_others_can_write_stops_status(world):
    cwd, _ = world
    _move_under_a_writable_parent(cwd)
    out = cli(
        "revocation",
        "status",
        "--pins",
        "box/pins.json",
        "--state",
        "box/state",
        "--issuer",
        "acme",
        cwd=cwd,
    )
    assert out.returncode != 0 and "writable by group or others" in out.stderr


def test_ingest_refuses_a_store_others_can_write(world):
    cwd, _ = world
    (cwd / "list.json").write_text("{}")
    (cwd / "t.json").chmod(0o666)
    before = snapshot(cwd)
    out = cli(
        "revocation", "ingest", "list", "list.json", "--pins", "pins.json", "--state", "state", "--issuer", "acme",
        "--trusted-keys", "t.json", cwd=cwd,
    )  # fmt: skip
    assert out.returncode == 3 and "lets group or others write" in out.stderr
    assert snapshot(cwd) == before


@pytest.mark.parametrize("command", [enroll, rebaseline], ids=["enroll", "rebaseline"])
def test_a_pin_directory_that_cannot_be_read_changes_nothing(world, tmp_path_factory, command):
    """Mode 0300: the new pin could be renamed into place, and then the directory could not be opened to sync it."""
    cwd, fps = world
    box = tmp_path_factory.mktemp("pins")
    (box / "pins.json").write_bytes((cwd / "pins.json").read_bytes())
    (box / "pins.json").chmod(0o600)
    box.chmod(0o300)
    before = snapshot(cwd)
    try:
        if command is enroll:
            out = cli(
                "revocation",
                "enroll",
                *_pin_args(fps, str(box / "new.json"), "new-state"),
                "--trusted-keys",
                "t.json",
                cwd=cwd,
            )
        else:
            out = cli(
                "revocation",
                "rebaseline",
                *_pin_args(fps, str(box / "pins.json"), "state"),
                "--trusted-keys",
                "t.json",
                cwd=cwd,
            )
        assert out.returncode == 3, out.stderr
        assert snapshot(cwd) == before
    finally:
        box.chmod(0o700)
    assert sorted(p.name for p in box.iterdir()) == ["pins.json"]


def _sync_fails_after_the_rename(monkeypatch) -> None:
    """Only inside the pin save: its first sync is the file, its second is the directory after the rename."""
    real_sync, real_save, calls = st._sync, st.save_pin, []

    def second_call_fails(fd, fcntl):
        if calls:
            calls.append(fd)
            if len(calls) == 3:
                raise OSError("the directory could not be synced")
        return real_sync(fd, fcntl)

    def save(path, pin):
        calls.append("saving")
        return real_save(path, pin)

    monkeypatch.setattr(st, "_sync", second_call_fails)
    monkeypatch.setattr(st, "save_pin", save)


def test_enroll_keeps_the_record_when_the_pin_is_already_in_place(world, monkeypatch, capsys):
    cwd, fps = world
    with monkeypatch.context() as during:
        _sync_fails_after_the_rename(during)
        assert revocation_cli._cmd_enroll(_enroll_args(cwd, fps)) == 3
    assert "could not be synced" in capsys.readouterr().err
    pins = json.loads((cwd / "new-pins.json").read_text())["pins"]
    records = _state_records(cwd / "new-state")
    assert len(records) == 1
    assert pins["acme"]["enrollment_id"] in (cwd / "new-state" / records[0]).read_text()
    args = (
        "revocation",
        "status",
        "--pins",
        "new-pins.json",
        "--state",
        "new-state",
        "--issuer",
        "acme",
    )
    assert cli(*args, cwd=cwd).returncode == 0


def test_rebaseline_keeps_the_record_when_the_pin_is_already_in_place(world, monkeypatch, capsys):
    cwd, fps = world
    with monkeypatch.context() as during:
        _sync_fails_after_the_rename(during)
        assert revocation_cli._cmd_rebaseline(_Args(cwd, fps)) == 3
    assert "could not be synced" in capsys.readouterr().err
    pins = json.loads((cwd / "pins.json").read_text())["pins"]
    assert pins["acme"]["enrollment_id"] in _state_record(cwd).read_text()
    assert (
        cli(
            "revocation",
            "status",
            "--pins",
            "pins.json",
            "--state",
            "state",
            "--issuer",
            "acme",
            cwd=cwd,
        ).returncode
        == 0
    )


@pytest.mark.parametrize("command", [enroll, rebaseline], ids=["enroll", "rebaseline"])
def test_a_wrong_fingerprint_is_still_a_refusal(world, command):
    cwd, fps = world
    before = snapshot(cwd)
    out = command(cwd, dict(fps, authority="0" * 64))
    assert out.returncode == 2 and "fingerprint mismatch" in out.stderr
    assert snapshot(cwd) == before


@pytest.mark.parametrize("command", [enroll, rebaseline], ids=["enroll", "rebaseline"])
def test_a_refusal_that_a_usable_store_causes_is_still_exit_2(world, command):
    cwd, fps = world
    before = snapshot(cwd)
    out = command(cwd, fps, authority="report")
    assert out.returncode == 2 and "report-signing" in out.stderr
    after = snapshot(cwd)
    if (
        command is enroll
    ):  # the state directory is made before the store check refuses; it stays empty
        made = after.pop("new-state")
        assert made[1] is None
    assert after == before
