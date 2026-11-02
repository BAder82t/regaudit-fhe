"""An unusable trust store is an infrastructure failure: exit 3 from ``revocation enroll`` and ``rebaseline``, nothing changed.

``TrustStoreError`` is a ``ValueError``, so it has to be caught before the handler for a refusal.
"""

from __future__ import annotations

import json
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
