"""An unusable trust store is an infrastructure failure: exit 3 from ``revocation enroll`` and ``rebaseline``, nothing changed.

``TrustStoreError`` is a ``ValueError``, so it has to be caught before the handler for a refusal.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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


@pytest.mark.xfail(
    strict=True,
    reason="C3-06, open: rebaseline commits the state record before save_pin reads the pin file. Not part of C3-01.",
)
def test_rebaseline_on_malformed_pins_changes_nothing(world):
    cwd, fps = world
    (cwd / "pins.json").write_text("{")
    before = snapshot(cwd)
    rebaseline(cwd, fps)
    assert snapshot(cwd) == before


def test_rebaseline_that_failed_on_malformed_pins_still_fails_closed_and_can_be_repeated(world):
    cwd, fps = world
    pins = (cwd / "pins.json").read_bytes()
    (cwd / "pins.json").write_text("{")
    assert rebaseline(cwd, fps).returncode == 3
    (cwd / "pins.json").write_bytes(
        pins
    )  # the operator repairs the file: the old pin no longer matches the record
    stale = verify_cli(cwd)
    assert stale.returncode == 3, stale.stdout + stale.stderr
    assert json.loads(stale.stdout)["trust_status"] != "TRUSTED"
    assert rebaseline(cwd, fps).returncode == 0
    assert verify_cli(cwd).returncode == 1  # no list yet: refused by policy, as before the failure


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
        assert after.pop("new-state")[1] is None
    assert after == before
