"""``admin-describe`` and ``admin-apply``: what they refuse, what they write, and that a stop part-way changes nothing.

Every apply here runs the engine's real ``trust add`` enrolment code and the real engine check. Nothing is mocked except
where a test says what it simulates (a failure at one exact step, another account, or root).
"""

from __future__ import annotations

import ast
import contextlib
import fcntl
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest
import regaudit_portal.engine as engine_module
from helpers import (
    crafted_plan,
    fingerprint_of,
    issuer_signer,
    prepare_plan,
    snapshot,
)
from regaudit_portal import admin
from regaudit_portal.__main__ import main
from regaudit_portal.config import load_portal, read_settings, read_trust_store
from regaudit_portal.demo import create
from regaudit_portal.paths import default_config_folder
from test_setup import _forbid_writes

import regaudit_fhe as rf

PORTAL = Path(__file__).resolve().parents[1]
SAMPLES = PORTAL / "regaudit_portal" / "samples"


def _plan_file(tmp_path: Path, text: str | bytes, name: str = "setup-plan.json") -> Path:
    path = tmp_path / name
    path.write_bytes(text if isinstance(text, bytes) else text.encode())
    return path


def _expect(*signers: rf.Signer) -> list[str]:
    found = []
    for signer in signers:
        found += ["--expect-fingerprint", f"{signer.key_id}={fingerprint_of(signer)}"]
    return found


def _private_folder(path: Path) -> Path:
    path.mkdir(parents=True)
    os.chmod(path, 0o700)
    return path


def _entries(folder: Path) -> dict[str, tuple]:
    """What a folder holds, without the folder's own timestamp, which changes when a temporary folder comes and goes."""
    return {name: found for name, found in snapshot(folder).items() if name != "."}


def _no_control_characters(*texts: str) -> None:
    for text in texts:
        assert not re.search(r"[\x00-\x09\x0b-\x1f\x7f\x80-\x9f‪-‮⁦-⁩]", text), repr(text)


# ----------------------------------------------------------------------------- a first setup


def test_a_first_setup_creates_the_standard_folder_and_both_files_privately(
    home, tmp_path, run, northwind
):
    text = prepare_plan([northwind])
    plan = _plan_file(tmp_path, text)
    code, out, err = run("admin-describe", plan)
    assert (
        code == 0
        and "Destination check: it can be applied here." in out
        and fingerprint_of(northwind) not in out
    )
    code, out, err = run("admin-apply", plan, *_expect(northwind))
    assert code == 0, err
    folder = default_config_folder()
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    assert sorted(p.name for p in folder.iterdir()) == ["portal-config.json", "trust-store.json"]
    for name in ("portal-config.json", "trust-store.json"):
        info = (folder / name).stat()
        assert (
            stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
        )
    from regaudit_portal.plan import read_plan

    written = read_plan(text.encode())
    assert (folder / "portal-config.json").read_text() == written.configuration_text()
    assert (folder / "trust-store.json").read_text() == written.trust_list_text()
    assert written.configuration_text() in out and written.trust_list_text().rstrip() in out
    assert "Restart it to use this configuration" in out
    assert not list(folder.parent.glob(".regaudit-admin-*"))
    portal = load_portal(folder / "portal-config.json")
    assert portal.profile == "confidential" and portal.approved_count == 1
    code, out, _ = run("check-config")
    assert code == 0 and out.startswith("usable: profile confidential, 1 approved issuer entry")


def test_the_trust_list_on_disk_is_what_regaudit_fhe_trust_add_writes(home, tmp_path, run):
    signers = [issuer_signer("Northwind Ltd", "nw-1"), issuer_signer("Ünïcode GmbH", "u-2")]
    assert (
        run("admin-apply", _plan_file(tmp_path, prepare_plan(signers)), *_expect(*signers))[0] == 0
    )
    store = tmp_path / "by-hand.json"
    for signer in signers:
        key = tmp_path / f"{signer.key_id}.pub"
        key.write_text(signer.public_key_pem())
        done = subprocess.run(  # noqa: S603 - the engine's own command, fixed arguments
            [sys.executable, "-m", "regaudit_fhe.cli", "trust", "add", "--store", str(store), "--key-id",
             signer.key_id, "--issuer", signer.issuer, "--public-key", str(key), "--fingerprint",
             fingerprint_of(signer)],
            capture_output=True, text=True, timeout=60, check=False,
        )  # fmt: skip
        assert done.returncode == 0, done.stderr
    assert (default_config_folder() / "trust-store.json").read_bytes() == store.read_bytes()


def test_a_first_setup_into_an_existing_private_folder_with_other_files_leaves_them_alone(
    tmp_path, home, run, northwind
):
    folder = _private_folder(tmp_path / "custom" / "config")
    os.chmod(folder.parent, 0o755)  # noqa: S103 - readable by others, changeable only by this account
    (folder / "replay.db").write_bytes(b"kept")
    (folder / ".DS_Store").write_bytes(b"finder")
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    code, _, err = run("admin-apply", plan, "--config-folder", folder, *_expect(northwind))
    assert code == 0, err
    assert (folder / "replay.db").read_bytes() == b"kept" and (
        folder / ".DS_Store"
    ).read_bytes() == b"finder"
    assert not list(folder.glob(".regaudit-admin-*"))
    assert (folder / "trust-store.json").stat().st_nlink == 1
    read_trust_store(read_settings(folder / "portal-config.json"))


def test_a_relative_config_folder_is_taken_from_where_the_command_runs(
    tmp_path, home, run, northwind, monkeypatch
):
    work = _private_folder(tmp_path / "work")
    monkeypatch.chdir(work)
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    assert run("admin-apply", plan, "--config-folder", "here", *_expect(northwind))[0] == 0
    assert (work / "here" / "portal-config.json").is_file()


def test_the_fingerprints_can_be_typed_at_the_terminal_instead(home, tmp_path, run, monkeypatch):
    signers = [issuer_signer("First Ltd", "first-1"), issuer_signer("Second Ltd", "second-1")]
    asked = []

    def answer(question: str) -> str:
        asked.append(question)
        signer = signers[len(asked) - 1]
        return fingerprint_of(signer).upper() + "\n"

    monkeypatch.setattr(admin, "ask_on_terminal", answer)
    code, _, err = run("admin-apply", _plan_file(tmp_path, prepare_plan(signers)))
    assert code == 0, err
    assert (
        '"First Ltd" (key id first-1)' in asked[0] and '"Second Ltd" (key id second-1)' in asked[1]
    )
    assert all(fingerprint_of(s) not in q for s, q in zip(signers, asked, strict=True))


@pytest.mark.skipif(not hasattr(os, "openpty"), reason="needs a pseudo-terminal")
def test_the_fingerprint_is_asked_on_a_real_terminal_and_never_read_from_standard_input(
    home, tmp_path, northwind
):
    """The command runs with a pseudo-terminal as its controlling terminal, as it does in Terminal."""
    import select
    import termios

    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    master, slave = os.openpty()

    def controlling_terminal() -> None:
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-m", "regaudit_portal", "admin-apply", str(plan)],
        env=_env(home), cwd=PORTAL, stdin=slave, stdout=slave, stderr=slave,
        preexec_fn=controlling_terminal,
    )  # fmt: skip
    os.close(slave)
    seen = b""
    try:
        deadline = time.monotonic() + 60
        while b"by another route: " not in seen and time.monotonic() < deadline:
            if select.select([master], [], [], 1)[0]:
                seen += os.read(master, 4096)
        assert b'"Northwind Ltd" (key id northwind-2026)' in seen
        os.write(master, fingerprint_of(northwind).encode() + b"\n")
        while proc.poll() is None and time.monotonic() < deadline:
            if select.select([master], [], [], 1)[0]:
                with contextlib.suppress(OSError):
                    seen += os.read(master, 4096)
        assert proc.wait(timeout=30) == 0, seen.decode(errors="replace")
    finally:
        if proc.poll() is None:
            proc.kill()
        os.close(master)
    assert (
        b"Applied setup plan" in seen and (default_config_folder() / "portal-config.json").is_file()
    )


def test_without_a_terminal_and_without_expect_fingerprint_it_refuses(
    home, tmp_path, run, northwind, monkeypatch
):
    def no_terminal(_question):
        raise OSError("no controlling terminal")

    monkeypatch.setattr(admin, "ask_on_terminal", no_terminal)
    code, _, err = run("admin-apply", _plan_file(tmp_path, prepare_plan([northwind])))
    assert code == 2 and "There is no terminal to ask in" in err
    assert not default_config_folder().exists()


def test_the_apply_module_never_reads_standard_input_and_asks_on_the_terminal_itself():
    source = (PORTAL / "regaudit_portal" / "admin.py").read_text()
    code = "\n".join(line for line in source.splitlines() if not line.strip().startswith("#"))
    tree = ast.parse(source)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "stdin" not in attributes and "input" not in names and "getpass" not in names
    assert '"/dev/tty"' in code and "os.read(0" not in code
    assert not attributes & {"environ", "getenv", "environb"} and "getenv" not in names


# ----------------------------------------------------------------------------- the typed fingerprint is the control


def test_a_hostile_plan_with_an_attackers_key_is_refused_when_the_real_issuers_fingerprint_is_typed(
    home, tmp_path, run, northwind
):
    """A web page made a browser download a plan that looks right: the real issuer's name and key id, the attacker's
    key, and a checksum that matches. The administrator types the fingerprint the real issuer gave them."""
    attacker = issuer_signer(northwind.issuer, northwind.key_id)
    content = json.loads(prepare_plan([northwind]))
    content["issuers"][0]["public_key_pem"] = attacker.public_key_pem()
    hostile = _plan_file(tmp_path, crafted_plan(content), "hostile.json")
    before = snapshot(home)
    code, out, err = run("admin-describe", hostile)
    assert code == 0 and fingerprint_of(attacker) not in out  # nothing to copy from
    code, out, err = run("admin-apply", hostile, *_expect(northwind))
    assert (
        code == 2 and "does not match the key in the plan" in err and "Nothing was changed" in err
    )
    assert fingerprint_of(attacker) not in err + out and fingerprint_of(northwind) not in err + out
    assert snapshot(home) == before and not default_config_folder().exists()


def test_a_hostile_plan_that_carries_its_own_matching_fingerprint_is_refused_before_anything_else(
    home, tmp_path, run, northwind
):
    attacker = issuer_signer(northwind.issuer, northwind.key_id)
    content = json.loads(prepare_plan([northwind]))
    content["issuers"][0]["public_key_pem"] = attacker.public_key_pem()
    content["issuers"][0]["fingerprint"] = fingerprint_of(attacker)
    hostile = _plan_file(tmp_path, crafted_plan(content), "hostile.json")
    for argv in (("admin-describe", hostile), ("admin-apply", hostile, *_expect(northwind))):
        code, out, err = run(*argv)
        assert code == 2 and "members a setup plan never has (fingerprint)" in err + out
    code, _, err = run(
        "admin-apply",
        hostile,
        "--expect-fingerprint",
        f"{northwind.key_id}={fingerprint_of(attacker)}",
    )
    assert code == 2 and not default_config_folder().exists()


@pytest.mark.parametrize(
    "shape, accepted",
    [
        (lambda fp: fp.upper(), True),
        (lambda fp: f"  {fp}  ", True),
        (lambda fp: ":".join(re.findall("..", fp)), False),
        (lambda fp: " ".join(re.findall("....", fp)), False),
        (lambda fp: fp[:-1], False),
        (lambda fp: fp.replace("a", "а", 1) if "a" in fp else "а" + fp[1:], False),
        (lambda fp: fp.translate(str.maketrans("0123456789", "０１２３４５６７８９")), False),
        (lambda fp: fp[:20] + "​" + fp[20:], False),
        (lambda fp: fp[:-1] + ("1" if fp[-1] != "1" else "2"), False),
        (lambda fp: "", False),
    ],
)
def test_fingerprint_near_misses_at_apply_time(home, tmp_path, run, northwind, shape, accepted):
    typed = shape(fingerprint_of(northwind))
    code, out, err = run(
        "admin-apply",
        _plan_file(tmp_path, prepare_plan([northwind])),
        "--expect-fingerprint",
        f"{northwind.key_id}={typed}",
    )
    assert (code == 0) is accepted, err
    if not accepted:
        assert default_config_folder().exists() is False and "Nothing was changed" in err
        if typed.strip():
            assert typed.strip() not in err
        _no_control_characters(out, err)


@pytest.mark.parametrize(
    "given, said",
    [
        (["--expect-fingerprint", "first-1=x"], "No fingerprint was given for"),
        (["--expect-fingerprint", "nobody=abc"], "with the key id of an issuer in the plan"),
        (["--expect-fingerprint", "no-equals-sign"], "must be KEY_ID=FINGERPRINT"),
    ],
)
def test_fingerprints_must_be_given_for_exactly_the_issuers_in_the_plan(
    home, tmp_path, run, given, said
):
    signers = [issuer_signer("First Ltd", "first-1"), issuer_signer("Second Ltd", "second-1")]
    code, _, err = run("admin-apply", _plan_file(tmp_path, prepare_plan(signers)), *given)
    assert code == 2 and said in err


def test_the_same_key_id_given_twice_is_refused(home, tmp_path, run, northwind):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    code, _, err = run("admin-apply", plan, *_expect(northwind), *_expect(northwind))
    assert code == 2 and "Two fingerprints were given" in err


def test_there_is_no_option_that_skips_the_typed_fingerprint(capsys):
    import argparse

    seen: dict[str, argparse.ArgumentParser] = {}
    real = argparse.ArgumentParser.parse_args

    def capture(self, args=None, namespace=None):
        seen.setdefault("parser", self)
        raise SystemExit(0)

    argparse.ArgumentParser.parse_args = capture
    try:
        with contextlib.suppress(SystemExit):
            main(["admin-apply", "x"])
    finally:
        argparse.ArgumentParser.parse_args = real
    parser = seen["parser"]
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    options = {o for action in sub.choices["admin-apply"]._actions for o in action.option_strings}
    assert options == {
        "-h",
        "--help",
        "--config-folder",
        "--expect-fingerprint",
        "--expect-plan-sha256",
    }
    tree = ast.parse((PORTAL / "regaudit_portal" / "admin.py").read_text())
    identifiers = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    identifiers |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    identifiers |= {
        n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.ClassDef))
    }
    identifiers |= {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
    for word in ("skip", "force", "bypass", "insecure", "unsafe", "override", "no_verify"):
        assert not [i for i in identifiers if word in i.lower()], word
    options = {
        n.value.split("=")[0]
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith("--")
    }
    # The only options it writes are those of the engine's own trust add command, which it runs.
    assert options == {"--store", "--key-id", "--issuer", "--public-key", "--fingerprint"}, options


def test_the_bundled_demonstration_key_is_refused_by_fingerprint_at_apply_time(
    home, tmp_path, run, northwind
):
    from regaudit_fhe._keys import spki_fingerprint

    pem = json.loads((SAMPLES / "demo-trust-list.json").read_text())["entries"][
        "demo-only-synthetic-key"
    ]["public_key_pem"]
    content = json.loads(prepare_plan([northwind]))
    content["issuers"][0]["public_key_pem"] = pem
    plan = _plan_file(tmp_path, crafted_plan(content))
    code, _, err = run(
        "admin-apply", plan, "--expect-fingerprint", f"{northwind.key_id}={spki_fingerprint(pem)}"
    )
    assert code == 2 and "demonstration keys" in err and "never be enrolled" in err
    assert not default_config_folder().exists()


def test_the_weak_settings_plan_is_flagged_at_the_top_before_it_can_be_applied(
    home, tmp_path, run, northwind
):
    """The plan a reviewer ran: the real issuer's key, the development profile, 3650 days and replay mode check. The
    typed fingerprint matches, so it can be applied, but the summary must say plainly what it weakens first."""
    plan = _plan_file(
        tmp_path,
        prepare_plan([northwind], profile="development", max_age_days=3650, replay_mode="check"),
    )
    code, out, _ = run("admin-describe", plan)
    lines = out.splitlines()
    assert code == 0
    assert lines[0].startswith("Notice: the profile is development. It is for trying things out.")
    assert lines[1].startswith("Notice: the maximum report age is 3650 days.")
    assert lines[2].startswith("Notice: the replay mode is check.")
    assert (
        lines[3].startswith('Verifier id: "northwind-verifier".')
        and "your own organisation's id" in lines[3]
    )
    assert (
        out.index("Notice:")
        < out.index("Setup plan, content checksum")
        < out.index("Issuers to enrol")
    )
    code, out, _ = run("admin-describe", "--json", plan)
    body = json.loads(out)
    assert code == 0 and len(body["notices"]) == 3
    assert body["summary"].splitlines()[:3] == body["notices"]  # what the application shows, first
    assert (
        run("admin-apply", plan, *_expect(northwind))[0] == 0
    )  # still the administrator's choice to make
    assert load_portal(default_config_folder() / "portal-config.json").profile == "development"


def test_a_plan_without_weak_settings_starts_with_the_verifier_id(home, tmp_path, run, northwind):
    plan = _plan_file(tmp_path, prepare_plan([northwind], replay_mode="record"))
    code, out, _ = run("admin-describe", plan)
    assert (
        code == 0 and out.startswith('Verifier id: "northwind-verifier".') and "Notice:" not in out
    )
    assert json.loads(run("admin-describe", "--json", plan)[1])["notices"] == []


def test_a_plan_that_changed_since_it_was_described_is_refused(home, tmp_path, run, northwind):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    code, _, err = run("admin-apply", plan, "--expect-plan-sha256", "0" * 64, *_expect(northwind))
    assert code == 2 and "changed since it was described" in err


# ----------------------------------------------------------------------------- the plan file itself


def _tamper(text: str, change) -> bytes:
    content = json.loads(text)
    change(content)
    return json.dumps(content).encode()


@pytest.mark.parametrize(
    "label, change",
    [
        ("profile", lambda p: p["configuration"].update(profile="development")),
        ("verifier", lambda p: p["configuration"].update(verifier_id="mallory")),
        ("age", lambda p: p["configuration"].update(max_age_days=3650)),
        ("replay", lambda p: p["configuration"].update(replay_mode="record")),
        ("name", lambda p: p["issuers"][0].update(issuer="Mallory Ltd")),
        ("key id", lambda p: p["issuers"][0].update(key_id="mallory-1")),
        ("mode", lambda p: p.update(mode="add-issuers")),
    ],
)
def test_a_plan_edited_after_it_was_prepared_is_refused_and_nothing_is_written(
    home, tmp_path, run, northwind, label, change
):
    plan = _plan_file(tmp_path, _tamper(prepare_plan([northwind]), change))
    for argv in (("admin-describe", plan), ("admin-apply", plan, *_expect(northwind))):
        code, out, err = run(*argv)
        assert code == 2 and "refused" in err, (label, out, err)
    assert not default_config_folder().exists()


@pytest.mark.parametrize(
    "data",
    [
        b"\xef\xbb\xbf{}",
        b"\xff\xfe\x00{",
        b"{" * 3000,
        b"not json at all",
        b'{"format": "regaudit-portal-setup-plan", "format": "x"}',
        b" " * (64 * 1024 + 1),
    ],
)
def test_a_plan_that_is_not_plain_utf8_json_or_too_large_is_refused(home, tmp_path, run, data):
    code, _, err = run("admin-describe", _plan_file(tmp_path, data))
    assert code == 2 and err.startswith("refused: The plan")


def test_a_pipe_a_folder_or_a_missing_file_given_as_the_plan_is_refused_without_waiting(
    home, tmp_path, run
):
    pipe = tmp_path / "pipe.json"
    os.mkfifo(pipe)
    start = time.monotonic()
    assert run("admin-describe", pipe)[2].startswith("refused: The plan is not a regular file")
    assert time.monotonic() - start < 5
    assert "not a regular file" in run("admin-describe", tmp_path)[2]
    assert "cannot be opened" in run("admin-describe", tmp_path / "missing.json")[2]


def test_names_with_terminal_escape_sequences_never_reach_the_terminal(
    home, tmp_path, run, northwind
):
    content = json.loads(prepare_plan([northwind]))
    content["issuers"][0]["issuer"] = "\x1b]0;owned\x07\x1b[2J\x1b[31mNorthwind Ltd"
    plan = _plan_file(tmp_path, crafted_plan(content))
    for argv in (
        ("admin-describe", plan),
        ("admin-describe", "--json", plan),
        ("admin-apply", plan, *_expect(northwind)),
    ):
        code, out, err = run(*argv)
        assert code == 2 and "control or invisible character" in out + err
        _no_control_characters(out, err)
        assert "\x1b" not in out + err


# ----------------------------------------------------------------------------- the destination


def test_a_symbolic_link_as_the_configuration_folder_is_refused(home, tmp_path, run, northwind):
    real = _private_folder(tmp_path / "real")
    default_config_folder().symlink_to(real, target_is_directory=True)
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert code == 2 and "is a symbolic link" in err and list(real.iterdir()) == []


def test_a_symbolic_link_anywhere_above_the_folder_is_refused(home, tmp_path, run, northwind):
    real = _private_folder(tmp_path / "elsewhere")
    os.chmod(real, 0o755)  # noqa: S103 - readable by others, changeable only by this account
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    target = link / "inside" / "config"
    (real / "inside").mkdir(mode=0o755)
    code, _, err = run(
        "admin-apply",
        _plan_file(tmp_path, prepare_plan([northwind])),
        "--config-folder",
        target,
        *_expect(northwind),
    )
    assert code == 2 and f"{link} is a symbolic link" in err
    assert list((real / "inside").iterdir()) == []


@pytest.mark.parametrize("name", ["portal-config.json", "trust-store.json"])
def test_a_link_or_a_dangling_link_where_a_file_would_go_counts_as_existing(
    home, tmp_path, run, northwind, name
):
    folder = _private_folder(default_config_folder())
    victim = tmp_path / "victim.json"
    (folder / name).symlink_to(victim)  # dangling: following it would create the victim
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert code == 2 and "already" in err and not victim.exists()


@pytest.mark.parametrize("mode", [0o770, 0o777, 0o720, 0o702])
def test_a_folder_others_can_change_is_refused(home, tmp_path, run, northwind, mode):
    folder = _private_folder(default_config_folder())
    os.chmod(folder, mode)
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert code == 2 and "can be changed by group or others" in err and list(folder.iterdir()) == []


def test_a_folder_above_that_others_can_change_is_refused_unless_it_is_sticky(
    home, tmp_path, run, northwind
):
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o777)  # noqa: S103 - the point of the test
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    code, _, err = run(
        "admin-apply", plan, "--config-folder", shared / "config", *_expect(northwind)
    )
    assert code == 2 and f"{shared} can be changed by group or others" in err
    os.chmod(shared, 0o1777)  # noqa: S103 - like /tmp: others cannot rename or remove what is not theirs
    code, _, err = run(
        "admin-apply", plan, "--config-folder", shared / "config", *_expect(northwind)
    )
    assert code == 0, err


def test_a_folder_of_another_account_is_refused(home, tmp_path, run, northwind, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert code == 2 and "belongs to another account" in err


def test_it_refuses_to_run_as_root(home, tmp_path, run, northwind, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert code == 2 and "not as root" in err and not default_config_folder().exists()


@pytest.mark.parametrize("given", ["../escape", "a/../../b", "/tmp/../etc", ""])  # noqa: S108
def test_a_config_folder_with_dot_dot_or_empty_is_refused(home, tmp_path, run, northwind, given):
    code, _, err = run(
        "admin-apply",
        _plan_file(tmp_path, prepare_plan([northwind])),
        "--config-folder",
        given,
        *_expect(northwind),
    )
    assert code == 2 and "refused" in err


def test_a_config_folder_whose_parent_does_not_exist_is_refused(home, tmp_path, run, northwind):
    code, _, err = run(
        "admin-apply",
        _plan_file(tmp_path, prepare_plan([northwind])),
        "--config-folder",
        tmp_path / "no" / "such",
        *_expect(northwind),
    )
    assert code == 2 and "does not exist" in err and not (tmp_path / "no").exists()


def test_the_plan_never_chooses_the_destination(home, tmp_path, run, northwind):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    code, out, _ = run("admin-describe", plan)
    assert code == 0
    assert (
        f"Destination folder: {default_config_folder()} (the standard folder for this account)"
        in out
    )
    assert "The plan cannot choose it." in out


def test_an_existing_configuration_is_never_replaced(home, tmp_path, run, northwind):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    assert run("admin-apply", plan, *_expect(northwind))[0] == 0
    before = snapshot(default_config_folder())
    other = issuer_signer("Other Ltd", "other-1")
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([other]), "2.json"), *_expect(other)
    )
    assert code == 2 and "never replaces one" in err and snapshot(default_config_folder()) == before
    assert "applying it here is refused" in run("admin-describe", tmp_path / "2.json")[1]


def test_a_trust_list_without_a_configuration_is_explained_and_left_alone(
    home, tmp_path, run, northwind
):
    folder = _private_folder(default_config_folder())
    (folder / "trust-store.json").write_text("{}")
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert (
        code == 2
        and "stopped part-way can leave this" in err
        and (folder / "trust-store.json").read_text() == "{}"
    )


# ----------------------------------------------------------------------------- adding issuers


def _first_setup(tmp_path, run, signer) -> Path:
    assert (
        run(
            "admin-apply",
            _plan_file(tmp_path, prepare_plan([signer]), "first.json"),
            *_expect(signer),
        )[0]
        == 0
    )
    return default_config_folder()


def test_adding_issuers_appends_to_the_trust_list_and_leaves_the_configuration_alone(
    home, tmp_path, run, northwind
):
    folder = _first_setup(tmp_path, run, northwind)
    os.chmod(
        folder / "trust-store.json", 0o644
    )  # the mode regaudit-fhe trust add gives a trust list
    config_before = (
        (folder / "portal-config.json").read_bytes(),
        (folder / "portal-config.json").stat().st_mtime_ns,
    )
    entry_before = json.loads((folder / "trust-store.json").read_text())["entries"][
        northwind.key_id
    ]
    later = issuer_signer("Later Ltd", "later-1")
    plan = _plan_file(tmp_path, prepare_plan([later], mode="add-issuers"))
    assert run("admin-describe", plan)[0] == 0
    code, out, err = run("admin-apply", plan, *_expect(later))
    assert code == 0, err and "The configuration was not changed" in out
    entries = json.loads((folder / "trust-store.json").read_text())["entries"]
    assert (
        list(entries) == [northwind.key_id, later.key_id]
        and entries[northwind.key_id] == entry_before
    )
    assert stat.S_IMODE((folder / "trust-store.json").stat().st_mode) == 0o600
    assert (
        (folder / "portal-config.json").read_bytes(),
        (folder / "portal-config.json").stat().st_mtime_ns,
    ) == config_before
    assert load_portal(folder / "portal-config.json").approved_count == 2


def test_adding_a_key_id_that_is_already_there_is_refused(home, tmp_path, run, northwind):
    folder = _first_setup(tmp_path, run, northwind)
    before = snapshot(folder)
    again = issuer_signer("Northwind Ltd", northwind.key_id)
    plan = _plan_file(tmp_path, prepare_plan([again], mode="add-issuers"))
    code, _, err = run("admin-apply", plan, *_expect(again))
    assert code == 2 and "already in the trust list" in err and snapshot(folder) == before


def test_adding_the_same_key_under_another_key_id_is_refused_by_the_engine(
    home, tmp_path, run, northwind
):
    folder = _first_setup(tmp_path, run, northwind)
    before = snapshot(folder)
    relabelled = rf.Signer(
        "Northwind Ltd", "northwind-again", northwind.private_key, northwind.public_key
    )
    plan = _plan_file(tmp_path, prepare_plan([relabelled], mode="add-issuers"))
    code, _, err = run("admin-apply", plan, *_expect(relabelled))
    assert code == 2 and "register the same public key" in err and snapshot(folder) == before
    assert "The engine refuses the trust list this would make" in err


def test_adding_issuers_with_no_configuration_or_to_a_demonstration_is_refused(
    home, tmp_path, run, northwind
):
    plan = _plan_file(tmp_path, prepare_plan([northwind], mode="add-issuers"))
    code, _, err = run("admin-apply", plan, *_expect(northwind))
    assert code == 2 and "Use a first-setup plan" in err
    demo = create(tmp_path / "demo")
    folder = _private_folder(default_config_folder())
    for name in ("portal-config.json", "trust-store.json"):
        (folder / name).write_bytes((demo / name).read_bytes())
        os.chmod(folder / name, 0o600)
    code, _, err = run("admin-apply", plan, *_expect(northwind))
    assert code == 2 and "existing configuration is a demonstration" in err


@pytest.mark.parametrize("setting", [None, "customer"])
def test_adding_issuers_to_the_bundled_key_without_the_demonstration_setting_is_refused(
    home, tmp_path, run, northwind, setting
):
    """The demonstration files copied in and their setting removed or changed: refused, and nothing is written."""
    plan = _plan_file(tmp_path, prepare_plan([northwind], mode="add-issuers"))
    demo = create(tmp_path / "demo")
    folder = _private_folder(default_config_folder())
    config = json.loads((demo / "portal-config.json").read_text())
    config.pop("trust_mode")
    if setting is not None:
        config["trust_mode"] = setting
    (folder / "portal-config.json").write_text(json.dumps(config))
    (folder / "trust-store.json").write_bytes((demo / "trust-store.json").read_bytes())
    for name in ("portal-config.json", "trust-store.json"):
        os.chmod(folder / name, 0o600)
    before = snapshot(folder)
    code, out, err = run("admin-apply", plan, *_expect(northwind))
    assert code == 2 and "Enrolled" not in out
    assert (
        "The existing configuration cannot be used: trust_mode: the trust list holds the portal's bundled"
        in err
    )
    assert snapshot(folder) == before


@pytest.mark.parametrize("place", ["../outside.json", "/etc/outside.json", "sub/inner.json"])
def test_adding_to_a_trust_list_outside_the_configuration_folder_is_refused(
    home, tmp_path, run, northwind, place
):
    folder = _first_setup(tmp_path, run, northwind)
    config = folder / "portal-config.json"
    data = json.loads(config.read_text())
    data["trust_store"] = place
    config.write_text(json.dumps(data))
    later = issuer_signer("Later Ltd", "later-1")
    code, _, err = run(
        "admin-apply",
        _plan_file(tmp_path, prepare_plan([later], mode="add-issuers")),
        *_expect(later),
    )
    assert code == 2 and "names a trust list outside its own folder" in err


def test_a_trust_list_that_is_a_link_is_not_added_to(home, tmp_path, run, northwind):
    folder = _first_setup(tmp_path, run, northwind)
    real = tmp_path / "real-store.json"
    (folder / "trust-store.json").rename(real)
    (folder / "trust-store.json").symlink_to(real)
    later = issuer_signer("Later Ltd", "later-1")
    code, _, err = run(
        "admin-apply",
        _plan_file(tmp_path, prepare_plan([later], mode="add-issuers")),
        *_expect(later),
    )
    assert code == 2 and "is not a regular file" in err and later.key_id not in real.read_text()


# ----------------------------------------------------------------------------- a stop part-way changes nothing


def test_a_failure_while_creating_the_folder_leaves_no_folder_and_no_temporary_files(
    home, tmp_path, run, northwind, monkeypatch
):
    def fails(*_args, **_kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "rename", fails)
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert code == 2 and "Nothing was changed" in err
    assert (
        not default_config_folder().exists()
        and list(default_config_folder().parent.iterdir()) == []
    )


@pytest.mark.parametrize("stop", [OSError(28, "No space left on device"), KeyboardInterrupt()])
def test_a_stop_between_the_trust_list_and_the_configuration_takes_the_trust_list_away_again(
    home, tmp_path, run, northwind, monkeypatch, stop
):
    folder = _private_folder(default_config_folder())
    real_link, calls = os.link, []

    def second_fails(*args, **kwargs):
        calls.append(args)
        if len(calls) == 2:
            raise stop
        return real_link(*args, **kwargs)

    monkeypatch.setattr(os, "link", second_fails)
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert len(calls) == 2 and code in (1, 2) and "Nothing was changed" in err
    assert (
        list(folder.iterdir()) == []
    )  # unchanged: no trust list, no configuration, no temporary folder


def test_if_taking_the_trust_list_away_fails_too_it_says_exactly_what_state_the_folder_is_in(
    home, tmp_path, run, northwind, monkeypatch
):
    folder = _private_folder(default_config_folder())
    real_link, real_unlink, calls = os.link, os.unlink, []

    def second_fails(*args, **kwargs):
        calls.append(args)
        if len(calls) == 2:
            raise OSError(5, "Input/output error")
        return real_link(*args, **kwargs)

    def unlink(path, *args, dir_fd=None, **kwargs):
        if path == "trust-store.json" and dir_fd is not None and calls:
            raise OSError(1, "Operation not permitted")
        return real_unlink(path, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(os, "link", second_fails)
    monkeypatch.setattr(os, "unlink", unlink)
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert (
        code == 1
        and "the configuration was not" in err
        and "does not use a trust list without a configuration" in err
    )
    assert (folder / "trust-store.json").exists() and not (folder / "portal-config.json").exists()


def test_a_stop_while_enrolling_leaves_nothing_behind(home, tmp_path, run, northwind, monkeypatch):
    from regaudit_fhe import cli

    def interrupted(_argv):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "main", interrupted)
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert code == 1 and "stopped: Nothing was changed." in err
    assert list(default_config_folder().parent.iterdir()) == []


@pytest.mark.parametrize("existing", [False, True])
def test_a_failure_after_the_files_are_in_place_says_they_are_and_exits_4(
    home, tmp_path, run, northwind, monkeypatch, existing
):
    """Syncing the folder to disk is the step after the move. If it fails the setup is in use: say so, never
    'nothing was changed', and give the launcher the status that tells it to restart the portal."""
    if existing:
        _private_folder(default_config_folder())
    real, folders = admin._sync, []

    target = default_config_folder() if existing else default_config_folder().parent

    def sync(fd):
        """Fail the sync of the folder that the files were just moved into, once."""
        if not folders and os.path.samestat(os.fstat(fd), os.stat(target)):
            folders.append(fd)
            raise OSError(5, "Input/output error")
        return real(fd)

    monkeypatch.setattr(admin, "_sync", sync)
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert code == 4 and "Nothing was changed" not in err, err
    assert (
        "The new files are in place, but flushing them to the disk failed (Input/output error)"
        in err
    ), err
    assert (default_config_folder() / "portal-config.json").is_file()


def test_a_stop_asked_for_while_files_are_put_in_place_waits_until_they_are():
    with admin._own_signal_handling(admin._stop_like_ctrl_c):
        reached = []
        with pytest.raises(KeyboardInterrupt), admin._held_signals():
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.2)  # the handler has run by now, and did not stop this block
            reached.append("after the stop")
        assert reached == ["after the stop"]
        with pytest.raises(KeyboardInterrupt):
            os.kill(os.getpid(), signal.SIGHUP)
            time.sleep(1)


def test_a_stop_between_the_two_links_lands_after_both_and_is_reported_as_complete(
    home, tmp_path, run, northwind, monkeypatch
):
    folder = _private_folder(default_config_folder())
    real_link, calls = os.link, []

    def link_then_stop(*args, **kwargs):
        done = real_link(*args, **kwargs)
        calls.append(1)
        if len(calls) == 1:
            os.kill(
                os.getpid(), signal.SIGTERM
            )  # arrives between the trust list and the configuration
            time.sleep(0.2)
        return done

    monkeypatch.setattr(os, "link", link_then_stop)
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert len(calls) == 2 and code == 4 and "stopped: The change is complete" in err, err
    assert sorted(p.name for p in folder.iterdir()) == ["portal-config.json", "trust-store.json"]
    read_trust_store(read_settings(folder / "portal-config.json"))


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGHUP, signal.SIGINT])
def test_a_command_started_with_stops_ignored_can_still_be_stopped(home, tmp_path, northwind, sig):
    """A launcher that ignores SIGTERM passes that on to what it starts. The command sets its own handling."""
    import select
    import termios

    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    master, slave = os.openpty()

    def start() -> None:
        for each in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(each, signal.SIG_IGN)
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-m", "regaudit_portal", "admin-apply", str(plan)],
        env=_env(home), cwd=PORTAL, stdin=slave, stdout=slave, stderr=slave, preexec_fn=start,
    )  # fmt: skip
    os.close(slave)
    seen = b""
    try:
        deadline = time.monotonic() + 60
        while b"by another route: " not in seen and time.monotonic() < deadline:
            if select.select([master], [], [], 1)[0]:
                seen += os.read(master, 4096)
        proc.send_signal(sig)
        # Keep reading: a process that exits waits for what it wrote to its terminal to be read.
        while proc.poll() is None and time.monotonic() < deadline:
            if select.select([master], [], [], 0.2)[0]:
                try:
                    seen += os.read(master, 4096)
                except OSError:
                    break
        assert proc.wait(timeout=10) == 1, seen.decode(errors="replace")
    finally:
        if proc.poll() is None:
            proc.kill()
        os.close(master)
    assert b"stopped: Nothing was changed." in seen and not default_config_folder().exists()


def test_a_failure_while_replacing_the_trust_list_leaves_the_old_one(
    home, tmp_path, run, northwind, monkeypatch
):
    folder = _first_setup(tmp_path, run, northwind)
    before = _entries(folder), (folder / "trust-store.json").read_bytes()

    def fails(*_args, **_kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "rename", fails)
    later = issuer_signer("Later Ltd", "later-1")
    code, _, err = run(
        "admin-apply",
        _plan_file(tmp_path, prepare_plan([later], mode="add-issuers")),
        *_expect(later),
    )
    assert code == 1 and "Nothing was changed" in err
    assert (_entries(folder), (folder / "trust-store.json").read_bytes()) == before


def test_a_trust_list_changed_by_someone_else_while_adding_is_not_overwritten(
    home, tmp_path, run, northwind, monkeypatch
):
    folder = _first_setup(tmp_path, run, northwind)
    store = folder / "trust-store.json"
    real = admin._engine_still_recognised

    def meanwhile():
        real()
        data = json.loads(store.read_text())
        data["entries"][northwind.key_id]["status"] = "compromised"
        store.write_text(json.dumps(data))

    monkeypatch.setattr(admin, "_engine_still_recognised", meanwhile)
    later = issuer_signer("Later Ltd", "later-1")
    code, _, err = run(
        "admin-apply",
        _plan_file(tmp_path, prepare_plan([later], mode="add-issuers")),
        *_expect(later),
    )
    assert code == 2 and "changed while this ran" in err
    assert json.loads(store.read_text())["entries"][northwind.key_id]["status"] == "compromised"
    assert later.key_id not in store.read_text()


def test_if_the_engine_stops_passing_before_the_files_are_moved_into_place_nothing_changes(
    home, tmp_path, run, northwind, monkeypatch
):
    real, calls = engine_module.check_engine, []

    def second_fails(*args, **kwargs):
        calls.append(1)
        return (
            real()
            if len(calls) < 2
            else engine_module.Identity(False, "ENGINE_NOT_RECOGNISED", "changed", None)
        )

    monkeypatch.setattr(admin, "check_engine", second_fails)
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert (
        code == 2 and "no longer passes its check" in err and not default_config_folder().exists()
    )


@pytest.mark.parametrize("command", ["admin-describe", "admin-apply"])
def test_with_an_engine_that_is_not_the_recognised_release_nothing_is_described_or_applied(
    home, tmp_path, run, northwind, monkeypatch, command
):
    monkeypatch.setattr(engine_module, "RELEASE_FILES_SHA256", "0" * 64)
    extra = _expect(northwind) if command == "admin-apply" else []
    code, _, err = run(command, _plan_file(tmp_path, prepare_plan([northwind])), *extra)
    assert code == 3 and "verification unavailable" in err and not default_config_folder().exists()


# ----------------------------------------------------------------------------- killed part-way, and two at once


def _env(home: Path) -> dict[str, str]:
    """The account, with a temporary folder of the test's own: a process killed here leaves its private bytecode
    folder behind, and it should stay inside the test's folder."""
    tmp = home.parent / "tmp"
    tmp.mkdir(mode=0o700, exist_ok=True)
    return {**os.environ, "HOME": str(home), "PYTHONPATH": str(PORTAL), "TMPDIR": str(tmp)}


_KILL_AT = """
import os, signal, sys
which, at = sys.argv[1], int(sys.argv[2])
real, calls = getattr(os, which), []
def hook(*args, **kwargs):
    calls.append(1)
    if len(calls) == at:
        os.kill(os.getpid(), signal.SIGKILL)
    return real(*args, **kwargs)
setattr(os, which, hook)
from regaudit_portal.__main__ import main
sys.exit(main(sys.argv[3:]))
"""


def _killed(home: Path, which: str, at: int, *argv) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-c", _KILL_AT, which, str(at), *map(str, argv)],
        env=_env(home), cwd=PORTAL, capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip


def test_killed_before_the_new_folder_is_moved_into_place_the_folder_does_not_exist(
    home, tmp_path, run, northwind
):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    done = _killed(home, "rename", 1, "admin-apply", plan, *_expect(northwind))
    assert done.returncode == -signal.SIGKILL
    assert (
        not default_config_folder().exists()
    )  # unchanged: the portal still finds no configuration
    leftovers = list(default_config_folder().parent.glob(".regaudit-admin-*"))
    assert len(leftovers) == 1 and stat.S_IMODE(leftovers[0].stat().st_mode) == 0o700
    code, out, _ = run("admin-describe", plan)
    assert code == 0 and f"Left by an apply that was stopped: {leftovers[0]}" in out
    assert run("admin-apply", plan, *_expect(northwind))[0] == 0


def test_killed_between_the_trust_list_and_the_configuration_the_portal_still_sees_no_configuration(
    home, tmp_path, run, northwind
):
    folder = _private_folder(default_config_folder())
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    done = _killed(home, "link", 2, "admin-apply", plan, *_expect(northwind))
    assert done.returncode == -signal.SIGKILL
    assert (folder / "trust-store.json").exists() and not (folder / "portal-config.json").exists()
    code, _, err = run("check-config")
    assert code == 3 and "there is no configuration" in err  # the setup is not in use
    code, _, err = run("admin-apply", plan, *_expect(northwind))
    assert code == 2 and "stopped part-way can leave this" in err


def _left_by_a_killed_apply(home, tmp_path, northwind) -> tuple[Path, list[Path]]:
    folder = _private_folder(default_config_folder())
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    assert (
        _killed(home, "link", 2, "admin-apply", plan, *_expect(northwind)).returncode
        == -signal.SIGKILL
    )
    leftovers = sorted(folder.glob(".regaudit-admin-*")) + sorted(
        folder.parent.glob(".regaudit-admin-*")
    )
    assert leftovers and (folder / "trust-store.json").exists()
    return plan, leftovers


def test_describe_lists_the_leftover_folders_also_when_it_refuses_the_stray_trust_list(
    home, tmp_path, run, northwind
):
    plan, leftovers = _left_by_a_killed_apply(home, tmp_path, northwind)
    code, out, _ = run("admin-describe", plan)
    assert (
        code == 2
        and "Destination check: applying it here is refused. There is already a trust list" in out
    )
    for item in leftovers:
        assert f"Left by an apply that was stopped: {item}. The portal does not use it." in out
    code, out, _ = run("admin-describe", plan, "--json")
    body = json.loads(out)
    assert body["ok"] is False and all(
        f"Left by an apply that was stopped: {item}." in body["summary"] for item in leftovers
    )


def test_describe_lists_the_leftover_folders_with_any_refusal_after_the_folders_are_opened(
    home, tmp_path, run, northwind
):
    plan, leftovers = _left_by_a_killed_apply(home, tmp_path, northwind)
    (default_config_folder() / "trust-store.json").unlink()
    (default_config_folder() / "portal-config.json").write_text("{}")
    os.chmod(default_config_folder() / "portal-config.json", 0o600)
    code, out, _ = run("admin-describe", plan)  # now refused because a configuration is there
    assert code == 2 and "There is already a configuration" in out
    assert all(f"Left by an apply that was stopped: {item}." in out for item in leftovers)


def test_guard_off_dropping_the_leftovers_on_a_refusal_is_noticed(
    home, tmp_path, run, northwind, monkeypatch
):
    """The control: describing as before, the refusal comes without the leftover lines, and the check above fails."""
    plan, _leftovers = _left_by_a_killed_apply(home, tmp_path, northwind)
    real = admin._describe_destination

    def earlier(folder, plan):
        problem, found, warnings = real(folder, plan)
        return problem, (found if problem is None else []), warnings

    monkeypatch.setattr(admin, "_describe_destination", earlier)
    code, out, _ = run("admin-describe", plan)
    assert code == 2 and "Left by an apply that was stopped" not in out


_PENDING_STOP = """
import os, signal, sys
which = getattr(signal, sys.argv[1])
signal.pthread_sigmask(signal.SIG_BLOCK, {which})
os.kill(os.getpid(), which)  # held, as a stop that arrives in the first fraction of a second is
from regaudit_portal.__main__ import main
sys.exit(main(sys.argv[2:]))
"""


@pytest.mark.parametrize("sig", ["SIGTERM", "SIGINT", "SIGHUP"])
@pytest.mark.parametrize("command", ["admin-apply", "admin-describe"])
def test_a_stop_in_the_first_moment_is_quiet_and_exact(home, tmp_path, northwind, sig, command):
    """A stop sent before the command could install its handlers is held, then taken when it does. It must end as a
    plain stop that says nothing changed: no traceback and no death by signal."""
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    extra = _expect(northwind) if command == "admin-apply" else []
    done = subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-c", _PENDING_STOP, sig, command, str(plan), *extra],
        env=_env(home), cwd=PORTAL, capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 1, (done.returncode, done.stderr[-600:])
    assert "Traceback" not in done.stderr and "KeyboardInterrupt" not in done.stderr, done.stderr[
        -600:
    ]
    assert done.stderr.strip().splitlines()[-1] == "stopped: Nothing was changed."
    assert done.stdout == "" and not default_config_folder().exists()


def test_when_the_reader_of_its_output_goes_away_the_apply_still_finishes_cleanly(
    home, tmp_path, northwind
):
    """The launcher reads the command's output through pipes. If it quits mid-way, writing fails: the files must still
    be complete or untouched, and the command must end normally."""
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    proc = subprocess.Popen(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-m", "regaudit_portal", "admin-apply", str(plan), *_expect(northwind)],
        env=_env(home), cwd=PORTAL, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )  # fmt: skip
    proc.stdout.close()  # what the launcher's going away does to the pipes it held
    proc.stderr.close()
    assert proc.wait(timeout=120) == 0
    folder = default_config_folder()
    assert sorted(p.name for p in folder.iterdir()) == ["portal-config.json", "trust-store.json"]
    read_trust_store(read_settings(folder / "portal-config.json"))


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_a_stop_between_the_two_files_by_either_signal_lands_after_both(
    home, tmp_path, run, northwind, monkeypatch, sig
):
    folder = _private_folder(default_config_folder())
    real_link, calls = os.link, []

    def link_then_stop(*args, **kwargs):
        done = real_link(*args, **kwargs)
        calls.append(1)
        if len(calls) == 1:
            os.kill(os.getpid(), sig)
            time.sleep(0.2)
        return done

    monkeypatch.setattr(os, "link", link_then_stop)
    code, _, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert code == 4 and "stopped: The change is complete" in err, err
    assert sorted(p.name for p in folder.iterdir()) == ["portal-config.json", "trust-store.json"]


def test_while_another_apply_holds_the_folder_a_second_one_is_refused(
    home, tmp_path, run, northwind
):
    parent = default_config_folder().parent
    fd = os.open(parent, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        code, _, err = run(
            "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
        )
        assert code == 2 and "Another administrator setup is running" in err
    finally:
        os.close(fd)
    assert not default_config_folder().exists()


def test_two_applies_at_once_give_one_complete_setup_and_one_refusal(home, tmp_path, northwind):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    other = issuer_signer("Other Ltd", "other-1")
    second = _plan_file(tmp_path, prepare_plan([other]), "second.json")
    procs = [
        subprocess.Popen(  # noqa: S603 - this interpreter, fixed arguments
            [sys.executable, "-m", "regaudit_portal", "admin-apply", str(p), *_expect(s)],
            env=_env(home),
            cwd=PORTAL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for p, s in ((plan, northwind), (second, other))
    ]
    results = [(p.communicate(timeout=120)[1], p.returncode) for p in procs]
    results = [(code, err) for err, code in results]
    assert sorted(code for code, _ in results) == [0, 2], results
    settings = read_settings(default_config_folder() / "portal-config.json")
    assert len(read_trust_store(settings).entries) == 1
    assert not list(default_config_folder().parent.glob(".regaudit-admin-*"))


# ----------------------------------------------------------------------------- describe only looks


def test_describe_writes_nothing_for_either_kind_of_plan(
    home, tmp_path, run, northwind, monkeypatch
):
    first = _plan_file(tmp_path, prepare_plan([northwind]), "first.json")
    later = issuer_signer("Later Ltd", "later-1")
    adding = _plan_file(tmp_path, prepare_plan([later], mode="add-issuers"), "add.json")
    run("admin-describe", first)  # anything loaded once is loaded before writing is forbidden
    _first_setup(tmp_path, run, northwind)
    before = snapshot(tmp_path)
    with monkeypatch.context() as guarded:
        _forbid_writes(guarded)
        for plan in (first, adding):
            for extra in ((), ("--json",)):
                code, out, err = run("admin-describe", *extra, plan)
                assert "was called" not in out + err, out + err
                assert code == (2 if plan == first else 0), out + err
    assert snapshot(tmp_path) == before


def test_describe_json_gives_the_application_what_it_shows_and_no_fingerprint(
    home, tmp_path, run, northwind
):
    later = issuer_signer("Later Ltd", "later-1")
    code, out, _ = run(
        "admin-describe", "--json", _plan_file(tmp_path, prepare_plan([northwind, later]))
    )
    body = json.loads(out)
    assert (
        code == 0
        and body["ok"] is True
        and body["problem"] is None
        and body["mode"] == "first-setup"
    )
    assert body["issuers"] == [
        {"number": 1, "issuer": "Northwind Ltd", "key_id": "northwind-2026"},
        {"number": 2, "issuer": "Later Ltd", "key_id": "later-1"},
    ]
    assert re.fullmatch(r"[0-9a-f]{64}", body["plan_sha256"])
    assert not re.search(r"[0-9a-f]{64}", body["summary"].replace(body["plan_sha256"], ""))
    assert out.count("\n") == 1 and out.isascii()


def test_describe_json_says_why_a_plan_cannot_be_applied_here(home, tmp_path, run, northwind):
    _first_setup(tmp_path, run, northwind)
    code, out, _ = run(
        "admin-describe", "--json", _plan_file(tmp_path, prepare_plan([northwind]), "again.json")
    )
    body = json.loads(out)
    assert code == 2 and body["ok"] is False and "never replaces one" in body["problem"]
    code, out, _ = run("admin-describe", "--json", _plan_file(tmp_path, b"{", "broken.json"))
    assert code == 2 and json.loads(out) == {"ok": False, "problem": json.loads(out)["problem"]}


def test_every_message_is_free_of_control_characters(home, tmp_path, run, northwind):
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    outputs = [
        run("admin-describe", plan),
        run("admin-apply", plan, "--expect-fingerprint", f"{northwind.key_id}=" + "0" * 64),
        run("admin-apply", plan, *_expect(northwind)),
        run("admin-apply", plan, *_expect(northwind)),
    ]
    for _, out, err in outputs:
        _no_control_characters(out, err)


def test_admin_apply_always_writes_customer_trust_mode(home, tmp_path, run, northwind):
    folder = _first_setup(tmp_path, run, northwind)
    assert json.loads((folder / "portal-config.json").read_text())["trust_mode"] == "customer"
    portal = load_portal(folder / "portal-config.json")
    assert portal.trust_mode == "customer" and portal.demonstration is False


def test_issuers_are_never_added_to_a_configuration_marked_demonstration(
    home, tmp_path, run, northwind
):
    folder = _first_setup(tmp_path, run, northwind)
    config = folder / "portal-config.json"
    data = json.loads(config.read_text())
    data["trust_mode"] = "demonstration"
    config.write_text(json.dumps(data))
    before = (folder / "trust-store.json").read_bytes()
    later = issuer_signer("Later Ltd", "later-1")
    plan = _plan_file(tmp_path, prepare_plan([later], mode="add-issuers"))
    code, out, _ = run("admin-describe", plan)
    assert code == 2 and "existing configuration is a demonstration" in out
    code, _, err = run("admin-apply", plan, *_expect(later))
    assert code == 2 and "existing configuration is a demonstration" in err
    assert (folder / "trust-store.json").read_bytes() == before


@pytest.mark.parametrize("typed", ["northwind-2026", "Northwind Ltd"])
def test_a_key_id_or_name_typed_as_the_fingerprint_is_refused_as_not_a_fingerprint(
    home, tmp_path, run, northwind, typed
):
    """An issuer's key id or name never stands in for the fingerprint, and the message says so plainly."""
    code, _out, err = run(
        "admin-apply",
        _plan_file(tmp_path, prepare_plan([northwind])),
        "--expect-fingerprint",
        f"{northwind.key_id}={typed}",
    )
    assert code == 2 and not default_config_folder().exists()
    assert "is never a fingerprint" in err and "Nothing was changed" in err
    assert "without separators" not in err


def test_the_list_of_enrolled_issuers_after_applying_shows_name_and_key_id_but_no_fingerprint(
    home, tmp_path, run, northwind
):
    """The application shows this output in its "The setup plan was applied." dialog."""
    code, out, err = run(
        "admin-apply", _plan_file(tmp_path, prepare_plan([northwind])), *_expect(northwind)
    )
    assert code == 0, err
    enrolled = out.split("Enrolled:\n", 1)[1].splitlines()[0]
    assert enrolled == (
        f'  1. "{northwind.issuer}", key id {northwind.key_id}: the fingerprint you typed matched its key'
    )
    assert fingerprint_of(northwind) not in out + err
    assert fingerprint_of(northwind).upper() not in out + err


def test_a_first_setup_plan_on_an_existing_configuration_points_to_an_add_issuers_plan(
    home, tmp_path, run, northwind
):
    """The usual reason to apply a plan where a configuration already exists is to add an issuer."""
    plan = _plan_file(tmp_path, prepare_plan([northwind]))
    assert run("admin-apply", plan, *_expect(northwind))[0] == 0
    code, out, _ = run("admin-describe", "--json", plan)
    problem = json.loads(out)["problem"]
    assert code == 2 and "There is already a configuration" in problem
    assert 'To add issuers to it, prepare an "Add issuers" plan instead.' in problem
    assert "To start again, move the folder's files somewhere else first." in problem
