"""C3-09: under a strict profile, another local account must not be able to change which keys the verifier trusts.

Each outcome test makes a real change to a real store file and verifies real reports through the real CLI: one signed by
the enrolled key, and one signed by an outsider's key. Another process stands in for another account. The limit test at
the end pins down what this does not do.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import regaudit_fhe as rf
from regaudit_fhe import _storage_policy as policy_module
from regaudit_fhe import trust as trust_module
from regaudit_fhe.trust import TrustStoreError
from regaudit_fhe.verification import PolicyError, VerificationPolicy

from .test_revocation_tooling_and_cli import cli

STRICT = ["confidential", "high-assurance", "secure-v1"]
SERVER_ENV = {
    "REGAUDIT_FHE_REPLAY_MODE": "record",
    "REGAUDIT_FHE_VERIFIER_ID": "reg",
    "REGAUDIT_FHE_MAX_AGE_S": "3600",
}


def verify_cli(cwd: Path, report: str, store: str = "t.json", profile: str = "confidential"):
    db = cwd / f"replay-{report}-{profile}.db"
    db.unlink(missing_ok=True)
    out = cli(
        "verify", "-i", str(cwd / report), "--trusted-keys", store, "--profile", profile,
        "--max-age-seconds", "3600", "--replay-mode", "record", "--replay-db", str(db), "--verifier-id", "reg",
        cwd=cwd,
    )  # fmt: skip
    return out, (json.loads(out.stdout) if out.stdout.strip() else None)


def make_world(tmp_path: Path) -> Path:
    """A store enrolling one key, a report from that key, and a report from an outsider's key under the same issuer."""
    for name in ("issuer", "outsider"):
        out = cli(
            "keygen", "--key-id", name, "--issuer", "acme", "--private-key", f"{name}.pem",
            "--public-key", f"{name}.pub", cwd=tmp_path,
        )  # fmt: skip
        assert out.returncode == 0, out.stderr
        (tmp_path / f"{name}.fp").write_text(json.loads(out.stdout)["fingerprint_sha256"])
    assert cli(
        "trust", "add", "--store", "t.json", "--key-id", "issuer", "--issuer", "acme", "--public-key", "issuer.pub",
        "--fingerprint", (tmp_path / "issuer.fp").read_text(), cwd=tmp_path,
    ).returncode == 0  # fmt: skip
    (tmp_path / "in.json").write_text(json.dumps({"p": [0.2, 0.3, 0.5], "q": [0.25, 0.25, 0.5]}))
    for name, report in (("issuer", "trusted.json"), ("outsider", "outsider.json")):
        assert cli(
            "audit", "drift", "-i", "in.json", "-o", report, "--signing-key", f"{name}.pem", "--key-id", name,
            "--issuer", "acme", "--deployment-id", "p", "--audience", "reg", cwd=tmp_path,
        ).returncode == 0  # fmt: skip
    return tmp_path


@pytest.fixture
def world(tmp_path: Path) -> Path:
    return make_world(tmp_path)


def add_outsider(path: Path, world: Path) -> None:
    """What a writer of the file could do: enrol their own key under the issuer's name."""
    doc = json.loads(path.read_text())
    doc["entries"]["outsider"] = {
        "issuer": "acme",
        "public_key_pem": (world / "outsider.pub").read_text(),
        "status": "active",
    }
    path.write_text(json.dumps(doc))


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# ----------------------------------------------------------------------------- outcome: controls


@pytest.mark.parametrize("profile", STRICT)
@pytest.mark.parametrize("file_mode", [0o600, 0o640, 0o644, 0o400], ids=oct)
def test_a_store_nobody_else_can_write_decides_correctly_and_keeps_its_mode(
    world, profile, file_mode
):
    os.chmod(world / "t.json", file_mode)
    out, trusted = verify_cli(world, "trusted.json", profile=profile)
    assert out.returncode == 0 and trusted["trust_status"] == "TRUSTED", out.stderr
    out, outsider = verify_cli(world, "outsider.json", profile=profile)
    assert out.returncode == 1 and outsider["trust_status"] != "TRUSTED"
    assert mode(world / "t.json") == file_mode


def test_a_new_store_from_trust_add_is_accepted(world):
    assert mode(world / "t.json") == 0o644
    assert verify_cli(world, "trusted.json")[1]["trust_status"] == "TRUSTED"


def test_legitimate_enrollment_of_a_second_key_changes_the_outcome(world):
    assert verify_cli(world, "outsider.json")[0].returncode == 1
    out = cli(
        "trust", "add", "--store", "t.json", "--key-id", "outsider", "--issuer", "acme",
        "--public-key", "outsider.pub", "--fingerprint", (world / "outsider.fp").read_text(), cwd=world,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    assert verify_cli(world, "outsider.json")[1]["trust_status"] == "TRUSTED"


# ----------------------------------------------------------------------------- outcome: a store others can write


@pytest.mark.parametrize("profile", STRICT)
@pytest.mark.parametrize("file_mode", [0o666, 0o660, 0o620, 0o602], ids=oct)
def test_a_store_others_can_write_gives_no_verdict_even_after_it_is_changed(
    world, profile, file_mode
):
    before = (world / "t.json").read_bytes()
    os.chmod(world / "t.json", file_mode)
    for report in ("trusted.json", "outsider.json"):
        out, verdict = verify_cli(world, report, profile=profile)
        assert out.returncode == 3 and verdict is None, out.stdout + out.stderr
        assert "lets group or others write" in out.stderr
    assert (world / "t.json").read_bytes() == before and mode(world / "t.json") == file_mode
    add_outsider(world / "t.json", world)
    out, verdict = verify_cli(world, "outsider.json", profile=profile)
    assert out.returncode == 3 and verdict is None
    assert mode(world / "t.json") == file_mode


@pytest.mark.parametrize("profile", STRICT)
@pytest.mark.parametrize("dir_mode", [0o777, 0o770, 0o1777], ids=oct)
def test_a_store_replaced_through_a_directory_others_can_write_gives_no_verdict(
    world, profile, dir_mode
):
    box = world / "box"
    box.mkdir()
    (box / "t.json").write_bytes((world / "t.json").read_bytes())
    add_outsider(box / "t.json", world)
    os.chmod(box / "t.json", 0o644)
    os.chmod(box, dir_mode)
    out, verdict = verify_cli(world, "outsider.json", store="box/t.json", profile=profile)
    assert out.returncode == 3 and verdict is None
    assert "writable by group or others" in out.stderr
    assert mode(box) == dir_mode


def test_a_directory_higher_up_that_others_can_write_is_refused(world):
    high = world / "high"
    box = high / "box"
    box.mkdir(parents=True)
    (box / "t.json").write_bytes((world / "t.json").read_bytes())
    os.chmod(high, 0o777)  # noqa: S103 - the point of the test
    out, _ = verify_cli(world, "trusted.json", store="high/box/t.json")
    assert out.returncode == 3 and "high" in out.stderr


def test_a_sticky_directory_above_a_private_parent_is_accepted(world):
    high = world / "high"
    box = high / "box"
    box.mkdir(parents=True)
    os.chmod(box, 0o700)
    (box / "t.json").write_bytes((world / "t.json").read_bytes())
    os.chmod(high, 0o1777)  # noqa: S103 - the point of the test
    out, verdict = verify_cli(world, "trusted.json", store="high/box/t.json")
    assert out.returncode == 0 and verdict["trust_status"] == "TRUSTED", out.stderr


@pytest.mark.parametrize("profile", STRICT)
def test_a_symlink_at_the_store_path_is_refused(world, profile):
    target = world / "real.json"
    target.write_bytes((world / "t.json").read_bytes())
    (world / "link.json").symlink_to(target)
    out, verdict = verify_cli(world, "trusted.json", store="link.json", profile=profile)
    assert out.returncode == 3 and verdict is None and "symbolic link" in out.stderr


def test_a_symlink_swapped_in_after_the_location_check_is_refused_at_open(world, monkeypatch):
    target = world / "real.json"
    target.write_bytes((world / "t.json").read_bytes())
    (world / "link.json").symlink_to(target)
    monkeypatch.setattr(trust_module, "_store_location", lambda path: (None, str(path)))
    with pytest.raises(TrustStoreError, match="unreadable"):
        rf.TrustStore.from_json(world / "link.json", private_storage=True)


def test_a_symlinked_directory_in_a_directory_others_can_write_is_refused(world):
    shared = world / "shared"
    shared.mkdir()
    real = world / "real"
    real.mkdir(mode=0o700)
    (real / "t.json").write_bytes((world / "t.json").read_bytes())
    (shared / "link").symlink_to(real)
    os.chmod(shared, 0o777)  # noqa: S103 - the point of the test
    out, _ = verify_cli(world, "trusted.json", store="shared/link/t.json")
    assert out.returncode == 3 and "shared" in out.stderr


def test_a_fifo_is_refused_without_hanging(world):
    os.mkfifo(world / "fifo.json", 0o600)
    out, _ = verify_cli(world, "trusted.json", store="fifo.json")
    assert out.returncode == 3 and "not a regular file" in out.stderr


def test_a_store_with_a_second_name_is_refused(world):
    os.link(world / "t.json", world / "other.json")
    out, _ = verify_cli(world, "trusted.json")
    assert out.returncode == 3 and "more than one name" in out.stderr


def test_a_store_replaced_between_the_read_and_the_check_after_it_is_refused(world, monkeypatch):
    swap = world / "swap.json"
    swap.write_bytes((world / "t.json").read_bytes())
    add_outsider(swap, world)
    os.chmod(swap, 0o644)
    real_lstat = os.lstat

    def swapping(path, *args, **kwargs):
        if str(path).endswith("t.json") and swap.exists():
            os.replace(swap, world / "t.json")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(trust_module.os, "lstat", swapping)
    monkeypatch.setattr(trust_module, "_store_location", lambda path: (None, str(path)))
    with pytest.raises(TrustStoreError, match="replaced while it was read"):
        rf.TrustStore.from_json(world / "t.json", private_storage=True)


# ----------------------------------------------------------------------------- ownership and platform


def test_a_store_owned_by_another_account_is_refused_and_one_owned_by_root_is_not(world):
    info = os.stat(world / "t.json")

    def as_owner(uid):
        fields = list(info)
        fields[stat.ST_UID] = uid
        return os.stat_result(fields)

    owners = (os.geteuid(), 0)
    assert policy_module.file_problem(as_owner(0), owners=owners) is None
    assert policy_module.file_problem(as_owner(os.geteuid()), owners=owners) is None
    assert "another account" in policy_module.file_problem(
        as_owner(os.geteuid() + 1), owners=owners
    )


def test_a_store_of_another_account_is_refused_on_the_real_path(world, monkeypatch):
    real = os.geteuid()
    monkeypatch.setattr(trust_module, "_store_location", lambda path: (None, str(path)))
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    with pytest.raises(TrustStoreError, match="another account"):
        rf.TrustStore.from_json(world / "t.json", private_storage=True)


def test_a_directory_of_another_account_is_refused(world, monkeypatch):
    real = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    with pytest.raises(TrustStoreError, match="another account"):
        rf.TrustStore.from_json(world / "t.json", private_storage=True)


@pytest.mark.parametrize("missing", ["geteuid", "O_NOFOLLOW"])
def test_a_platform_that_cannot_establish_it_is_refused(world, monkeypatch, missing):
    monkeypatch.delattr(os, missing)
    with pytest.raises(TrustStoreError, match="this platform cannot establish"):
        rf.TrustStore.from_json(world / "t.json", private_storage=True)


def test_an_unknown_platform_is_refused(world, monkeypatch):
    monkeypatch.setattr(sys, "platform", "freebsd14")
    with pytest.raises(TrustStoreError, match="this platform cannot establish"):
        rf.TrustStore.from_json(world / "t.json", private_storage=True)


# ----------------------------------------------------------------------------- the library path


@pytest.mark.parametrize("profile", STRICT)
def test_a_store_loaded_without_the_flag_is_still_refused_by_a_strict_policy(world, profile):
    os.chmod(world / "t.json", 0o666)  # noqa: S103 - the point of the test
    store = rf.TrustStore.from_json(world / "t.json")
    assert "lets group or others write" in store.storage_problem
    with pytest.raises(PolicyError, match="another account could change"):
        VerificationPolicy(profile=profile, trust_store=store, max_age=None)


def test_development_still_loads_it_warns_and_is_not_protected(world):
    os.chmod(world / "t.json", 0o666)  # noqa: S103 - the point of the test
    add_outsider(world / "t.json", world)
    out, verdict = verify_cli(world, "outsider.json", profile="development")
    assert verdict["trust_status"] == "TRUSTED"
    assert "another account could change" in out.stderr


def test_a_store_built_in_memory_is_the_callers_boundary_and_no_file_was_checked():
    signer = rf.Signer.generate(issuer="acme", key_id="k")
    store = rf.TrustStore.from_dict(
        {
            "entries": {
                "k": {
                    "issuer": "acme",
                    "public_key_pem": signer.public_key_pem(),
                    "status": "active",
                }
            }
        }
    )
    assert store.storage_problem is None


def test_a_later_change_to_the_file_does_not_reach_a_store_already_loaded(world):
    store = rf.TrustStore.from_json(world / "t.json", private_storage=True)
    keys = set(store.keys)
    add_outsider(world / "t.json", world)
    assert set(store.keys) == keys and "outsider" not in store.keys


# ----------------------------------------------------------------------------- other loading paths


def _load_config(
    world: Path, store: Path, profile: str = "confidential"
) -> subprocess.CompletedProcess[str]:
    env = dict(
        os.environ,
        **SERVER_ENV,
        REGAUDIT_FHE_PROFILE=profile,
        REGAUDIT_FHE_TRUST_STORE=str(store),
        REGAUDIT_FHE_REPLAY_DB=str(world / "server-replay.db"),
    )
    code = (
        "from regaudit_fhe.server import load_config_from_env\n"
        "print(sorted(load_config_from_env().trust_store.keys))\n"
    )
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code],
        cwd=world,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.mark.parametrize("profile", STRICT)
def test_the_server_configuration_refuses_a_store_others_can_write(world, profile):
    os.chmod(world / "t.json", 0o666)  # noqa: S103 - the point of the test
    out = _load_config(world, world / "t.json", profile)
    assert out.returncode != 0 and "lets group or others write" in out.stderr


def test_the_server_configuration_accepts_a_safe_store(world):
    out = _load_config(world, world / "t.json")
    assert out.returncode == 0 and out.stdout.strip() == "['issuer']", out.stderr


def test_the_server_command_exits_2_on_a_store_others_can_write(world):
    os.chmod(world / "t.json", 0o666)  # noqa: S103 - the point of the test
    env = dict(
        os.environ,
        **SERVER_ENV,
        REGAUDIT_FHE_PROFILE="confidential",
        REGAUDIT_FHE_REPLAY_DB=str(world / "server-replay.db"),
    )
    out = subprocess.run(
        [sys.executable, "-m", "regaudit_fhe.cli", "serve", "--trust-store", "t.json"],
        cwd=world, env=env, capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert out.returncode == 2 and "lets group or others write" in out.stderr


def test_revocation_ceremonies_refuse_a_store_others_can_write_and_change_nothing(world):
    for name in ("authority", "anchor"):
        out = cli(
            "keygen", "--key-id", name, "--issuer", "acme", "--private-key", f"{name}.pem",
            "--public-key", f"{name}.pub", cwd=world,
        )  # fmt: skip
        (world / f"{name}.fp").write_text(json.loads(out.stdout)["fingerprint_sha256"])
    os.chmod(world / "t.json", 0o666)  # noqa: S103 - the point of the test
    out = cli(
        "revocation", "enroll", "--pins", "pins.json", "--state", "state", "--issuer", "acme",
        "--authority-key", "authority.pub", "--authority-fingerprint", (world / "authority.fp").read_text(),
        "--anchor-key", "anchor.pub", "--anchor-fingerprint", (world / "anchor.fp").read_text(),
        "--baseline-epoch", "0", "--trusted-keys", "t.json", cwd=world,
    )  # fmt: skip
    assert out.returncode == 3 and "lets group or others write" in out.stderr
    assert not (world / "pins.json").exists() and not (world / "state").exists()


# ----------------------------------------------------------------------------- macOS ACLs


macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACLs")


def set_acl(path: Path, entry: str) -> None:
    subprocess.run(["/bin/chmod", "+a", entry, str(path)], check=True, capture_output=True)  # noqa: S603


@macos
@pytest.mark.parametrize(
    "right", ["write", "append", "delete", "writesecurity", "chown", "writeattr"]
)
def test_an_acl_letting_others_change_the_store_is_refused(world, right):
    set_acl(world / "t.json", f"group:everyone allow {right}")
    out, verdict = verify_cli(world, "trusted.json")
    assert out.returncode == 3 and verdict is None and "ACL" in out.stderr


@macos
@pytest.mark.parametrize("right", ["add_file", "delete_child", "add_subdirectory", "write"])
def test_an_acl_letting_others_change_the_parent_directory_is_refused(world, right):
    box = world / "box"
    box.mkdir(mode=0o700)
    (box / "t.json").write_bytes((world / "t.json").read_bytes())
    set_acl(box, f"group:everyone allow {right}")
    out, verdict = verify_cli(world, "trusted.json", store="box/t.json")
    assert out.returncode == 3 and verdict is None and "ACL" in out.stderr


@macos
def test_an_acl_on_a_directory_higher_up_is_refused(world):
    high = world / "high"
    box = high / "box"
    box.mkdir(parents=True)
    (box / "t.json").write_bytes((world / "t.json").read_bytes())
    set_acl(high, "group:everyone allow add_file")
    out, _ = verify_cli(world, "trusted.json", store="high/box/t.json")
    assert out.returncode == 3 and "ACL" in out.stderr


@macos
@pytest.mark.parametrize(
    "entry",
    ["group:everyone deny delete", "group:everyone allow read", "group:everyone deny write"],
)
def test_an_acl_that_gives_nobody_write_is_accepted(world, entry):
    set_acl(world / "t.json", entry)
    out, verdict = verify_cli(world, "trusted.json")
    assert out.returncode == 0 and verdict["trust_status"] == "TRUSTED", out.stderr


@macos
def test_an_acl_giving_write_to_ourselves_is_accepted(world):
    set_acl(world / "t.json", f"{os.environ.get('USER') or os.getlogin()} allow write")
    out, verdict = verify_cli(world, "trusted.json")
    assert out.returncode == 0 and verdict["trust_status"] == "TRUSTED", out.stderr


@macos
def test_the_store_is_refused_when_the_acl_library_cannot_be_used(world, monkeypatch):
    def no_library(*_args, **_kwargs):
        raise OSError("no library")

    monkeypatch.setattr(policy_module.ctypes, "CDLL", no_library)
    with pytest.raises(TrustStoreError, match="cannot be read"):
        rf.TrustStore.from_json(world / "t.json", private_storage=True)


@pytest.mark.parametrize(
    "text",
    ["!#acl 1\nnonsense\n", "!#acl 1\nuser:AA:x:501:maybe:write\n", "!#acl 1\nuser:AA:x:501\n"],
)
def test_acl_text_that_cannot_be_read_fails_closed(text):
    assert "cannot be read reliably" in policy_module._acl_text_problem(text, "x")


@pytest.mark.parametrize(
    ("text", "bad"),
    [
        ("!#acl 1\ngroup:AA:everyone:12:deny:delete\n", False),
        ("!#acl 1\ngroup:AA:everyone:12:allow:read,readattr\n", False),
        ("!#acl 1\ngroup:AA:staff:20:allow:read,write\n", True),
        ("!#acl 1\nuser:AA:other:99999:allow:write\n", True),
        ("!#acl 1\ngroup:AA:everyone:12:allow:a_right_nobody_has_named\n", True),
        ("!#acl 1\nuser:AA:root:0:allow:write\n", False),
    ],
)
def test_acl_text_is_judged_by_who_can_write(text, bad):
    problem = policy_module._acl_text_problem(text, "x")
    assert (problem is not None) is bad


# ----------------------------------------------------------------------------- what this does not protect against


def test_limit_the_same_account_can_still_add_a_key_and_nothing_notices(world):
    """Not a guarantee: a statement of the limit. If this ever fails, the documented limit needs updating."""
    assert verify_cli(world, "outsider.json")[0].returncode == 1
    add_outsider(world / "t.json", world)
    os.chmod(world / "t.json", 0o600)
    out, verdict = verify_cli(world, "outsider.json")
    assert out.returncode == 0 and verdict["trust_status"] == "TRUSTED"
