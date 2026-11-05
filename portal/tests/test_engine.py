"""Only the published regaudit-fhe 0.2.1 may produce a verdict. Any other engine is refused, with no fallback."""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import importlib.util
import io
import logging
import marshal
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import regaudit_portal.app as portal_app
import regaudit_portal.config as portal_config
import regaudit_portal.engine as engine_module
from helpers import client_for, post
from regaudit_portal.config import EngineProblem, load_portal
from regaudit_portal.engine import (
    RELEASE,
    RELEASE_FILES_SHA256,
    UnsafeTree,
    check_engine,
    files_digest,
)

import regaudit_fhe

PACKAGE = Path(regaudit_fhe.__file__).parent
TESTS = Path(__file__).parent

REFUSED_STATUS = {"ready": False, "state": "unavailable"}


# ----------------------------------------------------------------------------- the installed engine is the release
# These need no git and no tag, and they do not skip. They fail in any environment whose engine is not the published
# 0.2.1: a source checkout, a modified install, another version.


def test_the_installed_engine_reports_version_0_2_1():
    assert regaudit_fhe.__version__ == RELEASE == "0.2.1"
    assert importlib.metadata.version("regaudit-fhe") == "0.2.1"


def test_the_installed_engine_files_hash_to_the_pinned_digest():
    assert files_digest(PACKAGE) == RELEASE_FILES_SHA256
    assert documented_recipe_digest(PACKAGE) == RELEASE_FILES_SHA256


def test_the_installed_engine_passes_the_portals_own_check():
    identity = check_engine()
    assert identity.ok and identity.reason == "OK" and identity.detail == ""
    assert identity.engine is not None and identity.engine["version"] == "0.2.1"


def test_the_distributions_own_record_hashes_agree_with_the_installed_files():
    """The installer's RECORD lists a SHA-256 for each file it put down. They must still be what is on disk."""
    files = importlib.metadata.distribution("regaudit-fhe").files or []
    hashed = [f for f in files if f.hash is not None and f.parts[0] == "regaudit_fhe"]
    assert len(hashed) >= 46, (
        "the RECORD has no hashes for the engine: this is not a wheel installation"
    )
    for entry in hashed:
        assert entry.hash is not None and entry.hash.mode == "sha256"
        digest = hashlib.sha256(Path(str(entry.locate())).read_bytes()).digest()
        assert base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == entry.hash.value, str(
            entry
        )


# ----------------------------------------------------------------------------- anything else is refused


def _modified_copy(tmp_path: Path) -> Path:
    copy = tmp_path / "regaudit_fhe"
    shutil.copytree(PACKAGE, copy, ignore=shutil.ignore_patterns("__pycache__"))
    with (copy / "verification.py").open("a") as handle:
        handle.write("\n# changed\n")
    return copy


def _unreadable(_folder):
    raise OSError("unreadable")


def _crashes(_folder):
    raise RuntimeError("the hash could not be computed")


def _no_engine():
    return None


def test_a_modified_file_set_is_refused_even_though_the_version_string_is_right(tmp_path):
    copy = _modified_copy(tmp_path)
    assert (
        "0.2.1" in (copy / "__init__.py").read_text()
    )  # the right version string, a different file set
    identity = check_engine(copy)
    assert (
        not identity.ok and identity.reason == "ENGINE_NOT_RECOGNISED" and identity.engine is None
    )
    assert str(copy) in identity.detail  # for the administrator's terminal


def test_a_renamed_or_added_engine_file_is_refused(tmp_path):
    copy = tmp_path / "regaudit_fhe"
    shutil.copytree(PACKAGE, copy, ignore=shutil.ignore_patterns("__pycache__"))
    (copy / "py.typed").rename(copy / "py.typed.moved")
    assert check_engine(copy).reason == "ENGINE_NOT_RECOGNISED"
    (copy / "py.typed.moved").rename(copy / "py.typed")
    (copy / "extra.py").write_text("")
    assert check_engine(copy).reason == "ENGINE_NOT_RECOGNISED"


def test_an_engine_that_is_not_installed_is_refused(monkeypatch):
    monkeypatch.setattr(engine_module, "_locate", _no_engine)
    identity = check_engine()
    assert not identity.ok and identity.reason == "ENGINE_MISSING" and identity.engine is None


def test_an_engine_whose_files_cannot_be_read_is_refused(monkeypatch):
    monkeypatch.setattr(engine_module, "files_digest", _unreadable)
    identity = check_engine()
    assert not identity.ok and identity.reason == "ENGINE_UNREADABLE" and identity.engine is None


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a file whose permissions forbid it")
def test_an_engine_file_that_the_account_cannot_read_is_refused(tmp_path):
    copy = tmp_path / "regaudit_fhe"
    shutil.copytree(PACKAGE, copy, ignore=shutil.ignore_patterns("__pycache__"))
    (copy / "trust.py").chmod(0)
    try:
        identity = check_engine(copy)
    finally:
        (copy / "trust.py").chmod(0o600)
    assert not identity.ok and identity.reason == "ENGINE_UNREADABLE"


def test_a_folder_with_no_files_is_refused_and_has_no_digest(tmp_path):
    with pytest.raises(OSError, match="no files"):
        files_digest(tmp_path)
    assert check_engine(tmp_path).reason == "ENGINE_UNREADABLE"


def test_an_integrity_computation_that_fails_is_a_refusal_never_a_pass(monkeypatch):
    monkeypatch.setattr(engine_module, "files_digest", _crashes)
    identity = check_engine()
    assert not identity.ok and identity.reason == "ENGINE_CHECK_FAILED" and identity.engine is None
    assert "RuntimeError" in identity.detail


@pytest.mark.parametrize("version", ["0.3.0", "0.2.2", "0.2.0", "", None])
def test_any_other_version_is_refused_even_if_the_files_were_the_release(monkeypatch, version):
    monkeypatch.setattr(regaudit_fhe, "__version__", version)
    identity = check_engine()
    assert not identity.ok and identity.reason == "ENGINE_VERSION" and identity.engine is None


def test_a_distribution_record_for_another_version_is_refused(monkeypatch):
    monkeypatch.setattr(engine_module, "_distribution_version", lambda: "0.3.0")
    assert check_engine().reason == "ENGINE_VERSION"


def test_files_that_match_but_are_not_the_ones_in_use_are_refused(tmp_path):
    identical = tmp_path / "regaudit_fhe"
    shutil.copytree(PACKAGE, identical, ignore=shutil.ignore_patterns("__pycache__"))
    assert files_digest(identical) == RELEASE_FILES_SHA256
    assert check_engine(identical).reason == "ENGINE_LOCATION"


def test_a_refused_engine_is_never_imported_by_the_check(tmp_path):
    """The files are hashed first. A modified engine must not be run just to be inspected."""
    marker = tmp_path / "ran"
    package = tmp_path / "regaudit_fhe"
    package.mkdir()
    (package / "__init__.py").write_text(
        f"open({str(marker)!r}, 'w').close()\n__version__ = '0.2.1'\n"
    )
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]);"
        "from regaudit_portal.engine import check_engine;"
        "i = check_engine(); print(i.reason); sys.exit(0 if not i.ok else 1)"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code, str(tmp_path)],
        capture_output=True, text=True, timeout=60, check=False,
        env=dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1])),
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "ENGINE_NOT_RECOGNISED"
    assert not marker.exists(), "the damaged engine was executed by the check"


# ----------------------------------------------------------------------------- the portal gives nothing then


def test_load_portal_refuses_when_the_engine_is_refused(demo, monkeypatch):
    monkeypatch.setattr(engine_module, "files_digest", _crashes)
    with pytest.raises(EngineProblem, match="ENGINE_CHECK_FAILED"):
        load_portal(demo / "portal-config.json")


def test_a_portal_started_with_a_refused_engine_is_unavailable_and_verifies_nothing(
    demo, monkeypatch
):
    monkeypatch.setattr(engine_module, "files_digest", _crashes)
    monkeypatch.setattr(portal_app, "_parse", _must_not_run)
    monkeypatch.setattr(portal_app, "verify", _must_not_run)
    client = client_for(demo / "portal-config.json")
    assert client.app.state.ready is False
    status = client.get("/api/status")
    assert status.status_code == 200 and status.json() == REFUSED_STATUS
    for name in ("1-trusted.json", "2-untrusted-signer.json"):
        response = post(client, demo, name)
        assert response.status_code == 503
        body = response.json()
        assert (
            body["state"] == "unavailable" and "verification" not in body and "engine" not in body
        )
        assert str(demo) not in response.text and "RuntimeError" not in response.text


def _must_not_run(*_args, **_kwargs):
    raise AssertionError("work was done for a request the portal had to refuse")


def test_an_engine_that_goes_bad_after_start_up_is_refused_before_the_upload_is_read(
    demo, monkeypatch
):
    client = client_for(demo / "portal-config.json")
    assert post(client, demo, "1-trusted.json").status_code == 200
    monkeypatch.setattr(engine_module, "files_digest", _crashes)
    monkeypatch.setattr(portal_app, "_read_limited", _must_not_run)
    monkeypatch.setattr(portal_app, "_parse", _must_not_run)
    monkeypatch.setattr(portal_app, "verify", _must_not_run)
    assert client.get("/api/status").json() == REFUSED_STATUS
    response = post(client, demo, "1-trusted.json")
    assert response.status_code == 503 and response.json()["state"] == "unavailable"
    assert "verification" not in response.json() and str(demo) not in response.text


def test_the_portal_works_again_when_the_engine_passes_again(demo, monkeypatch):
    client = client_for(demo / "portal-config.json")
    with monkeypatch.context() as broken:
        broken.setattr(engine_module, "files_digest", _crashes)
        assert post(client, demo, "1-trusted.json").status_code == 503
    assert client.get("/api/status").json()["ready"] is True
    assert post(client, demo, "1-trusted.json").json()["verification"]["trust_status"] == "TRUSTED"


def test_the_engine_is_checked_three_times_for_every_verification(demo, monkeypatch):
    """Before the upload is read, immediately before the engine's verify is called, and immediately after it returns."""
    calls = []
    real = engine_module.check_engine

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    client = client_for(
        demo / "portal-config.json"
    )  # starting the portal checks the engine too, so count from here
    monkeypatch.setattr(portal_app, "check_engine", counting)
    for _ in range(3):
        assert post(client, demo, "1-trusted.json").status_code == 200
    assert len(calls) == 9


def _verify_calls(monkeypatch):
    """Record every call to the engine's verify, and let it run."""
    calls = []
    real = portal_app.verify

    def recording(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(portal_app, "verify", recording)
    return calls


def test_a_change_made_while_the_upload_is_arriving_is_caught_before_verify_is_called(
    demo, monkeypatch
):
    """The engine is still fine when the upload starts. It is not when the last byte has arrived."""
    calls = _verify_calls(monkeypatch)
    real_read = portal_app._read_limited

    async def read_then_break(request):
        raw = await real_read(request)
        monkeypatch.setattr(
            engine_module, "files_digest", _crashes
        )  # an engine file changes during the upload
        return raw

    monkeypatch.setattr(portal_app, "_read_limited", read_then_break)
    client = client_for(demo / "portal-config.json")
    response = post(client, demo, "1-trusted.json")
    assert calls == [], (
        "verify was called although the engine had already stopped passing its check"
    )
    assert response.status_code == 503 and response.json()["state"] == "unavailable"
    assert "verification" not in response.json() and "engine" not in response.json()


def test_a_change_made_while_the_engine_verifies_gives_no_verdict_and_no_export(demo, monkeypatch):
    """The engine passes before verify is called and fails after it returns: the result is discarded."""
    real = portal_app.verify

    def verify_then_break(*args, **kwargs):
        result = real(*args, **kwargs)
        monkeypatch.setattr(engine_module, "files_digest", _crashes)
        return result

    monkeypatch.setattr(portal_app, "verify", verify_then_break)
    client = client_for(demo / "portal-config.json")
    response = post(client, demo, "1-trusted.json")
    assert response.status_code == 503 and response.json()["state"] == "unavailable"
    body = response.json()
    assert not {"verification", "explanation", "engine", "report_sha256", "fhe_notice"} & set(body)
    assert "TRUSTED" not in response.text and str(demo) not in response.text
    assert client.get("/api/status").json() == REFUSED_STATUS  # and nothing can be saved either


def test_a_verdict_is_returned_when_the_engine_passes_all_three_checks(demo, monkeypatch):
    calls = _verify_calls(monkeypatch)
    body = post(client_for(demo / "portal-config.json"), demo, "1-trusted.json").json()
    assert calls == [1] and body["verification"]["trust_status"] == "TRUSTED"
    assert body["engine"]["release_files"] == "IDENTICAL"


def test_the_check_is_cheap_enough_to_repeat_for_every_verification():
    import time

    check_engine()  # the first call imports the engine
    started = time.perf_counter()
    for _ in range(10):
        assert check_engine().ok
    assert (time.perf_counter() - started) / 10 < 0.05  # under 50 ms each; it takes about 5 ms


def test_no_option_flag_or_environment_variable_can_change_which_engine_is_accepted(monkeypatch):
    package = Path(__file__).parents[1] / "regaudit_portal"
    for path in package.glob("*.py"):
        text = path.read_text()
        assert "os.environ" not in text and "getenv" not in text, path.name
    flags = set(re.findall(r'add_argument\(\s*"(-[-a-z]+)"', (package / "__main__.py").read_text()))
    assert flags == {"--config", "--port"}
    monkeypatch.setattr(engine_module, "files_digest", _crashes)
    for name in (
        "REGAUDIT_PORTAL_ALLOW_ANY_ENGINE",
        "REGAUDIT_FHE_ALLOW_UNVERIFIED",
        "PORTAL_DEBUG",
        "DEVELOPMENT",
    ):
        monkeypatch.setenv(name, "1")
    assert check_engine().ok is False


# ----------------------------------------------------------------------------- what the result says about the engine


def test_the_status_and_every_result_name_the_engine_that_was_checked(client, demo):
    status = client.get("/api/status").json()["engine"]
    body = post(client, demo, "1-trusted.json").json()
    assert body["engine"] == status
    assert status["version"] == "0.2.1" and status["release_files"] == "IDENTICAL"
    assert status["api"] == "regaudit_fhe.verify_report"
    assert status["summary"].startswith("Verdicts are produced by")
    assert (
        "installed source files are identical to the published 0.2.1 release" in status["summary"]
    )
    assert "again before each verification" in status["summary"]
    assert body["portal_version"]
    assert not {"published_release", "storage_protections"} & set(status)


def test_the_portal_calls_the_verification_function_the_engine_publishes():
    assert portal_app.verify is regaudit_fhe.verify_report


def test_the_label_says_it_covers_installed_source_files_only_and_is_no_defence(client, demo):
    engine = post(client, demo, "1-trusted.json").json()["engine"]
    assert engine["check_scope"] == (
        "This comparison covers the installed source files only. It does not show which code is actually "
        "running, and it is not a defence against a tampered environment."
    )
    for text in (engine["summary"], engine["check_scope"]):
        assert "proves" not in text and "guarantee" not in text and "verified to be" not in text


def test_nothing_describes_a_verdict_shown_from_an_unrecognised_engine():
    """The warn-and-continue behaviour is gone: no code, text or flag for it remains."""
    package = Path(__file__).parents[1] / "regaudit_portal"
    text = "\n".join(
        p.read_text() for p in [*package.glob("*.py"), *(package / "static").glob("*")]
    )
    for gone in (
        "ENGINE_NOT_PUBLISHED_RELEASE",
        "published_release",
        "not the published verifier",
        "DIFFERENT",
    ):
        assert gone not in text, gone
    assert not hasattr(portal_config, "identify") and not hasattr(engine_module, "identify")


# ----------------------------------------------------------------------------- the digest recipe is the documented one


def documented_recipe_digest(folder: Path) -> str:
    """The recipe as the comment above ``RELEASE_FILES_SHA256`` words it, written out again without the portal's code."""
    names = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        names += [Path(root, f).relative_to(folder).as_posix() for f in files]
    names.sort(key=lambda name: name.split("/"))  # step 3: part by part
    stream = b""
    for name in names:
        file_hash = hashlib.sha256(
            (folder / name).read_bytes()
        ).hexdigest()  # lowercase hex, 64 characters
        stream += name.encode("utf-8") + b"\0" + file_hash.encode("ascii") + b"\n"
    return hashlib.sha256(stream).hexdigest()


def test_the_documented_recipe_gives_the_same_digest_as_the_code_for_any_copy(tmp_path):
    copy = tmp_path / "regaudit_fhe"
    shutil.copytree(PACKAGE, copy, ignore=shutil.ignore_patterns("__pycache__"))
    assert documented_recipe_digest(copy) == files_digest(copy)


def test_the_order_is_by_path_parts_and_not_by_plain_text(tmp_path):
    """Plain text order puts 'a.py' before 'a/b.py' and the documented order puts the folder first."""
    names = ("a.py", "a-b.py", "a/b.py", "a/c.py", "schemas.py", "schemas/x.json")
    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name)
    plain = hashlib.sha256()
    for name in sorted(names):
        content = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        plain.update(name.encode() + b"\0" + content.encode() + b"\n")
    assert files_digest(tmp_path) == documented_recipe_digest(tmp_path)
    assert files_digest(tmp_path) != plain.hexdigest()


def test_pycache_folders_are_left_out_wherever_they_are(tmp_path):
    (tmp_path / "a.py").write_text("x")
    before = files_digest(tmp_path)
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "a.cpython-312.pyc").write_bytes(b"compiled")
    (tmp_path / "sub" / "__pycache__").mkdir(parents=True)
    (tmp_path / "sub" / "__pycache__" / "b.pyc").write_bytes(b"compiled")
    assert files_digest(tmp_path) == before


# ----------------------------------------------------------------------------- plain files only


def _copy(tmp_path: Path) -> Path:
    copy = tmp_path / "regaudit_fhe"
    shutil.copytree(PACKAGE, copy, ignore=shutil.ignore_patterns("__pycache__"))
    return copy


def _refused_as_unsafe(copy: Path, *words: str) -> None:
    with pytest.raises(UnsafeTree) as raised:
        files_digest(copy)
    identity = check_engine(copy)
    assert not identity.ok and identity.reason == "ENGINE_TREE_UNSAFE" and identity.engine is None
    for word in words:
        assert word in str(raised.value) and word in identity.detail


def test_a_symbolic_link_to_a_folder_holding_an_extra_python_file_is_refused(tmp_path):
    copy = _copy(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "extra.py").write_text("print('planted')\n")
    (copy / "linked").symlink_to(outside, target_is_directory=True)
    _refused_as_unsafe(copy, "linked", "symbolic link")


def test_a_symbolic_link_to_a_file_or_to_nothing_is_refused(tmp_path):
    copy = _copy(tmp_path)
    (copy / "alias.py").symlink_to(copy / "trust.py")
    _refused_as_unsafe(copy, "alias.py", "symbolic link")
    (copy / "alias.py").unlink()
    (copy / "dangling.py").symlink_to(tmp_path / "does-not-exist.py")
    _refused_as_unsafe(copy, "dangling.py")


def test_a_symbolic_link_deep_inside_the_tree_is_refused(tmp_path):
    copy = _copy(tmp_path)
    (copy / "fhe" / "more.py").symlink_to(copy / "fhe" / "params.py")
    _refused_as_unsafe(copy, "more.py")


def test_something_that_is_not_a_regular_file_is_refused(tmp_path):
    copy = _copy(tmp_path)
    os.mkfifo(copy / "pipe")
    _refused_as_unsafe(copy, "pipe", "not a regular file")


def test_a_python_file_inside_pycache_is_refused_and_so_is_any_stray_entry_there(tmp_path):
    copy = _copy(tmp_path)
    cache = copy / "__pycache__"
    cache.mkdir()
    (cache / "verification.cpython-312.pyc").write_bytes(
        b"compiled"
    )  # an ordinary bytecode file is fine
    assert files_digest(copy) == RELEASE_FILES_SHA256
    (cache / "evil.py").write_text("print('planted')\n")
    _refused_as_unsafe(copy, "evil.py", "__pycache__")
    (cache / "evil.py").unlink()
    (cache / "readme.txt").write_text("x")
    _refused_as_unsafe(copy, "readme.txt")
    (cache / "readme.txt").unlink()
    (cache / "sub").mkdir()
    _refused_as_unsafe(copy, "sub", "folder inside __pycache__")
    (cache / "sub").rmdir()
    (cache / "alias.cpython-312.pyc").symlink_to(cache / "verification.cpython-312.pyc")
    _refused_as_unsafe(copy, "alias.cpython-312.pyc")


def test_a_python_file_in_a_nested_pycache_is_refused_too(tmp_path):
    copy = _copy(tmp_path)
    (copy / "fhe" / "__pycache__").mkdir()
    (copy / "fhe" / "__pycache__" / "params.py").write_text("x = 1\n")
    _refused_as_unsafe(copy, "params.py")


def test_the_installed_engine_has_no_links_and_no_stray_entries():
    assert not any(p.is_symlink() for p in PACKAGE.rglob("*"))
    assert files_digest(PACKAGE) == RELEASE_FILES_SHA256


# ----------------------------------------------------------------------------- the log does not grow without limit


def _portal_records(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == "regaudit_portal"]


def test_a_failing_check_is_logged_once_per_change_of_state_and_a_recovery_once(
    demo, monkeypatch, caplog
):
    caplog.set_level(logging.INFO, logger="regaudit_portal")
    client = client_for(demo / "portal-config.json")
    caplog.clear()
    for _ in range(5):
        assert client.get("/api/status").json()["ready"] is True
    assert _portal_records(caplog) == [], "nothing is logged while the engine passes"
    with monkeypatch.context() as broken:
        broken.setattr(engine_module, "files_digest", _crashes)
        for _ in range(30):
            assert client.get("/api/status").json() == REFUSED_STATUS
            assert post(client, demo, "1-trusted.json").status_code == 503
        errors = [r for r in _portal_records(caplog) if r.levelno >= logging.ERROR]
        assert len(errors) == 1 and "ENGINE_CHECK_FAILED" in errors[0].getMessage(), len(errors)
        caplog.clear()
        broken.setattr(
            engine_module, "_locate", _no_engine
        )  # it now fails differently: logged again, once
        for _ in range(30):
            assert client.get("/api/status").json() == REFUSED_STATUS
        different = _portal_records(caplog)
        assert len(different) == 1 and "ENGINE_MISSING" in different[0].getMessage()
    caplog.clear()
    for _ in range(30):
        assert client.get("/api/status").json()["ready"] is True
        assert post(client, demo, "1-trusted.json").status_code == 200
    recovered = _portal_records(caplog)
    assert len(recovered) == 1 and recovered[0].levelno == logging.WARNING
    assert "available again" in recovered[0].getMessage()
    caplog.clear()
    with monkeypatch.context() as broken_again:
        broken_again.setattr(engine_module, "files_digest", _crashes)
        for _ in range(3):
            client.get("/api/status")
    assert len([r for r in _portal_records(caplog) if r.levelno >= logging.ERROR]) == 1


def test_the_check_is_never_cached_whatever_is_logged(demo, monkeypatch):
    client = client_for(demo / "portal-config.json")
    assert client.get("/api/status").json()["ready"] is True
    monkeypatch.setattr(engine_module, "files_digest", _crashes)
    assert client.get("/api/status").json() == REFUSED_STATUS
    assert post(client, demo, "1-trusted.json").status_code == 503


# ----------------------------------------------------------------------------- no compiled file is loaded from the package


def _pyc(kind: str, source: Path, marker: Path) -> bytes:
    """Bytecode for ``source`` plus one extra statement that creates ``marker``, with the header of the given kind."""
    text = source.read_bytes()
    code = compile(
        text + f"\nopen({str(marker)!r}, 'w').close()\n".encode(),
        str(source),
        "exec",
        dont_inherit=True,
    )
    body = marshal.dumps(code)
    magic = importlib.util.MAGIC_NUMBER
    if kind == "timestamp":  # valid as long as the recorded time and size are the source's
        info = source.stat()
        return (
            magic
            + struct.pack("<I", 0)
            + struct.pack("<II", int(info.st_mtime) & 0xFFFFFFFF, len(text))
            + body
        )
    if kind == "unchecked-hash":  # loaded without looking at the source at all
        return magic + struct.pack("<I", 0b01) + b"\0" * 8 + body
    return (
        magic + struct.pack("<I", 0b11) + importlib.util.source_hash(text) + body
    )  # checked-hash: source matches


def _planted_engine(tmp_path: Path, kind: str) -> tuple[Path, Path]:
    """A copy of the published engine, source untouched, with modified bytecode planted for ``verification.py``."""
    copy = _copy(tmp_path / kind)
    marker = tmp_path / f"ran-{kind}"
    cache = copy / "__pycache__"
    cache.mkdir()
    name = f"verification.{sys.implementation.cache_tag}.pyc"
    (cache / name).write_bytes(_pyc(kind, copy / "verification.py", marker))
    return copy.parent, marker


def _run(code: str, path_first: Path) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=120, check=False,
        env=dict(os.environ, PYTHONPATH=os.pathsep.join([str(path_first), str(Path(__file__).parents[1])])),
    )  # fmt: skip


@pytest.mark.parametrize("kind", ["timestamp", "unchecked-hash", "checked-hash"])
def test_planted_bytecode_next_to_the_published_source_does_not_run(tmp_path, kind):
    path_first, marker = _planted_engine(tmp_path, kind)
    # The setup works: without the portal, Python loads the planted bytecode and the marker appears.
    control = _run("import regaudit_fhe", path_first)
    assert control.returncode == 0, control.stderr
    assert marker.exists(), (
        f"the planted {kind} bytecode was not loaded by plain Python, so this test would prove nothing"
    )
    marker.unlink()
    # With the portal, the source is the published one, the check passes, and the modified bytecode never runs.
    checked = _run(
        "from regaudit_portal.engine import check_engine; i = check_engine(); print(i.ok, i.reason)",
        path_first,
    )
    assert checked.returncode == 0, checked.stderr
    assert checked.stdout.split() == ["True", "OK"]
    assert not marker.exists(), f"the modified {kind} bytecode ran: in-tree bytecode was loaded"


def test_the_bytecode_cache_is_a_new_private_folder_that_is_removed_at_exit(tmp_path):
    code = (
        "import os, stat, sys, tempfile\n"
        "import regaudit_portal\n"
        "folder = sys.pycache_prefix\n"
        "print(folder); print(oct(stat.S_IMODE(os.stat(folder).st_mode)))\n"
        "print(os.path.dirname(folder) == tempfile.gettempdir())\n"
        "import regaudit_fhe; print(regaudit_fhe.__cached__.startswith(folder))\n"
    )
    first, second = _run(code, tmp_path), _run(code, tmp_path)
    for run in (first, second):
        assert run.returncode == 0, run.stderr
    folder, mode, in_temp, in_prefix = first.stdout.split()
    assert mode == "0o700" and in_temp == "True" and in_prefix == "True"
    assert folder != second.stdout.split()[0], "a new folder each time, never shared or reused"
    assert not Path(folder).exists(), "removed when the process exited"


# ----------------------------------------------------------------------------- development-time cross-check


def test_the_release_digest_is_the_one_the_v021_tag_has(tmp_path):
    """A development-time cross-check, not a product behaviour. It needs a clone that has the v0.2.1 tag.

    It ties the pinned digest to ``git archive v0.2.1``, independently of any wheel. An exported copy of the portal has
    no git history and no tag, so it skips there, which is expected. The tests above need neither and do not skip:
    they check the installed engine against the pinned digest, and against the installer's own RECORD.
    """
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed")
    try:
        root = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [git, "rev-parse", "--show-toplevel"], cwd=TESTS, capture_output=True, text=True, timeout=60, check=True
        ).stdout.strip()  # fmt: skip
        # Run at the top: inside a subfolder, git archive silently includes only that subfolder.
        archive = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [git, "archive", f"v{RELEASE}:src/regaudit_fhe"],
            cwd=root, capture_output=True, timeout=60, check=True,
        ).stdout  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        pytest.skip(f"no git checkout with the v{RELEASE} tag here (expected in an exported copy)")
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(tmp_path, filter="data")
    assert sum(1 for p in tmp_path.rglob("*") if p.is_file()) == 46
    assert files_digest(tmp_path) == RELEASE_FILES_SHA256
    assert documented_recipe_digest(tmp_path) == RELEASE_FILES_SHA256
