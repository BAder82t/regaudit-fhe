"""The macOS build installs exactly the pinned wheels, and the engine among them is the release the portal accepts."""

import json
import re
from pathlib import Path

from regaudit_portal import engine

HERE = Path(__file__).resolve().parents[1] / "installer" / "macos"


def _lines():
    return [
        x
        for x in (HERE / "requirements.lock").read_text().splitlines()
        if x and not x.startswith("#")
    ]


def test_every_wheel_is_pinned_with_a_hash():
    lines = _lines()
    assert len(lines) > 10
    for line in lines:
        assert re.fullmatch(
            r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+ --hash=sha256:[0-9a-f]{64}", line
        ), line


def test_the_engine_is_pinned_to_the_release_the_portal_accepts():
    pins = dict(line.split(" ")[0].split("==") for line in _lines())
    assert pins["regaudit-fhe"] == engine.RELEASE


def test_the_runtime_is_pinned_by_hash_and_names_its_checks():
    runtime = json.loads((HERE / "runtime.json").read_text())
    assert re.fullmatch(r"[0-9a-f]{64}", runtime["sha256"])
    assert runtime["name"].endswith("aarch64-apple-darwin-install_only.tar.gz")
    assert runtime["sums_url"].endswith("/SHA256SUMS") and runtime["url"].startswith(
        "https://github.com/"
    )


def test_the_build_script_refuses_what_the_portal_would_refuse():
    text = (HERE / "build_app.py").read_text()
    assert "--require-hashes" in text and "--only-binary=:all:" in text and "--no-deps" in text
    assert "check_engine" in text and "not the recognised release" in text


def test_the_build_ships_no_compiled_files_for_the_installed_packages():
    text = (HERE / "build_app.py").read_text()
    assert "--no-compile" in text and '"__pycache__"' in text


def test_the_launcher_hands_the_portal_a_pipe_and_the_portal_watches_it():
    swift = (HERE / "launcher" / "main.swift").read_text()
    assert (
        "--exit-when-input-closes" in swift
        and "Pipe()" in swift
        and "standardInput = input" in swift
    )
    assert '"-I", "-B"' in swift
    assert (
        "exit-when-input-closes"
        in (HERE.parents[1] / "regaudit_portal" / "__main__.py").read_text()
    )


def test_the_build_ships_the_administrator_programs_the_icon_and_a_read_me():
    text = (HERE / "build_app.py").read_text()
    assert "regaudit_fhe.cli" in text and "regaudit_portal" in text and '"tools"' in text
    assert "AppIcon" in text and "iconutil" in text
    assert "READ ME FIRST.txt" in text and "approved_limitation" in text
    assert "LSMultipleInstancesProhibited" not in text


def test_the_build_keeps_the_bundle_free_of_what_it_created():
    text = (HERE / "build_app.py").read_text()
    assert '"-I",\n            "-B",' in text.replace("\r", "") or '"-B"' in text
    assert "known_bytecode" in text and "pip-*.dist-info" in text
    assert "launcher_sha256_before_signing" in text and "application_tree_sha256" in text


def test_the_icon_sources_are_there():
    assert (HERE / "icon" / "vaultbytes-mark.svg").read_text().lstrip().startswith("<svg")
    assert (HERE / "icon" / "make_icon.swift").is_file()


def test_the_administrator_programs_find_the_application_through_a_symbolic_link():
    text = (HERE / "build_app.py").read_text()
    assert 'while [ -L "$self" ]' in text and "readlink" in text


def test_the_launcher_does_not_tell_a_local_copy_to_be_downloaded_again():
    swift = (HERE / "launcher" / "main.swift").read_text()
    assert "Download it again" not in swift and "disk image again" in swift
