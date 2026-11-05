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
