"""The portal cannot import the library's label module (it is pinned to the published 0.2.1 engine), so its copy of
the two fixed sentences is compared with the library's text here, as text. Runs only where the library source with
``claim_labels`` is importable (the repository's own test run); the portal's own run skips it."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from regaudit_portal import explain

LIB = Path(__file__).resolve().parents[2] / "src" / "regaudit_fhe" / "claim_labels.py"
PORTAL_STATIC = Path(__file__).resolve().parents[1] / "regaudit_portal" / "static"

if not LIB.is_file():
    pytest.skip("the library source is not part of this checkout", allow_module_level=True)

TEXT = LIB.read_text()


def _constant(name: str) -> str:
    match = re.search(rf'^{name} = "([^"]+)"$', TEXT, re.M)
    assert match is not None
    return match.group(1)


def test_the_two_sentences_are_the_library_ones() -> None:
    assert (
        explain.NOT_ESTABLISHED
        == _constant("NOT_ESTABLISHED")
        == "Encrypted execution not established."
    )
    assert _constant("INVARIANT") == explain.INVARIANT


def test_the_page_shows_both_sentences_before_any_script_runs() -> None:
    html = (PORTAL_STATIC / "index.html").read_text()
    assert explain.NOT_ESTABLISHED in html and explain.INVARIANT in html


def test_no_portal_text_calls_a_declared_plaintext_report_plaintext_execution() -> None:
    assert "No encryption: this report states" not in (Path(explain.__file__).read_text())
    for phrase in (
        "encrypted audit",
        "computed under encryption",
        "FHE verified",
        "privacy preserved",
    ):
        for source in (
            Path(explain.__file__),
            PORTAL_STATIC / "index.html",
            PORTAL_STATIC / "app.js",
        ):
            assert phrase.lower() not in source.read_text().lower(), (phrase, source.name)
