"""Words the portal must not use, and claims it must not make."""

from __future__ import annotations

import re
from pathlib import Path

from regaudit_portal.engine import RELEASE_FILES_SHA256

_TEXT_FILES = [
    *(Path(__file__).parents[1] / "regaudit_portal" / "static").glob("*"),
    *(Path(__file__).parents[1] / "regaudit_portal").glob("*.py"),
    Path(__file__).parents[1] / "README.md",
    Path(__file__).parents[1] / "SECURITY.md",
]


def _portal_text() -> str:
    return "\n".join(path.read_text() for path in _TEXT_FILES if path.name != "demo.py")


def test_the_portal_never_calls_what_it_does_an_audit():
    # "regaudit-fhe", "audit_run_id" and other names are not the word; the word on its own is.
    assert not re.search(r"\baudit(s|ed|ing|or|ors)?\b", _portal_text(), re.IGNORECASE)


def test_the_portal_makes_no_claim_of_certification_assurance_approval_or_proof_of_encryption():
    # The approved limitation text says "security guarantees requiring them", which is a warning, not a claim.
    # (In engine.py the sentence is split over two string literals, hence the optional quote and space.)
    text = re.sub(r'security[\s"]*guarantees requiring them', "", _portal_text().lower())
    for phrase in (
        "certified", "production assurance", "production-ready", "regulator approved", "approved by a regulator",
        "guarantee", "fhe execution is proven", "proves encryption", "authoritative revocation",
    ):  # fmt: skip
        assert phrase not in text, phrase
    for match in re.finditer(r"certification", text):
        assert text[max(0, match.start() - 24) : match.start()].endswith("not a regulatory "), text[
            match.start() - 40 : match.end()
        ]


README = Path(__file__).parents[1] / "README.md"
_STATIC = Path(__file__).parents[1] / "regaudit_portal" / "static"


def test_the_readme_starts_with_what_a_first_time_user_needs():
    text = README.read_text()
    before, _, rest = text.partition("## Try it in five minutes with synthetic data")
    assert "## Before you start" in before and rest
    for needed in (
        "separate small local app",
        "does not describe it",
        "Mac or a Linux computer",
        "Windows is not supported",
        "python3 --version",
        "Python 3.10",
        "drag the `portal` folder",
        "The page works only while the portal is running",
        "the administrator starts it",
        "Keeping it running",
        "https://github.com/BAder82t/regaudit-fhe",
        "Download ZIP",
        "or from your administrator",
        "~/portal-demo/sample-reports",
    ):
        assert needed in before, needed
    assert "nohup" not in before, "the command to keep it running comes after the install steps"
    for needed in (
        "Cmd+Shift+G",
        "Ctrl+L",
        "/Users/YOURNAME/portal-demo/sample-reports",
        "/home/YOURNAME/portal-demo/sample-reports",
        "drag a file onto the page",
    ):
        assert needed in rest, needed
    assert text.count("Windows is not supported") == 1, "said once, at the top"


def test_the_readme_gives_the_keep_it_running_command_after_the_environment_exists():
    text = README.read_text()
    created, installed = text.index("python3 -m venv .venv"), text.index(".venv/bin/pip install .")
    keeping = text.index("## Keeping it running")
    assert created < installed < keeping
    assert text.index("nohup .venv/bin/regaudit-portal serve", keeping) > keeping
    assert text.count("nohup") == 1 and "kill $(cat portal.pid)" in text[keeping:]


def test_the_readme_says_what_to_do_if_the_virtual_environment_step_fails_without_claiming_a_test():
    text = README.read_text()
    step = text[text.index("2. Create a private Python environment") :].split("\n", 1)[0]
    assert "ensurepip" in step and "python3-venv" in step and "installed first" in step
    assert "`sudo apt install python3-venv`" in step and "Debian and Ubuntu" in step
    assert "Other systems need the equivalent package from their package manager" in step
    assert "tested" not in step.lower()


def test_the_readme_says_honestly_what_the_engine_check_covers_and_what_it_does_not():
    text = README.read_text()
    for said in (
        "refuses, rather than skips, a symbolic link",
        "`__pycache__` folder that is not a regular `.pyc` file",
        "bytecode cache at a new private folder",
        "no compiled `.pyc` file next to the engine's source is ever loaded",
        "`.pth` files",
        "the libraries the engine uses",
        "the portal's own files",
        "The check does not cover everything",
        "immediately before the engine's verify is called, and again immediately after it returns",
        "logged once when it starts failing and once when it recovers",
        "removed when the portal exits normally, on Ctrl-C and on SIGTERM",
        "killed hard (SIGKILL)",
        "It stops cleanly and prints one line",
        "which stops it as cleanly as Ctrl-C does",
    ):
        assert said in text, said


def test_the_readme_says_the_engine_label_covers_installed_source_files_only():
    text = README.read_text()
    assert "installed source files" in text
    assert "not a defence against a tampered environment" in text
    assert "does not show which code is actually running" in text
    assert "identical to the published 0.2.1 release" in text
    assert RELEASE_FILES_SHA256 in text


def test_the_readme_says_verifier_id_matters_for_reports_that_name_an_audience():
    text = README.read_text()
    assert "names no audience is not refused for this reason" in text
    assert "high-assurance" in text and "every one of them is refused" not in text


def test_the_size_limit_is_called_1_mb_everywhere_and_never_1_mib():
    assert "MiB" not in _portal_text()
    assert "1 MB" in README.read_text() and "1 MB" in (_STATIC / "app.js").read_text()
