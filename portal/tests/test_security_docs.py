"""The security document and the README carry the approved text unchanged, and the FHE warning near their top."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from regaudit_portal.explain import FHE_NOTICE
from test_security_notice import APPROVED_FULL, STATIC, _text_of

PORTAL = Path(__file__).parents[1]


@pytest.mark.parametrize("name", ["SECURITY.md", "README.md"])
def test_the_security_document_and_the_readme_carry_the_full_text_unchanged(name):
    assert APPROVED_FULL in (PORTAL / name).read_text()


def test_the_readme_puts_it_in_its_deployment_section():
    text = (PORTAL / "README.md").read_text()
    deployment = text[text.index("\n## Deployment") :]
    deployment = deployment[: deployment.index("\n## What it does not do")]
    assert APPROVED_FULL in deployment


def test_the_old_sentence_about_the_trust_list_and_replay_record_is_gone_everywhere():
    old = "does not check who can change the trust list or the replay record"
    for path in [*PORTAL.rglob("*.py"), *PORTAL.rglob("*.md"), *STATIC.glob("*")]:
        if "build" in path.parts or "egg-info" in str(path) or "tests" in path.parts:
            continue
        assert old not in path.read_text(), path
    assert "storage_protections" not in (PORTAL / "regaudit_portal" / "engine.py").read_text()


def test_the_portal_text_adds_no_technical_detail_beyond_the_approved_text():
    texts = [(STATIC / name).read_text() for name in ("index.html", "security.html", "app.js")]
    texts += [(PORTAL / name).read_text() for name in ("README.md", "SECURITY.md")]
    for text in texts:
        assert not re.search(
            r"symlink|chmod|umask|toctou|race condition|exploit|\bcve\b",
            text,
            re.I,
        )


def test_the_fhe_warning_is_near_the_top_of_the_readme_and_in_the_security_document_and_its_page(
    client,
):
    readme = (PORTAL / "README.md").read_text().splitlines()
    assert any(FHE_NOTICE in line for line in readme[:12])
    assert FHE_NOTICE in (PORTAL / "SECURITY.md").read_text()
    assert (
        FHE_NOTICE in (PORTAL / "SECURITY.md").read_text().split("##")[1]
    )  # under its own first heading
    assert FHE_NOTICE in _text_of(client.get("/security").text)
