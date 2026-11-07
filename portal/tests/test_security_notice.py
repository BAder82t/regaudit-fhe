"""The approved security text is carried unchanged, and the FHE warning cannot be taken out unnoticed."""

from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from helpers import post
from regaudit_portal.engine import (
    SECURITY_LIMITATION,
    SECURITY_LIMITATION_PARAGRAPHS,
    SECURITY_LIMITATION_SHORT,
    SECURITY_LIMITATION_TITLE,
)
from regaudit_portal.explain import FHE_NOTICE

PORTAL = Path(__file__).parents[1]
STATIC = PORTAL / "regaudit_portal" / "static"
SAMPLES = (
    "1-trusted.json",
    "2-untrusted-signer.json",
    "3-valid-signature-wrong-issuer.json",
    "4-changed-after-signing.json",
    "7-declares-encrypted-backend.json",
)

# The approved text, copied here word for word and independently of the portal's code. If this changes, the approved
# text changed. The em dash in the title is part of it.
APPROVED_TITLE = "Security limitation — published v0.2.1"
APPROVED = (
    "Published regaudit-fhe v0.2.1 does not enforce the strict filesystem ownership and writable-permission "
    "protections for local trust-store and replay-state files introduced in the experimental code.",
    "Users with sufficient filesystem access may be able to modify those files. A valid report signature does not "
    "prove that the signing key was enrolled by an authenticated administrator.",
    "These protections are not included in the published v0.2.1 package. Do not rely on that version for security "
    "guarantees requiring them.",
)
APPROVED_FULL = "\n\n".join((APPROVED_TITLE, *APPROVED))


def _text_of(html: str) -> str:
    return unescape(re.sub(r"<[^>]+>", "\n", html))


# ----------------------------------------------------------------------------- the approved text, verbatim


def test_the_portals_constants_are_the_approved_text_word_for_word():
    assert SECURITY_LIMITATION_TITLE == APPROVED_TITLE
    assert SECURITY_LIMITATION_PARAGRAPHS == APPROVED
    assert SECURITY_LIMITATION == APPROVED_FULL


def test_the_page_the_warning_links_to_is_served_by_the_portal_with_the_full_text(client):
    response = client.get("/security")
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/html")
    assert APPROVED_FULL.replace("\n\n", "\n") in "\n".join(
        line.strip() for line in _text_of(response.text).splitlines() if line.strip()
    )
    assert (
        "http://" not in response.text and "https://" not in response.text
    )  # nothing is fetched from outside
    assert "script-src 'self'" in response.headers["content-security-policy"]
    head = client.head("/security")
    assert head.status_code == 200 and head.content == b""


def test_the_page_the_warning_links_to_needs_no_network(client):
    page = client.get("/security").text
    for url in re.findall(r'(?:href|src)="([^"]+)"', page):
        if url == "#main":  # the skip link, to the same page
            continue
        assert url.startswith("/") and not url.startswith("//"), (
            url
        )  # only this portal's own addresses
        assert client.get(url).status_code == 200, url


def test_every_result_and_the_status_carry_the_full_text(client, demo):
    assert client.get("/api/status").json()["engine"]["security_limitation"] == APPROVED_FULL
    for name in SAMPLES:
        assert post(client, demo, name).json()["engine"]["security_limitation"] == APPROVED_FULL


# ----------------------------------------------------------------------------- the short warning


def test_the_short_warning_is_faithful_to_the_full_text_and_adds_nothing():
    short = SECURITY_LIMITATION_SHORT
    assert short == (
        "Published v0.2.1 does not enforce strict ownership and permission protections for the local trust-store and "
        "replay-state files. A valid signature does not prove the key was enrolled by an authenticated administrator."
    )
    for fact in (
        "does not enforce",
        "ownership and permission protections",
        "trust-store and replay-state files",
    ):
        assert fact in short
    assert "does not prove the key was enrolled by an authenticated administrator" in short
    assert len(short) < len(" ".join(APPROVED))
    for detail in ("symlink", "chmod", "umask", "race", "advisory", "exploit"):
        assert detail not in short.lower() and detail not in APPROVED_FULL.lower()


def test_the_page_shows_the_short_warning_with_a_working_link_to_the_full_text(client):
    page = client.get("/").text
    assert (
        page.count(SECURITY_LIMITATION_SHORT) == 2
    )  # always on the page, and again in each result
    assert page.count('<a href="/security">Read the full limitation</a>') == 2
    assert client.get("/security").status_code == 200
    first = page.index(SECURITY_LIMITATION_SHORT)
    assert (
        'id="limitation"' in page[:first]
        and "hidden" not in page[page.rindex("<div", 0, first) : first]
    )


# ----------------------------------------------------------------------------- the FHE warning is permanent


def _result_section(html: str) -> str:
    start = html.index('<section id="result"')
    return html[start : html.index("</section>", start)]


def test_the_fhe_warning_is_in_the_result_section_of_the_page_and_never_hidden_by_the_script():
    html = (STATIC / "index.html").read_text()
    result = _result_section(html)
    assert (
        FHE_NOTICE in result and f'<p id="fhe-notice" class="statement">{FHE_NOTICE}</p>' in result
    )
    assert (
        FHE_NOTICE in html[: html.index('<section id="unavailable"')]
    )  # and in the notice that is always on the page
    script = (STATIC / "app.js").read_text()
    assert "fhe-notice" not in script and "limitation" not in script.replace(
        "security_limitation", ""
    )


@pytest.mark.parametrize("name", SAMPLES)
def test_every_result_carries_the_fhe_warning_whatever_the_verdict_and_says_encryption_was_not_verified(
    client, demo, name
):
    body = post(client, demo, name).json()
    assert body["fhe_notice"] == FHE_NOTICE
    assert body["encryption_declarations"]["encryption_verified"] is False
    assert FHE_NOTICE.startswith("Signature verification does not verify that any FHE")


def test_the_saved_file_is_the_whole_response_so_the_warning_is_in_every_export():
    script = (STATIC / "app.js").read_text()
    download = script[
        script.index("async function download()") : script.index("async function start()")
    ]
    assert "Object.assign({ report_file_name: lastSaved.name }, lastSaved.body)" in download
    assert "JSON.stringify(saved" in download
