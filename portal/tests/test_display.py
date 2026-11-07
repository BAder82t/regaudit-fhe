"""The issuer line cannot read as approval for a withdrawn key, and a signer's text cannot reorder the page's own."""

from __future__ import annotations

import json
import unicodedata
from pathlib import Path

import pytest
from helpers import client_for, make_portal, post, post_bytes, signed_report
from regaudit_portal.explain import _UNSAFE_CATEGORIES, declarations, describe, printable

from regaudit_fhe.reports import ParameterSet

STATIC = Path(__file__).parents[1] / "regaudit_portal" / "static"


# ----------------------------------------------------------------------------- the issuer line and withdrawn keys


def _result(**change):
    clean = {
        "trust_status": "INVALID", "blocking_reasons": [], "reasons": [], "consumption": "NOT_CHECKED",
        "replay_durable": None, "issuer_trusted": True, "chronology": "NONE", "trust_history": "UNPROVEN",
        "integrity_valid": True, "key_status": "active", "accepted": False,
    }  # fmt: skip
    return {**clean, **change}


@pytest.mark.parametrize(
    ("entry", "status", "reason"),
    [
        ({"status": "compromised"}, "compromised", "KEY_COMPROMISED_NO_CHRONOLOGY"),
        (
            {"status": "retired", "retired_at": "2000-01-01T00:00:00Z"},
            "retired",
            "KEY_RETIRED_NO_CHRONOLOGY",
        ),
        ({"not_before": "2999-01-01T00:00:00Z"}, "active", "KEY_NOT_YET_VALID"),
    ],
    ids=["compromised", "retired", "not-yet-valid"],
)
def test_a_withdrawn_or_not_yet_valid_key_is_never_called_approved(tmp_path, entry, status, reason):
    config, signer = make_portal(tmp_path / "p", entry=entry)
    body = post_bytes(client_for(config), signed_report(signer)).json()
    v, line = body["verification"], body["explanation"]["issuer"]
    # The premise: the verifier says issuer_trusted for a key that is enrolled for this issuer, whatever its status.
    assert (
        v["trust_status"] == "INVALID" and v["issuer_trusted"] is True and v["key_status"] == status
    )
    assert reason in v["blocking_reasons"]
    assert line.startswith("Not approved"), line
    assert "Passed" not in line and "is approved for this issuer" not in line
    assert ("marked it " + status in line) or reason == "KEY_NOT_YET_VALID"
    assert "before the key became valid" in line or reason != "KEY_NOT_YET_VALID"
    assert body["explanation"]["display"]["issuer_note"] == (
        "matches your administrator's list, but the report was not accepted"
    )


def test_a_revoked_key_is_never_called_approved_either():
    """The portal's own trust-store form has no 'revoked' status, so this is the verifier's result for another form."""
    revoked = _result(
        key_status="revoked", blocking_reasons=["KEY_REVOKED"], reasons=["KEY_REVOKED"]
    )
    line = describe(revoked, "confidential")["issuer"]
    assert line.startswith("Not approved") and "marked it revoked" in line and "Passed" not in line


def test_an_active_key_still_passes_and_a_withdrawn_one_accepted_under_rules_says_so_with_a_limit():
    assert describe(_result(), "confidential")["issuer"].startswith("Passed: this key is approved")
    limited = describe(
        _result(key_status="retired", trust_status="TRUSTED", accepted=True), "confidential"
    )
    assert (
        limited["issuer"].startswith("Accepted with a limit")
        and "marked it retired" in limited["issuer"]
    )
    odd = describe(_result(key_status="something-new"), "confidential")["issuer"]
    assert odd.startswith("Not confirmed") and "Passed" not in odd


def test_an_unconfirmed_issuer_name_keeps_its_caveat(client, demo):
    note = post(client, demo, "2-untrusted-signer.json").json()["explanation"]["display"][
        "issuer_note"
    ]
    assert note == "as stated in the report, not confirmed"
    accepted = post(client, demo, "1-trusted.json").json()["explanation"]["display"]["issuer_note"]
    assert accepted == ""


# ----------------------------------------------------------------------------- control and direction characters

BIDI_AND_CONTROL = [
    "‪", "‫", "‬", "‭", "‮",  # embeddings and overrides
    "⁦", "⁧", "⁨", "⁩",  # isolates
    "​", "‌", "‍", "‎", "‏", "؜",  # zero width and marks
    "⁠", "﻿", "­", " ", " ",  # joiner, BOM, soft hyphen, separators
    "\x00", "\x07", "\x1b", "\n", "\r", "\t", "\x85",  # controls
    "\U000e0001", "\U000e0041", "",  # tag characters and private use
]  # fmt: skip


@pytest.mark.parametrize("char", BIDI_AND_CONTROL, ids=lambda c: f"U+{ord(c):04X}")
def test_every_control_and_direction_character_is_made_visible(char):
    shown = printable(f"Acme{char}Ltd")
    assert char not in shown
    assert shown == f"Acme\\u{{{ord(char):04X}}}Ltd"
    assert all(unicodedata.category(c) not in _UNSAFE_CATEGORIES for c in shown)


def test_ordinary_text_is_left_alone_and_long_text_is_cut_and_said_to_be():
    assert printable("Société Générale – 東京 (ACME)") == "Société Générale – 東京 (ACME)"
    long = printable("x" * 500)
    assert long == "x" * 200 + " (shortened)"
    assert printable(None) == "None"


def test_a_signer_cannot_reverse_the_pages_own_words_through_the_issuer(tmp_path):
    issuer = "Acme ‮)detsurt ton(⁩ Ltd"
    config, signer = make_portal(tmp_path / "p", issuer=issuer)
    body = post_bytes(client_for(config), signed_report(signer)).json()
    shown = body["explanation"]["display"]
    assert body["verification"]["trust_status"] == "TRUSTED"
    assert (
        body["verification"]["issuer"] == issuer
    )  # the verifier's value is kept exactly, for the saved result
    assert "‮" not in shown["issuer"] and "⁩" not in shown["issuer"]
    assert shown["issuer"] == "Acme \\u{202E})detsurt ton(\\u{2069} Ltd"
    details = shown["technical_details"]
    assert details.isascii() and "\\u202e" in details
    assert json.loads(details) == body["verification"]  # escaped for display, equal in value


def test_a_backend_name_with_direction_characters_is_made_visible_too(tmp_path):
    config, signer = make_portal(tmp_path / "p")
    odd = ParameterSet(backend="tenseal‮ckks")
    claims = post_bytes(client_for(config), signed_report(signer, parameter_set=odd)).json()[
        "encryption_declarations"
    ]
    assert claims["backend"] == "tenseal\\u{202E}ckks" and "‮" not in json.dumps(
        claims, ensure_ascii=False
    )
    assert (
        declarations(type("E", (), {"backend": "x⁧", "parameter_set": {}})(), "INVALID")["backend"]
        == "x\\u{2067}"
    )


def test_the_page_shows_only_the_display_copies_of_signer_text():
    script = (STATIC / "app.js").read_text()
    assert "e.display" in script and "d.issuer" in script and "d.technical_details" in script
    assert "v.issuer" not in script and "JSON.stringify(v" not in script
    assert "claims.security_bits_text" in script and "claims.security_bits_note" not in script
