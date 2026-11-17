"""Every plain-language line the portal can write, for customer trust and for a demonstration, swept for wrong words.

The lines are made from the verifier's result alone, so every branch can be reached with made-up results: each reason
code blocking and not, each key status, each verdict, each replay and time state, and both kinds of profile. In a
demonstration no line may speak of an administrator's rules, say "approved", or call a key "the demonstration issuer"
(a demonstration configuration can list any key). For customer trust no line may speak of a demonstration.
"""

from __future__ import annotations

import itertools
import re

import pytest
from regaudit_portal import explain
from regaudit_portal.explain import DEMONSTRATION_NOTICE, DEMONSTRATION_TRUST_NOTICE, describe

CODES = [*sorted(explain._REASONS), "SOMETHING_NEW"]
STATUSES = ["active", "revoked", "compromised", "retired", "suspended"]
VERDICTS = ["TRUSTED", "SELF_SIGNED_ONLY", "INVALID", "SOMETHING_ELSE"]


def _results():
    base = {
        "issuer": "Northwind Ltd",
        "issued_at": "2026-10-01T09:00:00+00:00",
        "consumption": "NOT_RECORDED",
        "replay_durable": False,
        "chronology": "SIGNER_STATED",
        "trust_history": "UNPROVEN",
    }
    for verdict, trusted, status, integrity in itertools.product(
        VERDICTS, (True, False), STATUSES, (True, False)
    ):
        for code in CODES:
            for blocking in (True, False):
                yield {
                    **base,
                    "trust_status": verdict,
                    "accepted": verdict == "TRUSTED" and not blocking,
                    "issuer_trusted": trusted,
                    "key_status": status,
                    "integrity_valid": integrity,
                    "blocking_reasons": [code] if blocking else [],
                    "reasons": [code],
                }
    for consumption, durable, chronology, history in itertools.product(
        ("RECORDED_LOCAL", "NOT_RECORDED"),
        (True, False),
        ("AUTHENTICATED", "SIGNER_STATED"),
        ("FRESH", "UNPROVEN"),
    ):
        yield {
            **base,
            "trust_status": "TRUSTED",
            "accepted": True,
            "issuer_trusted": True,
            "key_status": "active",
            "integrity_valid": True,
            "blocking_reasons": [],
            "reasons": [],
            "consumption": consumption,
            "replay_durable": durable,
            "chronology": chronology,
            "trust_history": history,
        }


def _lines(explained: dict) -> list[str]:
    found = [
        explained[key] for key in ("verdict", "means", "signature", "issuer") if explained[key]
    ]
    found += [reason["meaning"] for reason in explained["reasons"]]
    found += [warning["message"] for warning in explained["warnings"]]
    found += [explained["display"]["issuer_note"]] if explained["display"]["issuer_note"] else []
    return found


def _every_line(demonstration: bool) -> set[str]:
    lines: set[str] = set()
    for result in _results():
        for profile in ("confidential", "development"):
            for notice in (DEMONSTRATION_NOTICE, DEMONSTRATION_TRUST_NOTICE):
                lines.update(
                    _lines(describe(result, profile, demonstration=demonstration, notice=notice))
                )
    return lines


def test_the_sweep_reaches_every_branch_of_the_wording():
    lines = _every_line(False)
    for expected in (
        "Passed: this key is approved for this issuer under your administrator's rules.",
        "Not confirmed: the key matches the one enrolled for this issuer, but its status is not one this portal knows.",
        *explain._REASONS.values(),
        explain._UNKNOWN_REASON,
    ):
        assert expected in lines, expected
    assert any(line.startswith("Not approved for this report:") for line in lines)
    assert any(line.startswith("Accepted with a limit:") for line in lines)
    assert any(line.startswith("Not approved: ") for line in lines)


@pytest.fixture(scope="module")
def demonstration_lines() -> set[str]:
    return _every_line(True)


def test_no_demonstration_line_speaks_of_an_administrator(demonstration_lines):
    for line in demonstration_lines:
        if (
            line == DEMONSTRATION_TRUST_NOTICE
        ):  # the notice says what it is not: trust set up by an administrator
            continue
        assert "administrator" not in line.lower(), line


def test_no_demonstration_line_says_approved(demonstration_lines):
    for line in demonstration_lines:
        assert not re.search(r"\bapprov", line, re.IGNORECASE), line


def test_no_demonstration_line_calls_a_key_the_demonstration_issuer(demonstration_lines):
    for line in demonstration_lines:
        assert "the demonstration issuer" not in line.lower(), line


def test_the_demonstration_issuer_line_says_where_the_key_is_listed(demonstration_lines):
    assert (
        "Passed: this key is listed for this issuer in the demonstration trust list."
        in demonstration_lines
    )
    assert (
        "This means it came from an issuer listed in the demonstration trust list and has not changed since it was "
        "signed. It does not mean the report's findings are correct."
    ) in demonstration_lines


def test_no_customer_line_speaks_of_a_demonstration():
    for line in _every_line(False):
        assert "demonstration" not in line.lower(), line


def test_guard_off_the_earlier_demonstration_words_are_caught(monkeypatch):
    """The control: with the earlier replacements, the sweep finds "approved" and "the demonstration issuer"."""
    earlier = tuple(
        (old, "the demonstration issuer")
        if old.startswith("an issuer your administrator")
        else (old, new)
        for old, new in explain._DEMONSTRATION_WORDS
        if not old.startswith(("Passed: this key is approved", "Not approved", "Nobody your"))
    )
    monkeypatch.setattr(explain, "_DEMONSTRATION_WORDS", earlier)
    lines = _every_line(True)
    assert any("the demonstration issuer" in line for line in lines)
    assert any(re.search(r"\bapprov", line, re.IGNORECASE) for line in lines)
