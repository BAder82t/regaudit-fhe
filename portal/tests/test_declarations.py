"""What the signer says about encryption is shown as a statement, never as a finding, and the verdict is the engine's own."""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from helpers import backend_verdict, client_for, make_portal, post, post_bytes, signed_report
from regaudit_portal.explain import declarations

from regaudit_fhe.reports import ParameterSet

SAMPLES = (
    "1-trusted.json",
    "2-untrusted-signer.json",
    "3-valid-signature-wrong-issuer.json",
    "4-changed-after-signing.json",
    "7-declares-encrypted-backend.json",
)


# ----------------------------------------------------------------------------- what the signer says about encryption


def test_a_plaintext_report_is_shown_as_no_encryption_and_its_number_as_a_legacy_field(
    client, demo
):
    body = post(client, demo, "1-trusted.json").json()
    claims = body["encryption_declarations"]
    assert claims["kind"] == "PLAINTEXT" and claims["backend"] == "plaintext"
    assert claims["statement"] == "No encryption: this report states it was computed on plaintext."
    assert claims["security_bits"] == 128
    assert claims["security_bits_note"] == "legacy field, not a security level"
    assert claims["encryption_verified"] is False
    assert body["verification"]["trust_status"] == "TRUSTED"


def test_a_report_that_names_an_encrypted_backend_is_shown_as_a_declaration_nobody_checked(
    client, demo
):
    body = post(client, demo, "7-declares-encrypted-backend.json").json()
    claims = body["encryption_declarations"]
    assert claims["kind"] == "ENCRYPTED_BACKEND_DECLARED" and claims["backend"] == "tenseal-ckks"
    assert claims["statement"] == (
        "The signer declares an encrypted backend. This portal cannot verify that encryption was used."
    )
    assert claims["security_bits"] == 192
    assert claims["security_bits_note"] == "declared by the signer, not verified"
    assert claims["encryption_verified"] is False
    assert "does not show that any encrypted (FHE) computation happened" in claims["note"]
    # TRUSTED still means what it always meant: the signer is approved. It says nothing about the declaration.
    assert body["verification"]["trust_status"] == "TRUSTED"


@pytest.mark.parametrize("name", SAMPLES)
def test_the_number_is_never_called_a_security_level_or_a_protection(client, demo, name):
    text = json.dumps(post(client, demo, name).json()).lower()
    assert "128-bit" not in text and "bit security" not in text and "-bit protection" not in text
    assert text.count("security level") == text.count("not a security level")


@pytest.mark.parametrize("name", ["2-untrusted-signer.json", "4-changed-after-signing.json"])
def test_a_report_that_was_not_accepted_gets_the_declaration_as_unverified_text(client, demo, name):
    body = post(client, demo, name).json()
    note = body["encryption_declarations"]["note"]
    assert body["verification"]["trust_status"] == "INVALID"
    assert "was not accepted" in note and "only what the file says" in note
    assert body["encryption_declarations"]["statement"].startswith("No encryption")


def test_a_rejected_report_whose_signature_passed_is_not_called_unverified(client, demo):
    """Sample 3 has a valid signature and the wrong issuer. The page must not say both 'passed' and 'not verified'."""
    body = post(client, demo, "3-valid-signature-wrong-issuer.json").json()
    assert body["explanation"]["signature"].startswith("Passed")
    note = body["encryption_declarations"]["note"]
    assert "not verified" not in note and "unverified" not in note
    assert "only what the file says" in note and "Nothing has established them" in note


def _env(backend, parameter_set):
    return SimpleNamespace(backend=backend, parameter_set=parameter_set)


@pytest.mark.parametrize(
    ("backend", "kind"),
    [
        ("plaintext", "PLAINTEXT"),
        ("tenseal-ckks", "ENCRYPTED_BACKEND_DECLARED"),
        ("openfhe-ckks", "ENCRYPTED_BACKEND_DECLARED"),
        ("something-else", "UNRECOGNIZED_BACKEND"),
        ("Plaintext", "UNRECOGNIZED_BACKEND"),
        ("", "NOT_STATED"),
        (None, "NOT_STATED"),
        (5, "NOT_STATED"),
    ],
)
def test_each_kind_of_backend_gets_its_own_wording(backend, kind):
    claims = declarations(_env(backend, {"security_bits": 128}), "TRUSTED")
    assert claims["kind"] == kind and claims["encryption_verified"] is False
    if kind != "PLAINTEXT":
        assert "No encryption" not in claims["statement"]
        assert claims["security_bits_note"] == "declared by the signer, not verified"
    assert "cannot" in claims["statement"] or kind == "PLAINTEXT"


@pytest.mark.parametrize(
    ("bits", "state"),
    [
        (0, "SHOWN"),
        (128, "SHOWN"),
        (10**6 - 1, "SHOWN"),
        (10**6, "TOO_LARGE"),
        (10**12, "TOO_LARGE"),
        (-(10**9), "TOO_LARGE"),
        (True, "NOT_A_WHOLE_NUMBER"),
        ("128", "NOT_A_WHOLE_NUMBER"),
        (1.5, "NOT_A_WHOLE_NUMBER"),
        (None, "NOT_A_WHOLE_NUMBER"),
        ([128], "NOT_A_WHOLE_NUMBER"),
    ],
)
@pytest.mark.parametrize(
    ("backend", "note"),
    [
        ("plaintext", "legacy field, not a security level"),
        ("tenseal-ckks", "declared by the signer, not verified"),
    ],
)
def test_a_security_bits_value_is_always_described_and_never_made_to_look_absent(
    backend, note, bits, state
):
    claims = declarations(_env(backend, {"security_bits": bits}), "TRUSTED")
    text = claims["security_bits_text"]
    assert claims["security_bits_state"] == state and claims["security_bits_note"] == note
    assert text.endswith(f"({note})") and not text.startswith("none")
    if state == "SHOWN":
        assert claims["security_bits"] == bits and text == f"{bits} ({note})"
    else:
        assert claims["security_bits"] is None  # not echoed, and the state says why
        assert ("too large to display" in text) is (state == "TOO_LARGE")
        assert ("not a whole number" in text) is (state == "NOT_A_WHOLE_NUMBER")


def test_a_report_with_no_security_bits_field_says_none_and_why():
    for parameter_set in ({}, None, {"backend": "plaintext"}):
        claims = declarations(_env("plaintext", parameter_set), "TRUSTED")
        assert claims["security_bits_state"] == "ABSENT" and claims["security_bits"] is None
        assert claims["security_bits_note"] is None
        assert claims["security_bits_text"] == "none (the report has no security_bits field)"


def test_a_huge_security_bits_value_in_a_real_signed_report_is_called_too_large(tmp_path):
    config, signer = make_portal(tmp_path / "p")
    huge = ParameterSet(security_bits=10**12)
    claims = post_bytes(client_for(config), signed_report(signer, parameter_set=huge)).json()[
        "encryption_declarations"
    ]
    assert claims["security_bits_state"] == "TOO_LARGE" and claims["security_bits"] is None
    assert (
        claims["security_bits_text"]
        == "a value too large to display (legacy field, not a security level)"
    )


def test_a_missing_parameter_set_is_survivable_and_a_long_name_is_shortened():
    assert declarations(_env("plaintext", None), "TRUSTED")["security_bits"] is None
    long_name = "x" * 5000
    claims = declarations(_env(long_name, {}), "INVALID")
    assert len(claims["backend"]) == 64 and claims["backend_shortened"] is True


# ----------------------------------------------------------------------------- the displayed verdict is the engine's


@pytest.mark.parametrize("name", SAMPLES)
def test_the_verdict_fields_are_exactly_the_engines_in_every_case(client, demo, name):
    body = post(client, demo, name).json()
    direct = backend_verdict(demo, name)
    assert body["verification"] == direct
    for field in (
        "trust_status",
        "accepted",
        "integrity_valid",
        "issuer_trusted",
        "blocking_reasons",
        "reasons",
    ):
        assert body["verification"][field] == direct[field]
    assert body["explanation"]["reasons"] == [
        {"code": r["code"], "blocking": r["blocking"], "meaning": r["meaning"]}
        for r in body["explanation"]["reasons"]
    ]
    assert [r["code"] for r in body["explanation"]["reasons"] if r["blocking"]] == direct[
        "blocking_reasons"
    ]


def test_the_page_shows_the_status_word_from_the_response_and_never_computes_one():
    script = (Path(__file__).parents[1] / "regaudit_portal" / "static" / "app.js").read_text()
    assert "v.trust_status" in script
    assert not re.search(
        r"""["']TRUSTED["']\s*(\?|:)|["'](INVALID|SELF_SIGNED_ONLY)["']""",
        script.replace(
            'v.trust_status === "TRUSTED" ? "verdict trusted" : "verdict"',
            "",
        ),
    )


# ----------------------------------------------------------------------------- the saved result carries all of it


def test_the_response_the_page_saves_carries_the_verdict_the_engine_and_the_declaration(
    client, demo
):
    body = post(client, demo, "7-declares-encrypted-backend.json").json()
    assert set(body) >= {
        "verification", "explanation", "encryption_declarations", "engine", "report_sha256", "checked_at",
        "portal_version", "not_a_claim",
    }  # fmt: skip
    assert body["verification"] == backend_verdict(demo, "7-declares-encrypted-backend.json")
    saved = json.loads(json.dumps(body))
    assert saved["engine"]["version"] == "0.2.1"
    assert saved["encryption_declarations"]["statement"].startswith(
        "The signer declares an encrypted backend"
    )
