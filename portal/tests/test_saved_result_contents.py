"""The README says what a saved result shows about the report and what it leaves out. This pins that text to what the Portal returns."""

from __future__ import annotations

import json
from pathlib import Path

from helpers import post_bytes

README = Path(__file__).parents[1] / "README.md"
IDENTIFYING = (
    "deployment_id",
    "audit_run_id",
    "issuer",
    "key_id",
    "issued_at",
    "primitive",
    "regulations",
    "parameter_set_hash",
)


def test_the_readme_names_every_value_read_from_the_report_that_a_result_carries(client, demo):
    answer = post_bytes(client, (demo / "sample-reports" / "1-trusted.json").read_bytes()).json()
    verification = answer["verification"]
    assert all(name in verification for name in IDENTIFYING), [
        n for n in IDENTIFYING if n not in verification
    ]
    text = README.read_text()
    section = text[
        text.index("### What a saved result shows about the report") : text.index(
            "## For the administrator"
        )
    ]
    for words in (
        "deployment id",
        "run id",
        "issuer name",
        "key id",
        "file name you chose",
        "SHA-256",
        "report type",
        "regulations",
    ):
        assert words in section, words
    assert "not free of identifying information" in section
    assert "no report contents" not in text.lower() and "no sensitive" not in text.lower()


def test_a_result_holds_no_key_no_report_body_and_no_path_of_this_computer(client, demo):
    raw = (demo / "sample-reports" / "1-trusted.json").read_bytes()
    answer = post_bytes(client, raw).json()
    saved = json.dumps(answer)
    original = json.loads(raw)
    for forbidden in (
        "BEGIN PUBLIC KEY",
        "BEGIN PRIVATE KEY",
        "public_key_pem",
        str(demo),
        "portal-config.json",
        'trust-store.json"',
    ):
        assert forbidden not in saved, forbidden
    # the report's own body is not copied into the result
    for member in ("result", "payload", "body", "signed_body", "signature"):
        if (
            member in original
            and isinstance(original[member], dict | list | str)
            and len(json.dumps(original[member])) > 40
        ):
            assert json.dumps(original[member]) not in saved, member
