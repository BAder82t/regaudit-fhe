"""The portal's demonstration keys are recognised by fingerprint, and its demonstration names by name, everywhere."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from regaudit_portal import demonstration
from regaudit_portal.demo import create

import regaudit_fhe as rf
from regaudit_fhe._keys import spki_fingerprint

SAMPLES = Path(__file__).parents[1] / "regaudit_portal" / "samples"


def _bundled_keys() -> set[str]:
    keys = set()
    trust = json.loads((SAMPLES / "demo-trust-list.json").read_text())
    keys |= {e["public_key_pem"] for e in trust["entries"].values()}
    for report in (SAMPLES / "reports").glob("*.json"):
        keys.add(json.loads(report.read_text())["receipt"]["public_key_pem"])
    return keys


def test_the_pinned_fingerprints_are_exactly_the_keys_in_the_bundled_samples():
    computed = {spki_fingerprint(pem) for pem in _bundled_keys()}
    assert computed == demonstration.PINNED_FINGERPRINTS
    assert demonstration.fingerprints() == demonstration.PINNED_FINGERPRINTS


def test_every_bundled_demonstration_key_is_recognised(monkeypatch):
    for pem in _bundled_keys():
        assert demonstration.is_demonstration_entry(pem)
        assert demonstration.is_demonstration_key(spki_fingerprint(pem).upper())


def test_the_pinned_list_still_works_if_the_sample_files_could_not_be_read(monkeypatch):
    demonstration.fingerprints.cache_clear()
    monkeypatch.setattr(demonstration, "_sample_keys", lambda: set())
    try:
        assert demonstration.fingerprints() == demonstration.PINNED_FINGERPRINTS
    finally:
        demonstration.fingerprints.cache_clear()


def test_demo_setup_keys_are_not_recognised_by_their_keys_only_its_configuration_says_so(tmp_path):
    """Its keys are new each time, so nothing can tell them apart from real keys. Its configuration's trust_mode is
    the control (see test_demonstration_trust.py)."""
    root = create(tmp_path / "d")
    made = json.loads((root / "trust-store.json").read_text())
    for entry in made["entries"].values():
        assert not demonstration.is_demonstration_entry(entry["public_key_pem"])
    assert json.loads((root / "portal-config.json").read_text())["trust_mode"] == "demonstration"


@pytest.mark.parametrize(
    "issuer, key_id",
    [
        ("DEMO-ONLY synthetic issuer", "demo-only-synthetic-key"),
        ("Example Synthetic Issuer", "synthetic-issuer-key"),
        ("Demo Analytics Ltd", "demo-2026"),
        ("Synthetic Data Works", "synthetic-1"),
    ],
)
def test_no_name_or_key_id_makes_a_key_a_demonstration(issuer, key_id):
    """Only the exact bundled keys are demonstration keys. A legitimate issuer is never one because of its name."""
    signer = rf.Signer.generate(issuer=issuer, key_id=key_id)
    assert not demonstration.is_demonstration_entry(signer.public_key_pem())


def test_the_module_has_no_rule_about_names_or_key_ids():
    source = (Path(demonstration.__file__)).read_text()
    for gone in (
        "is_demonstration_name",
        "is_demonstration_key_id",
        "_NAMES",
        "_KEY_IDS",
        "_NAME_PREFIXES",
    ):
        assert gone not in source, gone
