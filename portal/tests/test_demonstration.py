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
        assert demonstration.is_demonstration_entry("anything", "Anyone Ltd", pem)
        assert demonstration.is_demonstration_key(spki_fingerprint(pem).upper())


def test_the_pinned_list_still_works_if_the_sample_files_could_not_be_read(monkeypatch):
    demonstration.fingerprints.cache_clear()
    monkeypatch.setattr(demonstration, "_sample_keys", lambda: set())
    try:
        assert demonstration.fingerprints() == demonstration.PINNED_FINGERPRINTS
    finally:
        demonstration.fingerprints.cache_clear()


def test_demo_setup_keys_are_recognised_by_the_names_it_always_writes(tmp_path):
    made = json.loads((create(tmp_path / "d") / "trust-store.json").read_text())
    for key_id, entry in made["entries"].items():
        assert demonstration.is_demonstration_entry(
            key_id, entry["issuer"], entry["public_key_pem"]
        )
        assert not demonstration.is_demonstration_key(spki_fingerprint(entry["public_key_pem"]))


@pytest.mark.parametrize(
    "name",
    [
        "DEMO-ONLY synthetic issuer",
        "demo-only unenrolled signer",
        "Example Synthetic Issuer",
        " EXAMPLE SYNTHETIC ISSUER ",
    ],
)
def test_demonstration_names_are_recognised_without_regard_to_case(name):
    assert demonstration.is_demonstration_name(name)


@pytest.mark.parametrize(
    "key_id",
    ["demo-only-synthetic-key", "DEMO-ONLY-X", "synthetic-issuer-key", "synthetic-outsider-key"],
)
def test_demonstration_key_ids_are_recognised(key_id):
    assert demonstration.is_demonstration_key_id(key_id)


def test_an_ordinary_issuer_is_not_a_demonstration():
    signer = rf.Signer.generate(issuer="Northwind Ltd", key_id="nw-1")
    assert not demonstration.is_demonstration_entry(
        "nw-1", "Northwind Ltd", signer.public_key_pem()
    )
    assert not demonstration.is_demonstration_name("Demonstrably Real Ltd")
    assert not demonstration.is_demonstration_key_id("demo-2026")
