"""Replay the adversarial corpus files against the prototype and prove the corpus is frozen."""

from __future__ import annotations

import json

import pytest

from . import corpus
from .gen_fixtures import make_world

MANIFEST = json.loads((corpus.CORPUS_DIR / "manifest.json").read_text())


def test_corpus_has_the_expected_breadth():
    assert len(MANIFEST) == 41
    kinds = {m["kind"] for m in MANIFEST.values()}
    assert kinds == {"list", "list-foreign", "transition", "recovery"}
    expected = {m["expect"] for m in MANIFEST.values()}
    for code in (
        "REVOCATION_WRONG_ISSUER", "REVOCATION_AUTHORITY_MISMATCH", "REVOCATION_SIGNATURE_INVALID",
        "REVOCATION_ROLLBACK", "REVOCATION_FORK", "REVOCATION_NOT_MONOTONE", "REVOCATION_MALFORMED",
        "REVOCATION_AUTHORITY_SUPERSEDED", "REVOCATION_AUTHORITY_COMPROMISED",
        "REVOCATION_TRANSITION_GAP", "REVOCATION_TRANSITION_CYCLE",
        "REVOCATION_RECOVERY_ANCHOR_ABSENT", "REVOCATION_RECOVERY_BASELINE_UNKNOWN", "ACCEPT",
    ):  # fmt: skip
        assert code in expected, code


@pytest.mark.parametrize("name", sorted(MANIFEST))
def test_corpus_case(name):
    meta = MANIFEST[name]
    data = (corpus.CORPUS_DIR / meta["file"]).read_bytes()
    accepted, code, _ = corpus.run_case(make_world(), meta["kind"], meta["preset"], data)
    if meta["expect"] == corpus.ACCEPT:
        assert accepted and code is None, (name, code)
    else:
        assert not accepted and code == meta["expect"], (name, code)


def test_corpus_is_frozen_files_equal_regeneration(tmp_path):
    corpus.write_corpus(tmp_path)
    for path in sorted(tmp_path.iterdir()):
        assert (corpus.CORPUS_DIR / path.name).read_bytes() == path.read_bytes(), path.name
    assert {p.name for p in corpus.CORPUS_DIR.iterdir()} == {p.name for p in tmp_path.iterdir()}


def test_gap_and_repeat_notes_are_part_of_the_contract():
    w = make_world()
    for name, note in (
        ("list-gap-epoch5", "REVOCATION_EPOCH_GAP"),
        ("list-replay-epoch2", "REVOCATION_REPEAT"),
    ):
        meta = MANIFEST[name]
        data = (corpus.CORPUS_DIR / meta["file"]).read_bytes()
        *_, notes = corpus.run_case(w, meta["kind"], meta["preset"], data)
        assert note in notes
