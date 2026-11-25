"""P3-04: the claim labels change no decision, no exit code and no default JSON key.

``golden_claims/corpus.json`` was captured from the engine before the labels existed: eight signed reports (valid
plaintext, valid with declared TenSEAL parameters, valid legacy v1 twice, tampered, stranger key, too old, replayed)
with the library verdict for each, and the CLI exit code and stdout JSON for six of them. Nothing here may differ.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests import _claims_corpus as corpus

GOLDEN = json.loads(corpus.GOLDEN.read_text())


def test_the_corpus_covers_the_required_cases() -> None:
    assert set(GOLDEN["verdicts"]) == {
        "valid_plaintext_v2",
        "valid_fhe_declared_v2",
        "valid_v1_plaintext",
        "valid_v1_fhe_declared",
        "tampered_v2",
        "stranger_v2",
        "expired_v2",
        "replayed_v2",
    }
    statuses = {k: v["trust_status"] for k, v in GOLDEN["verdicts"].items()}
    assert statuses["valid_plaintext_v2"] == "TRUSTED"
    assert statuses["tampered_v2"] == statuses["stranger_v2"] == "INVALID"


@pytest.mark.parametrize("name", sorted(GOLDEN["verdicts"]))
def test_library_verdict_is_identical_to_the_golden_one(name: str) -> None:
    now = corpus.run_all()[name]
    assert now == GOLDEN["verdicts"][name]
    assert list(now) == list(GOLDEN["verdicts"][name])  # the same keys in the same order


def test_cli_exit_code_and_default_stdout_are_identical_to_the_golden_ones(tmp_path: Path) -> None:
    run = corpus.run_cli(tmp_path)
    for name, golden in GOLDEN["cli"].items():
        assert run[name]["exit"] == golden["exit"], name
        assert run[name]["stdout"] == golden["stdout"], name
        assert list(run[name]["stdout"]) == list(golden["stdout"]), name


def test_the_labels_never_decide(tmp_path: Path) -> None:
    """Whatever the label module says, the verdict is the one the engine gave: replacing it changes nothing."""
    import regaudit_fhe.claim_labels as labels

    before = corpus.run_all()
    original = labels.assess
    labels.assess = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("must not be consulted"))  # type: ignore[assignment]
    try:
        assert corpus.run_all() == before  # verify() never calls the label module
    finally:
        labels.assess = original  # type: ignore[assignment]
