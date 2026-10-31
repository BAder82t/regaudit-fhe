"""The revocation-list prototype must stay outside the shipped package and the published protocol."""

from __future__ import annotations

from pathlib import Path

import regaudit_fhe as rf

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "regaudit_fhe"


def test_no_shipped_source_mentions_the_prototype_format():
    for path in SRC.rglob("*"):
        if path.is_file() and path.suffix in {".py", ".json", ".typed"}:
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert "revocation-list" not in text, path
            assert "revocation_list" not in text, path


def test_no_schema_is_registered_or_shipped_for_it():
    assert not [p for p in (SRC / "schemas").iterdir() if "revocation" in p.name]
    assert not [n for n in rf.list_schemas() if "revocation" in n]


def test_prototype_lives_under_tests_and_the_draft_schema_under_docs_proposals():
    from . import proto

    assert Path(proto.__file__).resolve().is_relative_to(ROOT / "tests")
    assert (ROOT / "docs/proposals/revocation-list.v1/revocation-list.v1.schema.json").is_file()
    assert not (SRC / "revocation.py").exists()


def test_the_package_exposes_no_revocation_list_api():
    assert not [n for n in dir(rf) if "revocation_list" in n.lower()]
