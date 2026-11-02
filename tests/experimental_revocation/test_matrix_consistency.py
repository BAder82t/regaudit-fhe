"""The test matrix is checked, not trusted: every named test exists where its label says it does, every row has its
columns, and the reason codes in the code, the matrix and the proposal agree."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MATRIX = ROOT / "docs/proposals/revocation-list.v1/TEST_MATRIX.md"
SPEC = ROOT / "docs/TRUST_REVOCATION_PROTOCOL_PROPOSAL.md"
# Files as they were at f3e2a55, the draft v1 prototype. "existing" may only name tests from these.
EXISTING = (
    "test_revocation_prototype.py",
    "test_authority_lifecycle.py",
    "test_worked_examples.py",
    "test_corpus.py",
    "test_frozen.py",
)
NEW = (
    "test_v2_verifier_rules.py",
    "test_state_and_gate.py",
    "test_recovery_and_latch_rules.py",
    "test_published_and_migration.py",
    "test_matrix_consistency.py",
    "test_not_shipped.py",
    "../test_replay_policy_floor.py",
    "../test_revocation_file_store.py",
    "../test_revocation_public_gate.py",
    "../test_revocation_tooling_and_cli.py",
    "../test_revocation_hostile_sequences.py",
    "../test_replay_migration.py",
    "../test_replay_expiry_edge.py",
    "../test_trust_history_floor.py",
    "../test_f09_issuer_substitution.py",
    "../test_f09_development_label.py",
    "../test_f09_store_migration.py",
    "../test_replay_shared_and_omitted.py",
    "../test_secure_profile_v1.py",
    "../test_issuer_name_rule.py",
    "../test_trust_store_exact_class.py",
    "../test_migration_operator_declared.py",
    "../test_response_mode.py",
)
SOURCES = ("_revocation.py", "_revocation_state.py", "_revocation_gate.py")
SRC = ROOT / "src" / "regaudit_fhe"
CODE = re.compile(r"\bREVOCATION_[A-Z_]+")


def _names(files: tuple[str, ...]) -> set[str]:
    out: set[str] = set()
    for name in files:
        tree = ast.parse((HERE / name).read_text(encoding="utf-8"))
        out |= {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    return out


def rows() -> list[list[str]]:
    found = []
    for line in MATRIX.read_text(encoding="utf-8").splitlines():
        if re.match(r"^\| [A-Z]\d\d\w* \|", line):
            found.append([c.strip() for c in line.strip().strip("|").split(" | ")])
    return found


def test_every_row_has_six_filled_columns_and_a_unique_id():
    table = rows()
    assert len(table) >= 100
    ids = [r[0] for r in table]
    assert len(ids) == len(set(ids)), [i for i in ids if ids.count(i) > 1]
    for row in table:
        assert len(row) == 6 and all(row), row


def test_every_named_test_exists_where_its_label_says():
    existing, new = _names(EXISTING), _names(NEW)
    corpus = set(json.loads((HERE / "corpus/manifest.json").read_text()))
    for row in rows():
        cell = row[5]
        if cell == "none":
            continue
        label = None
        for part in cell.split(";"):
            part = part.strip()
            found = re.match(r"^(existing|new): (.*)$", part)
            if found:
                label, part = found.groups()
            assert label is not None, row
            pool = existing if label == "existing" else new
            if part.startswith("corpus:"):
                assert label == "existing" and part[7:] in corpus, (row[0], part)
            else:
                assert part in pool, (row[0], label, part)


def test_every_new_numbered_test_appears_in_the_matrix():
    text = MATRIX.read_text(encoding="utf-8")
    missing = [
        n for n in _names(NEW) if re.match(r"test_[A-Z]\d\d", n) and n not in text
    ]
    assert not missing, missing


def _registry() -> set[str]:
    section = SPEC.read_text(encoding="utf-8").split("## 15. Reason codes")[1].split("\n## ")[0]
    notes = (MATRIX.parent / "IMPLEMENTATION_NOTES.md").read_text(encoding="utf-8")
    return set(CODE.findall(section)) | set(CODE.findall(notes))


def test_codes_in_the_code_and_the_matrix_are_all_in_the_registry():
    registry = _registry()
    code_side: set[str] = set()
    for name in SOURCES:
        code_side |= set(CODE.findall((SRC / name).read_text(encoding="utf-8")))
    assert code_side <= registry, sorted(code_side - registry)
    assert set(CODE.findall(MATRIX.read_text(encoding="utf-8"))) <= registry
    test_side = set(CODE.findall((HERE / "proto.py").read_text(encoding="utf-8")))
    assert registry <= code_side | test_side, sorted(registry - code_side - test_side)


def test_every_registered_code_has_a_matrix_row():
    text = MATRIX.read_text(encoding="utf-8")
    missing = sorted(c for c in _registry() if c not in text)
    assert not missing, missing


def test_the_gate_table_matches_the_infrastructure_codes():
    from . import trust_gate as tg

    table = SPEC.read_text(encoding="utf-8").split("### 10.2 The gate")[1].split("**Rollback")[0]
    exit3 = {m for m in CODE.findall(table) if re.search(rf"`{m}` \| [^|]+ \| 3, 503", table)}
    assert exit3 == tg.INFRASTRUCTURE_CODES - {"REVOCATION_STATE_CONFLICT"}


def test_no_document_uses_forbidden_assurance_language():
    forbidden = re.compile(
        r"\b(certified|certification|production[- ]ready|regulator[- ]approved|fully secure|"
        r"authoritative revocation is provided|proves? (that )?FHE|waived)\b",
        re.IGNORECASE,
    )
    for path in (
        SPEC,
        MATRIX,
        MATRIX.parent / "IMPLEMENTATION_PLAN.md",
        MATRIX.parent / "IMPLEMENTATION_NOTES.md",
        MATRIX.parent / "CHALLENGER_API.md",
    ):
        hits = forbidden.findall(path.read_text(encoding="utf-8"))
        assert not hits, (path.name, hits)


@pytest.mark.parametrize(
    "name",
    ["TEST_MATRIX.md", "IMPLEMENTATION_PLAN.md", "IMPLEMENTATION_NOTES.md", "CHALLENGER_API.md"],
)
def test_companion_documents_exist_and_are_not_empty(name):
    data = (MATRIX.parent / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() != hashlib.sha256(b"").hexdigest()
