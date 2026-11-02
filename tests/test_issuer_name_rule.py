"""One rule for an issuer's name, at enrollment, trust-store parsing and migration, and nothing is normalised."""

from __future__ import annotations

import json
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest

import regaudit_fhe as rf
from regaudit_fhe import _revocation_state as st
from regaudit_fhe._trust_lifecycle import MigrationRefused, migrate_store
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.trust import KeyEntry, TrustStoreError, issuer_name_problem
from regaudit_fhe.verification import VerificationPolicy, verify

SIGNER = rf.Signer.generate(issuer="acme", key_id="k")
PEM = SIGNER.public_key_pem()

BAD = {
    "empty": "",
    "space only": "   ",
    "tab only": "\t",
    "NUL": "acme\x00",
    "NUL inside": "ac\x00me",
    "newline": "acme\nbank",
    "trailing newline": "acme\n",
    "tab inside": "acme\tbank",
    "carriage return": "acme\rbank",
    "delete": "acme\x7f",
    "C1 control": "acme\x85",
    "NBSP only": " ",
    "NBSP inside": "Acme Bank",
    "ideographic space only": "　",
    "ideographic space inside": "Acme　Bank",
    "en space inside": "Acme Bank",
    "line separator": "acme bank",
    "paragraph separator": "acme bank",
    "leading space": " acme",
    "trailing space": "acme ",
    "leading NBSP": " acme",
    "zero-width space": "ac​me",
    "zero-width space only": "​",
    "zero-width joiner": "ac‍me",
    "zero-width non-joiner": "ac‌me",
    "word joiner": "ac⁠me",
    "BOM": "﻿acme",
    "soft hyphen": "ac­me",
    "left-to-right mark": "acme‎",
    "right-to-left mark": "acme‏",
    "right-to-left override": "‮acme",
    "left-to-right isolate": "⁦acme⁩",
    "tag character": "acme\U000e0041",
    "Hangul filler only": "ㅤ",
    "braille blank only": "⠀",
    "combining grapheme joiner": "ac͏me",
    "variation selector": "acme️",
    "Mongolian vowel separator": "ac᠎me",
    "private use": "acme",
    "unassigned": "acme\U000e0fff",
    "lone surrogate": "acme\ud800",
    "combining acute only": "\u0301",
    "two combining marks only": "\u0301\u0323",
    "marks and a space only": "\u0301 \u0323",
    "enclosing mark only": "\u20dd",
    "spacing mark only": "\u0903",
    "null notehead only": "\U0001d159",
    "null notehead inside": "ac\U0001d159me",
    "Khitan filler only": "\U00016fe4",
    "Khitan filler inside": "ac\U00016fe4me",
    "object replacement only": "\ufffc",
    "object replacement inside": "ac\ufffcme",
    "halfwidth Hangul filler only": "\uffa0",
    "Hangul choseong filler only": "\u115f",
    "Hangul jungseong filler only": "\u1160",
    "Khmer inherent vowel only": "\u17b4",
    "supplementary variation selector only": "\U000e0100",
    "tag only": "\U000e0020",
    "ideographic half fill space only": "\u303f",
    "Egyptian full blank only": "\U00013441",
    "Egyptian half blank only": "\U00013442",
    "musical format only": "\U0001d173",
    "shorthand format only": "\U0001bca0",
}
GOOD = [
    "acme",
    "Acme Bank Ltd",
    "Banque Générale",
    "O'Reilly & Sons, Inc.",
    "ACME/UK-1.2_a",
    "株式会社東京",
    "Москва Банк",
    "بنك مصر",
    "בנק לאומי",
    "Crédit Agricole S.A. (France)",
    "Bank 🏦",
    "Banque Ge\u0301ne\u0301rale",
    "e\u0301cole",
    "धन बैंक",
    "ธนาคารกรุงเทพ",
    "בַּנְק",
    "Q\u0323uoc",
    "...",
    "123",
    "A",
]


def entries(issuer):
    return {"entries": {"k": {"issuer": issuer, "public_key_pem": PEM, "status": "active"}}}


def _cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", *args],
        capture_output=True,
        timeout=120,
        cwd=cwd,
        check=False,
    )


@pytest.mark.parametrize("name", sorted(BAD))
def test_the_rule_names_the_problem(name):
    assert issuer_name_problem(BAD[name]) is not None


@pytest.mark.parametrize("name", GOOD)
def test_legitimate_names_pass_the_rule_and_are_kept_byte_for_byte(name):
    assert issuer_name_problem(name) is None
    store = rf.TrustStore.from_dict(entries(name))
    assert store.entry("k").issuer == name and store.entry("k").issuer.encode() == name.encode()


@pytest.mark.parametrize("value", [None, 5, b"acme", ["acme"]])
def test_only_a_string_is_a_name(value):
    assert issuer_name_problem(value) == "must be a non-empty string"


# Default_Ignorable_Code_Point, Unicode 16: none of these renders as anything on its own.
_DEFAULT_IGNORABLE = [
    0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, *range(0x180B, 0x1810), *range(0x200B, 0x2010),
    *range(0x202A, 0x202F), *range(0x2060, 0x2070), 0x3164, *range(0xFE00, 0xFE10), 0xFEFF, 0xFFA0,
    *range(0xFFF0, 0xFFF9), *range(0x1BCA0, 0x1BCA4), *range(0x1D173, 0x1D17B), *range(0xE0000, 0xE1000),
]  # fmt: skip


@pytest.mark.parametrize("position", ["alone", "inside"])
def test_every_default_ignorable_code_point_is_refused(position):
    wrap = (lambda c: c) if position == "alone" else (lambda c: f"ac{c}me")
    accepted = [hex(c) for c in _DEFAULT_IGNORABLE if issuer_name_problem(wrap(chr(c))) is None]
    assert not accepted


def test_no_lone_code_point_outside_letters_numbers_punctuation_and_symbols_is_a_name():
    accepted = []
    for point in range(sys.maxunicode + 1):
        char = chr(point)
        if issuer_name_problem(char) is None and unicodedata.category(char)[0] not in "LNPS":
            accepted.append(hex(point))
    assert not accepted


def test_a_mark_after_a_base_character_is_part_of_a_name():
    for mark in ("\u0301", "\u20dd", "\u0903"):
        assert issuer_name_problem(f"a{mark}") is None


def test_the_name_is_kept_as_written_and_a_decomposed_form_stays_a_different_name():
    decomposed = "Banque Ge\u0301ne\u0301rale"
    assert rf.TrustStore.from_dict(entries(decomposed)).entry("k").issuer == decomposed
    assert unicodedata.normalize("NFC", decomposed) != decomposed


# ------------------------------------------------------------------ parsing


@pytest.mark.parametrize("name", sorted(BAD))
def test_parsing_refuses(name):
    with pytest.raises(TrustStoreError, match="issuer"):
        rf.TrustStore.from_dict(entries(BAD[name]))


@pytest.mark.parametrize("name", ["trailing space", "NUL", "right-to-left override", "NBSP only"])
def test_loading_a_file_refuses_and_the_cli_exits_3(name, tmp_path):
    (tmp_path / "t.json").write_text(json.dumps(entries(BAD[name])))
    with pytest.raises(TrustStoreError, match="issuer"):
        rf.TrustStore.from_json(tmp_path / "t.json")
    env = rf.envelope("drift", rf.audit_drift([0.5, 0.5], [0.4, 0.6]), signer=SIGNER)
    (tmp_path / "r.json").write_text(json.dumps(env.to_dict()))
    assert _cli("verify", "-i", "r.json", "--trusted-keys", "t.json", cwd=tmp_path).returncode == 3


@pytest.mark.parametrize("name", ["trailing space", "zero-width space"])
def test_direct_construction_refuses(name):
    entry = KeyEntry(key_id="k", public_key_pem=PEM, status="active", issuer=BAD[name])
    with pytest.raises(TrustStoreError, match="issuer"):
        rf.TrustStore(keys={"k": PEM}, entries={"k": entry})


# ------------------------------------------------------------------ enrollment


def _enrol(tmp_path: Path, issuer: str, store: str = "t.json"):
    (tmp_path / "k.pub").write_text(PEM)
    from regaudit_fhe._keys import spki_fingerprint

    return _cli(
        "trust", "add", "--store", store, "--key-id", "k", "--issuer", issuer, "--public-key", "k.pub",
        "--fingerprint", spki_fingerprint(PEM), cwd=tmp_path,
    )  # fmt: skip


@pytest.mark.parametrize(
    "name", [n for n in sorted(BAD) if "\x00" not in BAD[n] and "\ud800" not in BAD[n] and BAD[n]]
)
def test_trust_add_refuses_and_writes_nothing(name, tmp_path):
    out = _enrol(tmp_path, BAD[name])
    assert out.returncode == 2, out.stderr
    assert b"issuer" in out.stderr
    assert not (tmp_path / "t.json").exists()


@pytest.mark.parametrize("name", GOOD)
def test_trust_add_takes_a_legitimate_name(name, tmp_path):
    out = _enrol(tmp_path, name)
    assert out.returncode == 0, out.stderr
    assert json.loads((tmp_path / "t.json").read_text())["entries"]["k"]["issuer"] == name


@pytest.mark.parametrize("name", ["trailing space", "right-to-left mark"])
def test_a_revocation_pin_file_refuses(name, tmp_path):
    good = st.Pin("acme", PEM, "enr-1")
    st.save_pin(tmp_path / "ok.json", good)
    doc = json.loads((tmp_path / "ok.json").read_text())
    doc["pins"][BAD[name]] = {**doc["pins"].pop("acme"), "issuer": BAD[name]}
    (tmp_path / "ok.json").write_text(json.dumps(doc))
    with pytest.raises(st.PinStoreError, match="issuer"):
        st.load_pins(tmp_path / "ok.json")


@pytest.mark.parametrize("name", ["trailing space", "zero-width space", "NUL"])
def test_the_revocation_enrollment_ceremony_refuses(name, tmp_path):
    from datetime import datetime, timezone

    pin = st.Pin(BAD[name], PEM, "enr-1")
    with pytest.raises(st.PinStoreError, match="issuer"):
        st.save_pin(tmp_path / "pins.json", pin)
    with pytest.raises(st.PinStoreError, match="issuer"):
        st.enroll(
            st.FileStateStore(tmp_path / "state"),
            pin,
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        )


# ------------------------------------------------------------------ migration


@pytest.mark.parametrize("name", sorted(BAD))
def test_migration_refuses(name):
    with pytest.raises(MigrationRefused, match="never normalised|no issuer stated"):
        migrate_store({"keys": {"k": PEM}}, {"k": BAD[name]}, as_of="2026-11-02T00:00:00Z")


@pytest.mark.parametrize(
    "name", ["trailing space", "NBSP inside", "zero-width space", "right-to-left override"]
)
def test_the_cli_migration_refuses_and_writes_nothing(name, tmp_path):
    (tmp_path / "old.json").write_text(json.dumps({"keys": {"k": PEM}}))
    out = _cli(
        "trust",
        "migrate",
        "--source",
        "old.json",
        "--target",
        "new.json",
        "--issuer",
        f"k={BAD[name]}",
        cwd=tmp_path,
    )
    assert out.returncode == 2 and b"never normalised" in out.stderr
    assert not (tmp_path / "new.json").exists()


@pytest.mark.parametrize("name", GOOD)
def test_migration_takes_a_legitimate_name_unchanged(name):
    out, rows = migrate_store({"keys": {"k": PEM}}, {"k": name}, as_of="2026-11-02T00:00:00Z")
    assert out["entries"]["k"]["issuer"] == name and rows[0]["issuer"] == name


# ------------------------------------------------------------------ what the rule leaves alone


def test_a_lookalike_or_another_normal_form_is_a_different_name_not_an_ambiguous_one():
    """Not refused, and not treated as the same issuer: the comparison is byte for byte. A stated limit of the rule."""
    for enrolled, claimed in [
        ("Banque Générale", "Banque Générale"),
        ("acme", "аcme"),
        ("Acme Bank", "Acme  Bank"),
    ]:
        assert issuer_name_problem(claimed) is None
        store = rf.TrustStore.from_dict(
            {"entries": {"k": {"issuer": enrolled, "public_key_pem": PEM, "status": "active"}}}
        )
        who = rf.Signer(
            issuer=claimed, key_id="k", private_key=SIGNER.private_key, public_key=SIGNER.public_key
        )
        env = envelope_v2(
            "drift", rf.audit_drift([0.5, 0.5], [0.4, 0.6]), signer=who, deployment_id="p",
            audit_run_id="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6c1",
        )  # fmt: skip
        assert verify(env, VerificationPolicy(trust_store=store)).blocking_reasons == (
            "ISSUER_MISMATCH",
        )


@pytest.mark.parametrize(
    "name", ["trailing space", "right-to-left override", "NBSP only", "newline"]
)
def test_signing_is_not_covered_and_such_a_report_cannot_reach_a_store_that_binds_issuers(name):
    """The rule applies at enrollment, loading and migration. A signer can still write the name, as published versions can, and
    only a store with no issuers can then accept it, in development, labelled."""
    who = rf.Signer(
        issuer=BAD[name], key_id="k", private_key=SIGNER.private_key, public_key=SIGNER.public_key
    )
    env = envelope_v2(
        "drift", rf.audit_drift([0.5, 0.5], [0.4, 0.6]), signer=who, deployment_id="p",
        audit_run_id="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6c2",
    )  # fmt: skip
    bound = rf.TrustStore.from_dict(entries("acme"))
    assert verify(env, VerificationPolicy(trust_store=bound)).blocking_reasons == (
        "ISSUER_MISMATCH",
    )
    unbound = rf.TrustStore.from_dict({"keys": {"k": PEM}})
    res = verify(env, VerificationPolicy(trust_store=unbound))
    assert res.accepted and res.reasons == ("ISSUER_UNBOUND",)
