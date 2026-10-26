"""Trust-store files are parsed with the strict JSON policy: a duplicated key must not silently win."""

from __future__ import annotations

import pytest

from regaudit_fhe.trust import TrustStore, TrustStoreError

PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA" + "A" * 43 + "=\n-----END PUBLIC KEY-----\n"


def _write(tmp_path, text):
    p = tmp_path / "store.json"
    p.write_text(text, encoding="utf-8")
    return p


def test_a_duplicate_top_level_key_is_refused(tmp_path):
    p = _write(tmp_path, '{"keys": {}, "revoked": ["k1"], "revoked": []}')
    with pytest.raises(TrustStoreError, match="not valid JSON"):
        TrustStore.from_json(p)


def test_a_duplicate_entry_key_id_is_refused(tmp_path):
    body = '{"entries": {"kA": {"status": "compromised"}, "kA": {"status": "active"}}}'
    with pytest.raises(TrustStoreError, match="not valid JSON"):
        TrustStore.from_json(_write(tmp_path, body))


@pytest.mark.parametrize("text", ['{"keys": {"k": NaN}}', "﻿{}", '{"keys": {"k": Infinity}}'])
def test_non_strict_json_is_refused(tmp_path, text):
    with pytest.raises(TrustStoreError):
        TrustStore.from_json(_write(tmp_path, text))


def test_an_oversized_file_is_still_refused(tmp_path):  # larger than MAX_TRUST_STORE_BYTES (4 MiB)
    p = _write(tmp_path, " " * (5 * 1024 * 1024))
    with pytest.raises(TrustStoreError):
        TrustStore.from_json(p)


def test_a_misspelt_member_in_the_legacy_form_is_refused_not_ignored(tmp_path):
    """Found by Agent C: "revokd" used to load with an empty revocation list and accept a revoked key."""
    import json

    import regaudit_fhe as rf

    pem = rf.Signer.generate(issuer="i", key_id="k1").public_key_pem()
    good = TrustStore.from_json(
        _write(tmp_path, json.dumps({"keys": {"k1": pem}, "revoked": ["k1"]}))
    )
    assert "k1" in good.revoked
    for typo in ("revokd", "revoked_keys", "parameter_set_pin", "Revoked"):
        with pytest.raises(TrustStoreError, match="unknown member"):
            TrustStore.from_json(_write(tmp_path, json.dumps({"keys": {"k1": pem}, typo: ["k1"]})))
