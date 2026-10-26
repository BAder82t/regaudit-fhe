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
