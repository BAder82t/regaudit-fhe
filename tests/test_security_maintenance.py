"""Security-maintenance regressions: one-time warning, token hashing, /readyz, examples."""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import warnings
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
import regaudit_fhe.reports as reports

ROOT = Path(__file__).resolve().parent.parent


def _self_signed_envelope():
    signer = rf.Signer.generate(issuer="acme", key_id="k1")
    report = rf.audit_fairness(
        np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([0.0, 1.0])
    )
    return rf.envelope("fairness", report, signer=signer)


# ---------------------------------------------------------------------------
# One-time weak-verification warning (CodeQL #35)
# ---------------------------------------------------------------------------


def test_weak_receipt_warning_fires_once_then_stays_quiet():
    env = _self_signed_envelope()
    reports._WEAK_WARNING.reset()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert rf.verify_receipt(env) is True
        assert rf.verify_receipt(env) is True
    weak = [w for w in caught if "does NOT authenticate" in str(w.message)]
    assert len(weak) == 1 and issubclass(weak[0].category, UserWarning)


def test_weak_receipt_warning_is_exactly_once_across_threads():
    env = _self_signed_envelope()
    reports._WEAK_WARNING.reset()
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        rf.verify_receipt(env)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert len([w for w in caught if "does NOT authenticate" in str(w.message)]) == 1


def test_warning_is_not_emitted_when_trust_material_is_supplied():
    env = _self_signed_envelope()
    signer_pem = env.receipt["public_key_pem"]
    reports._WEAK_WARNING.reset()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert rf.verify_receipt(env, trusted_keys={"k1": signer_pem}, strict=True) is True
    assert not [w for w in caught if "does NOT authenticate" in str(w.message)]


def test_the_module_no_longer_mutates_a_global_for_the_warning():
    source = (ROOT / "src/regaudit_fhe/reports.py").read_text(encoding="utf-8")
    assert "global _VERIFY_RECEIPT_WEAK_WARNED" not in source


# ---------------------------------------------------------------------------
# API-token hashing (CodeQL py/weak-sensitive-data-hashing)
# ---------------------------------------------------------------------------

pytest.importorskip("fastapi")  # server.py needs the [server] extra to import
server = pytest.importorskip("regaudit_fhe.server")


def test_token_hash_is_a_keyed_hmac_sha256():
    salt = b"\x01" * 32
    expected = hmac.new(salt, b"s3cr3t-token", hashlib.sha256).digest()
    assert server._hash_token("s3cr3t-token", salt) == expected


def test_token_hash_matches_the_rfc_4231_hmac_sha256_test_vector():
    """RFC 4231 test case 1: key = 20 x 0x0b, data = "Hi There". An independent known answer."""
    assert server._hash_token("Hi There", b"\x0b" * 20).hex() == (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )


def test_token_hash_is_not_the_old_unkeyed_construction():
    salt = b"\x02" * 32
    assert server._hash_token("tok", salt) != hashlib.sha256(salt + b"tok").digest()


def test_token_hash_depends_on_both_key_and_token():
    base = server._hash_token("tok", b"\x03" * 32)
    assert server._hash_token("tok", b"\x04" * 32) != base
    assert server._hash_token("tok2", b"\x03" * 32) != base
    assert server._hash_token("tok", b"\x03" * 32) == base  # deterministic within a process
    assert len(base) == 32


def test_authentication_still_works_end_to_end_with_the_new_hash():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    cfg = server.ServerConfig(
        api_keys={"good-token-123": frozenset({"audit:read"})},
        dev_mode=False,
        max_body_bytes=1 << 20,
        rate_limit_per_min=600,
        request_timeout_s=10.0,
        cors_origins=(),
    )
    client = TestClient(server.build_app(config=cfg))
    ok = client.get("/v1/schemas", headers={"Authorization": "Bearer good-token-123"})
    assert ok.status_code == 200
    for bad in ("good-token-124", "", "Good-token-123"):
        r = client.get("/v1/schemas", headers={"Authorization": f"Bearer {bad}"})
        assert r.status_code == 401, bad
    assert client.get("/v1/schemas").status_code == 401


def test_caller_key_id_stays_an_opaque_twelve_hex_prefix():
    key_id = server._hash_token("tok", b"\x05" * 32).hex()[:12]
    assert re.fullmatch(r"[0-9a-f]{12}", key_id) and "tok" not in key_id


# ---------------------------------------------------------------------------
# /readyz must not return exception text (CodeQL py/stack-trace-exposure)
# ---------------------------------------------------------------------------


def _client():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    cfg = server.ServerConfig(
        api_keys={},
        dev_mode=True,
        max_body_bytes=1 << 20,
        rate_limit_per_min=600,
        request_timeout_s=10.0,
        cors_origins=(),
    )
    return TestClient(server.build_app(config=cfg))


def test_readyz_is_ready_with_no_error_text_when_healthy():
    body = _client().get("/readyz").json()
    assert body["ready"] is True and body["error"] is None
    assert "privacy_boundary_warning" in body


def test_readyz_does_not_leak_exception_detail(monkeypatch):
    secret = "/Users/deploy/.secrets/schemas/envelope.schema.json: boom"

    def broken(name):
        raise RuntimeError(secret)

    monkeypatch.setattr(server, "load_schema", broken)
    r = _client().get("/readyz")
    body = r.json()
    assert body["ready"] is False
    assert body["error"] == "schema bundle unavailable"
    assert secret not in r.text and "RuntimeError" not in r.text and "/Users" not in r.text
    assert "privacy_boundary_warning" in body  # still reported


def test_readyz_failure_detail_is_logged_server_side(monkeypatch):
    import logging

    def broken(name):
        raise RuntimeError("detail-for-operators")

    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    monkeypatch.setattr(server, "load_schema", broken)
    client = _client()  # builds the app (and its logger configuration) first
    logger = logging.getLogger("regaudit-fhe.server")
    handler = Capture(level=logging.WARNING)
    logger.addHandler(handler)
    try:
        client.get("/readyz")
    finally:
        logger.removeHandler(handler)
    ours = [r for r in records if r.getMessage() == "readyz_schema_unavailable"]
    assert ours and ours[0].error == "detail-for-operators"
    assert ours[0].error_type == "RuntimeError"


# ---------------------------------------------------------------------------
# Examples use the recommended API, not the deprecated `.valid`
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", sorted((ROOT / "examples").glob("*.py")), ids=lambda p: p.name)
def test_examples_do_not_read_the_deprecated_valid_attribute(path):
    text = path.read_text(encoding="utf-8")
    assert not re.search(r"\b(?:outcome|out|bad|result|res)\.valid\b", text), path.name
