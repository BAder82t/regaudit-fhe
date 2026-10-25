"""Server-side security-maintenance regressions: token hashing, HMAC key validation, /readyz.

These need the ``[server]`` extra. Only a *missing* FastAPI skips this module; if FastAPI is
installed, an import failure in ``regaudit_fhe.server`` is a real defect and fails collection.
FastAPI-independent regressions are in ``test_security_maintenance.py``.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import io
import json
import logging
import re

import pytest

if importlib.util.find_spec("fastapi") is None:
    pytest.skip("the [server] extra (fastapi) is not installed", allow_module_level=True)

import regaudit_fhe.server as server  # must fail loudly, never skip, if broken

needs_httpx = pytest.mark.skipif(
    importlib.util.find_spec("httpx") is None, reason="httpx (dev extra) is not installed"
)


# ---------------------------------------------------------------------------
# API-token hashing (CodeQL py/weak-sensitive-data-hashing)
# ---------------------------------------------------------------------------


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


@needs_httpx
def test_authentication_still_works_end_to_end_with_the_new_hash():
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


@needs_httpx
def test_readyz_is_ready_with_no_error_text_when_healthy():
    r = _client().get("/readyz")
    body = r.json()
    assert r.status_code == 200
    assert body["ready"] is True and body["error"] is None
    assert "privacy_boundary_warning" in body


@needs_httpx
def test_readyz_does_not_leak_exception_detail(monkeypatch):
    secret = "/Users/deploy/.secrets/schemas/envelope.schema.json: boom"

    def broken(name):
        raise RuntimeError(secret)

    monkeypatch.setattr(server, "load_schema", broken)
    r = _client().get("/readyz")
    body = r.json()
    assert r.status_code == 503
    assert body["ready"] is False
    assert body["error"] == "schema bundle unavailable"
    assert secret not in r.text and "RuntimeError" not in r.text and "/Users" not in r.text
    assert "privacy_boundary_warning" in body  # still reported


@needs_httpx
def test_readyz_failure_detail_is_logged_server_side(monkeypatch):
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
# HMAC key validation (explicit keys are refused, never silently replaced)
# ---------------------------------------------------------------------------


def _cfg(**kw):
    base = dict(
        api_keys={"good-token-123": frozenset({"audit:read"})},
        dev_mode=False,
        max_body_bytes=1 << 20,
        rate_limit_per_min=600,
        request_timeout_s=10.0,
        cors_origins=(),
    )
    base.update(kw)
    return server.ServerConfig(**base)


@pytest.mark.parametrize("bad", [b"", b"\x01", b"\x01" * 15])
def test_short_or_empty_hmac_key_is_rejected_by_build_app(bad):
    with pytest.raises(ValueError, match="at least 16 bytes"):
        server.build_app(config=_cfg(), salt=bad)


@pytest.mark.parametrize("bad", [b"", b"\x01" * 15])
def test_short_or_empty_hmac_key_is_rejected_by_make_auth_dependency(bad):
    with pytest.raises(ValueError, match="at least 16 bytes"):
        server.make_auth_dependency(_cfg(), salt=bad)


@pytest.mark.parametrize("bad", ["a-sixteen-char-str", 12345, object()])
def test_non_bytes_hmac_key_is_rejected(bad):
    with pytest.raises(TypeError, match="must be bytes"):
        server.build_app(config=_cfg(), salt=bad)


def test_rejection_messages_never_contain_the_key_material():
    secret = b"SHORT-SECRET"  # 12 bytes
    with pytest.raises(ValueError) as exc:
        server.build_app(config=_cfg(), salt=secret)
    assert "SHORT-SECRET" not in str(exc.value) and repr(secret) not in str(exc.value)
    assert secret.hex() not in str(exc.value)


@pytest.mark.parametrize("good", [b"\x07" * 16, b"\x07" * 32, bytearray(b"\x07" * 24)])
def test_keys_of_at_least_16_bytes_are_accepted(good):
    assert server.build_app(config=_cfg(), salt=good) is not None


def test_a_missing_key_defaults_to_a_fresh_random_key_per_app(monkeypatch):
    seen = []
    real = server.make_auth_dependency

    def spy(config, *, salt):
        seen.append(salt)
        return real(config, salt=salt)

    monkeypatch.setattr(server, "make_auth_dependency", spy)
    server.build_app(config=_cfg())
    server.build_app(config=_cfg())
    assert len(seen) == 2 and all(len(k) == 32 for k in seen) and seen[0] != seen[1]


@needs_httpx
def test_the_same_validated_key_is_used_at_startup_and_per_request():
    from fastapi.testclient import TestClient

    for key in (b"\x09" * 16, b"\x0a" * 32):
        client = TestClient(server.build_app(config=_cfg(), salt=key))
        ok = client.get("/v1/schemas", headers={"Authorization": "Bearer good-token-123"})
        assert ok.status_code == 200
        bad = client.get("/v1/schemas", headers={"Authorization": "Bearer good-token-124"})
        assert bad.status_code == 401


def test_key_id_depends_on_the_key_so_it_is_worker_local():
    a = server._hash_token("tok", b"\x01" * 16).hex()[:12]
    b = server._hash_token("tok", b"\x02" * 16).hex()[:12]
    assert a != b


# ---------------------------------------------------------------------------
# Structured logs: exception text cannot forge a record or inject fields
# ---------------------------------------------------------------------------

_HOSTILE = 'boom\n{"level": "INFO", "msg": "forged"}\r\n","injected": "yes", "x": "\u2028\u2029\x85'


def test_json_formatter_keeps_hostile_text_inside_one_json_record():
    record = logging.LogRecord(
        "regaudit-fhe.server", logging.WARNING, __file__, 1, "readyz_schema_unavailable", None, None
    )
    record.error = _HOSTILE
    record.error_type = "RuntimeError"
    line = server._JSONFormatter().format(record)
    assert "\n" not in line and "\r" not in line
    assert len(line.splitlines()) == 1  # Unicode-aware splitting (U+2028/2029/0085) too
    parsed = json.loads(line)
    assert parsed["error"] == _HOSTILE  # round-trips as data
    # Python >= 3.12 adds a ``taskName`` attribute to every record; it is emitted as null.
    assert set(parsed) - {"taskName"} == {"ts", "level", "msg", "logger", "error", "error_type"}
    assert "injected" not in parsed and parsed["msg"] == "readyz_schema_unavailable"


@needs_httpx
def test_readyz_failure_with_hostile_detail_logs_exactly_one_valid_json_line(monkeypatch):
    def broken(name):
        raise RuntimeError(_HOSTILE)

    monkeypatch.setattr(server, "load_schema", broken)
    client = _client()
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(server._JSONFormatter())
    handler.setLevel(logging.WARNING)
    logger = logging.getLogger("regaudit-fhe.server")
    logger.addHandler(handler)
    try:
        r = client.get("/readyz")
    finally:
        logger.removeHandler(handler)
    assert _HOSTILE not in r.text  # still not in the response
    lines = [ln for ln in buf.getvalue().splitlines() if "readyz_schema_unavailable" in ln]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["error"] == _HOSTILE and "injected" not in parsed
    # no second apparent record: every emitted line is itself valid JSON
    assert all(isinstance(json.loads(ln), dict) for ln in buf.getvalue().splitlines() if ln)


@needs_httpx
def test_readyz_is_503_when_the_schema_bundle_is_missing_from_the_package(monkeypatch, tmp_path):
    """A status-code-only probe must see 'not ready' as a failure (real loader, not a stub)."""
    from regaudit_fhe import schemas

    schemas.load_schema.cache_clear()  # an earlier test may have cached the schema
    monkeypatch.setattr(schemas, "__file__", str(tmp_path / "schemas.py"))  # no schemas/ next to it
    try:
        r = _client().get("/readyz")
    finally:
        monkeypatch.undo()
        schemas.load_schema.cache_clear()
    assert r.status_code == 503
    assert r.json()["ready"] is False
    assert str(tmp_path) not in r.text


@needs_httpx
def test_healthz_stays_200_when_not_ready(monkeypatch):
    """Liveness must not follow readiness, or an orchestrator would restart a live process."""

    def broken(name):
        raise RuntimeError("boom")

    monkeypatch.setattr(server, "load_schema", broken)
    assert _client().get("/healthz").status_code == 200
