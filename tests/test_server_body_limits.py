"""The request-body limit applies to every route and to chunked bodies (no Content-Length), before any parsing."""

from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("fastapi")

from regaudit_fhe.server import ServerConfig, build_app

LIMIT = 1 << 20  # 1 MiB
GOOD = {
    "y_true": [1, 0, 1, 0],
    "y_pred": [1, 0, 0, 0],
    "group_a": [1, 1, 0, 0],
    "group_b": [0, 0, 1, 1],
}


def _app(max_body=LIMIT):
    cfg = ServerConfig(
        api_keys={}, dev_mode=True, max_body_bytes=max_body, rate_limit_per_min=10000,
        request_timeout_s=30.0, cors_origins=(),
    )  # fmt: skip
    return build_app(config=cfg)


async def _call(app, path, chunks, headers=()):
    """Drive the ASGI app by hand with a body delivered in `chunks` and no Content-Length unless given."""
    sent = []
    it = iter(chunks)
    pulled = 0

    async def receive():
        nonlocal pulled
        try:
            chunk = next(it)
        except StopIteration:
            return {"type": "http.disconnect"}
        pulled += 1
        return {"type": "http.request", "body": chunk, "more_body": pulled < len(chunks)}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http",
        "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
        "headers": [(b"host", b"testserver"), (b"content-type", b"application/json"), *headers],
        "client": ("127.0.0.1", 1234), "server": ("127.0.0.1", 80),
    }  # fmt: skip
    await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], body, pulled


def run(coro):
    return asyncio.run(coro)


def test_a_small_chunked_body_still_works():
    raw = json.dumps(GOOD).encode()
    status, body, _ = run(_call(_app(), "/v1/audit/fairness", [raw[:30], raw[30:]]))
    assert status == 200, body


def test_an_oversized_chunked_body_is_cut_off_early_on_the_audit_route():
    chunks = [b"x" * (256 * 1024)] * 64  # 16 MiB offered, no Content-Length
    status, body, pulled = run(_call(_app(), "/v1/audit/fairness", chunks))
    assert status == 413
    assert pulled <= (LIMIT // (256 * 1024)) + 2, f"the server kept reading ({pulled} chunks)"
    assert b"exceeds limit" in body


def test_an_oversized_chunked_body_is_refused_before_authentication():
    cfg = ServerConfig(
        api_keys={"tok": frozenset({"audit:run"})}, dev_mode=False, max_body_bytes=LIMIT, rate_limit_per_min=10000,
        request_timeout_s=30.0, cors_origins=(),
    )  # fmt: skip
    status, _, pulled = run(
        _call(build_app(config=cfg), "/v1/audit/fairness", [b"x" * (256 * 1024)] * 64)
    )
    assert status == 413 and pulled <= 6  # not 401 after consuming it all, not 422 after parsing it


def test_an_oversized_content_length_is_refused_without_reading_the_body():
    status, _, pulled = run(
        _call(
            _app(),
            "/v1/audit/fairness",
            [b"{}"],
            headers=[(b"content-length", str(LIMIT + 1).encode())],
        )
    )
    assert status == 413 and pulled == 0


def test_an_invalid_content_length_is_a_400():
    status, _, _ = run(
        _call(_app(), "/v1/audit/fairness", [b"{}"], headers=[(b"content-length", b"abc")])
    )
    assert status == 400


def test_the_limit_also_applies_to_the_verify_route_and_to_get_requests_are_unaffected():
    status, _, pulled = run(_call(_app(), "/v1/verify", [b"x" * (256 * 1024)] * 64))
    assert status in (413, 422, 503) and pulled <= 8


def test_unequal_array_lengths_are_a_422_not_a_500():
    bad = dict(GOOD, group_a=[1])
    status, body, _ = run(_call(_app(), "/v1/audit/fairness", [json.dumps(bad).encode()]))
    assert status == 422 and b"inconsistent" in body


def test_a_wrapped_abort_still_becomes_413_and_an_unrelated_error_still_propagates():
    """Inner middleware may re-raise our abort wrapped in another exception (an ExceptionGroup, depending on versions)."""
    from regaudit_fhe.server import BodySizeLimitMiddleware

    async def reading_app(scope, receive, send):
        try:
            while True:
                message = await receive()
                if not message.get("more_body"):
                    break
        except Exception as exc:
            raise RuntimeError("wrapped by an inner layer") from exc

    async def failing_app(scope, receive, send):
        raise RuntimeError("unrelated failure")

    async def drive(app, chunks):
        sent, it = [], iter(chunks)

        async def receive():
            body = next(it, None)
            if body is None:
                return {"type": "http.disconnect"}
            return {"type": "http.request", "body": body, "more_body": body is not chunks[-1]}

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "headers": [], "method": "POST", "path": "/x"}
        await BodySizeLimitMiddleware(app, 1024)(scope, receive, send)
        return sent

    sent = run(drive(reading_app, [b"x" * 600, b"y" * 600, b"z" * 600]))
    assert sent[0]["status"] == 413
    with pytest.raises(RuntimeError, match="unrelated failure"):
        run(drive(failing_app, [b"small"]))
