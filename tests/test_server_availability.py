"""Availability hardening of the HTTP server: stalled bodies, budget release, 422 size, verify structure.

AI-assisted engineering tests, not an audit. Everything runs in process at the ASGI level (no sockets) with small
sizes and short deadlines. ``test_*_still_*`` and ``*_control`` tests are positive controls: a well-behaved
request, or a large-but-legal one, must keep working.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from typing import Any

import numpy as np
import pytest

pytest.importorskip("fastapi")

import regaudit_fhe as rf
from regaudit_fhe import server
from regaudit_fhe._limits import IngressBudget
from regaudit_fhe.replay import InMemoryReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.server import ServerConfig, build_app, load_config_from_env
from regaudit_fhe.trust import TrustStore
from regaudit_fhe.verification import PolicyError

GOOD = {
    "y_true": [1, 0, 1, 0],
    "y_pred": [1, 0, 0, 0],
    "group_a": [1, 1, 0, 0],
    "group_b": [0, 0, 1, 1],
}
GOOD_BODY = json.dumps(GOOD).encode()


def _cfg(**overrides: Any) -> ServerConfig:
    base: dict[str, Any] = dict(
        api_keys={},
        dev_mode=True,
        max_body_bytes=1 << 20,
        rate_limit_per_min=10**6,
        request_timeout_s=30.0,
        cors_origins=(),
    )
    base.update(overrides)
    return ServerConfig(**base)


@pytest.fixture
def budgets(monkeypatch: pytest.MonkeyPatch) -> list[IngressBudget]:
    made: list[IngressBudget] = []

    class Spy(IngressBudget):
        def __init__(self, limit: int) -> None:
            super().__init__(limit)
            made.append(self)

    monkeypatch.setattr(server, "IngressBudget", Spy)
    return made


def _scope(path: str, headers: list[tuple[bytes, bytes]] | None = None) -> dict[str, Any]:
    return {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
        "root_path": "", "client": ("127.0.0.1", 1234), "server": ("127.0.0.1", 8000),
        "headers": [(b"host", b"t"), (b"content-type", b"application/json"), *(headers or [])],
    }  # fmt: skip


async def _call(
    app: Any, path: str, receive: Any, headers: list[tuple[bytes, bytes]] | None = None
) -> tuple[Any, bytes, float]:
    sent: list[dict[str, Any]] = []

    async def send(m: dict[str, Any]) -> None:
        sent.append(m)

    t0 = time.perf_counter()
    await app(_scope(path, headers), receive, send)
    dt = time.perf_counter() - t0
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    return (
        status,
        b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"),
        dt,
    )


def _whole(body: bytes) -> Any:
    done = False

    async def receive() -> dict[str, Any]:
        nonlocal done
        if done:
            await asyncio.sleep(3600)
        done = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


def _stalled(first: bytes) -> Any:
    """One partial chunk, then silence: the client neither sends nor disconnects."""
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": first, "more_body": True}
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    return receive


def _paced(body: bytes, pieces: int, gap: float) -> Any:
    """The body in ``pieces`` chunks with ``gap`` seconds between them (slow but alive)."""
    size = -(-len(body) // pieces)
    chunks = [body[i : i + size] for i in range(0, len(body), size)]
    i = 0

    async def receive() -> dict[str, Any]:
        nonlocal i
        if i:
            await asyncio.sleep(gap)
        chunk = chunks[i]
        i += 1
        return {"type": "http.request", "body": chunk, "more_body": i < len(chunks)}

    return receive


def _disconnecting(first: bytes) -> Any:
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": first, "more_body": True}
        return {"type": "http.disconnect"}

    return receive


def _padded(n: int) -> bytes:
    return GOOD_BODY + b" " * (n - len(GOOD_BODY))


AUDIT = "/v1/audit/fairness"


# ---------------------------------------------------------------------------
# (a) stalled bodies: inactivity deadline
# ---------------------------------------------------------------------------


def test_a_stalled_body_is_answered_408_and_frees_the_budget_for_the_next_request(
    budgets: list[IngressBudget],
) -> None:
    async def go() -> None:
        app = build_app(
            config=_cfg(
                max_body_bytes=32768,
                max_inflight_body_bytes=65536,
                request_timeout_s=30.0,
                body_idle_timeout_s=0.4,
            )
        )
        b = budgets[-1]
        stall = [asyncio.ensure_future(_call(app, AUDIT, _stalled(b"x" * 32000))) for _ in range(2)]
        await asyncio.sleep(0.1)
        assert b.held == 64000
        # Before the deadline the budget is exhausted: a legal request is refused.
        assert (await _call(app, AUDIT, _whole(_padded(20000))))[0] == 503
        results = await asyncio.gather(*stall)
        assert [r[0] for r in results] == [408, 408]
        body = json.loads(results[0][1])
        assert body["code"] == "BODY_TIMEOUT" and body["operation"] == "audit"
        assert results[0][2] < 5.0  # long before the 30 s request timeout
        assert b.held == 0
        # Positive control: a legal request is served again.
        assert (await _call(app, AUDIT, _whole(GOOD_BODY)))[0] == 200

    asyncio.run(go())


def test_a_body_that_never_starts_is_also_cut_off() -> None:
    async def never() -> dict[str, Any]:
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def go() -> None:
        app = build_app(config=_cfg(body_idle_timeout_s=0.3))
        status, _, dt = await _call(app, AUDIT, never)
        assert status == 408 and dt < 3.0

    asyncio.run(go())


def test_a_slow_but_active_client_and_a_large_legal_body_are_unaffected_control(
    budgets: list[IngressBudget],
) -> None:
    async def go() -> None:
        app = build_app(config=_cfg(body_idle_timeout_s=0.5))
        # Eight chunks, 0.15 s apart: well past 0.5 s in total, never idle for 0.5 s.
        status, _, dt = await _call(app, AUDIT, _paced(GOOD_BODY + b" " * 800, 8, 0.15))
        assert status == 200 and dt > 0.9
        # A 900 KB legal body in one piece.
        assert (await _call(app, AUDIT, _whole(_padded(900_000))))[0] == 200
        assert budgets[-1].held == 0

    asyncio.run(go())


def test_the_idle_deadline_can_be_switched_off() -> None:
    async def go() -> None:
        app = build_app(config=_cfg(body_idle_timeout_s=0, request_timeout_s=0.5))
        status, _, _ = await _call(app, AUDIT, _stalled(b"x" * 10))
        assert status == 504  # only the whole-request timeout, as before

    asyncio.run(go())


def test_idle_deadline_applies_to_verify_too(budgets: list[IngressBudget]) -> None:
    async def go() -> None:
        app = build_app(config=_cfg(body_idle_timeout_s=0.3, allow_self_signed=True))
        status, body, _ = await _call(app, "/v1/verify", _stalled(b"x" * 100))
        assert status == 408 and json.loads(body)["operation"] == "verify"
        assert budgets[-1].held == 0

    asyncio.run(go())


# ---------------------------------------------------------------------------
# (b) the budget is always released
# ---------------------------------------------------------------------------


def test_budget_is_released_after_disconnect_cancellation_and_timeout(
    budgets: list[IngressBudget],
) -> None:
    async def go() -> None:
        app = build_app(
            config=_cfg(
                max_body_bytes=32768,
                max_inflight_body_bytes=65536,
                request_timeout_s=0.5,
                body_idle_timeout_s=0,
            )
        )
        b = budgets[-1]
        # client disconnect mid-body: a quiet 400, not an unhandled exception
        status, _, _ = await _call(app, AUDIT, _disconnecting(b"x" * 30000))
        assert status == 400 and b.held == 0
        # request timeout while stalled
        status, _, _ = await _call(app, AUDIT, _stalled(b"x" * 30000))
        assert status == 504 and b.held == 0
        # the surrounding task is cancelled (server shutdown, peer reset)
        t = asyncio.ensure_future(_call(app, AUDIT, _stalled(b"x" * 30000)))
        await asyncio.sleep(0.1)
        assert b.held == 30000
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
        await asyncio.sleep(0.3)
        assert b.held == 0
        # a refused (over-budget) request releases what it had read
        assert (await _call(app, AUDIT, _whole(GOOD_BODY)))[0] == 200

    asyncio.run(go())


# ---------------------------------------------------------------------------
# (c) authenticate before reading the body (opt in)
# ---------------------------------------------------------------------------

KEYS = {"k-run": frozenset({"audit:run"}), "k-read": frozenset({"audit:read"})}
BEARER = [(b"authorization", b"Bearer k-run")]
MALFORMED = b'{"y_true": [1,'


def test_default_order_is_unchanged_body_is_parsed_before_authentication() -> None:
    async def go() -> None:
        app = build_app(config=_cfg(dev_mode=False, api_keys=KEYS))
        assert (await _call(app, AUDIT, _whole(MALFORMED)))[0] == 422
        assert (await _call(app, AUDIT, _whole(GOOD_BODY)))[0] == 401

    asyncio.run(go())


def test_auth_before_body_refuses_without_reading_or_parsing(
    budgets: list[IngressBudget],
) -> None:
    pulled = 0

    async def counting() -> dict[str, Any]:
        nonlocal pulled
        pulled += 1
        return {"type": "http.request", "body": MALFORMED, "more_body": False}

    async def go() -> None:
        app = build_app(config=_cfg(dev_mode=False, api_keys=KEYS, auth_before_body=True))
        assert (await _call(app, AUDIT, counting))[0] == 401
        assert pulled == 0  # the body was never touched
        wrong_scope = [(b"authorization", b"Bearer k-read")]
        assert (await _call(app, AUDIT, _whole(MALFORMED), wrong_scope))[0] == 403
        # Positive control: an authorised caller is served exactly as before, malformed bodies still 422.
        assert (await _call(app, AUDIT, _whole(GOOD_BODY), BEARER))[0] == 200
        assert (await _call(app, AUDIT, _whole(MALFORMED), BEARER))[0] == 422
        assert budgets[-1].held == 0

    asyncio.run(go())


# ---------------------------------------------------------------------------
# (d) bounded 422
# ---------------------------------------------------------------------------


def test_a_schema_422_is_bounded_not_amplified() -> None:
    async def go() -> None:
        app = build_app(config=_cfg())
        body = json.dumps({**GOOD, "y_true": ["a"] * 20000}).encode()
        status, resp, _ = await _call(app, AUDIT, _whole(body))
        assert status == 422
        detail = json.loads(resp)["detail"]
        assert detail.startswith("payload does not conform to schema 'fairness.input'")
        assert "truncated" in detail
        assert len(resp) < 4096 < len(body)
        # a very long echoed value is cut too
        status, resp, _ = await _call(
            app, AUDIT, _whole(json.dumps({**GOOD, "y_true": "x" * 500_000}).encode())
        )
        assert status == 422 and len(resp) < 4096

    asyncio.run(go())


def test_a_short_schema_422_is_byte_for_byte_what_it_was() -> None:
    async def go() -> None:
        app = build_app(config=_cfg())
        status, resp, _ = await _call(
            app, AUDIT, _whole(json.dumps({**GOOD, "y_true": "x"}).encode())
        )
        assert status == 422
        detail = json.loads(resp)["detail"]
        assert detail == (
            "payload does not conform to schema 'fairness.input': y_true: 'x' is not of type 'array'"
        )

    asyncio.run(go())


def test_bounded_detail_boundaries() -> None:
    limit = server.MAX_SCHEMA_DETAIL_CHARS
    assert server._bounded_detail("a" * limit) == "a" * limit
    cut = server._bounded_detail("a" * (limit + 1))
    assert cut.startswith("a" * limit) and cut != "a" * (limit + 1) and "truncated" in cut


# ---------------------------------------------------------------------------
# (e) /v1/verify structure limits
# ---------------------------------------------------------------------------


def _envelopes() -> tuple[Any, dict[str, Any], dict[str, Any]]:
    signer = rf.Signer.generate(issuer="acme", key_id="acme-1")
    rep = rf.audit_fairness(
        *(np.array(GOOD[k], float) for k in ("y_true", "y_pred", "group_a", "group_b"))
    )
    v1 = rf.envelope("fairness", rep, signer=signer).to_dict()
    v2 = envelope_v2("fairness", rep, signer=signer, deployment_id="d").to_dict()
    return signer, v1, v2


def _dump(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


def test_verify_refuses_deep_and_wide_envelopes_before_parsing_but_serves_genuine_ones() -> None:
    _, v1, v2 = _envelopes()

    async def go() -> None:
        app = build_app(config=_cfg(allow_self_signed=True))
        for env in (v1, v2):  # positive controls
            assert (await _call(app, "/v1/verify", _whole(_dump({"envelope": env}))))[0] == 200
        deep = json.loads("[" * 30 + "]" * 30)
        status, body, _ = await _call(
            app, "/v1/verify", _whole(_dump({"envelope": {**v1, "result": {"x": deep}}}))
        )
        assert status == 422 and json.loads(body) == {"detail": "malformed envelope"}
        wide = {"envelope": {**v1, "result": {"x": [1] * 70000}}}
        status, body, _ = await _call(app, "/v1/verify", _whole(_dump(wide)))
        assert status == 422 and json.loads(body) == {"detail": "malformed envelope"}
        # just inside the limits is still answered with a verdict (200), exactly as before
        near = {
            "envelope": {**v1, "result": {"x": [1] * 60000, "y": json.loads("[" * 10 + "]" * 10)}}
        }
        assert (await _call(app, "/v1/verify", _whole(_dump(near))))[0] == 200

    asyncio.run(go())


def test_verify_limits_are_configurable_and_bad_values_are_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, v1, _ = _envelopes()

    async def go() -> None:
        app = build_app(config=_cfg(allow_self_signed=True, verify_max_json_depth=8))
        body = _dump({"envelope": {**v1, "result": {"x": json.loads("[" * 12 + "]" * 12)}}})
        assert (await _call(app, "/v1/verify", _whole(body)))[0] == 422

    asyncio.run(go())
    for name, bad in (
        ("REGAUDIT_FHE_VERIFY_MAX_JSON_DEPTH", "7"),
        ("REGAUDIT_FHE_VERIFY_MAX_ELEMENTS", "1023"),
        ("REGAUDIT_FHE_BODY_IDLE_TIMEOUT_S", "-1"),
        ("REGAUDIT_FHE_BODY_IDLE_TIMEOUT_S", "nan"),
        ("REGAUDIT_FHE_BODY_IDLE_TIMEOUT_S", "1e999"),
        ("REGAUDIT_FHE_VERIFY_MAX_ELEMENTS", "12 "),
    ):
        monkeypatch.setenv(name, bad)
        with pytest.raises(PolicyError):
            load_config_from_env()
        monkeypatch.delenv(name)
    monkeypatch.setenv("REGAUDIT_FHE_BODY_IDLE_TIMEOUT_S", "0")
    monkeypatch.setenv("REGAUDIT_FHE_AUTH_BEFORE_BODY", "1")
    cfg = load_config_from_env()
    assert cfg.body_idle_timeout_s == 0 and cfg.auth_before_body is True
    assert (cfg.verify_max_json_depth, cfg.verify_max_elements) == (16, 65536)


def test_embedding_config_values_are_validated() -> None:
    for kw in (
        {"body_idle_timeout_s": float("nan")},
        {"body_idle_timeout_s": -1.0},
        {"body_idle_timeout_s": True},
        {"verify_max_json_depth": 3},
        {"verify_max_elements": True},
        {"auth_before_body": "yes"},
    ):
        with pytest.raises(PolicyError):
            build_app(config=_cfg(**kw))


# ---------------------------------------------------------------------------
# (f) a timed-out verify keeps running (characterisation: pins the residual risk)
# ---------------------------------------------------------------------------


def _trusted_v2() -> tuple[TrustStore, bytes]:
    signer, _, v2 = _envelopes()
    store = TrustStore.from_dict(
        {
            "entries": {
                signer.key_id: {
                    "issuer": signer.issuer,
                    "public_key_pem": signer.public_key_pem(),
                    "status": "active",
                }
            }
        }
    )
    return store, _dump({"envelope": v2})


def _capture(name: str) -> tuple[logging.Logger, list[str]]:
    seen: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record.getMessage())

    log = logging.getLogger(name)
    log.handlers.clear()
    log.addHandler(Capture())
    log.setLevel(logging.INFO)
    return log, seen


def test_a_verify_submitted_before_the_504_still_records_and_the_retry_is_flagged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Documents, does not endorse: a verification SUBMITTED before the request times out runs to the end and, in
    replay ``record`` mode, records the report, so the 504 client's retry is REPLAY_DETECTED. Any change to this
    is a compatibility decision (docs/DEPLOYMENT.md, "Resource bounds"). No wall-clock race: the abandoned job
    blocks until the test has its 504, and the branch precondition (it was submitted) is asserted explicitly."""
    store, body = _trusted_v2()
    real = server.verify
    started, release, finished = threading.Event(), threading.Event(), threading.Event()

    def slow(env: Any, policy: Any) -> Any:
        if not started.is_set():  # the first (abandoned) verification only
            started.set()
            release.wait(30)
            try:
                return real(env, policy)
            finally:
                finished.set()
        return real(env, policy)

    monkeypatch.setattr(server, "verify", slow)
    log, seen = _capture("test-availability-replay-submitted")

    async def go() -> None:
        cache = InMemoryReplayCache()
        mk = lambda t: build_app(  # noqa: E731
            config=_cfg(
                trust_store=store, replay_cache=cache, replay_mode="record", request_timeout_s=t
            ),
            logger=log,
        )
        # 3 s is far above the few milliseconds the request needs to reach submission
        status, _, _ = await _call(mk(3.0), "/v1/verify", _whole(body))
        assert status == 504
        assert started.is_set(), "precondition: the verification was submitted before the 504"
        assert not cache._entries  # nothing recorded yet: the job is still blocked
        release.set()
        assert await asyncio.to_thread(finished.wait, 30)
        assert len(cache._entries) == 1  # the abandoned verification recorded the report
        status, resp, _ = await _call(mk(5.0), "/v1/verify", _whole(body))
        verdict = json.loads(resp)
        assert status == 200 and "REPLAY_DETECTED" in verdict["blocking_reasons"], verdict

    asyncio.run(go())
    assert "verify_request_abandoned" in seen


def test_a_verify_that_times_out_before_submission_records_nothing_and_the_retry_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other branch of "outcome unknown": when the timeout fires before the verification is submitted (here
    the request is still in its authentication dependency, which runs on a worker thread), verify() never runs,
    nothing is recorded and the retry is verified normally. This is what the earlier, timing-based test hit on a
    slow CI runner. Deterministic: the dependency outlasts the timeout, and the 504 is sent only after it returned."""
    store, body = _trusted_v2()
    real_scopes = server._check_scopes
    entered: list[str] = []
    real_verify = server.verify

    def counting_verify(env: Any, policy: Any) -> Any:
        entered.append("verify")
        return real_verify(env, policy)

    calls = [0]
    dep_done = threading.Event()

    def slow_scopes(caller: Any, scopes: Any) -> Any:
        calls[0] += 1
        if calls[0] == 1:
            time.sleep(0.6)  # longer than the 0.2 s request timeout below
            dep_done.set()
        return real_scopes(caller, scopes)

    monkeypatch.setattr(server, "verify", counting_verify)
    monkeypatch.setattr(server, "_check_scopes", slow_scopes)
    log, seen = _capture("test-availability-replay-not-submitted")

    async def go() -> None:
        cache = InMemoryReplayCache()
        mk = lambda t: build_app(  # noqa: E731
            config=_cfg(
                trust_store=store, replay_cache=cache, replay_mode="record", request_timeout_s=t
            ),
            logger=log,
        )
        status, _, _ = await _call(mk(0.2), "/v1/verify", _whole(body))
        assert status == 504
        # the 504 is sent only after the cancelled request has finished: the dependency returned, and the
        # endpoint (which submits the verification) never ran
        assert dep_done.is_set()
        assert calls[0] == 1 and entered == []  # never submitted
        assert not cache._entries
        status, resp, _ = await _call(mk(5.0), "/v1/verify", _whole(body))
        verdict = json.loads(resp)
        assert status == 200 and verdict["blocking_reasons"] == [], verdict
        assert entered == ["verify"] and len(cache._entries) == 1

    asyncio.run(go())
    assert "verify_request_abandoned" not in seen
