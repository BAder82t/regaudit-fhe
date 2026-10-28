"""Resource bounds of the HTTP server: input limits, bounded concurrency, health under load, no leftover work.

AI-assisted engineering tests. The concurrency tests replace the audit computation with a controllable stand-in
(``regaudit_fhe.server._audit_dispatch``), so they are deterministic and use no meaningful CPU; real-CPU numbers
come from ``scripts/resource_bounds_probe.py``.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

import httpx

from regaudit_fhe import server
from regaudit_fhe._limits import (
    AdmissionGate,
    GateRefused,
    InputLimitError,
    InputLimits,
    check_input_bounds,
)
from regaudit_fhe.server import ServerConfig, build_app
from tests._asgi import WithPeer

GOOD = {
    "y_true": [1, 0, 1, 0],
    "y_pred": [1, 0, 0, 0],
    "group_a": [1, 1, 0, 0],
    "group_b": [0, 0, 1, 1],
}


def _cfg(**overrides: Any) -> ServerConfig:
    base: dict[str, Any] = dict(
        api_keys={},
        dev_mode=True,
        max_body_bytes=1 << 20,
        rate_limit_per_min=100000,
        request_timeout_s=30.0,
        cors_origins=(),
    )
    base.update(overrides)
    return ServerConfig(**base)


def _client(app: Any) -> Any:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", timeout=30
    )


def _wide(n: int) -> dict[str, Any]:
    return {
        k: ([1, 0] * n)[:n] if k != "threshold" else v
        for k, v in {**GOOD, "threshold": 0.1}.items()
    }


# ---------------------------------------------------------------------------
# Input limits
# ---------------------------------------------------------------------------


def test_bounds_accept_exact_limit_and_refuse_one_more() -> None:
    lim = InputLimits(max_array_elements=10, max_total_elements=20, max_depth=3)
    check_input_bounds({"a": [0] * 10, "b": [0] * 10}, lim)  # exactly at both limits
    with pytest.raises(InputLimitError) as one:
        check_input_bounds({"a": [0] * 11}, lim)
    assert (one.value.limit, one.value.maximum) == ("max_array_elements", 10)
    with pytest.raises(InputLimitError) as tot:
        check_input_bounds({"a": [0] * 10, "b": [0] * 10, "c": [0]}, lim)
    assert tot.value.limit == "max_total_elements"
    with pytest.raises(InputLimitError) as deep:
        check_input_bounds({"a": [[[0]]]}, lim)  # depth 4 > 3
    assert deep.value.limit == "max_json_depth"
    with pytest.raises(InputLimitError) as members:
        check_input_bounds(
            {str(i): 0 for i in range(11)}, lim
        )  # object members count against the array limit
    assert members.value.limit == "max_array_elements"


def test_bounds_handle_very_deep_nesting_without_recursion() -> None:
    node: Any = []
    for _ in range(5000):
        node = [node]
    with pytest.raises(InputLimitError):
        check_input_bounds({"x": node}, InputLimits())


def test_oversized_array_is_refused_with_a_stable_body() -> None:
    app = build_app(
        config=_cfg(input_limits=InputLimits(max_array_elements=8, max_total_elements=64))
    )

    async def go() -> Any:
        async with _client(app) as c:
            return await c.post("/v1/audit/fairness", json=_wide(9))

    r = asyncio.run(go())
    assert r.status_code == 413
    assert r.json() == {
        "detail": "audit input has an array longer than the configured limit",
        "code": "INPUT_LIMIT_EXCEEDED",
        "limit": "max_array_elements",
        "maximum": 8,
    }


def test_refusal_does_not_echo_caller_keys() -> None:
    app = build_app(config=_cfg(input_limits=InputLimits(max_array_elements=8)))

    async def go() -> Any:
        async with _client(app) as c:
            return await c.post("/v1/audit/fairness", json={"SECRET-KEY-NAME": [0] * 9})

    r = asyncio.run(go())
    assert r.status_code == 413
    assert "SECRET-KEY-NAME" not in r.text


def test_legitimate_request_is_unchanged_by_the_limits() -> None:
    app = build_app(config=_cfg())

    async def go() -> Any:
        async with _client(app) as c:
            return await c.post("/v1/audit/fairness", json=GOOD)

    r = asyncio.run(go())
    assert r.status_code == 200
    assert r.json()["primitive"] == "fairness"


def test_default_limits_admit_the_largest_default_payload_shape() -> None:
    n = InputLimits().max_array_elements
    check_input_bounds(
        {k: [0, 1] * (n // 2) for k in ("y_true", "y_pred", "group_a", "group_b")}, InputLimits()
    )


def test_limits_come_from_the_environment_and_bad_values_refuse_to_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REGAUDIT_FHE_MAX_ARRAY_ELEMENTS", "123")
    monkeypatch.setenv("REGAUDIT_FHE_MAX_CONCURRENT_AUDITS", "3")
    cfg = server.load_config_from_env()
    assert cfg.input_limits.max_array_elements == 123
    assert cfg.max_concurrent_audits == 3
    assert server.load_config_from_env().input_limits.max_total_elements == 524288
    for name, bad in (
        ("REGAUDIT_FHE_MAX_ARRAY_ELEMENTS", "0"),
        ("REGAUDIT_FHE_MAX_CONCURRENT_AUDITS", "x"),
        ("REGAUDIT_FHE_QUEUE_WAIT_S", "nan"),
        ("REGAUDIT_FHE_MAX_QUEUED_AUDITS", "-1"),
        ("REGAUDIT_FHE_MAX_JSON_DEPTH", "2"),
        ("REGAUDIT_FHE_MAX_TOTAL_ELEMENTS", "0"),
        ("REGAUDIT_FHE_MAX_CONCORDANCE_SAMPLES", "0"),
        ("REGAUDIT_FHE_MAX_DISAGREEMENT_MODELS", "-3"),
        ("REGAUDIT_FHE_MAX_CONCORDANCE_SAMPLES", "many"),
    ):
        monkeypatch.setenv(name, bad)
        with pytest.raises(server.PolicyError):
            server.load_config_from_env()
        monkeypatch.delenv(name)
        monkeypatch.setenv("REGAUDIT_FHE_MAX_ARRAY_ELEMENTS", "123")


# ---------------------------------------------------------------------------
# AdmissionGate
# ---------------------------------------------------------------------------


def test_gate_bounds_running_and_waiting_and_refuses_the_rest() -> None:
    async def go() -> None:
        gate = AdmissionGate(max_running=1, max_waiting=1, wait_s=5)
        await gate.acquire()
        waiter = asyncio.ensure_future(gate.acquire())
        await asyncio.sleep(0)
        assert (gate.running, gate.waiting) == (1, 1)
        with pytest.raises(GateRefused) as full:
            await gate.acquire()
        assert full.value.reason == "queue_full"
        gate.release()  # hands the slot to the waiter
        await waiter
        assert (gate.running, gate.waiting) == (1, 0)
        gate.release()
        assert gate.running == 0

    asyncio.run(go())


def test_gate_wait_times_out_and_cancelled_waiter_leaves_no_trace() -> None:
    async def go() -> None:
        gate = AdmissionGate(max_running=1, max_waiting=2, wait_s=0.05)
        await gate.acquire()
        with pytest.raises(GateRefused) as late:
            await gate.acquire()
        assert late.value.reason == "queue_wait_timeout"
        assert gate.waiting == 0
        gate.wait_s = 5
        waiter = asyncio.ensure_future(gate.acquire())
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert gate.waiting == 0
        gate.release()
        assert gate.running == 0

    asyncio.run(go())


def test_gate_slot_granted_to_a_cancelled_waiter_is_returned() -> None:
    async def go() -> None:
        gate = AdmissionGate(max_running=1, max_waiting=1, wait_s=5)
        await gate.acquire()
        waiter = asyncio.ensure_future(gate.acquire())
        await asyncio.sleep(0)
        gate.release()  # grant ...
        waiter.cancel()  # ... and cancel before the waiter resumes
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert gate.running == 0 and gate.waiting == 0

    asyncio.run(go())


# ---------------------------------------------------------------------------
# Backpressure, no leftover work, health under load (stand-in for the audit computation)
# ---------------------------------------------------------------------------


class _Blocker:
    """Replaces ``_audit_dispatch``: each call blocks until released, and calls are counted."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.started = 0
        self.finished = 0
        self._lock = threading.Lock()

    def __call__(self, primitive: str, payload: dict[str, Any]) -> Any:
        with self._lock:
            self.started += 1
        self.release.wait(20)
        with self._lock:
            self.finished += 1
        return server._audit_dispatch_original(primitive, payload)


@pytest.fixture
def blocker(monkeypatch: pytest.MonkeyPatch) -> _Blocker:
    monkeypatch.setattr(server, "_audit_dispatch_original", server._audit_dispatch, raising=False)
    b = _Blocker()
    monkeypatch.setattr(server, "_audit_dispatch", b)
    return b


async def _until(pred: Any, limit: float = 5.0) -> None:
    end = time.monotonic() + limit
    while not pred():
        assert time.monotonic() < end, "condition not reached"
        await asyncio.sleep(0.01)


def test_overload_gets_a_deterministic_503_with_retry_after(blocker: _Blocker) -> None:
    app = build_app(config=_cfg(max_concurrent_audits=1, max_queued_audits=1, queue_wait_s=30.0))

    async def go() -> list[Any]:
        async with _client(app) as c:
            first = asyncio.ensure_future(c.post("/v1/audit/fairness", json=GOOD))
            await _until(lambda: blocker.started == 1)
            second = asyncio.ensure_future(
                c.post("/v1/audit/fairness", json=GOOD)
            )  # waits in the queue
            await asyncio.sleep(0.2)
            refused = [await c.post("/v1/audit/fairness", json=GOOD) for _ in range(3)]
            blocker.release.set()
            return [*refused, await first, await second]

    *refused, first, second = asyncio.run(go())
    for r in refused:
        assert r.status_code == 503
        assert r.headers["retry-after"] == "1"
        assert r.json() == {
            "detail": "the server is at capacity; retry later",
            "code": "SERVER_BUSY",
            "operation": "audit",
            "reason": "queue_full",
        }
    assert first.status_code == 200 and second.status_code == 200
    assert blocker.started == 2  # the refused requests never started a computation


def test_queue_wait_expiry_is_a_503_not_a_hang(blocker: _Blocker) -> None:
    app = build_app(config=_cfg(max_concurrent_audits=1, max_queued_audits=2, queue_wait_s=0.2))

    async def go() -> Any:
        async with _client(app) as c:
            first = asyncio.ensure_future(c.post("/v1/audit/fairness", json=GOOD))
            await _until(lambda: blocker.started == 1)
            t0 = time.monotonic()
            late = await c.post("/v1/audit/fairness", json=GOOD)
            waited = time.monotonic() - t0
            blocker.release.set()
            await first
            return late, waited

    late, waited = asyncio.run(go())
    assert late.status_code == 503 and late.json()["reason"] == "queue_wait_timeout"
    assert late.headers["retry-after"] == "1"
    assert 0.15 < waited < 3


def test_timed_out_requests_leave_no_work_behind(blocker: _Blocker) -> None:
    """A burst far larger than capacity, with a short request timeout: only the admitted computation ever runs.

    The queued requests are abandoned by the timeout; they must not start a computation afterwards, and the
    slot of the one that was running must come back only when its work really ends.
    """
    app = build_app(
        config=_cfg(
            max_concurrent_audits=1, max_queued_audits=4, queue_wait_s=30.0, request_timeout_s=0.3
        )
    )

    async def go() -> tuple[list[int], bool]:
        async with _client(app) as c:
            rs = await asyncio.gather(*[c.post("/v1/audit/fairness", json=GOOD) for _ in range(12)])
            statuses = sorted(r.status_code for r in rs)
            await asyncio.sleep(0.3)
            started_at_timeout = blocker.started
            # The abandoned job is still running, so its slot is still taken: capacity is not inflated.
            during = await c.post("/v1/audit/fairness", json=GOOD)
            blocker.release.set()
            await _until(lambda: blocker.finished == blocker.started)
            await asyncio.sleep(0.3)  # any queued-but-abandoned work would start now
            after = await c.post("/v1/audit/fairness", json=GOOD)
            assert started_at_timeout == 1
            assert during.status_code in (503, 504)
            assert after.status_code == 200
            return statuses, True

    statuses, _ = asyncio.run(go())
    assert statuses.count(504) == 5  # 1 running + 4 queued time out
    assert statuses.count(503) == 7  # the rest are refused at once
    # one computation for the burst and one for the final probe request: nothing queued ran late
    assert blocker.started == 2


def test_probes_stay_responsive_while_every_audit_slot_is_busy(blocker: _Blocker) -> None:
    app = build_app(config=_cfg(max_concurrent_audits=2, max_queued_audits=2, queue_wait_s=30.0))

    async def go() -> list[float]:
        async with _client(app) as c:
            jobs = [
                asyncio.ensure_future(c.post("/v1/audit/fairness", json=GOOD)) for _ in range(4)
            ]
            await _until(lambda: blocker.started == 2)
            lat = []
            for path in ("/healthz", "/readyz", "/healthz"):
                t0 = time.monotonic()
                r = await c.get(path)
                lat.append(time.monotonic() - t0)
                assert r.status_code == 200
            blocker.release.set()
            await asyncio.gather(*jobs)
            return lat

    lat = asyncio.run(go())
    assert max(lat) < 1.0, lat


def test_probes_do_not_depend_on_the_shared_thread_pool() -> None:
    """healthz/readyz are coroutines: they run on the event loop, not in a worker thread."""
    assert asyncio.iscoroutinefunction(_route(build_app(config=_cfg()), "/healthz"))
    assert asyncio.iscoroutinefunction(_route(build_app(config=_cfg()), "/readyz"))


def _route(app: Any, path: str) -> Any:
    return next(r.endpoint for r in app.routes if getattr(r, "path", None) == path)


def test_verify_is_bounded_too(monkeypatch: pytest.MonkeyPatch) -> None:
    hold = threading.Event()
    entered = threading.Event()
    real_verify = server.verify

    def slow_verify(env: Any, policy: Any) -> Any:
        entered.set()
        hold.wait(20)
        return real_verify(env, policy)

    monkeypatch.setattr(server, "verify", slow_verify)
    app = WithPeer(
        build_app(
            config=_cfg(
                allow_self_signed=True,
                max_concurrent_verifies=1,
                max_queued_audits=0,
                queue_wait_s=0.1,
            )
        ),
        server=("127.0.0.1", 8000),
    )

    async def go() -> list[Any]:
        async with _client(app) as c:
            env = (await c.post("/v1/audit/fairness", json=GOOD)).json()
            body = {"envelope": env}
            first = asyncio.ensure_future(c.post("/v1/verify", json=body))
            await _until(entered.is_set)
            second = await c.post("/v1/verify", json=body)
            hold.set()
            return [second, await first]

    second, first = asyncio.run(go())
    assert second.status_code == 503 and second.json()["operation"] == "verify"
    assert first.status_code == 200


# ---------------------------------------------------------------------------
# TimeoutMiddleware
# ---------------------------------------------------------------------------


async def _drive(app: Any) -> tuple[int | None, bytes]:
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app({"type": "http", "method": "GET", "path": "/"}, receive, send)
    start = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    return start, b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


def test_timeout_answers_504_and_cancels_the_downstream_call() -> None:
    state = {"cancelled": False}

    async def never_answers(scope: Any, receive: Any, send: Any) -> None:
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            state["cancelled"] = True
            raise

    status, body = asyncio.run(_drive(server.TimeoutMiddleware(never_answers, 0.1)))
    assert status == 504
    assert body == b'{"detail": "request timed out"}'
    assert state["cancelled"] is True


def test_timeout_does_not_truncate_a_response_that_has_started() -> None:
    async def slow_body(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await asyncio.sleep(0.3)  # longer than the timeout
        await send({"type": "http.response.body", "body": b"complete"})

    status, body = asyncio.run(_drive(server.TimeoutMiddleware(slow_body, 0.1)))
    assert (status, body) == (200, b"complete")


def test_timeout_leaves_fast_responses_and_errors_alone() -> None:
    async def ok(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def boom(scope: Any, receive: Any, send: Any) -> None:
        raise RuntimeError("downstream failure")

    assert asyncio.run(_drive(server.TimeoutMiddleware(ok, 5))) == (200, b"ok")
    with pytest.raises(RuntimeError, match="downstream failure"):
        asyncio.run(_drive(server.TimeoutMiddleware(boom, 5)))


# ---------------------------------------------------------------------------
# Connection-level settings
# ---------------------------------------------------------------------------


def test_uvicorn_options_defaults_and_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("uvicorn")
    opts = server.uvicorn_options_from_env()
    assert opts["timeout_keep_alive"] == 5
    assert opts["limit_concurrency"] == 256
    assert opts["timeout_graceful_shutdown"] == 20
    assert "http" in opts  # the header-deadline protocol
    monkeypatch.setenv("REGAUDIT_FHE_LIMIT_CONCURRENCY", "0")
    monkeypatch.setenv("REGAUDIT_FHE_HEADER_TIMEOUT_S", "0")
    monkeypatch.setenv("REGAUDIT_FHE_TIMEOUT_GRACEFUL_SHUTDOWN_S", "0")
    opts = server.uvicorn_options_from_env()
    assert (
        "limit_concurrency" not in opts
        and "http" not in opts
        and "timeout_graceful_shutdown" not in opts
    )
    monkeypatch.setenv("REGAUDIT_FHE_TIMEOUT_KEEP_ALIVE_S", "abc")
    with pytest.raises(server.PolicyError):
        server.uvicorn_options_from_env()


def _serve(protocol: Any) -> tuple[Any, int, threading.Thread]:
    import uvicorn

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    config = uvicorn.Config(
        build_app(config=_cfg()),
        host="127.0.0.1",
        port=port,
        log_level="error",
        lifespan="off",
        http=protocol,
    )
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    return srv, port, thread


def _closed(sock: socket.socket, within: float) -> bool:
    sock.settimeout(within)
    try:
        return sock.recv(1) == b""
    except TimeoutError:
        return False
    except OSError:
        return True


@pytest.mark.parametrize("deadline", [True, False])
def test_header_deadline_closes_stalled_header_connections(deadline: bool) -> None:
    pytest.importorskip("uvicorn")
    protocol = server.header_deadline_protocol(0.5) if deadline else "auto"
    assert protocol is not None
    srv, port, thread = _serve(protocol)
    try:
        silent = socket.create_connection(("127.0.0.1", port))
        partial = socket.create_connection(("127.0.0.1", port))
        partial.sendall(
            b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-Slow: 1\r\n"
        )  # header block never completed
        # a normal request, then a second one on the same kept-alive connection, both still work
        ok = socket.create_connection(("127.0.0.1", port))
        for _ in range(2):
            ok.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            ok.settimeout(3)
            got = b""
            while b'"ok"}' not in got:
                got += ok.recv(4096)
            assert got.startswith(b"HTTP/1.1 200")
        # slow BODY after complete headers is not a header stall: the deadline must not fire
        body = socket.create_connection(("127.0.0.1", port))
        body.sendall(
            b"POST /v1/audit/fairness HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{"
        )
        # stalled-header sockets are closed by the deadline (only when it is installed)
        assert _closed(silent, 2.0) is deadline
        assert _closed(partial, 0.5) is deadline
        assert _closed(body, 0.1) is False
        for s in (silent, partial, ok, body):
            s.close()
    finally:
        srv.should_exit = True
        thread.join(10)
