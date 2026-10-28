"""Bypass attempts against the audit input limits (0.1.1), each with the exact status and body.

The limits are independent: request body size, per-array length, aggregate array elements, nesting depth,
and (for the two super-linear primitives) samples / models. Every attempt below must be answered before
any schema validation or primitive runs, or must be rejected by an existing check with a fixed body.
"""

from __future__ import annotations

import gzip
import json
import logging
import random
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from regaudit_fhe import server
from regaudit_fhe._limits import InputLimits
from regaudit_fhe.cli import SCHEMAS
from regaudit_fhe.server import ServerConfig, build_app

H = {"Authorization": "Bearer t", "Content-Type": "application/json"}
ALL = sorted(SCHEMAS)


def _client(**kw: Any) -> TestClient:
    base: dict[str, Any] = dict(
        api_keys={"t": frozenset({"admin"})},
        dev_mode=False,
        max_body_bytes=1 << 20,
        rate_limit_per_min=10**6,
        request_timeout_s=120.0,
        cors_origins=(),
    )
    base.update(kw)
    return TestClient(build_app(config=ServerConfig(**base), logger=logging.getLogger("t")))


def _refusal(limit: str, maximum: int, detail: str) -> dict[str, Any]:
    return {"detail": detail, "code": "INPUT_LIMIT_EXCEEDED", "limit": limit, "maximum": maximum}


ARRAY = "audit input has an array longer than the configured limit"
TOTAL = "audit input has more elements in total than the configured limit"
DEPTH = "audit input is nested deeper than the configured limit"


def _post(c: TestClient, primitive: str, body: Any, headers: dict[str, str] = H) -> Any:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return c.post(f"/v1/audit/{primitive}", content=raw, headers=headers)


def test_defaults_are_the_documented_ones() -> None:
    lim = InputLimits()
    assert (lim.max_array_elements, lim.max_total_elements, lim.max_depth) == (131072, 524288, 4)
    assert (lim.max_concordance_samples, lim.max_disagreement_models) == (8192, 32)


# ---- the largest legal request of every primitive is still served --------------------------------------

N = 131072  # the owner-decided per-array maximum


def _largest(primitive: str) -> dict[str, Any]:
    rnd = random.Random(7)
    f = [round(rnd.random(), 4) for _ in range(N)]
    bits = [rnd.randint(0, 1) for _ in range(N)]
    lim = InputLimits()
    if primitive == "fairness":
        return {"y_true": bits, "y_pred": bits, "group_a": bits, "group_b": bits}
    if primitive == "drift":
        return {"p": f, "q": f}
    if primitive == "calibration":
        return {"scores": f, "quantiles": f}
    if primitive == "provenance":
        return {"attributions": f, "row_ids": list(range(N)), "n_buckets": 16, "k": 4}
    if primitive == "disagreement":
        polys = [
            [round(rnd.random(), 3) for _ in range(4)] for _ in range(lim.max_disagreement_models)
        ]
        return {"model_polynomials": polys, "test_input": f}
    n = lim.max_concordance_samples
    return {"risk": f[:n], "time": f[:n], "event": bits[:n]}


@pytest.mark.parametrize("primitive", ALL)
def test_largest_legal_request_is_served(primitive: str) -> None:
    body = _largest(primitive)
    c = _client(max_body_bytes=32 << 20)
    r = _post(c, primitive, body)
    assert r.status_code == 200, r.text
    assert r.json()["primitive"] == primitive
    assert set(r.json()["receipt"]) >= {"sha256", "signature_b64", "key_id"}


# ---- bypass attempts ------------------------------------------------------------------------------------


@pytest.mark.parametrize("primitive", ALL)
def test_one_element_over_the_array_limit_is_refused_on_every_route(primitive: str) -> None:
    r = _post(_client(max_body_bytes=8 << 20), primitive, {"x": [0] * (N + 1)})
    assert r.status_code == 413
    assert r.json() == _refusal("max_array_elements", N, ARRAY)


@pytest.mark.parametrize("primitive", ALL)
def test_several_max_size_arrays_hit_the_aggregate_limit_on_every_route(primitive: str) -> None:
    body = {f"a{i}": [0] * N for i in range(5)}  # 5 x 131072 > 4 x 131072
    r = _post(_client(max_body_bytes=8 << 20), primitive, body)
    assert r.status_code == 413
    assert r.json() == _refusal("max_total_elements", 4 * N, TOTAL)


def test_aggregate_limit_counts_arrays_hidden_in_nested_containers() -> None:
    body = {"a": [[0] * N, [0] * N], "b": {"c": [0] * N, "d": [0] * N}, "e": [0]}
    r = _post(_client(max_body_bytes=8 << 20), "fairness", body)
    assert r.status_code == 413
    assert r.json()["limit"] == "max_total_elements"


@pytest.mark.parametrize(
    "body",
    [
        {"a": {"b": {"c": {"d": {}}}}},  # objects, depth 5
        {"a": [[[[1]]]]},  # arrays, depth 6
        {"a": [{"b": [{"c": 1}]}]},  # mixed
    ],
)
def test_nesting_beyond_the_depth_limit_is_refused(body: dict[str, Any]) -> None:
    r = _post(_client(), "drift", body)
    assert r.status_code == 413
    assert r.json() == _refusal("max_json_depth", 4, DEPTH)


def test_very_deep_nesting_is_refused_without_recursion_errors() -> None:
    raw = b'{"a":' + b"[" * 60 + b"]" * 60 + b"}"  # within the parser's own limit of 64
    r = _post(_client(), "drift", raw)
    assert r.status_code == 413
    assert r.json()["limit"] == "max_json_depth"
    r = _post(_client(), "drift", b"[" * 100000 + b"]" * 100000)  # beyond it: a fixed parse refusal
    assert r.status_code == 422
    assert r.json() == {"detail": "request body is not strict JSON"}


def test_a_huge_object_member_count_is_bounded_like_an_array() -> None:
    body = {f"k{i}": 0 for i in range(N + 1)}
    r = _post(_client(max_body_bytes=8 << 20), "drift", body)
    assert r.status_code == 413
    assert r.json() == _refusal("max_array_elements", N, ARRAY)


def test_many_empty_containers_are_cheap_and_end_in_a_schema_refusal() -> None:
    r = _post(_client(max_body_bytes=8 << 20), "drift", {"p": [[]] * 1000, "q": [[]] * 1000})
    assert r.status_code == 422
    assert isinstance(r.json()["detail"], str)


@pytest.mark.parametrize(
    "token",
    [
        b"1" * 5000,
        b"1e999",
        b"-1e999",
        b"1e308",
        b"NaN",
        b"Infinity",
        b"-Infinity",
        b'"1"',
        b"null",
    ],
)
def test_unusual_numerics_never_reach_a_signature(token: bytes) -> None:
    body = b'{"p":[' + token + b',0.5],"q":[0.5,0.5]}'
    r = _post(_client(), "drift", body)
    assert r.status_code in (200, 422), r.text
    if r.status_code == 422:
        assert set(r.json()) == {"detail"}
        assert isinstance(r.json()["detail"], str)
    else:  # a finite number that is legal: the signed report must be finite and verifiable
        assert "NaN" not in r.text
        assert r.json()["receipt"]["sha256"]


@pytest.mark.parametrize("token", [b"1" * 5000, b"1e999", b"NaN", b"Infinity", b'"1"'])
def test_unusual_numerics_are_refused_with_a_fixed_or_schema_body(token: bytes) -> None:
    r = _post(_client(), "drift", b'{"p":[' + token + b',0.5],"q":[0.5,0.5]}')
    assert r.status_code == 422
    body = r.json()
    assert set(body) == {"detail"}
    if token != b'"1"':  # a string-as-number is a schema refusal; the rest never parse
        assert body == {"detail": "request body is not strict JSON"}


def test_overflowing_float_arithmetic_is_not_signed() -> None:
    body = {"model_polynomials": [[1e308] * 4] * 3, "test_input": [1e308]}
    r = _post(_client(), "disagreement", body)
    assert r.status_code == 422
    assert r.json() == {"detail": "the audit input is inconsistent (see the input schema)"}


def test_strings_as_numbers_are_a_schema_refusal() -> None:
    r = _post(_client(), "drift", {"p": ["0.5", "0.5"], "q": [0.5, 0.5]})
    assert r.status_code == 422
    assert set(r.json()) == {"detail"}


def test_duplicate_keys_repeat_to_hide_a_large_array_are_refused() -> None:
    raw = b'{"p":[0.5],"p":' + json.dumps([0] * 1000).encode() + b',"q":[0.5]}'
    r = _post(_client(), "drift", raw)
    assert r.status_code == 422
    assert r.json() == {"detail": "request body is not strict JSON"}


def test_gzip_bodies_are_not_decompressed() -> None:
    bomb = gzip.compress(b'{"p":[' + b"0," * 200000 + b'0],"q":[0]}')
    assert len(bomb) < 10000  # small on the wire, large if (wrongly) expanded
    r = _post(_client(), "drift", bomb, {**H, "Content-Encoding": "gzip"})
    assert r.status_code == 422
    assert r.json() == {"detail": "request body is not strict JSON"}


def test_chunked_body_over_the_element_limit_is_refused_by_the_limit() -> None:
    def chunks() -> Any:
        yield b'{"p":['
        for _ in range(8):
            yield b"0," * 1000
        yield b'0],"q":[0]}'

    c = _client(input_limits=InputLimits(max_array_elements=5000))
    r = c.post("/v1/audit/drift", content=chunks(), headers=H)
    assert r.status_code == 413
    assert r.json() == _refusal("max_array_elements", 5000, ARRAY)


def test_chunked_body_over_the_byte_limit_stops_reading() -> None:
    def chunks() -> Any:
        for _ in range(100):
            yield b" " * 1024

    r = _client(max_body_bytes=4096).post("/v1/audit/drift", content=chunks(), headers=H)
    assert r.status_code == 413
    assert r.json() == {"detail": "request body exceeds limit 4096 bytes"}


def test_concordance_and_disagreement_cost_limits() -> None:
    c = _client(max_body_bytes=8 << 20)
    n = InputLimits().max_concordance_samples
    r = _post(
        c, "concordance", {"risk": [0.5] * (n + 1), "time": [1.0] * (n + 1), "event": [1] * (n + 1)}
    )
    assert r.status_code == 413
    assert r.json() == _refusal(
        "max_concordance_samples", n, "concordance input has more samples than the configured limit"
    )
    m = InputLimits().max_disagreement_models
    r = _post(
        c,
        "disagreement",
        {"model_polynomials": [[0.1, 0.2, 0.3, 0.4]] * (m + 1), "test_input": [0.5]},
    )
    assert r.status_code == 413
    assert r.json() == _refusal(
        "max_disagreement_models", m, "disagreement input has more models than the configured limit"
    )
    # the cost limits belong to their own primitive only
    r = _post(c, "drift", {"p": [0.5] * (n + 1), "q": [0.5] * (n + 1)})
    assert r.status_code == 200


def test_verify_route_bounds_nesting_and_size() -> None:
    from regaudit_fhe.reports import Signer
    from regaudit_fhe.trust import TrustStore

    signer = Signer.generate(issuer="acme", key_id="ka")
    store = TrustStore.from_dict(
        {
            "entries": {
                "ka": {
                    "issuer": "acme",
                    "public_key_pem": signer.public_key_pem(),
                    "status": "active",
                }
            }
        }
    )
    keys = {"t": frozenset({"audit:verify"})}
    deep = b'{"envelope":' + b"[" * 200 + b"]" * 200 + b"}"
    r = _client(api_keys=keys, trust_store=store).post("/v1/verify", content=deep, headers=H)
    assert r.status_code == 422
    assert r.json() == {"detail": "malformed envelope"}
    small = _client(api_keys=keys, trust_store=store, max_body_bytes=1000)
    r = small.post("/v1/verify", content=b" " * 5000, headers=H)
    assert r.status_code == 413
    assert r.json() == {"detail": "request body exceeds limit 1000 bytes"}


def test_no_batch_or_alternative_route_accepts_audit_input() -> None:
    c = _client()
    for path in ("/v1/audit", "/v1/audit/", "/v1/batch", "/v1/audit/drift/extra"):
        assert c.post(path, content=b"{}", headers=H).status_code in (404, 405)


# ---- invalid settings refuse to start -------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        {"max_array_elements": 0},
        {"max_total_elements": -1},
        {"max_depth": 0},
        {"max_concordance_samples": 0},
        {"max_disagreement_models": True},
    ],
)
def test_embedding_cannot_disable_a_limit_with_a_non_positive_value(bad: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        InputLimits(**bad)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("REGAUDIT_FHE_MAX_CONCURRENT_AUDITS", "0"),
        ("REGAUDIT_FHE_MAX_CONCURRENT_AUDITS", "two"),
        ("REGAUDIT_FHE_MAX_QUEUED_AUDITS", "-4"),
        ("REGAUDIT_FHE_MAX_ARRAY_ELEMENTS", "-1"),
        ("REGAUDIT_FHE_MAX_JSON_DEPTH", "1"),
        ("REGAUDIT_FHE_MAX_CONCORDANCE_SAMPLES", "0"),
        ("REGAUDIT_FHE_MAX_DISAGREEMENT_MODELS", "0"),
        ("REGAUDIT_FHE_LIMIT_CONCURRENCY", "-1"),
        ("REGAUDIT_FHE_HEADER_TIMEOUT_S", "inf"),
        ("REGAUDIT_FHE_TIMEOUT_KEEP_ALIVE_S", "abc"),
    ],
)
def test_invalid_resource_settings_refuse_to_start(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(server.PolicyError):
        server.load_config_from_env()
        server.uvicorn_options_from_env()


# ---- the shared in-flight body budget -------------------------------------------------------------------


def test_ingress_budget_unit() -> None:
    from regaudit_fhe._limits import IngressBudget

    b = IngressBudget(100)
    assert b.charge(60) and not b.charge(41) and b.charge(40)
    b.release(100)
    assert b.held == 0
    with pytest.raises(ValueError, match="positive integer"):
        IngressBudget(0)


def test_stalled_large_bodies_cannot_buffer_more_than_the_shared_budget() -> None:
    import asyncio

    app = build_app(
        config=ServerConfig(
            api_keys={"t": frozenset({"admin"})},
            dev_mode=False,
            max_body_bytes=1000,
            max_inflight_body_bytes=1000,
            rate_limit_per_min=10**6,
            request_timeout_s=30.0,
            cors_origins=(),
        )
    )

    def scope() -> dict[str, Any]:
        return {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
            "scheme": "http", "path": "/v1/audit/drift", "raw_path": b"/v1/audit/drift",
            "query_string": b"", "root_path": "",
            "headers": [(b"host", b"t"), (b"content-type", b"application/json"),
                        (b"authorization", b"Bearer t")],
            "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 80),
        }  # fmt: skip

    async def go() -> tuple[int, bytes, dict[str, str]]:
        first_chunk_sent = asyncio.Event()
        stall = asyncio.Event()

        async def recv_a() -> dict[str, Any]:
            if not first_chunk_sent.is_set():
                first_chunk_sent.set()
                return {"type": "http.request", "body": b" " * 700, "more_body": True}
            await stall.wait()
            return {"type": "http.disconnect"}

        async def send_a(message: dict[str, Any]) -> None:
            return None

        task_a = asyncio.create_task(app(scope(), recv_a, send_a))
        await first_chunk_sent.wait()
        await asyncio.sleep(0.05)  # A now holds 700 of the 1000 budgeted bytes

        sent: list[dict[str, Any]] = []
        chunks = iter([{"type": "http.request", "body": b" " * 700, "more_body": False}])

        async def recv_b() -> dict[str, Any]:
            return next(chunks, {"type": "http.disconnect"})

        async def send_b(message: dict[str, Any]) -> None:
            sent.append(message)

        await app(scope(), recv_b, send_b)
        stall.set()
        task_a.cancel()
        start = next(m for m in sent if m["type"] == "http.response.start")
        body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        return start["status"], body, {k.decode(): v.decode() for k, v in start["headers"]}

    status_code, body, headers = asyncio.run(go())
    assert status_code == 503
    assert headers["retry-after"] == "1"
    assert json.loads(body) == {
        "detail": "the server is at capacity; retry later",
        "code": "SERVER_BUSY",
        "operation": "audit",
        "reason": "ingress_budget",
    }


def test_budget_smaller_than_the_body_limit_refuses_to_start() -> None:
    with pytest.raises(server.PolicyError):
        build_app(
            config=ServerConfig(
                api_keys={}, dev_mode=True, max_body_bytes=2000, max_inflight_body_bytes=1000,
                rate_limit_per_min=10, request_timeout_s=30.0, cors_origins=(),
            )
        )  # fmt: skip


def test_invalid_budget_environment_refuses_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    for bad in ("0", "-5", "lots"):
        monkeypatch.setenv("REGAUDIT_FHE_MAX_INFLIGHT_BODY_BYTES", bad)
        with pytest.raises(server.PolicyError):
            server.load_config_from_env()
