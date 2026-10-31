"""Availability hardening over REAL sockets: uvicorn in a subprocess, raw socket clients.

AI-assisted engineering tests, not an audit. Each test starts ``regaudit-fhe serve`` on a loopback ephemeral
port (the same code path and uvicorn options as production), talks to it with plain sockets and reads what
comes back. Deadlines are shortened through the documented environment variables; sizes are small.

``*_control`` tests are positive controls: a legal request must keep working. The tests assert the behaviour
of the hardened server; they use only environment settings, so the same file can be pointed at an older source
tree (``REGAUDIT_QUAL_SRC=<dir containing regaudit_fhe/>``) to show which assertions fail without the change.
``REGAUDIT_QUAL_EVIDENCE=<file>`` appends one JSON line of measurements per scenario.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import numpy as np
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

import regaudit_fhe as rf
from regaudit_fhe.report_v2 import envelope_v2

GOOD = {
    "y_true": [1, 0, 1, 0],
    "y_pred": [1, 0, 0, 0],
    "group_a": [1, 1, 0, 0],
    "group_b": [0, 0, 1, 1],
}
PATH = "/v1/audit/fairness"
MAX_BODY = 1 << 20
IDLE_S = 1.0
REQUEST_TIMEOUT_S = 6.0
STALL_BYTES = 900_000  # leaves ~148 KiB of the 1 MiB in-flight budget for everybody else
LEGAL_BYTES = 300_000


def _evidence(name: str, **fields: Any) -> None:
    target = os.environ.get("REGAUDIT_QUAL_EVIDENCE")
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"scenario": name, **fields}) + "\n")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Server:
    def __init__(self, port: int, proc: subprocess.Popen[bytes], log: Path) -> None:
        self.port = port
        self.proc = proc
        self.log = log

    def log_text(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace")


def _start(tmp_path: Path, env_extra: dict[str, str]) -> Server:
    port = _free_port()
    env = dict(os.environ, REGAUDIT_FHE_DEV_MODE="1", REGAUDIT_FHE_RATE_LIMIT_PER_MIN="100000000")
    env.update(
        REGAUDIT_FHE_MAX_BODY_BYTES=str(MAX_BODY),
        REGAUDIT_FHE_MAX_INFLIGHT_BODY_BYTES=str(MAX_BODY),
        REGAUDIT_FHE_REQUEST_TIMEOUT_S=str(REQUEST_TIMEOUT_S),
        REGAUDIT_FHE_BODY_IDLE_TIMEOUT_S=str(IDLE_S),
    )
    env.update(env_extra)
    src = os.environ.get("REGAUDIT_QUAL_SRC")
    if src:
        env["PYTHONPATH"] = src
    log = tmp_path / f"server-{port}.log"
    code = (
        "import sys, regaudit_fhe; sys.stderr.write('SRC=' + regaudit_fhe.__file__ + '\\n'); "
        "sys.stderr.flush(); from regaudit_fhe.cli import main; raise SystemExit(main())"
    )
    with open(log, "wb") as fh:
        proc = subprocess.Popen(  # noqa: S603
            [
                sys.executable, "-c", code, "serve", "--host", "127.0.0.1", "--port", str(port),
                "--allow-self-signed",
            ],
            env=env,
            stdout=fh,
            stderr=fh,
        )  # fmt: skip
    server = Server(port, proc, log)
    for _ in range(200):
        try:
            if _get(port, "/healthz")[0] == 200:
                return server
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("server did not start: " + server.log_text()[-2000:])


@pytest.fixture
def make_server(tmp_path: Path) -> Iterator[Any]:
    started: list[Server] = []

    def make(**env: str) -> Server:
        s = _start(tmp_path, env)
        started.append(s)
        return s

    yield make
    for s in started:
        s.proc.terminate()
        try:
            s.proc.wait(10)
        except subprocess.TimeoutExpired:
            s.proc.kill()


def _recv_response(sock: socket.socket, timeout: float) -> tuple[int | None, bytes]:
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(1 << 16)
            if not chunk:
                break
            data += chunk
            head, sep, rest = data.partition(b"\r\n\r\n")
            if sep:
                length = None
                for line in head.split(b"\r\n")[1:]:
                    k, _, v = line.partition(b":")
                    if k.strip().lower() == b"content-length":
                        length = int(v)
                if length is not None and len(rest) >= length:
                    break
    except (TimeoutError, OSError):
        pass
    if not data.startswith(b"HTTP/"):
        return None, b""
    head, _, body = data.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), body


def _request_bytes(path: str, body: bytes, method: str = "POST") -> bytes:
    return (
        f"{method} {path} HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body


def _get(port: int, path: str, timeout: float = 3.0) -> tuple[int | None, bytes]:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n".encode())
        return _recv_response(s, timeout)


def _post(
    port: int, path: str, body: bytes, timeout: float = 20.0
) -> tuple[int | None, bytes, float]:
    t0 = time.perf_counter()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(_request_bytes(path, body))
        status, data = _recv_response(s, timeout)
    return status, data, time.perf_counter() - t0


def _padded(n: int) -> bytes:
    raw = json.dumps(GOOD).encode()
    return raw + b" " * (n - len(raw))


def _open_partial(port: int, nbytes: int, declared: int | None = None) -> socket.socket:
    """Headers declaring ``declared`` bytes, then ``nbytes`` of body, then nothing."""
    wire = _request_bytes(PATH, _padded(declared or nbytes + 100))
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(wire[: wire.index(b"\r\n\r\n") + 4 + nbytes])
    return s


def _wait_until_budget_is_held(port: int) -> None:
    """The partial body is charged once the server has read it; poll with a legal request that cannot fit."""
    deadline = time.time() + 5
    while time.time() < deadline:
        if _post(port, PATH, _padded(LEGAL_BYTES), 10)[0] == 503:
            return
        time.sleep(0.05)
    raise AssertionError("the stalled body never took the in-flight budget")


def _recovers(port: int, within: float) -> float | None:
    """Seconds until a legal LEGAL_BYTES request is answered 200 again, or None."""
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < within:
        if _post(port, PATH, _padded(LEGAL_BYTES), 10)[0] == 200:
            return time.perf_counter() - t0
        time.sleep(0.1)
    return None


# ---------------------------------------------------------------------------
# positive controls
# ---------------------------------------------------------------------------


def test_legal_audit_and_both_envelope_versions_still_work_control(make_server: Any) -> None:
    srv = make_server()
    status, data, _ = _post(srv.port, PATH, json.dumps(GOOD).encode())
    assert status == 200 and json.loads(data)["primitive"] == "fairness"
    # a large legal body (1 MiB, whitespace padded) is read in full
    assert _post(srv.port, PATH, _padded(MAX_BODY - 10))[0] == 200
    signer = rf.Signer.generate(issuer="acme", key_id="acme-1")
    rep = rf.audit_fairness(*(np.array(GOOD[k], float) for k in GOOD))
    v1 = rf.envelope("fairness", rep, signer=signer).to_dict()
    v2 = envelope_v2("fairness", rep, signer=signer, deployment_id="d").to_dict()
    for env in (v1, v2):
        status, data, _ = _post(srv.port, "/v1/verify", json.dumps({"envelope": env}).encode())
        assert status == 200, data
        body = json.loads(data)
        assert body["integrity_valid"] is True, (
            body
        )  # a self-signed envelope: verified, not trusted
        assert body["trust_status"] == "SELF_SIGNED_ONLY", body
    _evidence("controls", source=srv.log_text().splitlines()[0])


# ---------------------------------------------------------------------------
# stalled body: 408, recovery of the in-flight budget
# ---------------------------------------------------------------------------


def test_stalled_partial_body_is_cut_off_with_408_and_the_budget_recovers(
    make_server: Any,
) -> None:
    srv = make_server()
    assert _post(srv.port, PATH, _padded(LEGAL_BYTES))[0] == 200  # control: fits while idle
    stalled = _open_partial(srv.port, STALL_BYTES, declared=STALL_BYTES + 100)
    try:
        _wait_until_budget_is_held(srv.port)  # budget exhaustion: a legal request is refused 503
        t0 = time.perf_counter()
        status, data = _recv_response(stalled, REQUEST_TIMEOUT_S + 4)
        cut_after = time.perf_counter() - t0
        recovered = _recovers(srv.port, 10)
        _evidence(
            "stalled_body",
            cut_status=status,
            cut_after_s=round(cut_after, 2),
            recovered_after_s=None if recovered is None else round(recovered, 2),
            body=data.decode(errors="replace")[:200],
        )
        assert status == 408, (status, data)
        assert json.loads(data)["code"] == "BODY_TIMEOUT"
        assert cut_after < IDLE_S + 2.5
        assert recovered is not None and recovered < 1.0  # recovered as soon as the 408 released it
    finally:
        stalled.close()
    assert _get(srv.port, "/healthz")[0] == 200


def test_a_body_that_never_starts_is_also_cut_off(make_server: Any) -> None:
    srv = make_server()
    s = socket.create_connection(("127.0.0.1", srv.port), timeout=10)
    wire = _request_bytes(PATH, b"x" * 1000)
    s.sendall(wire[: wire.index(b"\r\n\r\n") + 4])
    t0 = time.perf_counter()
    status, _ = _recv_response(s, REQUEST_TIMEOUT_S + 4)
    s.close()
    _evidence("body_never_starts", status=status, after_s=round(time.perf_counter() - t0, 2))
    assert status == 408 and time.perf_counter() - t0 < IDLE_S + 2.5


def test_idle_deadline_can_be_switched_off(make_server: Any) -> None:
    srv = make_server(REGAUDIT_FHE_BODY_IDLE_TIMEOUT_S="0", REGAUDIT_FHE_REQUEST_TIMEOUT_S="3")
    stalled = _open_partial(srv.port, 1000)
    t0 = time.perf_counter()
    status, _ = _recv_response(stalled, 10)
    stalled.close()
    assert status == 504 and time.perf_counter() - t0 >= 2.5  # only the request timeout applies


# ---------------------------------------------------------------------------
# disconnects
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reset", [False, True], ids=["fin", "rst"])
def test_client_that_disconnects_mid_body_releases_the_budget_at_once(
    make_server: Any, reset: bool
) -> None:
    srv = make_server(
        REGAUDIT_FHE_BODY_IDLE_TIMEOUT_S="0"
    )  # the deadline must not be what saves us
    stalled = _open_partial(srv.port, STALL_BYTES)
    _wait_until_budget_is_held(srv.port)
    if reset:
        stalled.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    t0 = time.perf_counter()
    stalled.close()
    recovered = _recovers(srv.port, REQUEST_TIMEOUT_S - 2)
    log = srv.log_text()
    _evidence(
        "disconnect_" + ("rst" if reset else "fin"),
        recovered_after_s=None if recovered is None else round(recovered, 2),
        traceback_in_log="Traceback" in log,
        wall_s=round(time.perf_counter() - t0, 2),
    )
    assert recovered is not None and recovered < 2.0
    assert "Traceback" not in log and "Exception in ASGI application" not in log, log[-3000:]
    assert _get(srv.port, "/healthz")[0] == 200


def test_many_abandoned_clients_do_not_leak_budget(make_server: Any) -> None:
    srv = make_server()
    for i in range(20):
        s = _open_partial(srv.port, 40_000)
        if i % 2:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.close()
    assert _recovers(srv.port, 4) is not None
    assert _post(srv.port, PATH, _padded(MAX_BODY - 10))[0] == 200  # the whole budget is available
    assert "Traceback" not in srv.log_text()


# ---------------------------------------------------------------------------
# slow drip: what the idle deadline does NOT bound
# ---------------------------------------------------------------------------


def test_steady_drip_is_not_cut_by_the_idle_deadline_only_by_the_request_timeout(
    make_server: Any,
) -> None:
    srv = make_server(REGAUDIT_FHE_REQUEST_TIMEOUT_S="4")
    body = _padded(STALL_BYTES + 100)
    wire = _request_bytes(PATH, body)
    head = wire[: wire.index(b"\r\n\r\n") + 4]
    s = socket.create_connection(("127.0.0.1", srv.port), timeout=10)
    s.sendall(wire[: len(head) + STALL_BYTES])
    t0 = time.perf_counter()
    sent = len(head) + STALL_BYTES
    status = None
    while time.perf_counter() - t0 < 12 and sent < len(wire):
        try:
            s.sendall(wire[sent : sent + 1])
            sent += 1
        except OSError:
            break
        s.settimeout(0.4)  # one byte every ~0.4 s, well inside the 1 s idle deadline
        try:
            data = s.recv(65536)
            if data:
                status = int(data.split(b" ")[1])
                break
        except (TimeoutError, OSError):
            pass
    took = time.perf_counter() - t0
    s.close()
    _evidence("drip", status=status, after_s=round(took, 2))
    assert status == 504, status  # the request timeout, not the 1 s idle deadline
    assert 3.0 < took < 6.5
    assert _recovers(srv.port, 6) is not None


# ---------------------------------------------------------------------------
# error amplification and verify structure
# ---------------------------------------------------------------------------


def test_validation_error_response_is_not_amplified(make_server: Any) -> None:
    srv = make_server()
    n = 100_000
    bad = json.dumps({**GOOD, "y_true": ["a"] * n}).encode()
    status, data, took = _post(srv.port, PATH, bad, 60)
    _evidence(
        "422_amplification",
        request_bytes=len(bad),
        status=status,
        response_bytes=len(data),
        seconds=round(took, 2),
    )
    assert status == 422
    assert len(data) < 4096, len(data)
    # control: a short validation message is unchanged and a legal request still works
    status, data, _ = _post(srv.port, PATH, json.dumps({"y_true": [1, 0]}).encode())
    assert status == 422 and b"truncated" not in data
    assert _post(srv.port, PATH, json.dumps(GOOD).encode())[0] == 200


def test_verify_refuses_a_huge_flat_or_deep_body_but_serves_genuine_envelopes(
    make_server: Any,
) -> None:
    srv = make_server()
    signer = rf.Signer.generate(issuer="acme", key_id="acme-1")
    rep = rf.audit_fairness(*(np.array(GOOD[k], float) for k in GOOD))
    env = rf.envelope("fairness", rep, signer=signer).to_dict()
    assert _post(srv.port, "/v1/verify", json.dumps({"envelope": env}).encode())[0] == 200
    flat = json.dumps({"envelope": {**env, "result": {"x": [1] * 300_000}}}).encode()
    deep = (
        b'{"envelope": {"result": ' + b"[" * 2000 + b"]" * 2000 + b"}}"
    )  # within the body limit, far beyond depth 16
    out = {}
    for name, body in (("flat", flat), ("deep", deep)):
        status, data, took = _post(srv.port, "/v1/verify", body, 60)
        out[name] = (status, data.decode(errors="replace")[:80], round(took, 3))
    _evidence("verify_structure", **{k: list(v) for k, v in out.items()})
    for name in out:
        assert out[name][0] == 422, out
        assert json.loads(_post(srv.port, "/v1/verify", flat if name == "flat" else deep)[1]) == {
            "detail": "malformed envelope"
        }
    assert _post(srv.port, "/v1/verify", json.dumps({"envelope": env}).encode())[0] == 200
