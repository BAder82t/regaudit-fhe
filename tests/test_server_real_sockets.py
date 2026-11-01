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
IDLE_S = 3.0  # the idle deadline used by most tests; assertions on it are one-sided (never a tight upper bound)
REQUEST_TIMEOUT_S = 20.0  # far above IDLE_S so that a 408 can only come from the idle deadline
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


def _has_response(sock: socket.socket) -> bool:
    """True if the server has already written something to this (stalled) client connection."""
    sock.setblocking(False)
    try:
        return bool(sock.recv(1, socket.MSG_PEEK))
    except BlockingIOError:
        return False
    except OSError:
        return True
    finally:
        sock.setblocking(True)


def _hold_budget(srv: Server, opener: Any, attempts: int = 8) -> socket.socket:
    """Open a stalled upload with ``opener()`` and return it once it demonstrably holds the in-flight budget.

    The in-flight budget is first come, first served: a probe request that arrives while the stalled body is
    still being read can take budget the stalled request then fails to get, and it is the STALLED request that
    is refused (503, written to the stalled connection). That is correct behaviour and a race in the test, so
    the signal is two-sided and the attempt is repeated: the attempt succeeds when a probe that cannot fit is
    refused 503 while the stalled connection has received no answer; it is abandoned (and the budget awaited
    free) when the stalled connection got an answer first. Every probe is recorded for the failure message.
    """
    history: list[Any] = []
    for attempt in range(attempts):
        stalled = opener()
        t0 = time.perf_counter()
        probes: list[tuple[float, int | None]] = []
        while time.perf_counter() - t0 < 20:
            time.sleep(0.15)
            status, _, _ = _post(srv.port, PATH, _padded(LEGAL_BYTES), 30)
            probes.append((round(time.perf_counter() - t0, 2), status))
            if _has_response(stalled):
                break  # the stalled request itself lost the race, or was cut off
            if status == 503:
                return stalled
        history.append((attempt, probes[:4], probes[-2:], _has_response(stalled)))
        stalled.close()
        _recovers(srv.port, 20)
    raise AssertionError(
        f"no attempt held the in-flight budget; attempts={history}; log tail={srv.log_text()[-800:]}"
    )


def _full_budget_returns(port: int, within: float) -> list[Any]:
    """Poll with a legal body that needs the WHOLE in-flight budget until it is answered 200.

    Abandoned clients leave bytes in the kernel buffers that the server still reads (and charges) before it
    sees the end of the connection, so the budget drains in a short, load-dependent time and then stays free.
    Returns the (seconds, status) probes; the last one is 200 when the budget came back.
    """
    probes: list[Any] = []
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < within:
        status = _post(port, PATH, _padded(MAX_BODY - 10), 60)[0]
        probes.append((round(time.perf_counter() - t0, 2), status))
        if status == 200:
            break
        time.sleep(0.2)
    return probes


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
    stalled = _hold_budget(  # budget exhaustion: a legal request is refused 503 while it is held
        srv, lambda: _open_partial(srv.port, STALL_BYTES, declared=STALL_BYTES + 100)
    )
    try:
        t0 = time.perf_counter()
        status, data = _recv_response(stalled, REQUEST_TIMEOUT_S + 4)
        cut_after = time.perf_counter() - t0
        recovered = _recovers(srv.port, 20)
        _evidence(
            "stalled_body",
            cut_status=status,
            cut_after_s=round(cut_after, 2),
            recovered_after_s=None if recovered is None else round(recovered, 2),
            body=data.decode(errors="replace")[:200],
        )
        assert status == 408, (status, data)
        assert json.loads(data)["code"] == "BODY_TIMEOUT"
        assert cut_after < REQUEST_TIMEOUT_S  # the 408, not the request timeout, ended it
        assert recovered is not None and recovered < 5.0  # the 408 released the budget
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
    assert status == 408 and time.perf_counter() - t0 < REQUEST_TIMEOUT_S


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
    stalled = _hold_budget(srv, lambda: _open_partial(srv.port, STALL_BYTES))
    if reset:
        stalled.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    t0 = time.perf_counter()
    stalled.close()
    recovered = _recovers(srv.port, 15)
    log = srv.log_text()
    _evidence(
        "disconnect_" + ("rst" if reset else "fin"),
        recovered_after_s=None if recovered is None else round(recovered, 2),
        traceback_in_log="Traceback" in log,
        wall_s=round(time.perf_counter() - t0, 2),
    )
    assert recovered is not None
    assert "Traceback" not in log and "Exception in ASGI application" not in log, log[-3000:]
    assert _get(srv.port, "/healthz")[0] == 200


def test_many_abandoned_clients_do_not_leak_budget(make_server: Any) -> None:
    srv = make_server()
    for i in range(20):
        s = _open_partial(srv.port, 40_000)
        if i % 2:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.close()
    probes = _full_budget_returns(srv.port, 60)
    assert probes[-1][1] == 200, probes  # all of the budget came back; a leak would never recover
    assert "Traceback" not in srv.log_text()


# ---------------------------------------------------------------------------
# slow drip: what the idle deadline does NOT bound
# ---------------------------------------------------------------------------


def test_steady_drip_is_not_cut_by_the_idle_deadline_only_by_the_request_timeout(
    make_server: Any,
) -> None:
    srv = make_server(REGAUDIT_FHE_REQUEST_TIMEOUT_S="6")
    body = _padded(STALL_BYTES + 100)
    wire = _request_bytes(PATH, body)
    head = wire[: wire.index(b"\r\n\r\n") + 4]
    s = socket.create_connection(("127.0.0.1", srv.port), timeout=10)
    s.sendall(wire[: len(head) + STALL_BYTES])
    t0 = time.perf_counter()
    sent = len(head) + STALL_BYTES
    status = None
    while time.perf_counter() - t0 < 25 and sent < len(wire):
        try:
            s.sendall(wire[sent : sent + 1])
            sent += 1
        except OSError:
            break
        s.settimeout(0.4)  # one byte every ~0.4 s, well inside the 3 s idle deadline
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
    assert status == 504, status  # the request timeout (6 s), not the 3 s idle deadline
    assert took >= IDLE_S + 1  # it outlived the idle deadline, so the deadline did not end it
    assert _recovers(srv.port, 20) is not None


# ---------------------------------------------------------------------------
# error amplification and verify structure
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# owner-required real-socket cases (0.2.1 qualification)
# ---------------------------------------------------------------------------


def _head_end(wire: bytes) -> int:
    return wire.index(b"\r\n\r\n") + 4


def _trickle(
    port: int,
    wire: bytes,
    *,
    pieces: int,
    gap: float,
    first_gap: float | None = None,
    limit: float = 60.0,
) -> tuple[int | None, bytes, float]:
    """Send the headers, then the body in ``pieces`` equal parts, waiting ``gap`` s between them.

    ``first_gap`` is the wait between the headers and the first part (default: ``gap``). While waiting the
    client listens, so a response (for instance a 408) is read the moment it arrives.
    """
    head, body = wire[: _head_end(wire)], wire[_head_end(wire) :]
    size = -(-len(body) // pieces)
    parts = [body[i : i + size] for i in range(0, len(body), size)]
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    t0 = time.perf_counter()
    answered: bytes = b""

    def wait(seconds: float) -> bool:
        nonlocal answered
        s.settimeout(seconds)
        try:
            data = s.recv(1 << 16)
        except (TimeoutError, OSError):
            return False
        answered = data
        return True

    try:
        s.sendall(head)
        if wait(gap if first_gap is None else first_gap):
            return _finish(s, answered, t0)
        for i, part in enumerate(parts):
            if time.perf_counter() - t0 > limit:
                break
            try:
                s.sendall(part)
            except OSError:
                break
            if i < len(parts) - 1 and wait(gap):
                return _finish(s, answered, t0)
        status, rest = _recv_response(s, 30)
        return status, rest, time.perf_counter() - t0
    finally:
        s.close()


def _finish(s: socket.socket, first: bytes, t0: float) -> tuple[int | None, bytes, float]:
    data = first
    s.settimeout(2)
    try:
        while True:
            more = s.recv(1 << 16)
            if not more:
                break
            data += more
    except (TimeoutError, OSError):
        pass
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head.startswith(b"HTTP/") else None
    return status, body, time.perf_counter() - t0


def _genuine_envelopes() -> list[tuple[str, str, dict[str, Any]]]:
    rng = np.random.default_rng(20261031)
    signer = rf.Signer.generate(issuer="acme", key_id="acme-1")
    n = 2048
    reports = {
        "fairness": rf.audit_fairness(*(np.array(GOOD[k], float) for k in GOOD)),
        # the widest provenance result that is legal: k <= n_buckets <= 1024
        "provenance": rf.audit_provenance(
            np.abs(rng.standard_normal(n)), np.arange(n), n_buckets=1024, k=1024
        ),
        "concordance": rf.audit_concordance(
            rng.standard_normal(32),
            np.abs(rng.standard_normal(32)) * 100,
            (rng.uniform(size=32) < 0.7).astype(float),
        ),
        "calibration": rf.audit_calibration(rng.uniform(size=8), np.full(8, 0.5)),
        "drift": rf.audit_drift(np.eye(16)[2], np.eye(16)[12], drift_threshold=0.005),
        "disagreement": rf.audit_disagreement(
            [(0, 1, 0, 0), (0, 0.5, 0, 0), (0, 1.5, 0, 0)],
            np.linspace(-0.5, 0.5, 32),
            threshold=0.01,
        ),
    }
    out = []
    for name, rep in reports.items():
        out.append((name, "v1", rf.envelope(name, rep, signer=signer).to_dict()))
        out.append((name, "v2", envelope_v2(name, rep, signer=signer, deployment_id="d").to_dict()))
    return out


def _array_elements(obj: Any) -> int:
    """Sum of the lengths of every JSON array in ``obj`` (the quantity REGAUDIT_FHE_VERIFY_MAX_ELEMENTS caps)."""
    if isinstance(obj, dict):
        return sum(_array_elements(v) for v in obj.values())
    if isinstance(obj, list):
        return len(obj) + sum(_array_elements(v) for v in obj)
    return 0


def _dump(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


# (1) a VALID slow upload must still succeed -----------------------------------------------------


def test_valid_slow_uploads_that_outlast_the_idle_timeout_still_succeed_control(
    make_server: Any,
) -> None:
    srv = make_server(REGAUDIT_FHE_BODY_IDLE_TIMEOUT_S="3", REGAUDIT_FHE_REQUEST_TIMEOUT_S="60")
    # legal 1 MiB audit: 6 parts, 1 s apart, ~5 s in all (longer than the 3 s idle timeout, gaps well under it;
    # the same property was also shown once with the real 10 s default and 2 s gaps, 16 s in all)
    audit = _request_bytes(PATH, _padded(MAX_BODY - 10))
    status, data, took = _trickle(srv.port, audit, pieces=6, gap=1.0)
    _evidence("slow_valid_audit", status=status, seconds=round(took, 1))
    assert status == 200 and json.loads(data)["primitive"] == "fairness"
    assert took > 3.5
    signer = rf.Signer.generate(issuer="acme", key_id="acme-1")
    rep = rf.audit_fairness(*(np.array(GOOD[k], float) for k in GOOD))
    env = rf.envelope("fairness", rep, signer=signer).to_dict()
    verify = _request_bytes("/v1/verify", _dump({"envelope": env}))
    status, data, took = _trickle(srv.port, verify, pieces=5, gap=1.0)
    _evidence("slow_valid_verify", status=status, seconds=round(took, 1))
    assert status == 200 and json.loads(data)["integrity_valid"] is True and took > 3.5


# (2) idle-timeout boundary ---------------------------------------------------------------------


def test_idle_timeout_boundary_gap_under_succeeds_gap_over_gets_408(make_server: Any) -> None:
    srv = make_server(REGAUDIT_FHE_BODY_IDLE_TIMEOUT_S="4", REGAUDIT_FHE_REQUEST_TIMEOUT_S="40")
    wire = _request_bytes(PATH, _padded(4000))
    under = _trickle(srv.port, wire, pieces=3, gap=2.0)
    over = _trickle(srv.port, wire, pieces=3, gap=6.0)
    # headers sent, then the body only after a pause
    under_h = _trickle(srv.port, wire, pieces=1, gap=2.0)
    over_h = _trickle(srv.port, wire, pieces=1, gap=6.0)
    _evidence(
        "idle_boundary_idle4s",
        gap_2_0=under[0],
        gap_6_0=over[0],
        headers_then_2_0=under_h[0],
        headers_then_6_0=over_h[0],
    )
    assert under[0] == 200
    assert over[0] == 408 and json.loads(over[1])["code"] == "BODY_TIMEOUT"
    assert under_h[0] == 200
    assert over_h[0] == 408


def test_with_the_idle_timeout_off_a_long_pause_is_allowed_as_before(make_server: Any) -> None:
    srv = make_server(REGAUDIT_FHE_BODY_IDLE_TIMEOUT_S="0", REGAUDIT_FHE_REQUEST_TIMEOUT_S="12")
    wire = _request_bytes(PATH, _padded(4000))
    status, _, took = _trickle(srv.port, wire, pieces=2, gap=3.0)
    _evidence("idle_off_gap_3s", status=status, seconds=round(took, 1))
    assert status == 200 and took > 2.9


# (3) chunked transfer-encoding upload that stalls / disconnects ---------------------------------


def _chunked_head() -> bytes:
    return (
        f"POST {PATH} HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\n"
        "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    ).encode()


def _chunk(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode() + data + b"\r\n"


def test_chunked_upload_works_and_a_stalled_one_is_cut_off_and_recovers(make_server: Any) -> None:
    srv = make_server()
    body = _padded(LEGAL_BYTES)
    with socket.create_connection(("127.0.0.1", srv.port), timeout=10) as s:  # control
        s.sendall(_chunked_head())
        for i in range(0, len(body), 50_000):
            s.sendall(_chunk(body[i : i + 50_000]))
        s.sendall(b"0\r\n\r\n")
        assert _recv_response(s, 20)[0] == 200

    def open_stalled_chunked(port: int) -> socket.socket:
        c = socket.create_connection(("127.0.0.1", port), timeout=10)
        c.sendall(_chunked_head() + _chunk(_padded(STALL_BYTES)))  # a chunk, no terminator, silence
        return c

    stalled = _hold_budget(srv, lambda: open_stalled_chunked(srv.port))
    try:
        t0 = time.perf_counter()
        status, _ = _recv_response(stalled, REQUEST_TIMEOUT_S + 4)
        cut = time.perf_counter() - t0
        recovered = _recovers(srv.port, 20)
        _evidence(
            "chunked_stall",
            status=status,
            cut_after_s=round(cut, 2),
            recovered_after_s=None if recovered is None else round(recovered, 2),
        )
        assert status == 408 and cut < REQUEST_TIMEOUT_S
        assert recovered is not None and recovered < 5.0
    finally:
        stalled.close()
    # a chunked upload that disconnects: budget freed, no traceback. The idle deadline is off here so
    # that only the disconnect can free the budget (and the held-budget probe has no time window).
    srv = make_server(REGAUDIT_FHE_BODY_IDLE_TIMEOUT_S="0")
    s = _hold_budget(srv, lambda: open_stalled_chunked(srv.port))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
    assert _recovers(srv.port, 15) is not None
    assert "Traceback" not in srv.log_text()


def test_twenty_abandoned_mid_body_clients_then_a_full_legal_body_succeeds(
    make_server: Any,
) -> None:
    srv = make_server(
        REGAUDIT_FHE_BODY_IDLE_TIMEOUT_S="0"
    )  # only the disconnect can free the budget
    for i in range(20):
        s = _open_partial(srv.port, STALL_BYTES // 2)
        if i % 2:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.close()
    probes = _full_budget_returns(srv.port, 60)
    assert probes[-1][1] == 200, probes  # all of the budget came back; a leak would never recover
    assert "Traceback" not in srv.log_text()


# (4) error-response sizes ----------------------------------------------------------------------


@pytest.mark.parametrize("n", [1_000, 20_000, 100_000])
def test_422_for_thousands_of_validation_errors_is_bounded_by_bytes(
    make_server: Any, n: int
) -> None:
    # collecting the validator's errors costs seconds on a slow runner; the timeouts are far above that
    srv = make_server(REGAUDIT_FHE_REQUEST_TIMEOUT_S="300")
    bad = _dump({**GOOD, "y_true": ["a"] * n})  # one bad array of n elements: n validation errors
    status, data, took = _post(srv.port, PATH, bad, 300)
    _evidence(
        "422_size", n=n, request_bytes=len(bad), response_bytes=len(data), seconds=round(took, 2)
    )
    assert status == 422
    assert len(data) <= 2048 + 256, len(
        data
    )  # 2048-character detail plus the marker and JSON framing
    # short details are unchanged: an exact, small, untruncated message
    status, data, _ = _post(srv.port, PATH, _dump({"y_true": [1, 0]}))
    assert status == 422 and b"truncated" not in data and len(data) < 1024
    assert _post(srv.port, PATH, json.dumps(GOOD).encode())[0] == 200  # control: a legal audit


# (5) legitimate reports near the new verify limits ----------------------------------------------


def test_genuine_v1_and_v2_envelopes_of_all_six_primitives_verify_control(make_server: Any) -> None:
    srv = make_server()
    envs = _genuine_envelopes()
    assert len(envs) == 12
    widest = 0
    for name, version, env in envs:
        body = _dump({"envelope": env})
        widest = max(widest, _array_elements(env))
        status, data, _ = _post(srv.port, "/v1/verify", body)
        got = json.loads(data)
        assert status == 200 and got["integrity_valid"] is True, (name, version, status, got)
    _evidence("genuine_envelopes", count=len(envs), widest_array_elements=widest)
    assert widest > 3000  # the provenance result at n_buckets=1024 really was the widest


def test_verify_structure_limits_are_exact_at_the_boundaries(make_server: Any) -> None:
    """Depth counts nested JSON containers with the body object as depth 1 (so the envelope is 2 and its
    ``result`` 3); the element limit counts the lengths of all arrays in the body (and, separately, the
    members of any one object). 16 / 65 536 are accepted, 17 / 65 537 refused with 422."""
    srv = make_server()
    base = _genuine_envelopes()[0][2]  # fairness v1

    def post(result: Any) -> tuple[int | None, str]:
        status, data, _ = _post(
            srv.port, "/v1/verify", _dump({"envelope": {**base, "result": result}})
        )
        return status, data.decode(errors="replace")

    def nest(levels: int) -> Any:
        node: Any = []
        for _ in range(levels - 1):
            node = [node]
        return node

    refused = (422, '{"detail":"malformed envelope"}')
    rows: dict[str, Any] = {}
    # depth: body 1, envelope 2, result 3, then ``levels`` nested arrays -> depth = 3 + levels
    rows["depth16"] = post({"x": nest(13)})[0]
    rows["depth17"] = post({"x": nest(14)})
    # elements: other arrays in the body count too; pad to the exact total
    others = _array_elements({"envelope": {**base, "result": {"x": []}}})
    rows["elements65536"] = post({"x": [1] * (65_536 - others)})[0]
    rows["elements65537"] = post({"x": [1] * (65_537 - others)})
    # width of one object: 65 536 members accepted, 65 537 refused
    rows["members65536"] = post({f"k{i}": 0 for i in range(65_536)})[0]
    rows["members65537"] = post({f"k{i}": 0 for i in range(65_537)})
    _evidence(
        "verify_boundaries",
        **{k: (list(v) if isinstance(v, tuple) else v) for k, v in rows.items()},
    )
    assert rows["depth16"] == 200 and rows["elements65536"] == 200 and rows["members65536"] == 200
    for k in ("depth17", "elements65537", "members65537"):
        assert (rows[k][0], rows[k][1]) == (refused[0], refused[1]), (k, rows[k])


# (6) auth-before-body, default and opt-in ---------------------------------------------------------

KEY = "kQualSynthetic0123456789abcdefABCDEFG"
AUTH = {"REGAUDIT_FHE_DEV_MODE": "0", "REGAUDIT_FHE_API_KEYS": f"{KEY}:admin"}


def _post_auth(port: int, body: bytes, key: str | None) -> int | None:
    wire = _request_bytes(PATH, body)
    if key:
        i = wire.index(b"\r\n") + 2
        wire = wire[:i] + f"Authorization: Bearer {key}\r\n".encode() + wire[i:]
    with socket.create_connection(("127.0.0.1", port), timeout=20) as s:
        s.sendall(wire)
        return _recv_response(s, 20)[0]


def test_auth_before_body_default_is_unchanged_over_real_sockets(make_server: Any) -> None:
    srv = make_server(**AUTH)
    good, bad = json.dumps(GOOD).encode(), b'{"y_true": [1,'
    answers = {
        "authed_good": _post_auth(srv.port, good, KEY),
        "unauth_good": _post_auth(srv.port, good, None),
        "unauth_malformed": _post_auth(srv.port, bad, None),
        "authed_malformed": _post_auth(srv.port, bad, KEY),
    }
    _evidence("auth_default_off", **answers)
    assert answers == {
        "authed_good": 200,
        "unauth_good": 401,
        "unauth_malformed": 422,  # the body is still parsed before authentication (0.2.0 order)
        "authed_malformed": 422,
    }


def test_auth_before_body_opt_in_refuses_before_parsing_over_real_sockets(
    make_server: Any,
) -> None:
    srv = make_server(REGAUDIT_FHE_AUTH_BEFORE_BODY="1", **AUTH)
    good, bad = json.dumps(GOOD).encode(), b'{"y_true": [1,'
    answers = {
        "authed_good": _post_auth(srv.port, good, KEY),
        "unauth_good": _post_auth(srv.port, good, None),
        "unauth_malformed": _post_auth(srv.port, bad, None),
        "authed_malformed": _post_auth(srv.port, bad, KEY),
    }
    _evidence("auth_opt_in", **answers)
    assert answers == {
        "authed_good": 200,
        "unauth_good": 401,
        "unauth_malformed": 401,
        "authed_malformed": 422,
    }
