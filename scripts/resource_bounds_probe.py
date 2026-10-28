#!/usr/bin/env python3
"""Bounded resource-exhaustion probe for the regaudit-fhe HTTP server (synthetic data only).

AI-assisted engineering tooling, not an audit. Starts its own server on a loopback ephemeral port
(``regaudit-fhe serve`` code path, so the real uvicorn settings apply), runs bounded scenarios and prints a
JSON report. Needs the ``server`` and ``dev`` (psutil) extras. Every client call has a hard timeout and every
scenario has a bounded payload and concurrency, so a run cannot grow without limit.

    python scripts/resource_bounds_probe.py --scenarios seq,burst,timeout,halfopen --n 131064 \
        --concurrency 4,16 --out probe.json
    python scripts/resource_bounds_probe.py --env REGAUDIT_FHE_MAX_ARRAY_ELEMENTS=1000000 ...

``--n`` is the array length used for each of the four fairness arrays. The default body limit (1 MiB)
allows up to 131064.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import http.client
import json
import os
import platform
import socket
import statistics
import subprocess
import sys
import threading
import time

import psutil

KEY = "kProbeSynthetic0123456789abcdefABCDE"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def start(env_extra: dict[str, str]):
    port = free_port()
    env = dict(os.environ, REGAUDIT_FHE_API_KEYS=f"{KEY}:admin")
    env["REGAUDIT_FHE_RATE_LIMIT_PER_MIN"] = "100000000"
    env.update(env_extra)
    code = "from regaudit_fhe.cli import main; raise SystemExit(main())"
    p = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", code, "serve", "--host", "127.0.0.1", "--port", str(port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(150):
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            c.request("GET", "/healthz")
            if c.getresponse().status == 200:
                return p, port
        except OSError:
            time.sleep(0.1)
    p.kill()
    raise RuntimeError("server did not start")


def stop(p) -> None:
    p.terminate()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()


def payload(n: int) -> bytes:
    half = n // 2
    return json.dumps(
        {
            "y_true": [(i * 7) % 2 for i in range(n)],
            "y_pred": [(i * 5) % 2 for i in range(n)],
            "group_a": [1 if i < half else 0 for i in range(n)],
            "group_b": [0 if i < half else 1 for i in range(n)],
            "threshold": 0.1,
        },
        separators=(",", ":"),
    ).encode()


def post(port: int, body: bytes, timeout: float):
    h = {"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    t = time.perf_counter()
    try:
        c.request("POST", "/v1/audit/fairness", body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        return r.status, time.perf_counter() - t, dict(r.getheaders()), data
    except (OSError, http.client.HTTPException) as exc:
        return type(exc).__name__, time.perf_counter() - t, {}, b""
    finally:
        c.close()


_POLLER = r"""
import http.client, json, sys, threading, time
port, period, timeout = int(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3])
stop = threading.Event()
threading.Thread(target=lambda: (sys.stdin.read(), stop.set()), daemon=True).start()
out = []
while not stop.is_set():
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    t = time.perf_counter()
    try:
        c.request("GET", "/healthz")
        st = c.getresponse().status
    except (OSError, http.client.HTTPException) as exc:
        st = type(exc).__name__
    finally:
        c.close()
    out.append([st, time.perf_counter() - t])
    stop.wait(period)
print(json.dumps(out))
"""


class Health:
    """Polls GET /healthz on a fresh connection every ``period`` s from a SEPARATE process.

    A separate process keeps the poller out of the load generator's GIL, so the latency it records is the
    server's, not the client's.
    """

    def __init__(self, port: int, period: float = 0.1, timeout: float = 60.0) -> None:
        self.timeout = timeout
        self.proc = subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", _POLLER, str(port), str(period), str(timeout)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

    def start(self) -> None:
        pass

    def finish(self) -> dict:
        out, _ = self.proc.communicate(timeout=self.timeout + 10)  # closing stdin stops the poller
        samples = json.loads(out)
        lat = sorted(s[1] for s in samples if s[0] == 200)
        bad = [str(s[0]) for s in samples if s[0] != 200]
        if not lat:
            return {"samples": len(samples), "non200": bad[:5]}
        return {
            "samples": len(samples),
            "non200": len(bad),
            "median_ms": round(1000 * statistics.median(lat), 1),
            "p95_ms": round(1000 * lat[int(0.95 * (len(lat) - 1))], 1),
            "max_ms": round(1000 * lat[-1], 1),
        }


def counts(results) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in results:
        out[str(r[0])] = out.get(str(r[0]), 0) + 1
    return out


def cpu_s(proc: psutil.Process) -> float:
    t = proc.cpu_times()
    return t.user + t.system


def rss_mb(proc: psutil.Process) -> float:
    return proc.memory_info().rss / 2**20


class Peak(threading.Thread):
    def __init__(self, proc: psutil.Process) -> None:
        super().__init__(daemon=True)
        self.proc, self.peak, self._stop_evt = proc, 0.0, threading.Event()

    def run(self) -> None:
        while not self._stop_evt.is_set():
            try:
                self.peak = max(self.peak, rss_mb(self.proc))
            except psutil.Error:
                return
            self._stop_evt.wait(0.05)

    def finish(self) -> float:
        self._stop_evt.set()
        self.join(2)
        return round(self.peak, 1)


def scenario_seq(env, n, reps, client_timeout):
    p, port = start(env)
    try:
        proc = psutil.Process(p.pid)
        body = payload(n)
        r = [post(port, body, client_timeout) for _ in range(reps)]
        return {
            "body_bytes": len(body),
            "status": counts(r),
            "latency_s_median": round(statistics.median(x[1] for x in r), 3),
            "rss_mb_after": round(rss_mb(proc), 1),
        }
    finally:
        stop(p)


def scenario_burst(env, n, conc, client_timeout, drain_s):
    p, port = start(env)
    try:
        proc = psutil.Process(p.pid)
        body = payload(n)
        rss0, cpu0 = rss_mb(proc), cpu_s(proc)
        peak, health = Peak(proc), Health(port, timeout=client_timeout)
        peak.start()
        health.start()
        t0 = time.perf_counter()
        with cf.ThreadPoolExecutor(conc) as ex:
            res = list(ex.map(lambda _: post(port, body, client_timeout), range(conc)))
        wall = time.perf_counter() - t0
        h = health.finish()
        cpu_at_end = cpu_s(proc)
        # Residual work: how much more CPU the server burns after every client is done.
        time.sleep(drain_s)
        cpu_resid = cpu_s(proc) - cpu_at_end
        lat = [x[1] for x in res if x[0] == 200]
        ra = sorted(
            {x[2].get("Retry-After") or x[2].get("retry-after") for x in res if x[0] in (429, 503)}
            - {None}
        )
        return {
            "body_bytes": len(body),
            "concurrency": conc,
            "status": counts(res),
            "retry_after_values": ra,
            "wall_s": round(wall, 2),
            "ok_latency_s_median": round(statistics.median(lat), 2) if lat else None,
            "healthz": h,
            "rss_mb_idle": round(rss0, 1),
            "rss_mb_peak": peak.finish(),
            "server_cpu_s_during": round(cpu_at_end - cpu0, 2),
            f"server_cpu_s_in_{drain_s}s_after_clients_done": round(cpu_resid, 2),
        }
    finally:
        stop(p)


def scenario_halfopen(env, count, wait_s):
    p, port = start(env)
    socks = []
    try:
        for _ in range(count):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(
                b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-Slow: 1\r\n"
            )  # header block never finished
            socks.append(s)
        silent = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(count)]
        t0 = time.perf_counter()
        time.sleep(wait_s)

        def alive(s: socket.socket) -> bool:
            s.settimeout(0.2)
            try:
                return s.recv(1) != b""  # b"" -> peer closed
            except TimeoutError:
                return True
            except OSError:
                return False

        a_partial = sum(alive(s) for s in socks)
        a_silent = sum(alive(s) for s in silent)
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        t = time.perf_counter()
        c.request("GET", "/healthz")
        hz = c.getresponse().status
        return {
            "connections_each": count,
            "waited_s": round(time.perf_counter() - t0, 1),
            "partial_header_still_open": a_partial,
            "silent_still_open": a_silent,
            "healthz_status": hz,
            "healthz_ms": round(1000 * (time.perf_counter() - t), 1),
        }
    finally:
        for s in socks:
            s.close()
        stop(p)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default="seq,burst,timeout,halfopen")
    ap.add_argument("--n", type=int, default=131064, help="elements per fairness array")
    ap.add_argument("--concurrency", default="4,16")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--client-timeout", type=float, default=60.0)
    ap.add_argument("--drain-s", type=int, default=10)
    ap.add_argument("--halfopen-wait", type=float, default=20.0)
    ap.add_argument("--env", action="append", default=[], help="KEY=VALUE passed to the server")
    ap.add_argument("--out")
    a = ap.parse_args()
    env = dict(kv.split("=", 1) for kv in a.env)
    scen = a.scenarios.split(",")
    rep: dict = {
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
            "loadavg_start": [round(x, 1) for x in os.getloadavg()],
            "server_env": env,
            "n_per_array": a.n,
        }
    }
    if "seq" in scen:
        rep["seq"] = scenario_seq(env, a.n, a.reps, a.client_timeout)
    if "burst" in scen:
        rep["burst"] = [
            scenario_burst(env, a.n, int(c), a.client_timeout, a.drain_s)
            for c in a.concurrency.split(",")
        ]
    if "timeout" in scen:
        # Short server-side timeout: do refused/timed-out requests keep consuming CPU afterwards?
        e2 = dict(env, REGAUDIT_FHE_REQUEST_TIMEOUT_S="2")
        rep["timeout"] = scenario_burst(e2, a.n, 8, a.client_timeout, a.drain_s)
    if "halfopen" in scen:
        rep["halfopen"] = scenario_halfopen(env, 50, a.halfopen_wait)
    rep["environment"]["loadavg_end"] = [round(x, 1) for x in os.getloadavg()]
    text = json.dumps(rep, indent=2)
    print(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
