#!/usr/bin/env python3
"""Run ONE bounded burst against a regaudit-fhe container and report what the cgroup saw (synthetic data only).

AI-assisted engineering tooling, not an audit. Starts a container from an image you built, with explicit
memory, CPU and pid limits, drives concurrent audit requests plus a /healthz poller from separate processes,
samples ``docker stats`` for memory, reads ``OOMKilled`` from ``docker inspect`` and always removes the container.
It touches only the container it creates (label ``org.regaudit.prep=agent3`` by default).

    python scripts/resource_bounds_container.py --image regaudit-prep-after:test --n 131064 --concurrency 64 \
        --memory 512m --cpus 1
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resource_bounds_probe as P


def docker(*args: str, timeout: float = 60.0) -> str:
    out = subprocess.run(  # noqa: S603
        ["docker", *args],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return out.stdout.strip()


def mem_mib(name: str) -> float | None:
    raw = docker("stats", "--no-stream", "--format", "{{.MemUsage}}", name, timeout=30)
    try:
        used = raw.split("/")[0].strip()
        for suffix, mult in (("GiB", 1024.0), ("MiB", 1.0), ("KiB", 1 / 1024)):
            if used.endswith(suffix):
                return float(used[: -len(suffix)]) * mult
    except ValueError:
        # docker printed something that is not a number: report the usage as unknown.
        pass
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--n", type=int, default=131064)
    ap.add_argument("--concurrency", type=int, default=64)
    ap.add_argument("--memory", default="512m")
    ap.add_argument("--cpus", default="1")
    ap.add_argument("--pids", default="128")
    ap.add_argument("--label", default="org.regaudit.prep=agent3")
    ap.add_argument("--client-timeout", type=float, default=45.0)
    ap.add_argument("--env", action="append", default=[])
    ap.add_argument(
        "--run-arg",
        action="append",
        default=[],
        help="extra `docker run` flag, repeatable (for example --run-arg=--read-only)",
    )
    ap.add_argument("--out")
    a = ap.parse_args()

    name = f"regaudit-prep-{uuid.uuid4().hex[:8]}"
    port = P.free_port()
    cmd = [
        "run", "-d", "--name", name, "--label", a.label,
        "--memory", a.memory, "--memory-swap", a.memory, "--cpus", a.cpus, "--pids-limit", a.pids,
        "-p", f"127.0.0.1:{port}:8080",
        "-e", f"REGAUDIT_FHE_API_KEYS={P.KEY}:admin",
        "-e", "REGAUDIT_FHE_RATE_LIMIT_PER_MIN=100000000",
    ]  # fmt: skip
    for kv in a.env:
        cmd += ["-e", kv]
    cmd += a.run_arg
    cmd.append(a.image)
    report: dict = {"image": a.image, "memory": a.memory, "cpus": a.cpus, "n_per_array": a.n}
    cid = docker(*cmd, timeout=120)
    if not cid:
        print("container did not start", file=sys.stderr)
        return 2
    try:
        for _ in range(100):
            try:
                import http.client

                c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                c.request("GET", "/healthz")
                if c.getresponse().status == 200:
                    break
            except OSError:
                time.sleep(0.3)
        else:
            raise RuntimeError("container did not become healthy")
        body = P.payload(a.n)
        peak = [mem_mib(name) or 0.0]
        stop = threading.Event()

        def sample() -> None:
            while not stop.is_set():
                m = mem_mib(name)
                if m:
                    peak[0] = max(peak[0], m)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        health = P.Health(port, timeout=a.client_timeout)
        t0 = time.perf_counter()
        with cf.ThreadPoolExecutor(a.concurrency) as ex:
            res = list(ex.map(lambda _: P.post(port, body, a.client_timeout), range(a.concurrency)))
        wall = time.perf_counter() - t0
        report["healthz"] = health.finish()
        stop.set()
        sampler.join(30)
        # the container must still answer after the burst
        after = P.post(port, P.payload(100), 30)
        state = json.loads(docker("inspect", "--format", "{{json .State}}", name))
        report.update(
            {
                "body_bytes": len(body),
                "concurrency": a.concurrency,
                "status": P.counts(res),
                "wall_s": round(wall, 2),
                "peak_mem_mib_sampled": round(peak[0], 1),
                "oom_killed": state.get("OOMKilled"),
                "container_running_after": state.get("Running"),
                "exit_code": state.get("ExitCode"),
                "small_request_after_burst": str(after[0]),
            }
        )
    finally:
        docker("rm", "-f", name, timeout=60)
    text = json.dumps(report, indent=2)
    print(text)
    if a.out:
        Path(a.out).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
