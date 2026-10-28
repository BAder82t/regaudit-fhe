# Resource bounds: before/after measurements

AI-assisted engineering measurements. They are not an audit, a certification or a production assurance. They
describe one shared development machine (Apple M3 Max, 14 cores, macOS arm64, CPython 3.12.11, fastapi 0.162,
starlette 1.10, uvicorn 0.54, loopback) on which other jobs were running: the 1-minute load average was 23 to 44 at the
start of each run. Absolute times are therefore upper-ish and noisy; ratios and the status counts are the
reliable part. Three runs per cell; the values below are medians unless a range is shown.

Tooling: `scripts/resource_bounds_probe.py` (host) and `scripts/resource_bounds_container.py` (container).
"Before" is master `d0a4105`; "after" is this branch. Payload: the `fairness` input with four equal arrays of `n`
elements; `n = 131064` is the largest that fits the 1 MiB body limit (1 048 575 bytes), `n = 32768` is the largest the
new default limits accept (262 207 bytes). `/healthz` is polled from a **separate process** every 100 ms.

## Host: legal 1 MiB payloads (n = 131064)

| Scenario | Before | After, defaults | After, input limits raised (gate only) |
| --- | --- | --- | --- |
| One request, sequential | 200 in 1.7 s | **413** in 17 ms | 200 in 1.73 s |
| 16 concurrent | 16x 200 in 27.5 s; healthz median 3.1 s, max 4.1 s; RSS peak 565 MB | 16x 413 in 0.3 s | 4x 200 + 12x **503**, 7.6 s; healthz median 29 ms, max 0.8 to 1.0 s; RSS 196 MB |
| 64 concurrent | 59-61x 504 + 3-5 client timeouts, ~54 s; **healthz median 32.8 s, max 33.9 s**; RSS peak **911-1014 MB**; 11-17 s of CPU after the clients were gone | 64x 413 in 1.2 s; healthz max 0.7 s; RSS 233 MB | 6x 200 + 58x 503, 13.5 s; healthz median 28 ms, p95 0.45 s, max **4.2-4.5 s**; RSS 302-372 MB |
| 8 concurrent, server timeout 2 s: CPU burnt after every client had its answer | **10.3-10.8 s** | n/a (all 413) | **1.7-1.95 s** (the 2 running jobs) |

## Host: largest payload the defaults accept (n = 32768)

| Scenario | Before (no limit applies) | After, defaults |
| --- | --- | --- |
| One request, sequential | not measured separately (about 0.4 s of validation by proportion) | 200 in 0.43 s |
| 16 concurrent | not measured | 6x 200 + 10x 503 in 2.8 s; healthz median 28 ms, p95 74-114 ms, max 255-329 ms; RSS 103-107 MB |
| 64 concurrent | not measured | 8x 200 + 56x 503 in 4.2-4.6 s; healthz median 28 ms, p95 0.2-0.28 s, max **1.5-1.7 s**; RSS 127-136 MB |
| 8 concurrent, server timeout 2 s | n/a | 4x 200, 2x 504, 2x 503; CPU after clients done **0.6-0.68 s** |

Why the healthz maximum is not smaller at 64 concurrent: the 64 request bodies are parsed on the event loop
before the gate can refuse them (estimated at about 70 ms per 1 MiB body from the 4.2-4.5 s stall, not measured directly). The
input limits keep this down because a 262 KB body parses faster. The body-parse cost per accepted connection is
bounded by `REGAUDIT_FHE_MAX_BODY_BYTES` and `REGAUDIT_FHE_LIMIT_CONCURRENCY`, not removed; a reverse proxy that
caps connections and body size is still required.

## Host: connections that never finish their headers (50 partial + 50 silent)

| | Before | After (`REGAUDIT_FHE_HEADER_TIMEOUT_S=10`) |
| --- | --- | --- |
| Still open after the wait | 50/50 partial, 50/50 silent after 40 s | 0/50, 0/50 after 20 s |
| `/healthz` afterwards | 200 | 200 |

## Container (Docker Desktop VM; `--memory`, `--cpus 1`, `--pids-limit 128`; Python 3.13-slim base)

The shipped `Dockerfile` pins `python:3.14-slim-bookworm`; to avoid pulling a new base image these runs used a
scratch copy with `python:3.13-slim-bookworm` and without the `build-essential` apt layer (no package here needs it).
Both images were built from the respective commits with the same Dockerfile. No `[fhe]` extra.

| Scenario (64 concurrent) | Before | After |
| --- | --- | --- |
| n = 131064, `--memory 512m` | **OOMKilled=true, exit 137** (2 of 2 runs); all 64 clients got a connection reset; no answer afterwards | defaults: 64x 413 in 1.3 s, 128 MiB peak, container healthy, next request 200 |
| n = 131064, `--memory 512m`, input limits raised | (as above) | 6x 200 + 58x 503, 12.4 s, **213 MiB peak**, healthz median 13.5 ms / max 3.9 s, no OOM |
| n = 32768, `--memory 256m` | not run | 8x 200 + 56x 503 in 4.1 s, **92 MiB peak**, healthz median 13 ms / max 1.66 s, no OOM |
| n = 32768, `--memory 512m` | not run | 8x 200 + 56x 503 in 4.1 s, 90 MiB peak, no OOM |

Peak memory is sampled from `docker stats` (about once per second), so it can miss short peaks.

## What was not measured or is not claimed

- No Linux amd64, Windows or physical-server numbers; no idle-machine run (the host was never idle).
- The `[fhe]` (TenSEAL) path was not measured. The default `MAX_CONCURRENT_AUDITS=2` is a headroom choice for
  GIL-releasing native code; on the plaintext path one worker gave the same throughput (12 audits of 262 KB:
  6.3-9.5 s with 1, 2 or 4 workers, differences within noise) and lower probe latency.
- Thread-switch interval, 12 concurrent requests, n = 32768 (median / max healthz): 5 ms: 85 / 309 ms; 1 ms: 19 / 167 ms;
  0.5 ms: 10 / 258 ms (1 worker). 1 ms is the default.
- A cached `Draft202012Validator` was tried and **not shipped**: constructing the validator costs 0.003 ms against
  about 400 ms to validate 120 000 elements, so caching is not a measurable win. About 97 % of the large-request time
  is the per-element `enum` check inside `iter_errors`; the structure limits bound it instead of changing validation.
- A running audit cannot be interrupted (thread). The 0.6 s and 1.7-1.95 s residuals above are those jobs finishing.
