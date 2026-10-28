# Resource bounds: before/after measurements

AI-assisted engineering measurements. They are not an audit, a certification or a production assurance. They
describe one shared development machine (Apple M3 Max, 14 cores, macOS arm64, CPython 3.12.11, fastapi 0.162,
starlette 1.10, uvicorn 0.54, loopback) on which other jobs were running: the 1-minute load average was 23 to 44 at the
start of each run. Absolute times are therefore upper-ish and noisy; ratios and the status counts are the
reliable part. Three runs per cell; the values below are medians unless a range is shown.

> **Superseded defaults.** The tables below were measured with the first draft of the limits (32768 elements per
> array, 131072 in total, depth 8). The 0.1.1 candidate ships 131072 / 524288 / depth 4 plus the concordance,
> disagreement and in-flight-body limits; see "0.1.1 combined candidate" at the end of this file for the
> measurements that apply to the shipped defaults.

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

## 0.1.1 combined candidate (shipped defaults)

AI-assisted measurements, not an audit. Same shared machine (load average 33 to 40 at every run; Docker Desktop
VM, CPython 3.14 image), so times are directional and outcomes and memory are the evidence.

**Cost of the largest legal request per primitive** (one request, host, Python 3.12, full-precision floats):

| Primitive | Input | Body | CPU time | Peak RSS above baseline |
| --- | --- | --- | --- | --- |
| fairness | 4 x 131072 bits | 1.5 MB | 2.0 s | 35 MB |
| drift | 2 x 131072 floats | 5.3 MB | 1.1 s | 30 MB |
| calibration | 2 x 131072 floats | 5.3 MB | 0.8 s | 33 MB |
| provenance | 131072 floats + 131072 ids | 3.6 MB | 0.9 s | 46 MB |
| disagreement | 16 models x 131072 test points | 2.7 MB | 0.4 s | 33 MB |
| concordance | 1024 / 2048 / 4096 / 8192 / 16384 / 32768 samples | | 0.23 / 0.51 / 1.3 / 3.3 / 9.9 / 32 s | |
| concordance | 131072 samples | | more than 3 minutes (stopped) | |
| disagreement | 16 / 64 / 256 / 1024 models, 1024 test points | | 0.02 / 0.02 / 0.11 / 1.45 s | |

Concordance and disagreement are super-linear (O(n^2) and O(M^2)), which is why they have their own limits
(8192 samples, 32 models) in addition to the 131072-per-array limit.

**Overload in a container** (`--memory 512m --cpus 1 --pids-limit 256 --read-only --cap-drop ALL
--security-opt no-new-privileges`, image built from the combined tree):

| Scenario | Result |
| --- | --- |
| 64 concurrent legal fairness requests, 1 MiB each (the scenario that was OOM-killed at 512 MiB before the bounds) | 7 x 200, 57 x 503, peak 204 MiB, OOMKilled false, `/healthz` 46 of 46 answered 200 (median 7.5 ms, p95 1.6 s), a small request afterwards 200 |
| 64 concurrent fairness requests at the largest legal size (4 x 131072), body limit 8 MiB | 8 x 200, 56 x 503, peak 203 MiB, OOMKilled false |
| 64 concurrent drift requests with 5.3 MB bodies and 5 x 131072 arrays (body limit 16 MiB) **without** the in-flight body budget | OOM-killed: 64 x connection reset, peak 400 MiB sampled |
| the same with the in-flight body budget | 5 x 200, 59 x 503, 5 x 413 for the five-array request (total limit), 1 x 503, peak 191 MiB, OOMKilled false, `/healthz` 44 of 44 answered 200 (p95 0.5 s), 0.09 % CPU three seconds after the clients left |

The third row is why `REGAUDIT_FHE_MAX_INFLIGHT_BODY_BYTES` exists: the per-request body limit alone allows
`connections x body limit` bytes to be buffered before any gate can refuse a request.
