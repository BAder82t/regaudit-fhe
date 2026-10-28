# Deployment guide

This document covers the **HTTP audit server** shipped under the
``[server]`` extra of `regaudit-fhe`. For the underlying library and
its threat model, see [README.md](../README.md), [LICENSING.md](../LICENSING.md),
[COMPLIANCE.md](../COMPLIANCE.md), and [docs/THREAT_MODEL.md](THREAT_MODEL.md).

> **PRIVACY-BOUNDARY WARNING.** The HTTP server is a thin reference
> deployment. By itself it is **not a privacy boundary**. Production
> deployments must hold the CKKS secret key off-host (KMS / HSM),
> terminate TLS at the ingress, and apply the controls listed below.
> Read [docs/THREAT_MODEL.md](THREAT_MODEL.md) before exposing the
> server to untrusted clients.

---

## Install

```bash
pip install regaudit-fhe[server]
```

or, with the encrypted backend baked in:

```bash
pip install regaudit-fhe[server,fhe]
```

The `[server]` extra pulls FastAPI, uvicorn, and pydantic. The `[fhe]`
extra pulls TenSEAL.

---

## Configuration

All configuration is supplied via environment variables.

| Variable                              | Default       | Meaning                                                                 |
| ------------------------------------- | ------------- | ----------------------------------------------------------------------- |
| `REGAUDIT_FHE_API_KEYS`               | (empty)       | `<key>:<scope1,scope2>;<key>:<scope>` — bearer-token allow-list.        |
| `REGAUDIT_FHE_DEV_MODE`               | `0`           | `1` disables auth. Use only on a development workstation.               |
| `REGAUDIT_FHE_MAX_BODY_BYTES`         | `1048576`     | HTTP body size limit (1 MiB default).                                   |
| `REGAUDIT_FHE_RATE_LIMIT_PER_MIN`     | `60`          | Per-key tokens-per-minute for the in-process token bucket.              |
| `REGAUDIT_FHE_REQUEST_TIMEOUT_S`      | `30`          | Per-request timeout. Exceeding returns 504 and cancels the request (see "Resource bounds"). |
| `REGAUDIT_FHE_CORS_ORIGINS`           | (empty)       | Comma-separated CORS allow-list. Empty = no cross-origin response.      |
| `REGAUDIT_FHE_TRUST_STORE`            | (empty)       | Path to a `TrustStore` JSON. **Required for `/v1/verify`.** A missing, unreadable or malformed file aborts startup. |
| `REGAUDIT_FHE_ALLOW_SELF_SIGNED`      | `0`           | `1` (or `serve --allow-self-signed`) lets `/v1/verify` answer `SELF_SIGNED_ONLY` when no trust store is set. Development only: refused under non-development profiles and on non-loopback binds; never yields `TRUSTED`. |
| `REGAUDIT_FHE_PROFILE`                | `development` | `development`, `confidential` or `high-assurance`. Anything else aborts startup. |
| `REGAUDIT_FHE_VERIFIER_ID`            | (empty)       | This verifier's audience identifier (required for `high-assurance`). |
| `REGAUDIT_FHE_MAX_AGE_S`              | (empty)       | Refuse reports older than this many seconds. Must be positive and finite; required outside development. |
| `REGAUDIT_FHE_REPLAY_DB`              | (empty)       | sqlite path for the **local** persistent replay cache. |
| `REGAUDIT_FHE_REPLAY_MODE`            | `off`         | `off`, `check` (look up only) or `record` (record at verification time). Required, with a persistent cache, outside development. |
| `REGAUDIT_FHE_TRUSTED_PROXIES`        | (empty)       | IPs/CIDRs allowed to vouch for a forwarded client. Used only by the development self-signed exposure check. |
| `REGAUDIT_FHE_MAX_ARRAY_ELEMENTS`     | `32768`       | Longest JSON array (and member count of any object) `/v1/audit` accepts. Over it: 413 `INPUT_LIMIT_EXCEEDED`. |
| `REGAUDIT_FHE_MAX_TOTAL_ELEMENTS`     | `131072`      | Sum of all array lengths in one `/v1/audit` payload.                    |
| `REGAUDIT_FHE_MAX_JSON_DEPTH`         | `8`           | Deepest JSON nesting `/v1/audit` accepts (the schemas need 4).          |
| `REGAUDIT_FHE_MAX_CONCURRENT_AUDITS`  | `2`           | Audits computed at the same time (dedicated worker threads).            |
| `REGAUDIT_FHE_MAX_QUEUED_AUDITS`      | `4`           | Audits allowed to wait for a free slot (also the verify queue). Beyond it: 503 at once. |
| `REGAUDIT_FHE_QUEUE_WAIT_S`           | `5`           | Longest wait for a slot before a 503 `queue_wait_timeout`.              |
| `REGAUDIT_FHE_MAX_CONCURRENT_VERIFIES`| `4`           | Verifications computed at the same time.                                |
| `REGAUDIT_FHE_HEADER_TIMEOUT_S`       | `10`          | `serve` only. Close a connection that has not finished its request headers in this time. `0` disables. |
| `REGAUDIT_FHE_TIMEOUT_KEEP_ALIVE_S`   | `5`           | `serve` only. Idle keep-alive timeout.                                  |
| `REGAUDIT_FHE_LIMIT_CONCURRENCY`      | `256`         | `serve` only. uvicorn `--limit-concurrency`: connections/tasks beyond it get an immediate 503. `0` disables. |
| `REGAUDIT_FHE_TIMEOUT_GRACEFUL_SHUTDOWN_S` | `20`     | `serve` only. Seconds to let in-flight requests finish on shutdown. `0` waits forever. |
| `REGAUDIT_FHE_SWITCH_INTERVAL_S`      | `0.001`       | `serve` only. Interpreter thread switch interval (default CPython: 0.005). `0` leaves it unchanged. |

### Scopes

The server enforces four scopes:

| Scope            | Grants                                            |
| ---------------- | ------------------------------------------------- |
| `audit:run`      | `POST /v1/audit/<primitive>`                      |
| `audit:verify`   | `POST /v1/verify`                                 |
| `audit:read`     | `GET /v1/schemas`, `GET /v1/schemas/<name>`       |
| `admin`          | All of the above; full access.                    |

Encode them in `REGAUDIT_FHE_API_KEYS` per key, e.g.::

    REGAUDIT_FHE_API_KEYS="kRunnerAbcXyz:audit:run,audit:read;kVerifierMno:audit:verify"

> Treat API keys as long-lived secrets. Rotate quarterly. Inject through
> a secret manager (Kubernetes Secret, AWS Secrets Manager, Vault); do
> not bake into images.

---

## Endpoints

| Method | Path                              | Auth          | Purpose                                          |
| ------ | --------------------------------- | ------------- | ------------------------------------------------ |
| GET    | `/healthz`                        | none          | Liveness probe — process is alive.              |
| GET    | `/readyz`                         | none          | Readiness probe + privacy-boundary warning. **200** when ready, **503** (same JSON body, `ready: false`) when the schema bundle cannot be loaded. |
| GET    | `/version`                        | none          | Library + Python + TenSEAL versions.            |
| GET    | `/v1/schemas`                     | `audit:read`  | List bundled JSON Schemas.                      |
| GET    | `/v1/schemas/{name}`              | `audit:read`  | Fetch a specific schema.                        |
| POST   | `/v1/audit/{primitive}`           | `audit:run`   | Run an audit primitive; returns signed envelope. Refusals: `413` (body or input limit), `422`, `429` (per-key rate), `503` (`SERVER_BUSY`, with `Retry-After`), `504` (timeout). See "Resource bounds". |
| POST   | `/v1/verify`                      | `audit:verify`| Verify a signed envelope against the trust store. Returns 503 if none is configured (unless the development-only self-signed check is enabled, which can never accept a report) or if the replay store is unavailable outside development. |

`/v1/verify` fails closed: with no trust store it returns **503** rather
than a verdict. Its response keeps `valid`, `primitive`, `issued_at` and
`regulations`, and adds `trust_status` (`TRUSTED`, `SELF_SIGNED_ONLY` or
`INVALID`), `integrity_valid` and `timestamp_status`. `valid` is true only
when `trust_status` is `TRUSTED`. Note that `/v1/audit/{primitive}` signs
with an ephemeral issuer key, so envelopes it produces can only ever be
`SELF_SIGNED_ONLY` until a long-lived signer is wired in.

**Entry points.** `regaudit-fhe serve` is the usual way to run the server and
`build_app()` is a supported embedding entry point (it is in
`regaudit_fhe.server.__all__`). The security checks do not depend on the CLI:
`build_app()` validates the verification policy at build time, `/v1/verify`
fails closed without a trust store, and the development self-signed check
re-verifies on **every request** that the profile is `development`, that the
server socket is a loopback TCP address, that the peer is known and loopback, and that no forwarding header is present unless a trusted-proxy policy
vouches for it. Only the *startup* bind-host check remains CLI-only, since only
the CLI knows its bind address. Limits: a header-less local reverse proxy cannot
be told apart from a direct local client (do not enable the development option
behind one). Unix sockets (for which uvicorn reports no server address) are refused
for the development option only; normal trusted verification over a Unix socket is
unaffected.

**Replay detection is local.** `record` mode marks a report as seen in this
verifier's store when it is verified. It is not coupled to any downstream
operation, it is not a crash-safe exactly-once guarantee, and independent
verifiers that do not share a store can each accept the same report once. With
`record` mode on, any caller holding the `audit:verify` scope who has a valid
report can consume its `audit_run_id` before the intended relying party does.
`check` mode only looks up and never records. A stateless verification response
reports `consumption: NOT_CHECKED`. Every replay-checked response also reports
`replay_durable` (`false` for the in-memory cache, whose records are lost when the
process exits).

Every request gets an `X-Request-Id` (echoed if supplied; generated
otherwise). Every response carries the same value.

---

## Logging

JSON, one line per request, written to stdout. The line includes
`request_id`, `method`, `path`, `status`, `duration_ms`, `client`. The
audit endpoint additionally logs `key_id`, `primitive`, `depth_consumed`,
`envelope_digest`. **Request and response bodies are never logged**;
audit payloads may carry PHI/PII.

Forward stdout to your aggregator (Loki, Datadog, CloudWatch). Do not
turn on uvicorn `--log-level debug` in production: it would echo
request bodies.

---

## Rate limiting

The default rate limiter is an in-process token bucket. It does not
synchronise across replicas. Two production patterns work:

1. **Single replica** — rely on the in-process bucket.
2. **Multi-replica behind a load balancer** — terminate rate limiting
   at the load balancer (HAProxy, NGINX, ALB, Cloud Armor) and set
   `REGAUDIT_FHE_RATE_LIMIT_PER_MIN` to a generous per-replica cap so
   a single misbehaving client cannot saturate one replica.

If you require strict global limits across replicas, swap the
in-process token bucket for a Redis-backed counter; the
`TokenBucketRateLimiter` interface is small enough to subclass.

---

## Resource bounds

The audit primitives are CPU-bound pure Python, and JSON Schema validation of a large array cannot be
interrupted. A 1 MiB body (the body limit) holds up to about 500 000 array elements, which cost seconds of CPU
per request before these bounds existed (see `docs/RESOURCE_BOUNDS_MEASUREMENTS.md`, AI-assisted measurements,
not an audit). The server now bounds the work at four points. Defaults are safe for a single small replica;
tune them for your deployment.

1. **Input structure (`/v1/audit` only).** Before schema validation the parsed payload is checked against the
   limits below. A violation is refused with `413`:

   ```json
   {"detail": "audit input has an array longer than the configured limit",
    "code": "INPUT_LIMIT_EXCEEDED", "limit": "max_array_elements", "maximum": 131072}
   ```

   `limit` is one of `max_array_elements`, `max_total_elements`, `max_json_depth`, `max_concordance_samples`,
   `max_disagreement_models`. The refusal never echoes keys or values from the request. The CLI
   (`regaudit-fhe audit ...`) is not limited. Every setting must be a positive integer; an invalid value makes the
   server refuse to start, and there is no value that turns a limit off.

   | Setting | Default | Why this value |
   | --- | --- | --- |
   | `REGAUDIT_FHE_MAX_ARRAY_ELEMENTS` | `131072` | Owner-decided maximum for one array (and for the member count of one object). The input schemas themselves set no `maxItems`; 131072 is a policy value, not a schema value. |
   | `REGAUDIT_FHE_MAX_TOTAL_ELEMENTS` | `524288` | Sum of all array lengths in one payload. The widest input is `fairness`: four equal-length arrays, 4 x 131072. Every primitive's largest request at the per-array maximum therefore fits; a fifth maximum array does not. Measured peak memory of such a request is about 50 MB above baseline (Python 3.12), which keeps six admitted requests (2 running + 4 queued) inside 512 MiB. |
   | `REGAUDIT_FHE_MAX_JSON_DEPTH` | `4` | The root object is depth 1. The deepest valid input is `disagreement` (`model_polynomials` is an array of 4-number arrays): depth 3. One level of headroom; anything deeper is invalid under the schemas anyway (every input schema has `additionalProperties: false`). Minimum accepted setting: 3. |
   | `REGAUDIT_FHE_MAX_CONCORDANCE_SAMPLES` | `8192` | The concordance circuit does O(n^2) vector work: measured 0.5 s at 2048 samples, 3.3 s at 8192, 9.9 s at 16384, 32 s at 32768 (loaded host, directional), and minutes at 131072, which would hold an audit slot far past any request timeout. |
   | `REGAUDIT_FHE_MAX_DISAGREEMENT_MODELS` | `32` | The disagreement circuit sums M(M-1)/2 pairwise terms over the test input. 32 models is 496 pairs (about 2 s at 131072 test points); 1024 models measured 1.45 s with only 1024 test points. |

   **Compatibility.** The previous server accepted any payload that fit the body limit. Requests that exceeded
   the limits above now get `413` (for example a `concordance` request with more than 8192 samples, which on the
   previous server ran for tens of seconds to minutes). With the default 1 MiB body limit, the per-array limit
   is rarely the binding one: 131072 full-precision floats are about 2.6 MB. Raise `REGAUDIT_FHE_MAX_BODY_BYTES`
   together with these limits if you need the full sizes, and raise the matching memory limit.

   **Order of checks.** The body-size limit is enforced while the body is read, but a body within that limit is
   read and parsed (strictly, on the event loop) *before* the structure limits and the concurrency gate can
   refuse it. A large accepted body therefore still costs parse time and memory first; only a proxy in front can
   refuse it earlier.
2. **Bounded concurrency with backpressure.** At most `REGAUDIT_FHE_MAX_CONCURRENT_AUDITS` audits compute at once
   (on dedicated threads) and at most `REGAUDIT_FHE_MAX_QUEUED_AUDITS` wait, each for at most
   `REGAUDIT_FHE_QUEUE_WAIT_S`. Everything else is refused immediately:

   ```http
   HTTP/1.1 503 Service Unavailable
   Retry-After: 1

   {"detail": "the server is at capacity; retry later", "code": "SERVER_BUSY",
    "operation": "audit", "reason": "queue_full"}
   ```

   `reason` is `queue_full` or `queue_wait_timeout`. `/v1/verify` has its own gate
   (`REGAUDIT_FHE_MAX_CONCURRENT_VERIFIES`, same queue length and wait). `503 SERVER_BUSY` is not the per-key
   `429` rate limit: clients should back off and retry, and operators should scale out or raise the limits.
   Because the work is pure Python, more than one or two concurrent audits do not add throughput on one CPU
   (measured); raise `MAX_CONCURRENT_AUDITS` only if you run the `[fhe]` backend on spare cores and have
   measured a gain.
3. **Timeouts cancel.** When `REGAUDIT_FHE_REQUEST_TIMEOUT_S` expires the request is answered `504` and
   cancelled; a request waiting for a slot leaves the queue. A computation that is already running on its thread
   cannot be interrupted, so its slot stays taken until it ends: after a timeout at most
   `MAX_CONCURRENT_AUDITS` jobs, each bounded by the input limits, keep running. Before this change every
   queued request still ran to completion after its 504.
4. **Probes.** `/healthz` and `/readyz` are coroutines served on the event loop, never on a worker thread.
   `regaudit-fhe serve` also lowers the interpreter thread-switch interval (`REGAUDIT_FHE_SWITCH_INTERVAL_S`,
   default 1 ms) so the loop gets the GIL back quickly while audits compute. They stay available while every audit
   slot is busy, but they are not isolated from a saturated CPU: on a one-CPU container, size
   the probe timeouts (below) for a few hundred milliseconds under full load.

### Connection-level settings (`regaudit-fhe serve`)

| Setting | Default | Effect |
| --- | --- | --- |
| `REGAUDIT_FHE_HEADER_TIMEOUT_S` | `10` | Closes a connection that has not completed its request headers (silent, or stalled mid-header). uvicorn has no such timer; this is a small protocol subclass (`server.header_deadline_protocol`) and does not apply to slow bodies, which `REGAUDIT_FHE_REQUEST_TIMEOUT_S` covers. |
| `REGAUDIT_FHE_TIMEOUT_KEEP_ALIVE_S` | `5` | uvicorn `--timeout-keep-alive`: idle time between requests. |
| `REGAUDIT_FHE_LIMIT_CONCURRENCY` | `256` | uvicorn `--limit-concurrency`: beyond it new requests get an immediate `503` from uvicorn (plain text, no `Retry-After`) **including probes**. Size it above the reverse proxy's connection pool. |
| `REGAUDIT_FHE_TIMEOUT_GRACEFUL_SHUTDOWN_S` | `20` | uvicorn `--timeout-graceful-shutdown`. Keep it below the orchestrator's kill grace period. |

### Sizing guidance (indicative; measure your own workload)

- **One process per container.** The rate limiter, the gates and the replay cache are per process, and the work is
  CPU-bound under the GIL, so `uvicorn --workers N` adds memory and splits the gates without making one request
  faster. Scale with replicas behind the proxy. (`serve` runs a single process; it has no `--workers` flag.)
- **CPU.** Give the container 1 to 2 CPUs. At the default limits one worst-case accepted audit costs on the
  order of 0.3 to 0.6 s of one CPU on a recent laptop-class core; budget `rate_limit x that` per key per
  minute.
- **Memory.** The parsed payload dominates: at the default limits the container peaked near 130 MB RSS under a
  64-way burst (Python 3.12, host measurement); allow 256 MiB at least, 512 MiB comfortably. Before the bounds, a
  64-way burst of 1 MiB payloads reached about 800 MB to 1 GB RSS and was OOM-killed at `--memory 512m`.
- **Probes.** Use a readiness/liveness timeout of at least 2 s and a failure threshold of 3 or more; the
  image's `HEALTHCHECK` allows 5 s.

### What the limits do not guarantee

These are application-level limits. They do not prevent every denial-of-service scenario: bodies up to the body
limit are still read and parsed before any gate can refuse them, connections and unauthenticated requests are not
rate-limited by the application, and a running computation cannot be interrupted. `REGAUDIT_FHE_LIMIT_CONCURRENCY`
is enforced by uvicorn itself and answers a plain-text `503` without `Retry-After` and without the JSON body shown
above; only `SERVER_BUSY` (from the audit and verify gates) is a structured JSON refusal with `Retry-After`. Do not
assume one error format across all overload refusals.

### Reverse-proxy requirements

The application bounds work per process; it does not replace a proxy. Exposed deployments need upstream controls for
request body size, connection limits, header and body timeouts, and per-client rate enforcement. Configure the proxy (nginx, Envoy, HAProxy,
a cloud load balancer) to:

- terminate TLS and enforce a **request-header read timeout** (nginx `client_header_timeout`), a **body read
  timeout** (`client_body_timeout`) and a **maximum body size** (`client_max_body_size`) at or below
  `REGAUDIT_FHE_MAX_BODY_BYTES`;
- limit connections and request rate **per client address**, including failed authentication (the in-process
  limiter counts only authenticated audit and verify calls, so unauthenticated floods are not throttled by the
  application);
- keep a bounded upstream connection pool to the server (below `REGAUDIT_FHE_LIMIT_CONCURRENCY`) and set an
  upstream timeout a little above `REGAUDIT_FHE_REQUEST_TIMEOUT_S`;
- retry `503` only with backoff and honour `Retry-After`; never retry `504` on a non-idempotent path blindly;
- restrict `/docs`, `/openapi.json`, `/version` and the probes to the networks that need them.

### Container limits

Always run the container with explicit limits, for example
`docker run --memory 512m --cpus 1 --pids-limit 128 ...`. The server's own memory use is bounded by the settings
above, but only a cgroup limit protects the host from a mistake in them.

---

## Docker

A multi-stage `Dockerfile` is shipped at the repository root. Build:

```bash
docker build -t regaudit-fhe:current .
```

Run:

```bash
docker run --rm -p 8080:8080 \
  -e REGAUDIT_FHE_API_KEYS="$(cat api_keys.txt)" \
  -e REGAUDIT_FHE_RATE_LIMIT_PER_MIN=120 \
  regaudit-fhe:current
```

The image runs as the unprivileged `regaudit` (UID 10001) account, has
no shell installed, and exposes only port 8080. The
`HEALTHCHECK` directive polls `/healthz` every 30 seconds; configure a
separate `/readyz` probe at the orchestrator layer. `/healthz` stays 200 while the process is alive even
when `/readyz` answers 503, so a failing readiness probe removes an instance from rotation without
restarting it.

**Do not expose the server directly to untrusted clients.** The request body is limited (1 MiB by default,
including chunked bodies), audit inputs are bounded in structure and concurrency (next section), and a request
timeout cancels the request; terminate TLS, authenticate, and enforce size, rate and time limits on every route in a
reverse proxy anyway (see "Reverse-proxy requirements"). Revoking a key in the trust store needs a server restart.

`/healthz`, `/readyz`, `/version`, `/docs` and `/openapi.json` are served without authentication by design
(`/version` discloses the library, Python and TenSEAL versions). Put them behind your ingress policy if
that is not acceptable; `/v1/*` always requires a bearer token.

To bake in the encrypted backend, uncomment the `[fhe]` install line in
the Dockerfile (adds ~120 MiB).

---

## Kubernetes (reference)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: regaudit-fhe
spec:
  replicas: 2
  selector:
    matchLabels: { app: regaudit-fhe }
  template:
    metadata:
      labels: { app: regaudit-fhe }
    spec:
      automountServiceAccountToken: false
      containers:
      - name: server
        image: regaudit-fhe:current
        ports: [{ containerPort: 8080 }]
        readinessProbe:
          httpGet: { path: /readyz, port: 8080 }
          initialDelaySeconds: 5
        livenessProbe:
          httpGet: { path: /healthz, port: 8080 }
          initialDelaySeconds: 5
        env:
        - name: REGAUDIT_FHE_RATE_LIMIT_PER_MIN
          value: "120"
        - name: REGAUDIT_FHE_API_KEYS
          valueFrom: { secretKeyRef: { name: regaudit-keys, key: tokens } }
        securityContext:
          runAsNonRoot: true
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities: { drop: [ALL] }
        resources:
          requests: { cpu: "200m", memory: "256Mi" }
          limits:   { cpu: "1",    memory: "512Mi" }
```

Add a NetworkPolicy that restricts ingress to your API gateway and
limits egress to the destinations the deployment actually requires
(KMS, observability, regulator portal — whichever apply).

---

## Production checklist

- [ ] HTTPS termination at the ingress (TLS 1.2+, OCSP stapling).
- [ ] API keys stored in a secret manager, rotated quarterly.
- [ ] WAF in front of the server (block obvious payload classes).
- [ ] CORS allow-list explicitly populated; no `*`.
- [ ] Log forwarding to your aggregator with PII-stripping retention
      policies.
- [ ] Metrics scraped from your runtime (Prometheus, Datadog) — the
      JSON access logs are sufficient for request-rate / error-rate
      dashboards.
- [ ] Alert on `5xx` spikes, sustained `429` (capacity), `504`
      (timeouts), and any unauthenticated traffic to `/v1/...`.
- [ ] Run `regaudit-fhe schema --list` and `regaudit-fhe verify` end-
      to-end against a synthetic envelope after every deploy.
- [ ] Quarterly tabletop: rehearse key compromise + rotation.

---

## What this server still does NOT do

- Encrypt the network payload itself — that is your TLS terminator's
  job.
- Authenticate the issuer for you. The server signs envelopes with
  whatever Ed25519 key you generate or pass in; the verifying party
  decides which `key_id` to trust.
- Hold the CKKS secret key. That key MUST live in a separate KMS
  account / HSM, accessed only by the auditor decryption host.
- Isolate probes from CPU saturation. `/healthz` runs on the event loop and stays prompt while audit slots are
  busy, but a computation on a worker thread shares one interpreter (and one GIL) with it.
- Interrupt a running computation. A timeout cancels the request and removes it from the queue; a job already
  computing runs to its end (bounded by the input limits and `MAX_CONCURRENT_AUDITS`).
- Throttle unauthenticated traffic or share capacity fairly between keys: the gates are first-come first-served per
  process, and one key can use all slots within its rate limit. Do both at the proxy.
- Replace your incident-response or vulnerability-management programme.

Each of those gaps is operator-side: TLS, KMS, and runbooks live with
the deployment, not with this binary.
