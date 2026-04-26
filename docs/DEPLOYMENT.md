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
| `REGAUDIT_FHE_REQUEST_TIMEOUT_S`      | `30`          | Per-request timeout. Exceeding returns 504.                             |
| `REGAUDIT_FHE_CORS_ORIGINS`           | (empty)       | Comma-separated CORS allow-list. Empty = no cross-origin response.      |

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
| GET    | `/readyz`                         | none          | Readiness probe + privacy-boundary warning.     |
| GET    | `/version`                        | none          | Library + Python + TenSEAL versions.            |
| GET    | `/v1/schemas`                     | `audit:read`  | List bundled JSON Schemas.                      |
| GET    | `/v1/schemas/{name}`              | `audit:read`  | Fetch a specific schema.                        |
| POST   | `/v1/audit/{primitive}`           | `audit:run`   | Run an audit primitive; returns signed envelope.|
| POST   | `/v1/verify`                      | `audit:verify`| Verify a signed envelope.                       |

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
separate `/readyz` probe at the orchestrator layer.

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
- Replace your incident-response or vulnerability-management programme.

Each of those gaps is operator-side: TLS, KMS, and runbooks live with
the deployment, not with this binary.
