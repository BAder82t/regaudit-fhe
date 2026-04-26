"""HTTP audit server (production-hardened reference build).

Exposes every audit primitive as a POST endpoint that consumes the
JSON Schema bundled in :mod:`regaudit_fhe.schemas` and emits an
Ed25519-signed audit envelope. The implementation includes:

  - bearer-token authentication and scope-based authorization,
  - bounded request body size,
  - in-process per-key rate limiting (token bucket),
  - per-request timeout,
  - structured JSON access logs that never echo audit payloads,
  - permissive-by-default CORS that becomes deny-list when configured,
  - /healthz, /readyz, /version probes.

PRIVACY-BOUNDARY WARNING
------------------------

This server is **not a privacy boundary** by itself.

  - The default execution path runs the *plaintext* SlotVec model.
    Inputs are visible to the host process, the operating system, and
    any sidecar with shared memory access.
  - Encrypted execution requires the optional ``[fhe]`` extra AND a
    deployment that withholds the CKKS secret key from the audit host
    (KMS / HSM / dedicated decryptor).
  - Issuer authenticity is whatever Ed25519 key you supply. Verifiers
    decide which ``key_id`` to trust.

The server logs the warning on startup and surfaces it in the
``/readyz`` response.

Optional dependency. Install with::

    pip install regaudit-fhe[server]

Configuration via environment variables (see docs/DEPLOYMENT.md):

    REGAUDIT_FHE_API_KEYS              - <key>:<scope1,scope2>;<key>:<scope>
    REGAUDIT_FHE_DEV_MODE              - "1" disables auth (dev only)
    REGAUDIT_FHE_MAX_BODY_BYTES        - max request body size (default 1 MiB)
    REGAUDIT_FHE_RATE_LIMIT_PER_MIN    - tokens per minute per key (default 60)
    REGAUDIT_FHE_REQUEST_TIMEOUT_S     - per-request timeout in seconds
    REGAUDIT_FHE_CORS_ORIGINS          - comma-separated allow-list

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Sequence

try:
    from fastapi import (Body, Depends, FastAPI, HTTPException, Request,
                         Response, status)
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
    from starlette.middleware.base import BaseHTTPMiddleware
    HAVE_FASTAPI = True
except Exception:
    HAVE_FASTAPI = False


from . import __version__ as LIB_VERSION
from .cli import SCHEMAS, _audit_dispatch
from .reports import AuditEnvelope, verify_receipt
from .schemas import SchemaError, list_schemas, load_schema


PRIVACY_WARNING = (
    "regaudit-fhe HTTP server: NOT A PRIVACY BOUNDARY by itself. The "
    "default execution path is plaintext; encrypted execution requires "
    "the [fhe] extra AND key custody held off-host. See server module "
    "docstring and docs/DEPLOYMENT.md before exposing publicly."
)


SCOPE_RUN = "audit:run"
SCOPE_VERIFY = "audit:verify"
SCOPE_READ = "audit:read"
SCOPE_ADMIN = "admin"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServerConfig:
    api_keys: Dict[str, frozenset]
    dev_mode: bool
    max_body_bytes: int
    rate_limit_per_min: int
    request_timeout_s: float
    cors_origins: Sequence[str]


def _parse_api_keys(raw: str) -> Dict[str, frozenset]:
    out: Dict[str, frozenset] = {}
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            continue
        key, scopes = entry.split(":", 1)
        key = key.strip()
        scopes_set = frozenset(s.strip() for s in scopes.split(",") if s.strip())
        if key:
            out[key] = scopes_set
    return out


def load_config_from_env() -> ServerConfig:
    return ServerConfig(
        api_keys=_parse_api_keys(os.environ.get("REGAUDIT_FHE_API_KEYS", "")),
        dev_mode=os.environ.get("REGAUDIT_FHE_DEV_MODE", "0") == "1",
        max_body_bytes=int(os.environ.get("REGAUDIT_FHE_MAX_BODY_BYTES",
                                           1 << 20)),
        rate_limit_per_min=int(os.environ.get(
            "REGAUDIT_FHE_RATE_LIMIT_PER_MIN", "60")),
        request_timeout_s=float(os.environ.get(
            "REGAUDIT_FHE_REQUEST_TIMEOUT_S", "30")),
        cors_origins=tuple(s.strip() for s in os.environ.get(
            "REGAUDIT_FHE_CORS_ORIGINS", "").split(",") if s.strip()),
    )


# ---------------------------------------------------------------------------
# Structured JSON logging
# ---------------------------------------------------------------------------


_RESERVED_LOG_FIELDS = frozenset({
    "args", "msecs", "relativeCreated", "exc_info", "exc_text",
    "stack_info", "pathname", "filename", "module", "lineno",
    "funcName", "created", "thread", "threadName", "processName",
    "process", "name", "levelname", "levelno", "msg", "message",
    "logger",
})


class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        import json
        payload: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                time.gmtime(record.created)),
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        for key, value in record.__dict__.items():
            if key in payload or key in _RESERVED_LOG_FIELDS:
                continue
            if isinstance(value, (str, int, float, bool, type(None))):
                payload[key] = value
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JSONFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    return logging.getLogger("regaudit-fhe.server")


# ---------------------------------------------------------------------------
# Rate limiter — in-process token bucket
# ---------------------------------------------------------------------------


class TokenBucketRateLimiter:
    """Per-key token bucket. In-process only.

    Suitable for single-replica reference deployments. Production
    deployments behind a load balancer must move state to Redis or a
    distributed counter; this implementation does not synchronise
    across processes.
    """

    def __init__(self, capacity_per_min: int) -> None:
        self.capacity = max(int(capacity_per_min), 1)
        self.refill_rate = self.capacity / 60.0
        self._buckets: Dict[str, list[float]] = defaultdict(
            lambda: [float(self.capacity), time.monotonic()]
        )

    def acquire(self, key: str) -> bool:
        now = time.monotonic()
        bucket = self._buckets[key]
        elapsed = now - bucket[1]
        bucket[0] = min(self.capacity, bucket[0] + elapsed * self.refill_rate)
        bucket[1] = now
        if bucket[0] >= 1.0:
            bucket[0] -= 1.0
            return True
        return False

    def reset(self) -> None:
        self._buckets.clear()


# ---------------------------------------------------------------------------
# Middlewares
# ---------------------------------------------------------------------------


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self.max_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": (
                            f"request body exceeds limit "
                            f"{self.max_bytes} bytes"
                        )})
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "invalid Content-Length"})
        return await call_next(request)


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        return response


class TimeoutMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, timeout_s: float) -> None:
        super().__init__(app)
        self.timeout_s = timeout_s

    async def dispatch(self, request: Request, call_next):
        try:
            return await asyncio.wait_for(call_next(request),
                                          timeout=self.timeout_s)
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=504,
                content={"detail": "request timed out"})


class StructuredAccessLogMiddleware(BaseHTTPMiddleware):
    """Logs request metadata; NEVER logs the request or response body."""

    def __init__(self, app, logger: logging.Logger) -> None:
        super().__init__(app)
        self.logger = logger

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        method = request.method
        path = request.url.path
        client = request.client.host if request.client else "-"
        request_id = getattr(request.state, "request_id", "-")
        try:
            response: Response = await call_next(request)
            elapsed = (time.perf_counter() - start) * 1000.0
            self.logger.info(
                "http_request",
                extra={
                    "request_id": request_id, "method": method,
                    "path": path, "status": response.status_code,
                    "duration_ms": round(elapsed, 2), "client": client,
                })
            return response
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000.0
            self.logger.error(
                "http_unhandled_exception",
                extra={
                    "request_id": request_id, "method": method,
                    "path": path, "duration_ms": round(elapsed, 2),
                    "client": client, "exception": type(exc).__name__,
                })
            raise


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Caller:
    key_id: str
    scopes: frozenset


def _extract_bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def make_auth_dependency(config: ServerConfig
                          ) -> Callable[..., Caller]:
    def dependency(request: Request) -> Caller:
        if config.dev_mode:
            return Caller(key_id="dev", scopes=frozenset({SCOPE_ADMIN}))
        token = _extract_bearer(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="bearer token required",
                headers={"WWW-Authenticate": "Bearer"})
        scopes = config.api_keys.get(token)
        if scopes is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="unknown bearer token",
                headers={"WWW-Authenticate": "Bearer"})
        return Caller(key_id=token, scopes=scopes)

    return dependency


def _check_scopes(caller: Caller, required: Iterable[str]) -> Caller:
    required_set = frozenset(required)
    if SCOPE_ADMIN in caller.scopes:
        return caller
    missing = required_set - caller.scopes
    if missing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"missing required scope(s): {','.join(sorted(missing))}")
    return caller


if HAVE_FASTAPI:

    class VerifyRequest(BaseModel):
        envelope: Dict[str, Any]


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def build_app(*, config: Optional[ServerConfig] = None,
              logger: Optional[logging.Logger] = None
              ) -> Any:
    if not HAVE_FASTAPI:
        raise RuntimeError(
            "FastAPI not installed. Run `pip install regaudit-fhe[server]`."
        )
    config = config or load_config_from_env()
    logger = logger or configure_logging()
    rate_limiter = TokenBucketRateLimiter(config.rate_limit_per_min)

    if config.dev_mode:
        logger.warning("dev_mode_enabled",
                       extra={"warning": "auth disabled, do not use in prod"})
    logger.warning("privacy_boundary_warning",
                   extra={"warning": PRIVACY_WARNING})

    app = FastAPI(
        title="regaudit-fhe",
        description=("Encrypted regulatory audit primitives at CKKS "
                     "depth six. NOT a privacy boundary by itself; see "
                     "server module docstring."),
        version=LIB_VERSION,
    )

    app.add_middleware(StructuredAccessLogMiddleware, logger=logger)
    app.add_middleware(TimeoutMiddleware, timeout_s=config.request_timeout_s)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=config.max_body_bytes)
    app.add_middleware(RequestIdMiddleware)
    if config.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(config.cors_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["authorization", "content-type", "x-request-id"],
        )

    auth_dep = make_auth_dependency(config)

    def authed_with(*scopes: str
                    ) -> Callable[[Request], Caller]:
        def dep(request: Request) -> Caller:
            caller = auth_dep(request)
            return _check_scopes(caller, scopes)
        return dep

    def rate_limit_or_raise(caller: Caller) -> None:
        if not rate_limiter.acquire(caller.key_id):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="rate limit exceeded",
                headers={"Retry-After": "60"})

    # ----- Probes (no auth) ------------------------------------------------

    @app.get("/healthz")
    def healthz() -> Dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> Dict[str, Any]:
        try:
            load_schema("envelope")
            ready = True
            error = None
        except Exception as exc:
            ready = False
            error = str(exc)
        return {
            "ready": ready,
            "error": error,
            "privacy_boundary_warning": PRIVACY_WARNING,
        }

    @app.get("/version")
    def version() -> Dict[str, str]:
        try:
            import tenseal
            backend_version = tenseal.__version__
        except Exception:
            backend_version = "unavailable"
        return {
            "library_version": LIB_VERSION,
            "python": platform.python_version(),
            "tenseal": backend_version,
        }

    # ----- Schemas (read scope) -------------------------------------------

    @app.get("/v1/schemas")
    def schemas_index(caller: Caller = Depends(authed_with(SCOPE_READ))
                       ) -> Dict[str, Any]:
        return {"schemas": list(list_schemas())}

    @app.get("/v1/schemas/{name}")
    def schema_by_name(name: str,
                       caller: Caller = Depends(authed_with(SCOPE_READ))
                       ) -> Dict[str, Any]:
        try:
            return load_schema(name)
        except KeyError:
            raise HTTPException(404, f"unknown schema {name!r}")

    # ----- Audit (run scope) ----------------------------------------------

    @app.post("/v1/audit/{primitive}")
    def audit(primitive: str,
              payload: Dict[str, Any] = Body(...),
              caller: Caller = Depends(authed_with(SCOPE_RUN))
              ) -> Dict[str, Any]:
        rate_limit_or_raise(caller)
        if primitive not in SCHEMAS:
            raise HTTPException(404, f"unknown primitive {primitive!r}")
        try:
            env = _audit_dispatch(primitive, payload)
        except SchemaError as exc:
            raise HTTPException(422, str(exc))
        # Never log payload — it may contain PHI / PII.
        logger.info("audit_evaluated",
                    extra={"key_id": caller.key_id, "primitive": primitive,
                           "depth_consumed": env.depth_budget["consumed"],
                           "envelope_digest": env.receipt["sha256"]})
        return env.to_dict()

    # ----- Verify (verify scope) ------------------------------------------

    @app.post("/v1/verify")
    def verify(req: VerifyRequest = Body(...),
               caller: Caller = Depends(authed_with(SCOPE_VERIFY))
               ) -> Dict[str, Any]:
        rate_limit_or_raise(caller)
        env = AuditEnvelope.from_dict(req.envelope)
        valid = verify_receipt(env)
        logger.info("envelope_verified",
                    extra={"key_id": caller.key_id, "primitive": env.primitive,
                           "valid": valid})
        return {"valid": valid, "primitive": env.primitive,
                "issued_at": env.issued_at, "regulations": env.regulations}

    return app
