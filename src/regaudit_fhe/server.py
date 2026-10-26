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
    REGAUDIT_FHE_TRUST_STORE           - path to a TrustStore JSON; REQUIRED for /v1/verify
    REGAUDIT_FHE_ALLOW_SELF_SIGNED     - "1" lets /v1/verify report SELF_SIGNED_ONLY
                                         (development profile, loopback only)
    REGAUDIT_FHE_PROFILE               - development (default) | confidential | high-assurance
    REGAUDIT_FHE_VERIFIER_ID           - this verifier's audience identifier
    REGAUDIT_FHE_MAX_AGE_S             - reject reports older than this many seconds
    REGAUDIT_FHE_REPLAY_DB             - sqlite path for the local persistent replay cache
    REGAUDIT_FHE_REPLAY_MODE           - off (default) | check | record
    REGAUDIT_FHE_TRUSTED_PROXIES       - comma-separated IPs/CIDRs allowed to vouch for forwarded
                                         clients (development self-signed check only)

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import platform
import sys
import time
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

try:
    from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from starlette.concurrency import run_in_threadpool
    from starlette.middleware.base import BaseHTTPMiddleware

    HAVE_FASTAPI = True
except Exception:
    HAVE_FASTAPI = False


from . import __version__ as LIB_VERSION
from .canonical import CanonicalError, loads_strict
from .cli import SCHEMAS, _audit_dispatch
from .replay import ReplayCache, SqliteReplayCache
from .report_v2 import EnvelopeFormatError, parse_envelope
from .schemas import SchemaError, list_schemas, load_schema
from .trust import TrustStore
from .verification import (
    PolicyError,
    TimestampVerifier,
    TrustHistory,
    VerificationPolicy,
    VerificationUnavailable,
    verify,
)

__all__ = [
    "PRIVACY_WARNING",
    "Caller",
    "ServerConfig",
    "assert_safe_bind",
    "build_app",
    "check_dev_exposure",
    "load_config_from_env",
    "validate_trust_config",
]

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
    api_keys: dict[str, frozenset]
    dev_mode: bool
    max_body_bytes: int
    rate_limit_per_min: int
    request_timeout_s: float
    cors_origins: Sequence[str]
    # Issuer trust for /v1/verify. With no trust store the endpoint fails
    # closed (503) unless ``allow_self_signed`` is set.
    trust_store: TrustStore | None = None
    # Development-only. Lets /v1/verify report SELF_SIGNED_ONLY when no trust
    # store is configured. It can never produce a TRUSTED result or
    # ``accepted: true``.
    allow_self_signed: bool = False
    profile: str = "development"
    require_verified_timestamp: bool = False
    # Caller-pinned timestamp verifier (see verification.TimestampVerifier).
    # None means timestamps are reported UNVERIFIED; no authority is bundled.
    timestamp_verifier: TimestampVerifier | None = None
    verifier_id: str | None = None
    max_age_s: float | None = None
    allow_legacy_v1: bool | None = None
    trust_history: TrustHistory | None = None
    replay_cache: ReplayCache | None = None
    replay_mode: str = "off"
    # IPs / CIDRs allowed to vouch for a forwarded client address. Used only by
    # the development self-signed exposure check.
    trusted_proxies: tuple[str, ...] = ()

    def verification_policy(self) -> VerificationPolicy:
        """The single verification policy for this deployment (raises PolicyError)."""
        return VerificationPolicy(
            profile=self.profile,
            trust_store=self.trust_store,
            allow_self_signed=self.allow_self_signed,
            allow_legacy_v1=self.allow_legacy_v1,
            verifier_id=self.verifier_id,
            max_age=_max_age_from_seconds(self.max_age_s),
            timestamp_verifier=self.timestamp_verifier,
            require_verified_timestamp=self.require_verified_timestamp,
            trust_history=self.trust_history,
            replay_cache=self.replay_cache,
            replay_mode=self.replay_mode,
        )


def _max_age_from_seconds(seconds: float | None) -> timedelta | None:
    if seconds is None:
        return None
    try:
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError
        return timedelta(seconds=seconds)
    except (ValueError, OverflowError) as exc:
        raise PolicyError("max_age must be a positive, finite number of seconds") from exc


def validate_trust_config(config: ServerConfig) -> None:
    """Refuse configurations that would weaken issuer verification.

    Raises :class:`~regaudit_fhe.verification.PolicyError` (a ``RuntimeError``).
    The rules live in :class:`VerificationPolicy`, so the CLI, ``build_app()``
    and any embedding apply exactly the same ones.
    """
    config.verification_policy()


_FORWARDING_HEADERS = (
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-forwarded-server",
    "x-real-ip",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "via",
)


def _is_loopback_host(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)  # ::ffff:127.0.0.1 on older Pythons
    return bool((mapped or addr).is_loopback)


def _proxy_networks(entries: Sequence[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in entries:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            return []  # a malformed trusted-proxy policy trusts nobody
    return nets


def _in_networks(host: str, nets: Sequence[Any]) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in nets if net.version == addr.version)


def check_dev_exposure(
    scope: Mapping[str, Any], headers: Mapping[str, str], trusted_proxies: Sequence[str] = ()
) -> str | None:
    """Return a refusal reason, or ``None`` if the request may use a
    development-only verification option.

    The server socket the request actually arrived on must be a loopback TCP
    address, and the peer must be known. Unix sockets and unknown transports are
    refused; this concerns the development option only, never normal trusted
    verification. Client-supplied forwarding headers are never proof of loopback
    origin: if any are present the request is refused unless an
    explicit trusted-proxy policy names the immediate peer, in which case the
    original client is the rightmost ``X-Forwarded-For`` entry that is not
    itself a trusted proxy and must be loopback. A malformed policy trusts
    nobody.
    """
    server = scope.get("server")
    if not server or len(server) < 2 or server[1] is None:
        # No server address, or a Unix socket (ASGI reports ``[path, None]``;
        # uvicorn reports nothing at all). The transport origin cannot be
        # authenticated well enough to establish the loopback restriction.
        return "server socket is not an authenticated loopback TCP address"
    host = server[0]
    if not (isinstance(host, str) and _is_loopback_host(host)):
        return "server socket is not loopback"
    client = scope.get("client")
    if not client or not client[0]:
        return "peer address unknown"
    present = [h for h in _FORWARDING_HEADERS if h in headers]
    if not present:
        if not _is_loopback_host(str(client[0])):
            return "client is not loopback"
        return None
    nets = _proxy_networks(trusted_proxies)
    if not nets:
        return "forwarding headers present and no trusted-proxy policy is configured"
    if not _in_networks(str(client[0]), nets):
        return "forwarded request from an untrusted peer"
    xff = ",".join(_header_lines(headers, "x-forwarded-for"))
    if not xff:
        return "cannot establish the original client without X-Forwarded-For"
    origin: str | None = None
    for hop in reversed([h.strip() for h in xff.split(",")]):
        if not _is_loopback_host(hop) and not _valid_ip(hop):
            return "malformed X-Forwarded-For"
        if _in_networks(hop, nets):
            continue
        origin = hop
        break
    if origin is None or not _is_loopback_host(origin):
        return "original client is not loopback"
    return None


def _header_lines(headers: Mapping[str, str], name: str) -> list[str]:
    """Every line of a header (a proxy may append a line instead of merging, and
    the client controls the earlier ones)."""
    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        return [str(v) for v in getlist(name)]
    value = headers.get(name)
    return [value] if value else []


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _parse_api_keys(raw: str) -> dict[str, frozenset]:
    out: dict[str, frozenset] = {}
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


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def assert_safe_bind(host: str, *, dev_mode: bool, allow_self_signed: bool = False) -> None:
    """Refuse to start with a development-only option on a non-loopback bind.

    ``dev_mode`` disables bearer-token auth and ``allow_self_signed`` lets
    unauthenticated issuers through /v1/verify, so any non-loopback bind
    is treated as a misconfiguration. Raises :class:`RuntimeError`
    when the combination is unsafe so callers cannot accidentally
    expose them to a network.
    """
    if allow_self_signed and not _is_loopback(host):
        raise RuntimeError(
            f"--allow-self-signed refuses non-loopback bind: host={host!r}. "
            "It is a development-only option."
        )
    if not dev_mode:
        return
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # Hostnames (e.g. "localhost") are accepted only when they
        # resolve unambiguously to loopback. Treat anything else as
        # unsafe rather than performing DNS at startup.
        if host.lower() not in ("localhost",):
            raise RuntimeError(
                f"REGAUDIT_FHE_DEV_MODE=1 refuses non-loopback bind: "
                f"host={host!r}. Bind to 127.0.0.1, ::1, or localhost."
            ) from None
        return
    if not addr.is_loopback:
        raise RuntimeError(
            f"REGAUDIT_FHE_DEV_MODE=1 refuses non-loopback bind: "
            f"host={host!r}. Bind to 127.0.0.1, ::1, or localhost."
        )


def _env_float(name: str) -> float | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError as exc:
        raise PolicyError(f"{name} must be a number of seconds") from exc
    if not value > 0:
        raise PolicyError(f"{name} must be positive")
    return value


def load_config_from_env(*, trust_store_path: str | None = None) -> ServerConfig:
    """Build a :class:`ServerConfig` from the environment.

    A configured ``REGAUDIT_FHE_TRUST_STORE`` that is missing, unreadable or
    malformed raises :class:`~regaudit_fhe.trust.TrustStoreError`: the server
    never starts with a silently degraded verifier.
    """
    # An explicit path (the CLI flag) takes precedence, so a broken env value
    # is not even read.
    trust_path = (trust_store_path or os.environ.get("REGAUDIT_FHE_TRUST_STORE", "")).strip()
    replay_db = os.environ.get("REGAUDIT_FHE_REPLAY_DB", "").strip()
    config = ServerConfig(
        api_keys=_parse_api_keys(os.environ.get("REGAUDIT_FHE_API_KEYS", "")),
        dev_mode=os.environ.get("REGAUDIT_FHE_DEV_MODE", "0") == "1",
        max_body_bytes=int(os.environ.get("REGAUDIT_FHE_MAX_BODY_BYTES", 1 << 20)),
        rate_limit_per_min=int(os.environ.get("REGAUDIT_FHE_RATE_LIMIT_PER_MIN", "60")),
        request_timeout_s=float(os.environ.get("REGAUDIT_FHE_REQUEST_TIMEOUT_S", "30")),
        cors_origins=tuple(
            s.strip()
            for s in os.environ.get("REGAUDIT_FHE_CORS_ORIGINS", "").split(",")
            if s.strip()
        ),
        trust_store=TrustStore.from_json(trust_path) if trust_path else None,
        allow_self_signed=os.environ.get("REGAUDIT_FHE_ALLOW_SELF_SIGNED", "0") == "1",
        profile=os.environ.get("REGAUDIT_FHE_PROFILE", "development").strip(),
        verifier_id=os.environ.get("REGAUDIT_FHE_VERIFIER_ID", "").strip() or None,
        max_age_s=_env_float("REGAUDIT_FHE_MAX_AGE_S"),
        replay_cache=SqliteReplayCache(replay_db) if replay_db else None,
        replay_mode=os.environ.get("REGAUDIT_FHE_REPLAY_MODE", "off").strip(),
        trusted_proxies=tuple(
            p.strip()
            for p in os.environ.get("REGAUDIT_FHE_TRUSTED_PROXIES", "").split(",")
            if p.strip()
        ),
    )
    validate_trust_config(config)
    return config


# ---------------------------------------------------------------------------
# Structured JSON logging
# ---------------------------------------------------------------------------


_RESERVED_LOG_FIELDS = frozenset(
    {
        "args",
        "msecs",
        "relativeCreated",
        "exc_info",
        "exc_text",
        "stack_info",
        "pathname",
        "filename",
        "module",
        "lineno",
        "funcName",
        "created",
        "thread",
        "threadName",
        "processName",
        "process",
        "name",
        "levelname",
        "levelno",
        "msg",
        "message",
        "logger",
    }
)


# json.dumps(ensure_ascii=False) escapes "\n" and "\r" but leaves these Unicode line
# separators raw, and Unicode-aware splitters (str.splitlines, some shippers) treat them as
# record boundaries. Escaping them keeps one log record on one line; the JSON is unchanged.
_LINE_BREAKS = {0x85: "\\u0085", 0x2028: "\\u2028", 0x2029: "\\u2029"}


class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        for key, value in record.__dict__.items():
            if key in payload or key in _RESERVED_LOG_FIELDS:
                continue
            if isinstance(value, (str, int, float, bool, type(None))):
                payload[key] = value
        return json.dumps(payload, ensure_ascii=False, sort_keys=True).translate(_LINE_BREAKS)


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
        self._buckets: dict[str, list[float]] = defaultdict(
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


class _BodyTooLarge(Exception):
    """Raised inside the receive channel when a request body passes the limit."""


class BodySizeLimitMiddleware:
    """Pure ASGI. Rejects an oversized ``Content-Length`` up front AND counts the bytes actually received, so a
    chunked body (no ``Content-Length``) cannot exceed the limit either, on every route and before any
    authentication or parsing of the body."""

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, send, status: int, detail: str) -> None:
        body = json.dumps({"detail": detail}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                await self._reject(send, 400, "invalid Content-Length")
                return
            if too_big:
                await self._reject(send, 413, f"request body exceeds limit {self.max_bytes} bytes")
                return
        received = 0
        exceeded = False
        started = False

        async def limited_receive():
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise _BodyTooLarge
            return message

        async def tracking_send(message) -> None:
            # The framework turns a failed body read into its own 400; the client must see 413 instead.
            nonlocal started
            if exceeded:
                if not started:
                    started = True
                    await self._reject(
                        send, 413, f"request body exceeds limit {self.max_bytes} bytes"
                    )
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except Exception:
            # Depending on the Starlette/anyio versions our abort reaches us bare or wrapped in an
            # ExceptionGroup by an inner BaseHTTPMiddleware. Once we have aborted the read ourselves the
            # only cause of the failure is the oversize body, so answer 413; anything else propagates.
            if not exceeded:
                raise
            if not started:
                started = True
                await self._reject(send, 413, f"request body exceeds limit {self.max_bytes} bytes")


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
            return await asyncio.wait_for(call_next(request), timeout=self.timeout_s)
        except asyncio.TimeoutError:
            return JSONResponse(status_code=504, content={"detail": "request timed out"})


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
                    "request_id": request_id,
                    "method": method,
                    "path": path,
                    "status": response.status_code,
                    "duration_ms": round(elapsed, 2),
                    "client": client,
                },
            )
            return response
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000.0
            self.logger.error(
                "http_unhandled_exception",
                extra={
                    "request_id": request_id,
                    "method": method,
                    "path": path,
                    "duration_ms": round(elapsed, 2),
                    "client": client,
                    "exception": type(exc).__name__,
                },
            )
            raise


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Caller:
    key_id: str
    scopes: frozenset


def _extract_bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


MIN_HMAC_KEY_BYTES = 16


def _validated_hmac_key(key: object) -> bytes:
    """Return ``key`` as bytes, or raise if it cannot be a usable HMAC key.

    An explicitly supplied key must be at least :data:`MIN_HMAC_KEY_BYTES` long. Length is a
    floor, not proof of randomness: the key must also be unpredictable (use
    ``os.urandom``). Nothing about the value is put in the error message.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"HMAC key must be bytes, not {type(key).__name__}")
    if len(key) < MIN_HMAC_KEY_BYTES:
        raise ValueError(
            f"HMAC key must be at least {MIN_HMAC_KEY_BYTES} bytes (got {len(key)}); "
            "omit it to have a secure random key generated"
        )
    return bytes(key)


def _hash_token(token: str, key: bytes) -> bytes:
    """Keyed digest of a bearer token, for constant-time comparison only.

    HMAC-SHA256 under a per-process random key. The result is never stored or
    sent anywhere: it exists so that comparing a request's token with the
    configured ones does not depend on their lengths or contents. A slow
    password hash is not appropriate for high-entropy API tokens checked on
    every request.
    """
    return hmac.new(key, token.encode("utf-8"), hashlib.sha256).digest()


def _freeze_api_keys(
    api_keys: dict[str, frozenset], salt: bytes
) -> tuple[tuple[bytes, frozenset], ...]:
    return tuple((_hash_token(tok, salt), scopes) for tok, scopes in api_keys.items())


def make_auth_dependency(
    config: ServerConfig,
    *,
    salt: bytes,
) -> Callable[..., Caller]:
    """Build an auth dependency that compares bearer tokens in
    constant time.

    Tokens are hashed with a per-process random ``salt`` at server
    boot; the request's bearer is hashed under the same salt and
    compared against every stored hash with :func:`hmac.compare_digest`,
    OR-ing results so the time taken does not depend on which entry
    matched (or whether any matched). The resolved ``Caller.key_id``
    is the hex prefix of the hashed token, never the raw bearer — so
    log lines and rate-limit buckets do not leak credentials.
    """
    salt = _validated_hmac_key(salt)
    frozen = _freeze_api_keys(config.api_keys, salt)

    def dependency(request: Request) -> Caller:
        if config.dev_mode:
            return Caller(key_id="dev", scopes=frozenset({SCOPE_ADMIN}))
        token = _extract_bearer(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="bearer token required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        candidate = _hash_token(token, salt)
        matched_scopes: frozenset | None = None
        for stored_hash, scopes in frozen:
            if hmac.compare_digest(stored_hash, candidate):
                matched_scopes = scopes
        if matched_scopes is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="unknown bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return Caller(key_id=candidate.hex()[:12], scopes=matched_scopes)

    return dependency


def _check_scopes(caller: Caller, required: Iterable[str]) -> Caller:
    required_set = frozenset(required)
    if SCOPE_ADMIN in caller.scopes:
        return caller
    missing = required_set - caller.scopes
    if missing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"missing required scope(s): {','.join(sorted(missing))}",
        )
    return caller


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def build_app(
    *,
    config: ServerConfig | None = None,
    logger: logging.Logger | None = None,
    salt: bytes | None = None,
) -> Any:
    """Build the FastAPI application. A **supported embedding entry point**.

    Every security check lives here or in the library (the shared
    :class:`~regaudit_fhe.verification.VerificationPolicy`), never only in the
    ``regaudit-fhe serve`` CLI wrapper: the policy is validated at build time,
    ``/v1/verify`` fails closed without a trust store, and the development
    self-signed check re-verifies profile and network exposure on every
    request. What remains CLI-only is the *startup* bind-host check, because
    only the CLI knows its bind address; see ``docs/DEPLOYMENT.md``.

    ``salt`` is the HMAC key for bearer-token comparison. Leave it ``None`` (the
    default and the CLI's behaviour) for a fresh ``os.urandom(32)`` key per
    process. An explicit key must be ``bytes`` of at least 16 bytes, otherwise
    ``ValueError``/``TypeError`` is raised; it is never replaced silently.
    Length is only a floor: the key must also be unpredictable, because the
    ``key_id`` written to logs is derived from it.
    """
    if not HAVE_FASTAPI:
        raise RuntimeError("FastAPI not installed. Run `pip install regaudit-fhe[server]`.")
    config = config or load_config_from_env()
    policy = config.verification_policy()
    logger = logger or configure_logging()
    rate_limiter = TokenBucketRateLimiter(config.rate_limit_per_min)
    # An explicit key is validated, never silently replaced: a bad one is a configuration error.
    auth_salt = _validated_hmac_key(salt) if salt is not None else os.urandom(32)

    if config.dev_mode:
        logger.warning("dev_mode_enabled", extra={"warning": "auth disabled, do not use in prod"})
    logger.warning("privacy_boundary_warning", extra={"warning": PRIVACY_WARNING})

    app = FastAPI(
        title="regaudit-fhe",
        description=(
            "Encrypted regulatory audit primitives at CKKS "
            "depth six. NOT a privacy boundary by itself; see "
            "server module docstring."
        ),
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

    auth_dep = make_auth_dependency(config, salt=auth_salt)

    def authed_with(*scopes: str) -> Callable[[Request], Caller]:
        def dep(request: Request) -> Caller:
            caller = auth_dep(request)
            return _check_scopes(caller, scopes)

        return dep

    def rate_limit_or_raise(caller: Caller) -> None:
        if not rate_limiter.acquire(caller.key_id):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="rate limit exceeded",
                headers={"Retry-After": "60"},
            )

    # ----- Probes (no auth) ------------------------------------------------

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> Any:
        try:
            load_schema("envelope")
            ready = True
            error = None
        except Exception as exc:
            ready = False
            # Never return exception text to an unauthenticated probe: it can carry
            # file-system paths. The detail goes to the server log instead.
            error = "schema bundle unavailable"
            logger.warning(
                "readyz_schema_unavailable",
                extra={"error_type": type(exc).__name__, "error": str(exc)},
            )
        # A readiness probe that looks only at the status code must see "not ready" as a non-2xx.
        return JSONResponse(
            status_code=200 if ready else 503,
            content={
                "ready": ready,
                "error": error,
                "privacy_boundary_warning": PRIVACY_WARNING,
            },
        )

    @app.get("/version")
    def version() -> dict[str, str]:
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
    def schemas_index(caller: Caller = Depends(authed_with(SCOPE_READ))) -> dict[str, Any]:
        return {"schemas": list(list_schemas())}

    @app.get("/v1/schemas/{name}")
    def schema_by_name(
        name: str, caller: Caller = Depends(authed_with(SCOPE_READ))
    ) -> dict[str, Any]:
        try:
            return load_schema(name)
        except KeyError as exc:
            raise HTTPException(404, f"unknown schema {name!r}") from exc

    # ----- Audit (run scope) ----------------------------------------------

    @app.post("/v1/audit/{primitive}")
    def audit(
        primitive: str,
        payload: dict[str, Any] = Body(...),
        caller: Caller = Depends(authed_with(SCOPE_RUN)),
    ) -> dict[str, Any]:
        rate_limit_or_raise(caller)
        if primitive not in SCHEMAS:
            raise HTTPException(404, f"unknown primitive {primitive!r}")
        try:
            env = _audit_dispatch(primitive, payload)
        except SchemaError as exc:
            raise HTTPException(422, str(exc)) from exc
        except (ValueError, OverflowError) as exc:
            # The primitives reject inputs the schema cannot express (for example arrays of unequal length).
            # Say so with a 422. The log carries a fixed message and the exception class only: the exception
            # text can echo caller-supplied values.
            logger.warning("audit_input_rejected", extra={"error_type": type(exc).__name__})
            raise HTTPException(
                422, "the audit input is inconsistent (see the input schema)"
            ) from exc
        # Never log payload — it may contain PHI / PII.
        logger.info(
            "audit_evaluated",
            extra={
                "key_id": caller.key_id,
                "primitive": primitive,
                "depth_consumed": env.depth_budget["consumed"],
                "envelope_digest": env.receipt["sha256"],
            },
        )
        return env.to_dict()

    # ----- Verify (verify scope) ------------------------------------------

    @app.post("/v1/verify")
    async def verify_endpoint(
        request: Request, caller: Caller = Depends(authed_with(SCOPE_VERIFY))
    ) -> dict[str, Any]:
        rate_limit_or_raise(caller)
        if config.trust_store is None:
            # No trust material. Fail closed unless the development-only
            # self-signed check is enabled, and even then only for a
            # development profile reached over a loopback TCP socket. Both
            # checks run on every request, whatever entry point built the app.
            if not config.allow_self_signed:
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "issuer verification unavailable: no trust store configured "
                    "(set REGAUDIT_FHE_TRUST_STORE)",
                )
            if config.profile != "development":
                raise HTTPException(status.HTTP_403_FORBIDDEN, "development option refused")
            refusal = check_dev_exposure(request.scope, request.headers, config.trusted_proxies)
            if refusal is not None:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    f"development self-signed verification refused: {refusal}",
                )
        # Read the body ourselves so the size limit also covers chunked uploads
        # that carry no Content-Length, then parse it strictly.
        received = bytearray()
        async for chunk in request.stream():
            received.extend(chunk)
            if len(received) > config.max_body_bytes:
                raise HTTPException(
                    status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    f"request body exceeds limit {config.max_body_bytes} bytes",
                )
        try:
            payload = loads_strict(bytes(received), max_bytes=config.max_body_bytes)
            if not isinstance(payload, dict) or set(payload) != {"envelope"}:
                raise EnvelopeFormatError("BAD_TYPE", 'body must be {"envelope": {...}}')
            env = parse_envelope(payload["envelope"])
        except (CanonicalError, EnvelopeFormatError) as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "malformed envelope") from exc
        try:
            # verify() may block (sqlite replay store), so keep it off the event loop.
            result = await run_in_threadpool(verify, env, policy)
        except VerificationUnavailable as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
        if "REPLAY_STATE_UNAVAILABLE" in result.blocking_reasons:
            # Infrastructure failure, not a verdict on the report.
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "replay store unavailable; no verdict given"
            )
        logger.info(
            "envelope_verified",
            extra={
                "key_id": caller.key_id,
                "primitive": env.primitive,
                "valid": result.accepted,
                "trust_status": result.trust_status,
                "format": result.format,
                "reasons": list(result.reasons),
            },
        )
        response: dict[str, Any] = result.to_dict()
        return response

    return app
