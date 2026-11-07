"""The portal's few routes. Uploads are parsed as data and checked, and they are never kept.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response

from regaudit_fhe._limits import InputLimitError, InputLimits, check_input_bounds
from regaudit_fhe.canonical import CanonicalError, loads_strict
from regaudit_fhe.report_v2 import EnvelopeFormatError, parse_envelope_strict
from regaudit_fhe.verification import VerificationPolicy, verify

from . import __version__ as PORTAL_VERSION
from .config import ConfigProblem, EngineProblem, Portal, approved_entries, load_portal
from .engine import UNAVAILABLE_MESSAGE, Identity, check_engine
from .explain import FHE_NOTICE, NOT_A_CLAIM, declarations, describe

MAX_REPORT_BYTES = 1 << 20
MAX_REQUESTS_PER_MINUTE = 120
MAX_CONCURRENT = 4
BODY_TIMEOUT_S = 30.0
_LIMITS = InputLimits(max_array_elements=65536, max_total_elements=65536, max_depth=16)
_STATIC = Path(__file__).parent / "static"
_STATIC_FILES = {
    "app.js": (_STATIC / "app.js", "text/javascript"),
    "app.css": (_STATIC / "app.css", "text/css"),
}
_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
_NOT_READY = (
    "This portal cannot check reports right now, because its setup needs attention. Contact your administrator. "
    "No report can be checked until then."
)
_NOT_A_REPORT = (
    "This file is not a signed report this portal can read. Nothing was verified, so treat it as not accepted. "
    "Check you chose the right file, or ask whoever sent it."
)
_TOO_LARGE = (
    f"This file is over the {MAX_REPORT_BYTES // (1 << 20)} MB limit. Nothing was verified, so treat it as not accepted. "
    "A signed report is usually much smaller, so check you chose the right file."
)
_NO_VERDICT = (
    "The check could not be completed, so there is no verdict. Treat the report as not accepted."
)

logger = logging.getLogger("regaudit_portal")


class _TooLarge(Exception):
    pass


class _RateLimit:
    def __init__(self, limit: int) -> None:
        self._limit, self._lock, self._window, self._count = limit, threading.Lock(), 0, 0

    def allow(self) -> bool:
        with self._lock:
            now = int(time.monotonic() // 60)
            if now != self._window:
                self._window, self._count = now, 0
            self._count += 1
            return self._count <= self._limit


def _refusal(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": code, "message": message}, status_code=status)


class _EngineLog:
    """Say in the log when the engine check starts failing, fails differently, or recovers. Not on every call.

    The check itself is never cached, so a request that arrives while it fails is refused. Only the log line is
    once per change of state, so a page that is polled cannot make the log grow without limit.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: tuple[bool, str] = (True, "OK")

    def seen(self, identity: Identity) -> None:
        state = (identity.ok, identity.reason)
        with self._lock:
            changed = state != self._state
            self._state = state
        if not changed:
            return
        if identity.ok:
            logger.warning("verification is available again: the engine passes its check")
        else:
            logger.error("verification unavailable: %s: %s", identity.reason, identity.detail)


class _EngineRefused(Exception):
    """The engine failed its check while a verification was in flight. Nothing from it may be used."""


def _verify_between_checks(
    env: Any, policy: VerificationPolicy, watch: _EngineLog
) -> tuple[Any, Identity]:
    """Check the engine, verify, check again. A verdict is returned only if both checks pass.

    The first check is immediately before the engine's verify is called and the second immediately after it
    returns, so a change made while an upload was still arriving, or while the verification ran, cannot slip a
    verdict through. The second check's description of the engine is the one the response carries.
    """
    before = check_engine()
    watch.seen(before)
    if not before.ok:
        raise _EngineRefused
    result = verify(env, policy)
    after = check_engine()
    watch.seen(after)
    if not after.ok or after.engine is None:
        raise _EngineRefused
    return result, after


def _unavailable() -> JSONResponse:
    return JSONResponse(
        {"error": "unavailable", "state": "unavailable", "message": UNAVAILABLE_MESSAGE},
        status_code=503,
    )


async def _read_limited(request: Request) -> bytes:
    length = request.headers.get("content-length")
    if length is not None and (not length.isdigit() or int(length) > MAX_REPORT_BYTES):
        raise _TooLarge
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_REPORT_BYTES:
            raise _TooLarge
    return bytes(body)


def _parse(raw: bytes) -> Any:
    payload = loads_strict(raw, max_bytes=MAX_REPORT_BYTES)
    check_input_bounds(payload, _LIMITS)
    if not isinstance(payload, dict):
        raise EnvelopeFormatError("BAD_TYPE", "a report is a JSON object")
    return parse_envelope_strict(payload)


def _unavailable_status() -> dict[str, Any]:
    """Nothing about the configuration, versions or paths: those go to the administrator's terminal."""
    return {"ready": False, "state": "unavailable"}


def _status_body(portal: Portal | None, engine: dict[str, Any] | None = None) -> dict[str, Any]:
    if portal is None or engine is None:
        return {"ready": False, "message": _NOT_READY, "not_a_claim": NOT_A_CLAIM}
    policy: VerificationPolicy = portal.policy
    return {
        "ready": True,
        "policy_id": policy.policy_id,
        "policy_text": f"Policy {policy.policy_id}, {approved_entries(portal.approved_count)}.",
        "profile": portal.profile,
        "approved_count": portal.approved_count,
        "replay_mode": portal.replay_mode,
        "engine": engine,
        "not_a_claim": NOT_A_CLAIM,
    }


def build_app(config_path: str | Path, *, port: int) -> FastAPI:
    """A portal whose configuration is unusable still starts, says so, and gives no verdicts.

    The same holds when the engine is not the recognised release: nothing is verified, whatever else is configured.
    The engine is checked here, again by ``load_portal``, and before every verification.
    """
    portal: Portal | None
    engine_refused = False
    try:
        portal = load_portal(config_path)
    except ConfigProblem as exc:
        logger.error("portal not ready: %s", exc)
        portal = None
        engine_refused = isinstance(exc, EngineProblem)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.ready = portal is not None
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    origins = {f"http://{host}" for host in hosts}
    gate = asyncio.Semaphore(MAX_CONCURRENT)
    limit = _RateLimit(MAX_REQUESTS_PER_MINUTE)
    watch = _EngineLog()

    @app.middleware("http")
    async def guard(request: Request, call_next: Any) -> Response:
        # A page on another site, or a name rebound to this address, must not reach this.
        if request.headers.get("host") not in hosts:
            return _refusal(403, "bad_host", "Open this portal at its own local address.")
        origin = request.headers.get("origin")
        if origin is not None and origin not in origins:
            return _refusal(403, "bad_origin", "Requests must come from this portal's own page.")
        response: Response = await call_next(request)
        for name, value in _HEADERS.items():
            response.headers[name] = value
        return response

    # HEAD answers like GET, without a body, so a link checker or a browser's preflight gets the same headers.
    @app.api_route("/", methods=["GET", "HEAD"])
    def page() -> FileResponse:
        return FileResponse(_STATIC / "index.html", media_type="text/html")

    @app.api_route("/static/{name}", methods=["GET", "HEAD"])
    def static_file(name: str) -> Response:
        known = _STATIC_FILES.get(name)
        if known is None:
            return _refusal(404, "not_found", "Not found.")
        return FileResponse(known[0], media_type=known[1])

    @app.api_route("/security", methods=["GET", "HEAD"])
    def security() -> FileResponse:
        return FileResponse(_STATIC / "security.html", media_type="text/html")

    @app.api_route("/api/status", methods=["GET", "HEAD"])
    def status() -> dict[str, Any]:
        if engine_refused:
            return _unavailable_status()
        if portal is None:
            return _status_body(None)
        identity = check_engine()
        watch.seen(identity)
        if not identity.ok:
            return _unavailable_status()
        return _status_body(portal, identity.engine)

    @app.post("/api/verify")
    async def check(request: Request) -> Response:
        if engine_refused:
            return _unavailable()
        if portal is None:
            return _refusal(503, "not_ready", _NOT_READY)
        if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
            return _refusal(415, "bad_type", _NOT_A_REPORT)
        if not limit.allow():
            return _refusal(
                429, "too_many", "Too many checks in the last minute. Try again shortly."
            )
        # Before any of the upload is read: is the engine still the recognised release?
        identity = await run_in_threadpool(check_engine)
        watch.seen(identity)
        if not identity.ok or identity.engine is None:
            return _unavailable()
        try:
            raw = await asyncio.wait_for(_read_limited(request), BODY_TIMEOUT_S)
        except _TooLarge:
            return _refusal(413, "too_large", _TOO_LARGE)
        except asyncio.TimeoutError:
            return _refusal(408, "too_slow", "The upload took too long. Nothing was verified.")
        try:
            env = _parse(raw)
        except (
            CanonicalError,
            EnvelopeFormatError,
            InputLimitError,
            RecursionError,
            ValueError,
            TypeError,
        ):
            return _refusal(422, "not_a_report", _NOT_A_REPORT)
        try:
            async with gate:
                result, identity = await run_in_threadpool(
                    _verify_between_checks, env, portal.policy, watch
                )
        except _EngineRefused:
            return _unavailable()
        except Exception:
            logger.exception("verification failed")
            return _refusal(503, "no_verdict", _NO_VERDICT)
        verification = result.to_dict()
        return JSONResponse(
            {
                "verification": verification,
                "explanation": describe(verification, portal.profile),
                "encryption_declarations": declarations(env, verification["trust_status"]),
                "engine": identity.engine,
                "fhe_notice": FHE_NOTICE,
                "report_sha256": hashlib.sha256(raw).hexdigest(),
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "portal_version": PORTAL_VERSION,
                "not_a_claim": NOT_A_CLAIM,
            }
        )

    return app
