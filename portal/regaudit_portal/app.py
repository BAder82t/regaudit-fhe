"""The portal's few routes. Uploads are parsed as data and checked, and they are never kept.

The bundled samples are checked by their id from a list, against a demonstration policy that is used for nothing else.
An uploaded report is checked against the administrator's policy, or refused if there is none.

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
from .explain import DEMONSTRATION_NOTICE, FHE_NOTICE, NOT_A_CLAIM, declarations, describe
from .samples import DEMONSTRATION_ISSUER, Sample, Samples, SamplesProblem, load_samples
from .setup import readiness

MAX_REPORT_BYTES = 1 << 20
MAX_REQUESTS_PER_MINUTE = 120
MAX_CONCURRENT = 4
BODY_TIMEOUT_S = 30.0
_LIMITS = InputLimits(max_array_elements=65536, max_total_elements=65536, max_depth=16)
_STATIC = Path(__file__).parent / "static"
_STATIC_FILES = {
    "app.js": (_STATIC / "app.js", "text/javascript"),
    "app.css": (_STATIC / "app.css", "text/css"),
    "setup.js": (_STATIC / "setup.js", "text/javascript"),
    "vaultbytes-mark.svg": (_STATIC / "vaultbytes-mark.svg", "image/svg+xml"),
}
# The three typefaces the pages use, as files of this package. Nothing else in the folder can be asked for.
_FONT_FILES = {
    name: _STATIC / "fonts" / name
    for name in (
        "inter-latin-wght-normal.woff2",
        "space-grotesk-latin-wght-normal.woff2",
        "jetbrains-mono-latin-wght-normal.woff2",
    )
}
_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
        "font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
_NOT_READY = (
    "This portal cannot check reports right now, because its setup needs attention. Contact your administrator. "
    "No report can be checked until then."
)
_NOT_SET_UP = "Verification of your own reports is not set up yet. An administrator has to set up trust first."
_SAMPLES_UNAVAILABLE = "The demonstration samples cannot be used right now. Nothing was verified."
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


def _own_message(state: str) -> str:
    return _NOT_SET_UP if state == "not_set_up" else _NOT_READY


def _status_body(
    portal: Portal | None,
    engine: dict[str, Any],
    samples: Samples | None,
    own_state: str,
) -> dict[str, Any]:
    """Whether your own reports can be checked, which samples there are, and which engine would check them."""
    listing = samples.listing() if samples is not None else []
    if portal is None:
        return {
            "ready": False,
            "state": own_state,
            "message": _own_message(own_state),
            "samples": listing,
            "engine": engine,
            "not_a_claim": NOT_A_CLAIM,
        }
    policy: VerificationPolicy = portal.policy
    return {
        "ready": True,
        "state": "ready",
        "samples": listing,
        "policy_id": policy.policy_id,
        "policy_text": f"Policy {policy.policy_id}, {approved_entries(portal.approved_count)}.",
        "profile": portal.profile,
        "approved_count": portal.approved_count,
        "replay_mode": portal.replay_mode,
        "engine": engine,
        "not_a_claim": NOT_A_CLAIM,
    }


def _result_body(
    verification: dict[str, Any],
    explanation: dict[str, Any],
    env: Any,
    raw: bytes,
    identity: Identity,
    sample: Sample | None,
) -> dict[str, Any]:
    """What the page shows and what it saves. For a sample it also says, in the data, that it is a demonstration."""
    body = {
        "verification": verification,
        "explanation": explanation,
        "encryption_declarations": declarations(env, verification["trust_status"]),
        "engine": identity.engine,
        "fhe_notice": FHE_NOTICE,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "portal_version": PORTAL_VERSION,
        "not_a_claim": NOT_A_CLAIM,
        "synthetic_demonstration": sample is not None,
    }
    if sample is not None:
        body["demonstration"] = {
            "notice": DEMONSTRATION_NOTICE,
            "sample": {"id": sample.id, "title": sample.title},
            "issuer": DEMONSTRATION_ISSUER,
            "trust_list": "a demonstration trust list bundled with the portal, not set up by any administrator",
        }
    return body


def build_app(config_path: str | Path | None, *, port: int) -> FastAPI:
    """A portal whose configuration is unusable still starts, says so, and gives no verdicts for your own reports.

    With no configuration at all (``None``) it starts in welcome mode: the bundled samples work, and your own reports are
    not set up. The same holds for a configuration that cannot be used. When the engine is not the recognised release
    nothing is verified, samples included, whatever else is configured. The engine is checked here, again by
    ``load_portal``, and before every verification.
    """
    portal: Portal | None = None
    own_state = "not_set_up"
    start = check_engine()
    engine_refused = not start.ok
    if engine_refused:
        logger.error("portal not ready: engine: %s: %s", start.reason, start.detail)
    elif config_path is not None:
        try:
            portal = load_portal(config_path)
            own_state = "ready"
        except ConfigProblem as exc:
            logger.error("portal not ready: %s", exc)
            own_state = "needs_attention"
            engine_refused = isinstance(exc, EngineProblem)
    samples: Samples | None = None
    if not engine_refused:
        try:
            samples = load_samples()
        except SamplesProblem as exc:
            logger.error("the demonstration samples cannot be used: %s", exc)
    configured = Path(config_path).absolute() if config_path is not None else None

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.ready = portal is not None
    app.state.mode = (
        "unavailable"
        if engine_refused
        else {"ready": "ready", "not_set_up": "welcome"}.get(own_state, "needs-attention")
    )
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

    @app.api_route("/static/fonts/{name}", methods=["GET", "HEAD"])
    def font_file(name: str) -> Response:
        known = _FONT_FILES.get(name)
        if known is None:
            return _refusal(404, "not_found", "Not found.")
        return FileResponse(known, media_type="font/woff2")

    @app.api_route("/security", methods=["GET", "HEAD"])
    def security() -> FileResponse:
        return FileResponse(_STATIC / "security.html", media_type="text/html")

    @app.api_route("/setup", methods=["GET", "HEAD"])
    def setup_page() -> FileResponse:
        return FileResponse(_STATIC / "setup.html", media_type="text/html")

    @app.api_route("/api/setup", methods=["GET", "HEAD"])
    def setup_status() -> dict[str, Any]:
        """Read-only: what is in place, and what is not. It changes nothing and is reachable only with GET."""
        if engine_refused:
            return _unavailable_status()
        identity = check_engine()
        watch.seen(identity)
        if not identity.ok:
            return _unavailable_status()
        return readiness(
            configured,
            port=port,
            identity=identity,
            own_state=own_state,
            own_message=_own_message(own_state),
        )

    @app.api_route("/api/status", methods=["GET", "HEAD"])
    def status() -> dict[str, Any]:
        if engine_refused:
            return _unavailable_status()
        identity = check_engine()
        watch.seen(identity)
        if not identity.ok or identity.engine is None:
            return _unavailable_status()
        return _status_body(portal, identity.engine, samples, own_state)

    @app.post("/api/samples/{sample_id}/verify")
    async def check_sample(sample_id: str) -> Response:
        """Check one bundled sample, chosen by its id from the list. Nothing is uploaded and no body is read."""
        if engine_refused:
            return _unavailable()
        if samples is None:
            return _refusal(503, "samples_unavailable", _SAMPLES_UNAVAILABLE)
        sample = samples.get(sample_id)
        if sample is None:
            return _refusal(404, "not_found", "There is no such sample.")
        if not limit.allow():
            return _refusal(
                429, "too_many", "Too many checks in the last minute. Try again shortly."
            )
        identity = await run_in_threadpool(check_engine)
        watch.seen(identity)
        if not identity.ok or identity.engine is None:
            return _unavailable()
        try:
            raw = samples.read(sample)
            env = _parse(raw)
            async with gate:
                result, identity = await run_in_threadpool(
                    _verify_between_checks, env, samples.policy, watch
                )
        except _EngineRefused:
            return _unavailable()
        except Exception:
            logger.exception("verification of a sample failed")
            return _refusal(503, "no_verdict", _NO_VERDICT)
        verification = result.to_dict()
        explanation = describe(verification, "demonstration", demonstration=True)
        return JSONResponse(_result_body(verification, explanation, env, raw, identity, sample))

    @app.post("/api/verify")
    async def check(request: Request) -> Response:
        if engine_refused:
            return _unavailable()
        if portal is None:
            return _refusal(
                503,
                "not_set_up" if own_state == "not_set_up" else "not_ready",
                _own_message(own_state),
            )
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
        explanation = describe(verification, portal.profile)
        return JSONResponse(_result_body(verification, explanation, env, raw, identity, None))

    return app
