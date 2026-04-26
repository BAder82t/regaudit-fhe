"""HTTP audit server.

Exposes every audit primitive as a POST endpoint that accepts the same
JSON payload understood by the CLI (``regaudit-fhe audit <primitive>``)
and returns the regulator-facing audit envelope (with SHA-256 receipt).

Optional dependency. Install with::

    pip install regaudit-fhe[server]

Endpoints:

    POST /audit/fairness
    POST /audit/provenance
    POST /audit/concordance
    POST /audit/calibration
    POST /audit/drift
    POST /audit/disagreement
    POST /verify          (regulator-side receipt verification)
    GET  /healthz
    GET  /schema/<primitive>

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from typing import Any, Dict

try:
    from fastapi import Body, FastAPI, HTTPException
    from pydantic import BaseModel
    HAVE_FASTAPI = True
except Exception:
    HAVE_FASTAPI = False


from .cli import SCHEMAS, _audit_dispatch
from .reports import AuditEnvelope, verify_receipt


if HAVE_FASTAPI:

    class VerifyRequest(BaseModel):
        envelope: Dict[str, Any]


def build_app() -> Any:
    if not HAVE_FASTAPI:
        raise RuntimeError(
            "FastAPI not installed. Run `pip install regaudit-fhe[server]`."
        )

    app = FastAPI(
        title="regaudit-fhe",
        description="Encrypted regulatory audit primitives at CKKS depth six.",
        version="0.0.1",
    )

    @app.get("/healthz")
    def healthz() -> Dict[str, str]:
        return {"status": "ok", "version": "0.0.1"}

    @app.get("/schema/{primitive}")
    def schema(primitive: str) -> Dict[str, str]:
        if primitive not in SCHEMAS:
            raise HTTPException(404, f"unknown primitive {primitive!r}")
        return SCHEMAS[primitive]

    @app.post("/audit/{primitive}")
    def audit(primitive: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if primitive not in SCHEMAS:
            raise HTTPException(404, f"unknown primitive {primitive!r}")
        env = _audit_dispatch(primitive, payload)
        return env.to_dict()

    @app.post("/verify")
    def verify(req: VerifyRequest = Body(...)) -> Dict[str, Any]:
        env = AuditEnvelope.from_dict(req.envelope)
        return {"valid": verify_receipt(env),
                "primitive": env.primitive,
                "issued_at": env.issued_at,
                "regulations": env.regulations}

    return app
