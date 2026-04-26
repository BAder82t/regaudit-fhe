"""Example — drive the regaudit-fhe HTTP server from a Python client.

Spins up the FastAPI app in-process via Starlette's TestClient (zero
ports, fully self-contained), demonstrates the bearer-token auth +
scope contract, fires three real audit calls, and verifies one of the
returned signed envelopes. The same flow works against a deployed
``regaudit-fhe serve`` binary by swapping :class:`TestClient` for
``httpx.Client(base_url="https://your-host")``.

Requires the ``[server]`` extra::

    pip install regaudit-fhe[server]

Run::

    python examples/server_client.py
"""

from __future__ import annotations

import sys

try:
    from fastapi.testclient import TestClient
except Exception as exc:
    sys.exit(f"[server] extra not installed: {exc}")

import regaudit_fhe as rf
from regaudit_fhe.server import ServerConfig, build_app


def main() -> int:
    print("regaudit-fhe — server / client round-trip example\n")

    cfg = ServerConfig(
        api_keys={
            "k-runner":   frozenset({"audit:run", "audit:read"}),
            "k-verifier": frozenset({"audit:verify", "audit:read"}),
            "k-readonly": frozenset({"audit:read"}),
        },
        dev_mode=False,
        max_body_bytes=1 << 20,
        rate_limit_per_min=600,
        request_timeout_s=10.0,
        cors_origins=(),
    )
    client = TestClient(build_app(config=cfg))

    print("[1/5] /healthz + /version (no auth required)...")
    print(f"      health: {client.get('/healthz').json()}")
    print(f"      version: {client.get('/version').json()}\n")

    print("[2/5] Unauthenticated audit attempt — expect 401...")
    r = client.post("/v1/audit/fairness", json={
        "y_true": [1, 0], "y_pred": [1, 0],
        "group_a": [1, 0], "group_b": [0, 1],
    })
    print(f"      status={r.status_code} detail={r.json()['detail']!r}\n")
    assert r.status_code == 401

    print("[3/5] Wrong-scope audit attempt — expect 403...")
    r = client.post("/v1/audit/fairness",
                    headers={"Authorization": "Bearer k-readonly"},
                    json={"y_true": [1, 0], "y_pred": [1, 0],
                          "group_a": [1, 0], "group_b": [0, 1]})
    print(f"      status={r.status_code} detail={r.json()['detail']!r}\n")
    assert r.status_code == 403

    print("[4/5] Three real audits via /v1/audit/*...")
    audit_headers = {"Authorization": "Bearer k-runner"}
    fairness = client.post("/v1/audit/fairness", headers=audit_headers, json={
        "y_true":  [1, 0, 1, 1, 0, 1, 0, 0],
        "y_pred":  [1, 0, 1, 0, 0, 1, 1, 0],
        "group_a": [1, 1, 1, 1, 0, 0, 0, 0],
        "group_b": [0, 0, 0, 0, 1, 1, 1, 1],
    }).json()
    drift = client.post("/v1/audit/drift", headers=audit_headers, json={
        "p": [10, 20, 30, 40], "q": [12, 18, 32, 38],
        "drift_threshold": 0.005,
    }).json()
    cal = client.post("/v1/audit/calibration", headers=audit_headers, json={
        "scores": [0.1, 0.4, 0.7, 0.9],
        "quantiles": [0.5, 0.5, 0.5, 0.5],
    }).json()
    for env in (fairness, drift, cal):
        print(f"      {env['primitive']:13s} "
              f"depth={env['depth_budget']['consumed']}/"
              f"{env['depth_budget']['declared']} "
              f"sha256={env['receipt']['sha256'][:12]}...")
    print()

    print("[5/5] Verify the fairness envelope via /v1/verify...")
    r = client.post("/v1/verify",
                    headers={"Authorization": "Bearer k-verifier"},
                    json={"envelope": fairness})
    body = r.json()
    print(f"      status={r.status_code} valid={body['valid']} "
          f"primitive={body['primitive']} regulations={body['regulations']}\n")
    assert r.status_code == 200 and body["valid"] is True

    print("OK — full server/client round trip succeeded under bearer-token "
          "auth, scope checks, and signed envelope verification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
