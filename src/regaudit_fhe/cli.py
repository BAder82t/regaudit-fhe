"""regaudit-fhe command-line interface.

Usage examples:

    regaudit-fhe audit fairness --input fairness.json --output report.json
    regaudit-fhe audit drift   --input drift.json
    regaudit-fhe verify        --input report.json

Each primitive's input JSON shape is documented in docs/cli_inputs.md and
echoed by ``regaudit-fhe audit <primitive> --schema``.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np

from . import (
    audit_calibration,
    audit_concordance,
    audit_disagreement,
    audit_drift,
    audit_fairness,
    audit_provenance,
)
from .reports import AuditEnvelope, envelope, verify_envelope_or_raise, verify_receipt
from .schemas import SchemaError, list_schemas, load_schema, validate_input
from .trust import EnvelopeVerificationError, TrustStore, TrustStoreError

PRIMITIVES = {
    "fairness", "provenance", "concordance",
    "calibration", "drift", "disagreement",
}


SCHEMAS: dict[str, dict[str, Any]] = {
    "fairness": {
        "y_true": "[float]  binary outcome labels",
        "y_pred": "[float]  binary model predictions",
        "group_a": "[float]  protected-group A indicator (0/1)",
        "group_b": "[float]  protected-group B indicator (0/1)",
        "threshold": "float (optional, default 0.1)",
    },
    "provenance": {
        "attributions": "[float]  per-row influence/attribution magnitudes",
        "row_ids": "[int]    per-row training-data identifier",
        "n_buckets": "int     number of provenance buckets",
        "k": "int     top-K bucket count",
    },
    "concordance": {
        "risk": "[float]  risk-prediction scores",
        "time": "[float]  observed times",
        "event": "[float]  event indicators (0/1)",
    },
    "calibration": {
        "scores": "[float]  per-class non-conformity scores",
        "quantiles": "[float]  per-class calibration quantile thresholds",
    },
    "drift": {
        "p": "[float]  reference histogram",
        "q": "[float]  current histogram",
        "drift_threshold": "float (optional, default 0.05)",
    },
    "disagreement": {
        "model_polynomials": "[[a0, a1, a2, a3]]  per-model deg-3 surrogate",
        "test_input": "[float]  encrypted test input vector",
        "threshold": "float (optional, default 0.05)",
    },
}


def _audit_dispatch(primitive: str, payload: dict[str, Any]) -> AuditEnvelope:
    validate_input(primitive, payload)
    report: Any
    if primitive == "fairness":
        report = audit_fairness(
            np.asarray(payload["y_true"], dtype=float),
            np.asarray(payload["y_pred"], dtype=float),
            np.asarray(payload["group_a"], dtype=float),
            np.asarray(payload["group_b"], dtype=float),
            threshold=payload.get("threshold", 0.1),
        )
        return envelope("fairness", report)
    if primitive == "provenance":
        report = audit_provenance(
            np.asarray(payload["attributions"], dtype=float),
            np.asarray(payload["row_ids"], dtype=np.int64),
            int(payload["n_buckets"]),
            int(payload["k"]),
        )
        return envelope("provenance", report)
    if primitive == "concordance":
        report = audit_concordance(
            np.asarray(payload["risk"], dtype=float),
            np.asarray(payload["time"], dtype=float),
            np.asarray(payload["event"], dtype=float),
        )
        return envelope("concordance", report)
    if primitive == "calibration":
        report = audit_calibration(
            np.asarray(payload["scores"], dtype=float),
            np.asarray(payload["quantiles"], dtype=float),
        )
        return envelope("calibration", report)
    if primitive == "drift":
        report = audit_drift(
            np.asarray(payload["p"], dtype=float),
            np.asarray(payload["q"], dtype=float),
            drift_threshold=payload.get("drift_threshold", 0.05),
        )
        return envelope("drift", report)
    if primitive == "disagreement":
        report = audit_disagreement(
            payload["model_polynomials"],
            np.asarray(payload["test_input"], dtype=float),
            threshold=payload.get("threshold", 0.05),
        )
        return envelope("disagreement", report)
    raise ValueError(f"unknown primitive {primitive!r}")


def _cmd_audit(args: argparse.Namespace) -> int:
    if args.schema:
        print(json.dumps(SCHEMAS[args.primitive], indent=2))
        return 0
    payload = json.loads(Path(args.input).read_text())
    try:
        env = _audit_dispatch(args.primitive, payload)
    except SchemaError as exc:
        sys.stderr.write(f"input rejected: {exc}\n")
        return 2
    out = env.to_json()
    if args.output:
        Path(args.output).write_text(out + "\n")
    else:
        sys.stdout.write(out + "\n")
    return 0


def _cmd_schema(args: argparse.Namespace) -> int:
    if args.list:
        for name in list_schemas():
            print(name)
        return 0
    if not args.name:
        sys.stderr.write("regaudit-fhe schema: --list or NAME required\n")
        return 2
    try:
        schema = load_schema(args.name)
    except KeyError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    print(json.dumps(schema, indent=2))
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except Exception as exc:
        sys.stderr.write(
            f"regaudit-fhe serve requires the [server] extra: {exc}\n"
            "  pip install regaudit-fhe[server]\n"
        )
        return 2
    from .server import assert_safe_bind, build_app, load_config_from_env
    config = load_config_from_env()
    try:
        assert_safe_bind(args.host, dev_mode=config.dev_mode)
    except RuntimeError as exc:
        sys.stderr.write(f"refusing to start: {exc}\n")
        return 2
    uvicorn.run(build_app(config=config), host=args.host, port=args.port,
                log_level="info")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    body = json.loads(Path(args.input).read_text())
    env = AuditEnvelope.from_dict(body)

    trust_store: TrustStore | None = None
    if args.trusted_keys:
        try:
            trust_store = TrustStore.from_json(args.trusted_keys)
        except TrustStoreError as exc:
            sys.stderr.write(f"--trusted-keys: {exc}\n")
            return 2

    if trust_store is not None:
        try:
            verify_envelope_or_raise(env, trust_store=trust_store)
        except EnvelopeVerificationError as exc:
            print(json.dumps({
                "valid": False,
                "reason": type(exc).__name__,
                "detail": str(exc),
                "primitive": env.primitive,
                "issued_at": env.issued_at,
                "regulations": env.regulations,
                "trusted_issuer": True,
            }, indent=2))
            return 1
        print(json.dumps({
            "valid": True,
            "primitive": env.primitive,
            "issued_at": env.issued_at,
            "regulations": env.regulations,
            "trusted_issuer": True,
        }, indent=2))
        return 0

    if args.strict:
        sys.stderr.write(
            "--strict requires --trusted-keys to authenticate the issuer.\n"
        )
        return 2

    ok = verify_receipt(env)
    print(json.dumps({"valid": ok, "primitive": env.primitive,
                      "issued_at": env.issued_at,
                      "regulations": env.regulations,
                      "trusted_issuer": False}, indent=2))
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="regaudit-fhe",
        description="Encrypted regulatory audit primitives at CKKS depth six.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="Run an audit primitive.")
    audit.add_argument("primitive", choices=sorted(PRIMITIVES))
    audit.add_argument("--input", "-i", help="JSON input file")
    audit.add_argument("--output", "-o", help="JSON output file (default stdout)")
    audit.add_argument("--schema", action="store_true",
                       help="Print the expected input schema and exit.")
    audit.set_defaults(func=_cmd_audit)

    verify = sub.add_parser("verify",
                            help="Verify the receipt of an audit envelope.")
    verify.add_argument("--input", "-i", required=True,
                        help="Audit envelope JSON to verify")
    verify.add_argument("--trusted-keys",
                        help="Path to JSON object mapping key_id -> PEM "
                             "public key. Required for issuer authentication.")
    verify.add_argument("--strict", action="store_true",
                        help="Reject envelopes whose key_id is not in "
                             "--trusted-keys. Recommended for regulator-side "
                             "verifiers.")
    verify.set_defaults(func=_cmd_verify)

    serve = sub.add_parser("serve",
                           help="Run the HTTP audit server (requires [server]).")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", "-p", type=int, default=8080)
    serve.set_defaults(func=_cmd_serve)

    schema = sub.add_parser("schema",
                            help="Dump a bundled JSON Schema by name.")
    schema.add_argument("name", nargs="?",
                        help="Schema name (e.g. fairness.input, envelope).")
    schema.add_argument("--list", action="store_true",
                        help="List all bundled schema names.")
    schema.set_defaults(func=_cmd_schema)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
