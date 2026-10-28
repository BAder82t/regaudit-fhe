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
import math
import sys
from datetime import timedelta
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
from .canonical import MAX_INPUT_BYTES, CanonicalError
from .replay import ReplayStateError, SqliteReplayCache
from .report_v2 import EnvelopeFormatError, parse_envelope
from .reports import AuditEnvelope, envelope
from .schemas import SchemaError, list_schemas, load_schema, validate_input
from .trust import TrustStore, TrustStoreError
from .verification import (
    PROFILES,
    PolicyError,
    VerificationPolicy,
    VerificationUnavailable,
    verify,
)

PRIMITIVES = {
    "fairness",
    "provenance",
    "concordance",
    "calibration",
    "drift",
    "disagreement",
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
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    try:
        env = _audit_dispatch(args.primitive, payload)
    except (SchemaError, ValueError) as exc:
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
    import dataclasses

    from .server import (
        apply_switch_interval_from_env,
        assert_safe_bind,
        build_app,
        load_config_from_env,
        uvicorn_options_from_env,
        validate_trust_config,
    )

    try:
        config = load_config_from_env(trust_store_path=args.trust_store)
        if args.allow_self_signed:
            config = dataclasses.replace(config, allow_self_signed=True)
        validate_trust_config(config)
        server_options = uvicorn_options_from_env()
        apply_switch_interval_from_env()
    except (TrustStoreError, RuntimeError) as exc:
        sys.stderr.write(f"refusing to start: {exc}\n")
        return 2
    try:
        assert_safe_bind(
            args.host, dev_mode=config.dev_mode, allow_self_signed=config.allow_self_signed
        )
    except RuntimeError as exc:
        sys.stderr.write(f"refusing to start: {exc}\n")
        return 2
    uvicorn.run(
        build_app(config=config),
        host=args.host,
        port=args.port,
        log_level="info",
        **server_options,
    )
    return 0


def _positive_seconds(text: str) -> float:
    """argparse type: a positive, finite number of seconds that fits a timedelta."""
    try:
        value = float(text)
        if not math.isfinite(value) or value <= 0:
            raise ValueError
        timedelta(seconds=value)
    except (ValueError, OverflowError):
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a positive, finite number of seconds"
        ) from None
    return value


def _read_report(path: str) -> bytes:
    size = Path(path).stat().st_size
    if size > MAX_INPUT_BYTES:
        raise OSError(f"{size} bytes exceeds the {MAX_INPUT_BYTES}-byte limit")
    return Path(path).read_bytes()


def _cmd_verify(args: argparse.Namespace) -> int:
    """Exit 0 only if the report is accepted under the selected policy.

    0 accepted | 1 well-formed report refused by policy (including
    SELF_SIGNED_ONLY) | 2 invalid input, command usage or an incompatible
    combination of options | 3 a required trust or verification resource that
    was specified is unavailable or unusable (trust store, replay store). stdout
    carries the JSON verdict for exit 0 and 1 only.
    """
    try:
        env = parse_envelope(_read_report(args.input))
    except OSError as exc:
        sys.stderr.write(f"cannot read {args.input!r}: {exc}\n")
        return 2
    except (CanonicalError, EnvelopeFormatError) as exc:
        sys.stderr.write(f"malformed report: {exc}\n")
        return 2

    trust_store: TrustStore | None = None
    if args.trusted_keys is not None:  # supplied (even if empty) => it must be usable
        try:
            trust_store = TrustStore.from_json(args.trusted_keys.strip())
        except TrustStoreError as exc:
            sys.stderr.write(f"--trusted-keys: {exc}\n")
            return 3
    if trust_store is None and not args.allow_self_signed:
        sys.stderr.write(
            "no trust material: pass --trusted-keys to authenticate the issuer, or "
            "--allow-self-signed for a development-only integrity check "
            "(which can never accept a report).\n"
        )
        return 2

    replay_cache: SqliteReplayCache | None = None
    if args.replay_mode != "off":
        if not args.replay_db:
            sys.stderr.write("--replay-mode requires --replay-db\n")
            return 2
        try:
            replay_cache = SqliteReplayCache(args.replay_db)
        except ReplayStateError as exc:
            sys.stderr.write(f"--replay-db: {exc}\n")
            return 3

    try:
        policy = VerificationPolicy(
            profile=args.profile,
            trust_store=trust_store,
            allow_self_signed=args.allow_self_signed,
            allow_legacy_v1=False if args.refuse_legacy_v1 else None,
            verifier_id=args.verifier_id,
            max_age=timedelta(seconds=args.max_age_seconds) if args.max_age_seconds else None,
            replay_cache=replay_cache,
            replay_mode=args.replay_mode,
        )
    except PolicyError as exc:
        # An invalid or incompatible combination of options is a command
        # configuration error (2), not a failure of verification infrastructure.
        sys.stderr.write(f"invalid configuration: {exc}\n")
        return 2
    try:
        result = verify(env, policy)
    except VerificationUnavailable as exc:
        sys.stderr.write(f"verification not possible: {exc}\n")
        return 3

    if "REPLAY_STATE_UNAVAILABLE" in result.blocking_reasons:
        # The replay store could not be used while verifying. That is an
        # infrastructure failure, not a verdict on the report (exit 3, not 1).
        sys.stderr.write("verification not possible: the replay store was unavailable\n")
        return 3
    payload = result.to_dict()
    payload["trusted_issuer"] = result.issuer_trusted
    if not result.accepted:
        payload["reason"] = (
            result.blocking_reasons[0] if result.blocking_reasons else result.reasons[0]
        )
    print(json.dumps(payload, indent=2))
    return 0 if result.accepted else 1


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
    audit.add_argument(
        "--schema", action="store_true", help="Print the expected input schema and exit."
    )
    audit.set_defaults(func=_cmd_audit)

    verify_p = sub.add_parser(
        "verify",
        help="Verify an audit envelope (exit 0 only if accepted; see --help epilog).",
        epilog="Exit codes: 0 accepted; 1 refused by policy (including SELF_SIGNED_ONLY); "
        "2 invalid input, usage or incompatible options; 3 a specified trust or verification "
        "resource is unavailable or unusable.",
    )
    verify_p.add_argument("--input", "-i", required=True, help="Audit envelope JSON to verify")
    verify_p.add_argument(
        "--trusted-keys",
        help="Path to a TrustStore JSON (entries form, or the legacy keys/revoked/pins form). "
        "Required to authenticate the issuer.",
    )
    verify_p.add_argument(
        "--strict",
        action="store_true",
        help="Kept for compatibility: trust material is always required (see "
        "--allow-self-signed for the development-only alternative).",
    )
    verify_p.add_argument(
        "--allow-self-signed",
        action="store_true",
        help="DEVELOPMENT ONLY. Check integrity without trust material. The result is "
        "SELF_SIGNED_ONLY and the command exits 1, never 0. With --trusted-keys it has no "
        "effect in the development profile; it is refused (exit 2) in any other profile.",
    )
    verify_p.add_argument("--profile", choices=PROFILES, default="development")
    verify_p.add_argument("--verifier-id", help="This verifier's audience identifier.")
    verify_p.add_argument(
        "--max-age-seconds",
        type=_positive_seconds,
        help="Refuse reports older than this many seconds.",
    )
    verify_p.add_argument("--replay-db", help="sqlite file for the local persistent replay cache.")
    verify_p.add_argument(
        "--replay-mode",
        choices=("off", "check", "record"),
        default="off",
        help="Local replay detection. 'record' marks the report as seen in --replay-db "
        "(local only; not a global single-use guarantee).",
    )
    verify_p.add_argument(
        "--refuse-legacy-v1", action="store_true", help="Refuse report.v1 envelopes."
    )
    verify_p.set_defaults(func=_cmd_verify)

    serve = sub.add_parser("serve", help="Run the HTTP audit server (requires [server]).")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", "-p", type=int, default=8080)
    serve.add_argument(
        "--trust-store",
        help="TrustStore JSON used by /v1/verify (overrides REGAUDIT_FHE_TRUST_STORE). "
        "Without one, /v1/verify fails closed.",
    )
    serve.add_argument(
        "--allow-self-signed",
        action="store_true",
        help="DEVELOPMENT ONLY. Let /v1/verify report SELF_SIGNED_ONLY when no trust "
        "store is set. Never yields TRUSTED; refused outside the development "
        "profile and on non-loopback binds.",
    )
    serve.set_defaults(func=_cmd_serve)

    schema = sub.add_parser("schema", help="Dump a bundled JSON Schema by name.")
    schema.add_argument("name", nargs="?", help="Schema name (e.g. fairness.input, envelope).")
    schema.add_argument("--list", action="store_true", help="List all bundled schema names.")
    schema.set_defaults(func=_cmd_schema)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
