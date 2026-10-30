"""regaudit-fhe command-line interface.

Usage examples:

    regaudit-fhe audit fairness --input fairness.json --output report.json
    regaudit-fhe audit drift   --input drift.json
    regaudit-fhe verify        --input report.json

Each primitive's input JSON shape is echoed by ``regaudit-fhe audit <primitive> --schema``;
the full JSON Schemas are listed by ``regaudit-fhe schema --list``.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import stat
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

import numpy as np
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import (
    audit_calibration,
    audit_concordance,
    audit_disagreement,
    audit_drift,
    audit_fairness,
    audit_provenance,
)
from ._keys import load_ed25519_public_key, spki_fingerprint
from ._limits import active_limits, check_primitive_cost
from .canonical import MAX_INPUT_BYTES, CanonicalError, loads_strict
from .replay import ReplayStateError, SqliteReplayCache
from .report_v2 import AuditEnvelopeV2, EnvelopeFormatError, envelope_v2, parse_envelope_strict
from .reports import AuditEnvelope, Signer, commitments_for, envelope
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


def _run_primitive(primitive: str, payload: dict[str, Any]) -> Any:
    # Before schema validation and before any allocation: the same cost limits the server applies, so
    # the CLI and library path cannot reach an excessive allocation either.
    check_primitive_cost(primitive, payload, active_limits())
    validate_input(primitive, payload)
    if primitive == "fairness":
        return audit_fairness(
            np.asarray(payload["y_true"], dtype=float),
            np.asarray(payload["y_pred"], dtype=float),
            np.asarray(payload["group_a"], dtype=float),
            np.asarray(payload["group_b"], dtype=float),
            threshold=payload.get("threshold", 0.1),
        )
    if primitive == "provenance":
        return audit_provenance(
            np.asarray(payload["attributions"], dtype=float),
            np.asarray(payload["row_ids"], dtype=np.int64),
            int(payload["n_buckets"]),
            int(payload["k"]),
        )
    if primitive == "concordance":
        return audit_concordance(
            np.asarray(payload["risk"], dtype=float),
            np.asarray(payload["time"], dtype=float),
            np.asarray(payload["event"], dtype=float),
        )
    if primitive == "calibration":
        return audit_calibration(
            np.asarray(payload["scores"], dtype=float),
            np.asarray(payload["quantiles"], dtype=float),
        )
    if primitive == "drift":
        return audit_drift(
            np.asarray(payload["p"], dtype=float),
            np.asarray(payload["q"], dtype=float),
            drift_threshold=payload.get("drift_threshold", 0.05),
        )
    if primitive == "disagreement":
        return audit_disagreement(
            payload["model_polynomials"],
            np.asarray(payload["test_input"], dtype=float),
            threshold=payload.get("threshold", 0.05),
        )
    raise ValueError(f"unknown primitive {primitive!r}")


def _audit_dispatch(primitive: str, payload: dict[str, Any]) -> AuditEnvelope:
    """Run a primitive and wrap it in a report.v1 signed with an ephemeral key (legacy path)."""
    return envelope(primitive, _run_primitive(primitive, payload))


_EPHEMERAL_NOTE = (
    "note: this report.v1 is signed with an ephemeral key generated for this run, so it can "
    "only ever verify as SELF_SIGNED_ONLY. To issue a report a verifier can trust, sign with "
    "a long-lived key through the library (regaudit_fhe.envelope_v2); see "
    "examples/strict_verification_quickstart.py.\n"
)


def _cmd_audit(args: argparse.Namespace) -> int:
    if args.schema:
        print(json.dumps(SCHEMAS[args.primitive], indent=2))
        return 0
    if not args.input:
        sys.stderr.write(
            f"regaudit-fhe audit {args.primitive}: --input FILE is required "
            f"(see 'regaudit-fhe audit {args.primitive} --schema' for its shape)\n"
        )
        return 2
    try:
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        sys.stderr.write(f"cannot read {args.input!r}: {exc}\n")
        return 2
    except (ValueError, RecursionError) as exc:
        sys.stderr.write(f"{args.input!r} is not valid JSON: {exc}\n")
        return 2
    if not isinstance(payload, dict):
        sys.stderr.write(
            f"input rejected: {args.input!r} must contain a JSON object, "
            f"not {type(payload).__name__}\n"
        )
        return 2
    signing = _signing_args(args)
    if isinstance(signing, int):
        return signing
    try:
        env: AuditEnvelope | AuditEnvelopeV2
        if signing is None:
            env = _audit_dispatch(args.primitive, payload)
        else:
            env = envelope_v2(
                args.primitive,
                _run_primitive(args.primitive, payload),
                signer=signing,
                deployment_id=args.deployment_id,
                audience=args.audience or None,
                input_commitments=commitments_for(payload),
            )
    except SchemaError as exc:
        sys.stderr.write(f"input rejected: {exc}\n")
        return 2
    except ValueError as exc:  # e.g. mismatched vector lengths, non-finite values
        sys.stderr.write(f"input rejected: {exc}\n")
        return 2
    out = env.to_json()
    if args.output:
        try:
            Path(args.output).write_text(out + "\n")
        except OSError as exc:
            sys.stderr.write(f"cannot write {args.output!r}: {exc}\n")
            return 2
    else:
        sys.stdout.write(out + "\n")
    if signing is None:
        sys.stderr.write(_EPHEMERAL_NOTE)
    else:
        sys.stderr.write(
            f"signed report.v2 as key_id {signing.key_id!r} (issuer {signing.issuer!r}). "
            "It verifies as TRUSTED only for a verifier whose own trust store enrols this key: "
            "regaudit-fhe verify --input REPORT --trusted-keys STORE\n"
        )
    return 0


def _signing_args(args: argparse.Namespace) -> Signer | int | None:
    """Return a Signer for ``--signing-key``, None for the legacy ephemeral path, or an exit code."""
    given = [
        name
        for name in ("signing_key", "key_id", "issuer", "deployment_id")
        if getattr(args, name, None)
    ]
    if not given:
        if args.audience:
            sys.stderr.write("--audience needs --signing-key (it applies to report.v2 only)\n")
            return 2
        return None
    missing = [
        flag
        for flag, name in (
            ("--signing-key", "signing_key"),
            ("--key-id", "key_id"),
            ("--issuer", "issuer"),
            ("--deployment-id", "deployment_id"),
        )
        if not getattr(args, name, None)
    ]
    if missing:
        sys.stderr.write(
            f"signing a report.v2 needs all of --signing-key, --key-id, --issuer and "
            f"--deployment-id; missing {', '.join(missing)}\n"
        )
        return 2
    try:
        _check_private_key_mode(args.signing_key)
        pem = Path(args.signing_key).read_bytes()
    except OSError as exc:
        sys.stderr.write(f"cannot read signing key {args.signing_key!r}: {exc}\n")
        return 2
    try:
        return Signer.from_pem(
            issuer=args.issuer, key_id=args.key_id, private_pem=pem, password=None
        )
    except (ValueError, TypeError) as exc:
        sys.stderr.write(
            f"cannot load {args.signing_key!r} as an unencrypted Ed25519 private key (PEM): "
            f"{type(exc).__name__}\n"
        )
        return 2


def _check_private_key_mode(path: str) -> None:
    """Refuse a private key that other local users can read (like ssh does)."""
    if os.name != "posix":
        return
    mode = stat.S_IMODE(Path(path).stat().st_mode)
    if mode & 0o077:
        raise OSError(f"permissions {mode:04o} are too open; run: chmod 600 {path}")


def _write_new_file(path: str, data: bytes, mode: int) -> None:
    """Create ``path`` exclusively with ``mode``; never overwrite an existing file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise


def _cmd_keygen(args: argparse.Namespace) -> int:
    """Create a long-lived Ed25519 signing key. Exit 0 created | 2 refused (nothing overwritten)."""
    for flag, value in (("--key-id", args.key_id), ("--issuer", args.issuer)):
        if not value or len(value) > 256:
            sys.stderr.write(f"{flag} must be 1..256 characters\n")
            return 2
    if os.path.abspath(args.private_key) == os.path.abspath(args.public_key):
        sys.stderr.write("--private-key and --public-key must be different files\n")
        return 2
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    try:
        _write_new_file(args.private_key, private_pem, 0o600)
    except OSError as exc:
        sys.stderr.write(
            f"cannot create {args.private_key!r}: {exc} (existing files are never overwritten)\n"
        )
        return 2
    try:
        _write_new_file(args.public_key, public_pem, 0o644)
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.unlink(args.private_key)
        sys.stderr.write(
            f"cannot create {args.public_key!r}: {exc} (existing files are never overwritten)\n"
        )
        return 2
    fingerprint = spki_fingerprint(public_pem.decode("ascii"))
    print(
        json.dumps(
            {
                "key_id": args.key_id,
                "issuer": args.issuer,
                "algorithm": "ed25519",
                "fingerprint_sha256": fingerprint,
                "private_key": args.private_key,
                "public_key": args.public_key,
            },
            indent=2,
        )
    )
    sys.stderr.write(
        "The private key is an UNENCRYPTED file (mode 0600). Keep it out of version control and "
        "backups you do not control; for production use a KMS/HSM-backed signer through the "
        "library. Give the verifier the PUBLIC key and this fingerprint over a channel you "
        "trust, then have them run: regaudit-fhe trust add\n"
    )
    return 0


def _load_store_payload(path: str) -> dict[str, Any] | None:
    """The raw ``entries``-form payload of an existing trust store, or None if the file is absent."""
    if not Path(path).exists():
        return None
    payload = loads_strict(Path(path).read_bytes(), max_bytes=MAX_INPUT_BYTES)
    if not isinstance(payload, dict) or "entries" not in payload:
        raise TrustStoreError(
            f"{path!r} is not an 'entries' trust store; refusing to convert or overwrite it"
        )
    return payload


def _cmd_trust_add(args: argparse.Namespace) -> int:
    """Enrol one key in a trust store. Exit 0 enrolled | 2 refused | 3 store unusable.

    The key is added only when the operator names it and states its expected fingerprint.
    Nothing is ever enrolled from a report.
    """
    try:
        pem = Path(args.public_key).read_text(encoding="ascii")
        actual = spki_fingerprint(pem)
        load_ed25519_public_key(pem)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        sys.stderr.write(f"cannot use {args.public_key!r} as an Ed25519 public key: {exc}\n")
        return 2
    expected = args.fingerprint.strip().lower()
    if expected != actual:
        sys.stderr.write(
            "fingerprint mismatch: nothing enrolled. The public key file has SHA-256 "
            f"fingerprint {actual}, not {expected}. Compare it against the value the issuer "
            "gave you over a trusted channel.\n"
        )
        return 2
    if not args.key_id or len(args.key_id) > 256 or not args.issuer or len(args.issuer) > 256:
        sys.stderr.write("--key-id and --issuer must be 1..256 characters\n")
        return 2
    try:
        payload = _load_store_payload(args.store)
    except (TrustStoreError, CanonicalError, OSError, RecursionError) as exc:
        sys.stderr.write(f"--store: {exc}\n")
        return 3
    if payload is None:
        payload = {"entries": {}}
    entries = payload["entries"]
    if not isinstance(entries, dict):
        sys.stderr.write("--store: 'entries' must be an object\n")
        return 3
    if args.key_id in entries:
        sys.stderr.write(
            f"key_id {args.key_id!r} is already enrolled; rotate by enrolling the new key under a "
            "new key_id (existing entries are never replaced)\n"
        )
        return 2
    entries[args.key_id] = {
        "issuer": args.issuer,
        "public_key_pem": pem.strip().replace("\r\n", "\n") + "\n",
        "status": "active",
    }
    try:
        TrustStore.from_dict(payload)  # the same validation verification will apply
    except TrustStoreError as exc:
        sys.stderr.write(f"refused, nothing written: {exc}\n")
        return 2
    store_path = Path(args.store)
    try:
        fd, tmp = tempfile.mkstemp(dir=store_path.parent or ".", prefix=".trust-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, indent=2) + "\n")
            os.chmod(tmp, 0o644)
            os.replace(tmp, store_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
    except OSError as exc:
        sys.stderr.write(f"cannot write {args.store!r}: {exc}\n")
        return 2
    print(
        json.dumps(
            {
                "enrolled": args.key_id,
                "issuer": args.issuer,
                "fingerprint_sha256": actual,
                "store": args.store,
                "entries": len(entries),
            },
            indent=2,
        )
    )
    return 0


def _cmd_trust_list(args: argparse.Namespace) -> int:
    try:
        store = TrustStore.from_json(args.store)
    except TrustStoreError as exc:
        sys.stderr.write(f"--store: {exc}\n")
        return 3
    rows = []
    for key_id, pem in sorted(store.keys.items()):
        entry = store.entry(key_id)
        rows.append(
            {
                "key_id": key_id,
                "issuer": entry.issuer if entry else None,
                "status": entry.status if entry else None,
                "fingerprint_sha256": spki_fingerprint(pem),
            }
        )
    print(json.dumps(rows, indent=2))
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
    try:
        app = build_app(config=config)
    except RuntimeError as exc:  # PolicyError: an invalid numeric or budget setting
        sys.stderr.write(f"refusing to start: {exc}\n")
        return 2
    uvicorn.run(
        app,
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


def _refusal_hint(trust_status: str, reason: str | None) -> str:
    """One stderr line saying what a refusal means (stdout and the exit code are unchanged)."""
    if trust_status == "SELF_SIGNED_ONLY":
        return (
            "not accepted: SELF_SIGNED_ONLY. The report is intact and its signature matches the "
            "key embedded in it, but nothing shows who holds that key. Verify with "
            "--trusted-keys <your trust store> to authenticate the issuer."
        )
    return (
        f"not accepted: {trust_status} ({reason or 'see blocking_reasons'}). "
        "See blocking_reasons in the JSON above and docs/TRUST_SPEC.md."
    )


def _cmd_verify(args: argparse.Namespace) -> int:
    """Exit 0 only if the report is accepted under the selected policy.

    0 accepted | 1 well-formed report refused by policy (including
    SELF_SIGNED_ONLY) | 2 invalid input, command usage or an incompatible
    combination of options | 3 a required trust or verification resource that
    was specified is unavailable or unusable (trust store, replay store). stdout
    carries the JSON verdict for exit 0 and 1 only.
    """
    try:
        env = parse_envelope_strict(_read_report(args.input))
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
    if not result.accepted:
        sys.stderr.write(_refusal_hint(result.trust_status, payload.get("reason")) + "\n")
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
    audit.add_argument(
        "--signing-key",
        help="Private Ed25519 key (PEM, from 'regaudit-fhe keygen'). With --key-id, --issuer and "
        "--deployment-id the output is a report.v2 signed by this long-lived key instead of "
        "an ephemeral-key report.v1.",
    )
    audit.add_argument("--key-id", help="key_id the verifier's trust store knows this key by.")
    audit.add_argument("--issuer", help="Issuer name written into the signed report.")
    audit.add_argument("--deployment-id", help="Deployment identifier written into the report.")
    audit.add_argument(
        "--audience",
        action="append",
        help="Verifier identifier the report is meant for (repeatable); a verifier running with "
        "a different --verifier-id refuses it.",
    )
    audit.set_defaults(func=_cmd_audit)

    keygen = sub.add_parser(
        "keygen",
        help="Create a long-lived Ed25519 signing key (never overwrites).",
    )
    keygen.add_argument("--key-id", required=True)
    keygen.add_argument("--issuer", required=True)
    keygen.add_argument("--private-key", required=True, help="New file for the private key (0600).")
    keygen.add_argument("--public-key", required=True, help="New file for the public key (PEM).")
    keygen.set_defaults(func=_cmd_keygen)

    trust = sub.add_parser("trust", help="Manage a verifier's trust store.")
    trust_sub = trust.add_subparsers(dest="trust_command", required=True)
    t_add = trust_sub.add_parser(
        "add",
        help="Enrol one public key. Requires the fingerprint the issuer gave you.",
    )
    t_add.add_argument("--store", required=True, help="Trust store JSON (created if absent).")
    t_add.add_argument("--key-id", required=True)
    t_add.add_argument("--issuer", required=True)
    t_add.add_argument("--public-key", required=True, help="Issuer's public key (PEM file).")
    t_add.add_argument(
        "--fingerprint",
        required=True,
        help="Expected SHA-256 fingerprint of the key, received out of band. Enrolment is "
        "refused if the file does not match.",
    )
    t_add.set_defaults(func=_cmd_trust_add)
    t_list = trust_sub.add_parser("list", help="List the enrolled keys and their fingerprints.")
    t_list.add_argument("--store", required=True)
    t_list.set_defaults(func=_cmd_trust_list)

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
