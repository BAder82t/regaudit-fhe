"""``regaudit-fhe revocation ...`` and the revocation options of ``verify``. EXPERIMENTAL, off by default.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import stat
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import _revocation as rv
from . import _revocation_gate as gate
from . import _revocation_state as st
from . import _revocation_tooling as tooling
from ._keys import load_ed25519_public_key, spki_fingerprint
from .canonical import CanonicalError, loads_strict
from .reports import Signer
from .trust import TrustStore, TrustStoreError
from .verification import PolicyError


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2))


def _read_key_confirmed(path: str, fingerprint: str, what: str) -> str:
    """Out-of-band enrollment: the key file must match the fingerprint the issuer gave the operator."""
    try:
        pem = Path(path).read_text(encoding="ascii")
        load_ed25519_public_key(pem)
        actual = spki_fingerprint(pem)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot use {path!r} as the {what}'s Ed25519 public key: {exc}") from exc
    if actual != fingerprint.strip().lower():
        raise ValueError(
            f"{what}: fingerprint mismatch, nothing enrolled. The file has {actual}. Compare it against "
            "the value received out of band."
        )
    return pem.strip().replace("\r\n", "\n") + "\n"


def _state_dir(path: str) -> st.FileStateStore:
    directory = Path(path)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return st.FileStateStore(directory)


def _trust_store(path: str | None) -> TrustStore | None:
    return TrustStore.from_json(path) if path else None


def _baseline(args: argparse.Namespace) -> tuple[int | None, str | None]:
    if args.first_use:
        if args.baseline_epoch is not None or args.baseline_digest:
            raise ValueError("--first-use excludes a baseline")
        return None, None
    if args.baseline_epoch is None:
        raise ValueError(
            "state --baseline-epoch (0 if no list exists yet), or --first-use for advisory"
        )
    if args.baseline_epoch < 0:
        raise ValueError("--baseline-epoch must not be negative")
    if args.baseline_epoch > 0 and not re.fullmatch(r"[0-9a-f]{64}", args.baseline_digest or ""):
        raise ValueError("--baseline-digest (64 hex) is required when --baseline-epoch is above 0")
    if args.baseline_epoch == 0 and args.baseline_digest:
        raise ValueError("--baseline-epoch 0 means no list exists yet, so it takes no digest")
    return args.baseline_epoch, args.baseline_digest or None


def _pin_from_args(args: argparse.Namespace) -> st.Pin:
    authority = _read_key_confirmed(args.authority_key, args.authority_fingerprint, "authority")
    anchor = None
    if args.anchor_key:
        if not args.anchor_fingerprint:
            raise ValueError("--anchor-key needs --anchor-fingerprint")
        anchor = _read_key_confirmed(args.anchor_key, args.anchor_fingerprint, "recovery anchor")
    epoch, digest = _baseline(args)
    pin = st.Pin(
        issuer=args.issuer,
        authority_pem=authority,
        enrollment_id=uuid.uuid4().hex,
        recovery_pem=anchor,
        baseline_epoch=epoch,
        baseline_digest=digest,
        authority_generation=args.authority_generation,
        recovery_epoch=args.recovery_epoch,
        recovery_digest=args.recovery_digest or None,
    )
    try:
        st.check_pin(pin)
    except st.PinStoreError as exc:
        raise ValueError(str(exc)) from exc
    return pin


def _cmd_enroll(args: argparse.Namespace) -> int:
    """Exit 0 enrolled | 2 refused | 3 a store is unusable."""
    try:
        pin = _pin_from_args(args)
        store = _trust_store(args.trusted_keys)
        pins = st.load_pins(args.pins) if Path(args.pins).exists() else {}
    # TrustStoreError is a ValueError, so this comes first
    except (st.PinStoreError, TrustStoreError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 3
    except ValueError as exc:
        sys.stderr.write(f"refused, nothing enrolled: {exc}\n")
        return 2
    if pin.issuer in pins:
        sys.stderr.write("this issuer is already enrolled; re-baselining is a separate ceremony\n")
        return 2
    try:
        state = _state_dir(args.state)
        st.enroll(state, pin, store, now=_now())
        st.save_pin(args.pins, pin)
    except ValueError as exc:
        sys.stderr.write(f"refused, nothing enrolled: {exc}\n")
        return 2
    except (st.StateUnavailable, st.PinStoreError, OSError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 3
    _emit(
        {
            "enrolled": pin.issuer,
            "authority_fingerprint": spki_fingerprint(pin.authority_pem),
            "recovery_anchor_fingerprint": spki_fingerprint(pin.recovery_pem)
            if pin.recovery_pem
            else None,
            "enrollment_id": pin.enrollment_id,
            "baseline_epoch": pin.baseline_epoch,
            "state_store_scope": state.scope,
        }
    )
    return 0


def _cmd_rebaseline(args: argparse.Namespace) -> int:
    try:
        pin = _pin_from_args(args)
        store = _trust_store(args.trusted_keys)
        state = _state_dir(args.state)
        st.rebaseline(
            state,
            pin,
            now=_now(),
            trust_store=store,
            clear_effective=args.clear_key_actions,
            accept_loss=args.accept_loss,
            reset_policy_floor=args.reset_policy_floor,
        )
        st.save_pin(args.pins, pin)
    # TrustStoreError is a ValueError, so this comes first
    except (st.StateUnavailable, st.PinStoreError, TrustStoreError, OSError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 3
    except ValueError as exc:
        sys.stderr.write(f"refused: {exc}\n")
        return 2
    _emit({"rebaselined": pin.issuer, "enrollment_id": pin.enrollment_id})
    return 0


def _context_parts(args: argparse.Namespace) -> tuple[st.FileStateStore, st.Pin]:
    pins = st.load_pins(args.pins)
    pin = pins.get(args.issuer)
    if pin is None:
        raise st.PinStoreError(f"issuer {args.issuer!r} is not enrolled")
    return st.FileStateStore(args.state), pin


def _cmd_status(args: argparse.Namespace) -> int:
    try:
        state, pin = _context_parts(args)
        rec, _ = st.load(state, pin)
    except (st.PinStoreError, st.StateUnavailable) as exc:
        sys.stderr.write(f"{type(exc).__name__}: {exc}\n")
        return 3
    enrollment = rec.state.enrollments[pin.issuer]
    mark = rec.state.get(pin.issuer)
    _emit(
        {
            "issuer": pin.issuer,
            "seq": rec.seq,
            "authority_fingerprint": enrollment.authority_fingerprint,
            "generation": enrollment.generation,
            "recovery_epoch": enrollment.recovery_epoch,
            "compromised_authorities": enrollment.compromised,
            "superseded_authorities": list(enrollment.superseded),
            "mark": {
                "epoch": mark.epoch,
                "digest": mark.digest,
                "issued_at": mark.issued_at,
                "valid_until": mark.valid_until,
            }
            if mark
            else None,
            "key_actions": rec.effective,
            "contradiction": rec.contradiction,
            "policy_floor": rec.policy_floor,
            "state_store_scope": state.scope,
            "limit": rv.ROLLBACK_LIMIT,
        }
    )
    return 0


def _read_document(path: str) -> bytes:
    """Regular file, bounded. One byte over the limit is enough for the verifier to refuse it as malformed."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError(f"{path}: not a regular file")
        return handle.read(rv.MAX_BYTES + 1)


def _cmd_ingest(args: argparse.Namespace) -> int:
    """Exit 0 accepted | 1 refused | 3 a store is unusable."""
    try:
        state, pin = _context_parts(args)
        store = TrustStore.from_json(args.trusted_keys)
        raw = _read_document(args.document)
    except (st.PinStoreError, TrustStoreError, OSError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 3
    if args.kind == "list":
        out = st.ingest_list(state, pin, raw, store, _now())
    elif args.kind == "transition":
        out = st.ingest_transition(state, pin, raw, store, _now())
    else:
        out = st.ingest_recovery(state, pin, raw, store, _now())
    _emit({"accepted": out.accepted, "code": out.code, "notes": list(out.notes), "seq": out.seq})
    # The pin was just read, so "not enrolled" here is a document naming another issuer: a refusal.
    if out.code in gate.INFRASTRUCTURE_CODES and out.code != "REVOCATION_NOT_ENROLLED":
        return 3
    return 0 if out.accepted else 1


def _public_key(path: str | None) -> str | None:
    if not path:
        return None
    pem = Path(path).read_text(encoding="ascii")
    load_ed25519_public_key(pem)
    return pem


def _signer(path: str, issuer: str, key_id: str) -> Signer:
    if os.name == "posix" and stat.S_IMODE(Path(path).stat().st_mode) & 0o077:
        raise ValueError(f"{path}: permissions are too open; run: chmod 600 {path}")
    return Signer.from_pem(
        issuer=issuer, key_id=key_id, private_pem=Path(path).read_bytes(), password=None
    )


def _action(text: str, status: str) -> tooling.KeyAction:
    """KEY_ID,FINGERPRINT[,TIME[,SUCCESSOR_ID,SUCCESSOR_FINGERPRINT]]"""
    parts = text.split(",")
    if len(parts) not in (2, 3, 5):
        raise tooling.ActionRefused(f"cannot parse {text!r}")
    effective = parts[2] if len(parts) >= 3 and parts[2] else None
    successor = (parts[3], parts[4]) if len(parts) == 5 else None
    return tooling.KeyAction(parts[0], parts[1], status, effective, successor)


def _cmd_sign_list(args: argparse.Namespace) -> int:
    """Exit 0 signed | 2 refused, nothing signed or released | 3 the publisher state is unusable."""
    try:
        actions = (
            [_action(x, "retired") for x in args.retire or []]
            + [_action(x, "replaced") for x in args.replace or []]
            + [_action(x, "compromised") for x in args.compromise or []]
        )
        signer = _signer(args.signing_key, args.issuer, args.key_id)
        store = _trust_store(args.trusted_keys)
        if actions and store is None and not args.allow_unknown_keys:
            raise tooling.ActionRefused(
                "an entry can never be withdrawn, so check it against your report keys: pass --trusted-keys, "
                "or --allow-unknown-keys"
            )
        with tooling.publisher_lock(args.publisher_state):
            previous = tooling.load_publisher_state(args.publisher_state)
            if previous is None and not args.initial:
                raise tooling.ActionRefused(
                    "no publisher state at this path. Starting again at epoch 1 would be a fork, which stops "
                    "every verifier for this issuer. For a genuine first list, pass --initial"
                )
            if previous is not None and args.initial:
                raise tooling.ActionRefused("--initial, but a publisher state exists")
            recovery = None
            if args.after_recovery:
                recovery = loads_strict(_read_document(args.after_recovery), max_bytes=rv.MAX_BYTES)
                rv.validate_recovery_shape(recovery)
            result = tooling.next_list(
                issuer=args.issuer,
                authority=signer,
                generation=args.generation,
                previous=previous,
                actions=actions,
                now=_now(),
                valid_for=timedelta(hours=args.valid_for_hours),
                trust_store=store,
                recovery_anchor_pem=_public_key(args.recovery_anchor_key),
                allow_unknown_keys=args.allow_unknown_keys,
                after_recovery=recovery,
            )
            tooling.persist_before_release(args.publisher_state, result.document)
    except (
        ValueError,
        TypeError,
        OverflowError,
        OSError,
        RecursionError,
        CanonicalError,
        TrustStoreError,
    ) as exc:
        sys.stderr.write(f"refused, nothing released: {exc}\n")
        return 2
    try:
        Path(args.output).write_text(json.dumps(result.document, indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        # Persisted but not released. The next run moves on to a higher epoch: a gap, never a fork.
        sys.stderr.write(f"signed and recorded, but not written: {exc}\n")
        return 3
    _emit({"epoch": result.document["epoch"], "digest": result.digest, "output": args.output})
    return 0


def _cmd_sign_transition(args: argparse.Namespace) -> int:
    try:
        document = tooling.sign_transition_statement(
            issuer=args.issuer,
            from_signer=_signer(args.signing_key, args.issuer, args.key_id),
            from_generation=args.generation,
            to_signer=_signer(args.new_signing_key, args.issuer, args.new_key_id),
            now=_now(),
            trust_store=_trust_store(args.trusted_keys),
            recovery_anchor_pem=_public_key(args.recovery_anchor_key),
        )
        Path(args.output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    except (ValueError, TypeError, OSError, TrustStoreError) as exc:
        sys.stderr.write(f"refused, nothing released: {exc}\n")
        return 2
    _emit({"digest": rv.transition_digest(document), "output": args.output})
    return 0


def _cmd_sign_recovery(args: argparse.Namespace) -> int:
    try:
        previous = None
        if args.previous:
            previous = loads_strict(_read_document(args.previous), max_bytes=rv.MAX_BYTES)
            rv.validate_recovery_shape(previous)
        declares: list[tuple[str, str | None]] = []
        for item in args.declare:
            fingerprint, _, boundary = item.partition(",")
            declares.append((fingerprint, boundary or None))
        rebase = None
        if args.rebase_epoch is not None:
            rebase = {"epoch": args.rebase_epoch, "list_digest": args.rebase_digest}
        document = tooling.sign_recovery_statement(
            issuer=args.issuer,
            anchor=_signer(args.anchor_signing_key, args.issuer, args.anchor_key_id),
            new_authority=_signer(args.new_signing_key, args.issuer, args.new_key_id),
            new_generation=args.new_generation,
            recovery_epoch=args.recovery_epoch,
            declares=declares,
            now=_now(),
            previous=previous,
            rebase=rebase,
        )
        Path(args.output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    except (ValueError, TypeError, KeyError, OSError, RecursionError, CanonicalError) as exc:
        sys.stderr.write(f"refused, nothing released: {exc}\n")
        return 2
    _emit({"digest": rv.recovery_digest(document), "output": args.output})
    return 0


def _pin_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pins", required=True, help="Pinned-authority file.")
    parser.add_argument("--state", required=True, help="State directory (mode 0700).")
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--authority-key", required=True, help="Authority public key (PEM file).")
    parser.add_argument(
        "--authority-fingerprint", required=True, help="Received out of band; the file must match."
    )
    parser.add_argument("--anchor-key", help="Recovery anchor public key (PEM file).")
    parser.add_argument("--anchor-fingerprint", help="Received out of band; the file must match.")
    parser.add_argument(
        "--baseline-epoch", type=int, help="Newest list known out of band; 0 if none."
    )
    parser.add_argument("--baseline-digest", help="Digest of that list.")
    parser.add_argument("--first-use", action="store_true", help="No baseline. Advisory mode only.")
    parser.add_argument("--authority-generation", type=int, default=1)
    parser.add_argument("--recovery-epoch", type=int, default=0)
    parser.add_argument("--recovery-digest")
    parser.add_argument("--trusted-keys", help="Trust store, for the purpose checks.")


def add_parsers(sub: Any) -> None:
    rev = sub.add_parser(
        "revocation",
        help="EXPERIMENTAL: signed revocation data. Nothing here affects verify unless opted in.",
    )
    cmds = rev.add_subparsers(dest="revocation_command", required=True)

    enroll = cmds.add_parser(
        "enroll",
        help="Enrol an issuer's revocation authority, from fingerprints received out of band.",
    )
    _pin_args(enroll)
    enroll.set_defaults(func=_cmd_enroll)

    again = cmds.add_parser(
        "rebaseline",
        help="Ceremony after lost, restored or contradicted state. Never loosens as a side effect.",
    )
    _pin_args(again)
    again.add_argument("--accept-loss", action="store_true", help="The old record is gone: say so.")
    again.add_argument(
        "--clear-key-actions",
        action="store_true",
        help="Forget listed key actions. A local act, not an issuer statement.",
    )
    again.add_argument(
        "--reset-policy-floor",
        action="store_true",
        help="Forget the strictest gate settings served. A local act.",
    )
    again.set_defaults(func=_cmd_rebaseline)

    status = cmds.add_parser("status", help="Read-only view of one issuer's state.")
    status.add_argument("--pins", required=True)
    status.add_argument("--state", required=True)
    status.add_argument("--issuer", required=True)
    status.set_defaults(func=_cmd_status)

    ingest = cmds.add_parser("ingest", help="Verify one signed document and advance the state.")
    ingest.add_argument("kind", choices=["list", "transition", "recovery"])
    ingest.add_argument("document")
    ingest.add_argument("--pins", required=True)
    ingest.add_argument("--state", required=True)
    ingest.add_argument("--issuer", required=True)
    ingest.add_argument("--trusted-keys", required=True)
    ingest.set_defaults(func=_cmd_ingest)

    sign = cmds.add_parser(
        "sign-list",
        help="Issuer: sign the next cumulative list. Refuses hazardous actions before signing.",
    )
    sign.add_argument("--signing-key", required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--issuer", required=True)
    sign.add_argument("--generation", type=int, default=1)
    sign.add_argument(
        "--publisher-state", required=True, help="Written before the list is released."
    )
    sign.add_argument("--output", required=True)
    sign.add_argument("--valid-for-hours", type=float, default=48.0)
    sign.add_argument(
        "--trusted-keys",
        help="Your report keys: an action must name one, with its fingerprint, since an entry can never be withdrawn.",
    )
    sign.add_argument(
        "--allow-unknown-keys",
        action="store_true",
        help="An action names a key not in --trusted-keys.",
    )
    sign.add_argument(
        "--initial",
        action="store_true",
        help="This is the first list; no publisher state exists yet.",
    )
    sign.add_argument("--recovery-anchor-key", help="Anchor public key, for the purpose check.")
    sign.add_argument("--after-recovery", help="The statement that installed this signer.")
    sign.add_argument("--retire", action="append", help="KEY_ID,FINGERPRINT,TIME")
    sign.add_argument(
        "--replace",
        action="append",
        help="KEY_ID,FINGERPRINT,TIME,SUCCESSOR_ID,SUCCESSOR_FINGERPRINT",
    )
    sign.add_argument(
        "--compromise",
        action="append",
        help="KEY_ID,FINGERPRINT[,TIME]; no TIME = unknown boundary",
    )
    sign.set_defaults(func=_cmd_sign_list)

    rotate = cmds.add_parser("sign-transition", help="Issuer: routine rotation of the authority.")
    rotate.add_argument("--signing-key", required=True)
    rotate.add_argument("--key-id", required=True)
    rotate.add_argument("--issuer", required=True)
    rotate.add_argument("--generation", type=int, required=True)
    rotate.add_argument("--new-signing-key", required=True)
    rotate.add_argument("--new-key-id", required=True)
    rotate.add_argument("--trusted-keys")
    rotate.add_argument("--recovery-anchor-key", help="Anchor public key, for the purpose check.")
    rotate.add_argument("--output", required=True)
    rotate.set_defaults(func=_cmd_sign_transition)

    recover = cmds.add_parser("sign-recovery", help="Issuer: compromise recovery, by the anchor.")
    recover.add_argument("--anchor-signing-key", required=True)
    recover.add_argument("--anchor-key-id", required=True)
    recover.add_argument("--issuer", required=True)
    recover.add_argument("--new-signing-key", required=True)
    recover.add_argument("--new-key-id", required=True)
    recover.add_argument("--new-generation", type=int, required=True)
    recover.add_argument("--recovery-epoch", type=int, required=True)
    recover.add_argument("--declare", action="append", required=True, help="FINGERPRINT[,TIME]")
    recover.add_argument(
        "--previous", help="The previous statement, to keep declarations cumulative."
    )
    recover.add_argument("--rebase-epoch", type=int)
    recover.add_argument("--rebase-digest")
    recover.add_argument("--output", required=True)
    recover.set_defaults(func=_cmd_sign_recovery)


def add_verify_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--revocation-mode",
        choices=gate.MODES,
        default=gate.MODE_OFF,
        help="EXPERIMENTAL. 'off' (default) does not evaluate revocation and does not change this output. "
        "'required' fails closed without fresh evidence. Refused with --profile high-assurance: no "
        "independently protected state store is qualified.",
    )
    parser.add_argument("--revocation-pins", help="Pinned-authority file.")
    parser.add_argument(
        "--revocation-state", help="State directory (single-host, local file store)."
    )
    parser.add_argument(
        "--revocation-evidence-age-seconds",
        type=float,
        help="Oldest list to rely on. At most 86400, which is also the default.",
    )
    parser.add_argument(
        "--response-format",
        choices=("v1", "v2"),
        default="v1",
        help="v1 (default) is the unchanged output. v2 adds response_format, revocation_evaluation "
        "(not_evaluated, evaluated, required_but_unavailable) and a policy_evidence section, and also prints them "
        "when a required resource is unusable (exit 3). A revocation mode always uses v2.",
    )
    parser.add_argument(
        "--policy-evidence", action="store_true", help="The same as --response-format v2."
    )


def _evidence_age(seconds: float | None) -> timedelta:
    if seconds is None:
        return gate.DEFAULT_MAX_EVIDENCE_AGE
    if not math.isfinite(seconds) or seconds <= 0:
        raise PolicyError("--revocation-evidence-age-seconds must be positive and finite")
    try:
        return timedelta(seconds=seconds)
    except OverflowError as exc:
        raise PolicyError("--revocation-evidence-age-seconds is capped at 86400") from exc


def build_context(args: argparse.Namespace) -> gate.RevocationContext:
    """Raises ``PolicyError`` for a configuration error (exit 2), ``PinStoreError`` for a broken resource (exit 3)."""
    if args.profile == "high-assurance":
        raise PolicyError(gate.HIGH_ASSURANCE_UNAVAILABLE)
    if not args.revocation_pins or not args.revocation_state:
        raise PolicyError("--revocation-mode needs --revocation-pins and --revocation-state")
    return gate.RevocationContext(
        args.revocation_mode,
        st.FileStateStore(args.revocation_state),
        st.load_pins(args.revocation_pins),
        _evidence_age(args.revocation_evidence_age_seconds),
    )


def refuses_trust_add(pins_path: str, fingerprint: str) -> str | None:
    """Why ``trust add`` must refuse this key, if a pin names it as an authority or anchor."""
    for issuer, pin in st.load_pins(pins_path).items():
        if spki_fingerprint(pin.authority_pem) == fingerprint:
            return f"this key is {issuer}'s enrolled revocation authority"
        if pin.recovery_pem is not None and spki_fingerprint(pin.recovery_pem) == fingerprint:
            return f"this key is {issuer}'s enrolled recovery anchor"
    return None
