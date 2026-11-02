"""Local trust-store lifecycle edits: ``trust status`` / ``retire`` / ``revoke``.

Everything here works inside the EXISTING ``entries`` trust-store format
(``status``, ``retired_at``, ``compromised_from``, ``as_of``). It adds no schema
member, and it changes nothing about how a store is verified.

A local file is editable by anyone who can write it. This module makes honest
operator edits safe (validated, atomic, monotonic, never loosening); it cannot
make the file an independently protected revocation authority. See
``docs/TRUST_LIFECYCLE_PROPOSAL.md``.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
import tempfile
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ._keys import spki_fingerprint
from ._time import parse_rfc3339
from .canonical import CanonicalError, loads_strict
from .trust import (
    ISSUER_PROVENANCE_SUFFIX,
    MAX_TRUST_STORE_BYTES,
    OPERATOR_DECLARED,
    TrustStore,
    TrustStoreError,
    issuer_name_problem,
)

__all__ = [
    "LOCAL_NOTICE",
    "LifecycleRefused",
    "MigrationRefused",
    "migrate",
    "migrate_store",
    "retire",
    "revoke",
    "status_rows",
]

# A boundary this far past the operator's clock is refused as a typo or a replayed clock.
FUTURE_SKEW = timedelta(minutes=5)
BACKUP_SUFFIX = ".prev"


SCOPE = "LOCAL VERIFIER POLICY CHANGE"
LOCAL_NOTICE = (
    "LOCAL VERIFIER POLICY CHANGE: this edits only this verifier's own trust-store file. It is NOT "
    "evidence that the issuer authorised a revocation, it is not distributed to anyone, and anyone "
    "who can write the file can undo it."
)
ROLLBACK_NOTICE = (
    "no independently preserved high-water mark: a rollback of this file (and its .prev backup) to an "
    "earlier state cannot be detected by this tool or by verification"
)


class LifecycleRefused(ValueError):
    """The requested change is refused; nothing was written."""


def _utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _resolve(path: str) -> tuple[str, int]:
    """Follow symlinks to the real regular file; return (real path, permission bits).

    A symlinked store is edited THROUGH the link, so the link keeps pointing at the
    updated file (replacing the link itself would silently detach consumers of it).
    Directories, FIFOs and devices are refused before anything is read or created.
    """
    try:
        real = os.path.realpath(path, strict=True)
        info = os.stat(real)
    except FileNotFoundError as exc:
        raise TrustStoreError(f"trust-store {path!r} does not exist") from exc
    except OSError as exc:
        raise TrustStoreError(f"trust-store {path!r} is unusable: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise TrustStoreError(f"trust-store {path!r} is not a regular file")
    if info.st_size > MAX_TRUST_STORE_BYTES:
        raise TrustStoreError(
            f"trust-store {path!r} size {info.st_size} exceeds {MAX_TRUST_STORE_BYTES} bytes"
        )
    return real, stat.S_IMODE(info.st_mode)


def _read(path: str) -> tuple[str, int, bytes, dict[str, Any]]:
    real, mode = _resolve(path)
    try:
        raw = Path(real).read_bytes()
        payload = loads_strict(raw, max_bytes=MAX_TRUST_STORE_BYTES)
    except (OSError, CanonicalError, RecursionError) as exc:
        raise TrustStoreError(f"trust-store {path!r} is unusable: {exc}") from exc
    if not isinstance(payload, dict) or "entries" not in payload:
        raise TrustStoreError(
            f"{path!r} is not an 'entries' trust store; refusing to convert or edit it "
            "(re-enrol the keys with 'trust add' into a new entries store)"
        )
    try:
        TrustStore.from_dict(payload)
    except TrustStoreError as exc:
        raise TrustStoreError(f"{path!r} does not validate: {exc}") from exc
    return real, mode, raw, payload


def _store_form(path: str) -> str:
    """entries | legacy-keys | bare-mapping (from the file's own shape)."""
    try:
        payload = loads_strict(Path(path).read_bytes(), max_bytes=MAX_TRUST_STORE_BYTES)
    except (OSError, CanonicalError, RecursionError):
        return "unknown"
    if not isinstance(payload, dict):
        return "unknown"
    if "entries" in payload:
        return "entries"
    return "legacy-keys" if isinstance(payload.get("keys"), dict) else "bare-mapping"


def _warnings(mode: int) -> list[str]:
    if mode & 0o022:
        return [
            f"store is group- or world-writable (mode {mode:04o}): anyone who can write it can change trust"
        ]
    return []


def status_rows(path: str, key_id: str | None = None) -> dict[str, Any]:
    """Read-only summary. Works for both the entries form and the legacy form."""
    store = TrustStore.from_json(path)
    real, mode = _resolve(path)
    rows = []
    for kid in sorted(store.keys):
        if key_id is not None and kid != key_id:
            continue
        entry = store.entry(kid)
        assert entry is not None
        rows.append(
            {
                "key_id": kid,
                "issuer": entry.issuer,
                "status": entry.status,
                "not_before": _utc(entry.not_before) if entry.not_before else None,
                "retired_at": _utc(entry.retired_at) if entry.retired_at else None,
                "compromised_from": _utc(entry.compromised_from)
                if entry.compromised_from
                else None,
                "fingerprint_sha256": spki_fingerprint(store.keys[kid]),
                **({"issuer_source": "operator-declared"} if kid in store.issuer_declared else {}),
            }
        )
    if key_id is not None and not rows:
        raise LifecycleRefused(f"key_id {key_id!r} is not in the trust store")
    return {
        "store_form": _store_form(real),
        "store_mode": f"{mode:04o}",
        "warnings": _warnings(mode),
        "as_of": _utc(store.as_of) if store.as_of else None,
        "authenticated": False,
        "issuer_authorized": False,
        "scope": SCOPE,
        "rollback_detection": ROLLBACK_NOTICE,
        "note": "local file; unauthenticated and not an independent revocation authority",
        "keys": rows,
    }


def _write_atomic(path: str, data: bytes, expected_old: bytes, mode: int) -> None:
    """Back up the old bytes, then replace the store atomically and durably.

    Any failure before ``os.replace`` leaves the old store byte-identical. The
    store is re-read just before the replace; if it changed since this edit
    began, nothing is written (narrows, but does not close, a concurrent-writer race).
    ``path`` must already be the resolved real file. The store AND its ``.prev`` backup
    get exactly the permission bits the store had (never wider, never narrower); an
    explicit chmod makes the result independent of the umask. Ownership is not preserved.
    """
    target = Path(path)
    directory = target.parent if str(target.parent) else Path(".")
    backup = target.with_name(target.name + BACKUP_SUFFIX)
    tmp_paths: list[str] = []

    def stage(dest_data: bytes, mode: int) -> str:
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".trust-", suffix=".tmp")
        tmp_paths.append(tmp)
        with os.fdopen(fd, "wb") as handle:
            handle.write(dest_data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        return tmp

    try:
        new_tmp = stage(data, mode)
        backup_tmp = stage(expected_old, mode)
        if target.read_bytes() != expected_old:
            raise LifecycleRefused("the trust store changed while this edit was prepared; retry")
        os.replace(backup_tmp, backup)
        os.replace(new_tmp, target)
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        for tmp in tmp_paths:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


def _mutate(
    path: str,
    key_id: str,
    now: datetime,
    change: Callable[[dict[str, Any], datetime], None],
) -> dict[str, Any]:
    if now.tzinfo is None:
        raise LifecycleRefused("the clock must be timezone-aware")
    real, mode, raw, payload = _read(path)
    entries = payload["entries"]
    entry = entries.get(key_id)
    if entry is None:
        raise LifecycleRefused(f"key_id {key_id!r} is not in the trust store")
    before = {k: entry.get(k) for k in ("status", "retired_at", "compromised_from")}
    old_as_of = payload.get("as_of")
    if isinstance(old_as_of, str) and parse_rfc3339(old_as_of) > now + FUTURE_SKEW:
        raise LifecycleRefused(
            f"store as_of {old_as_of} is later than this machine's clock: possible clock "
            "rollback or a store from elsewhere; refusing to move as_of backwards"
        )
    change(entry, now)
    payload["as_of"] = _utc(now) if old_as_of is None else _utc(max(now, parse_rfc3339(old_as_of)))
    try:
        TrustStore.from_dict(payload)  # the validation verification will apply
    except TrustStoreError as exc:
        raise LifecycleRefused(f"refused, nothing written: {exc}") from exc
    data = (_dump(payload)).encode("utf-8")
    _write_atomic(real, data, raw, mode)
    return {
        "key_id": key_id,
        "before": before,
        "after": {k: entry.get(k) for k in ("status", "retired_at", "compromised_from")},
        "as_of": payload["as_of"],
        "store": path,
        "backup": real + BACKUP_SUFFIX,
        "store_mode": f"{mode:04o}",
        "warnings": _warnings(mode),
        "store_sha256": hashlib.sha256(data).hexdigest(),
        "scope": SCOPE,
        "issuer_authorized": False,
        "notice": LOCAL_NOTICE,
        "rollback_detection": ROLLBACK_NOTICE,
    }


def _dump(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload, indent=2) + "\n"


def _boundary(text: str, now: datetime, what: str) -> datetime:
    try:
        moment = parse_rfc3339(text)
    except ValueError as exc:
        raise LifecycleRefused(f"{what}: {exc}") from exc
    if moment > now + FUTURE_SKEW:
        raise LifecycleRefused(f"{what} {text} is in the future; refusing")
    return moment


def retire(path: str, key_id: str, *, at: str | None, now: datetime) -> dict[str, Any]:
    """active -> retired. Planned rotation; never undone, never re-dated."""
    when = _boundary(at, now, "--at") if at is not None else now

    def change(entry: dict[str, Any], _now: datetime) -> None:
        if entry.get("status") != "active":
            raise LifecycleRefused(
                f"key_id {key_id!r} is {entry.get('status')!r}; only an active key can be "
                "retired (status changes are one-way and boundaries are never re-dated)"
            )
        nb = entry.get("not_before")
        if isinstance(nb, str) and when < parse_rfc3339(nb):
            raise LifecycleRefused("--at is earlier than the key's not_before")
        entry["status"] = "retired"
        entry["retired_at"] = _utc(when)

    return _mutate(path, key_id, now, change)


def revoke(
    path: str, key_id: str, *, compromised_from: str | None, now: datetime
) -> dict[str, Any]:
    """active|retired -> compromised. No boundary means "unknown": everything it signed is refused.

    Never loosens: a retired key's compromise boundary may not be later than its
    retired_at (that would re-open the interval retirement already closed).
    ``retired_at`` cannot coexist with ``compromised`` in this format; the old
    value stays in the ``.prev`` backup.
    """
    boundary = _boundary(compromised_from, now, "--compromised-from") if compromised_from else None

    def change(entry: dict[str, Any], _now: datetime) -> None:
        status = entry.get("status")
        if status == "compromised":
            raise LifecycleRefused(
                f"key_id {key_id!r} is already compromised; its boundary is never edited"
            )
        if status == "retired" and boundary is not None:
            retired_at = parse_rfc3339(entry["retired_at"])
            if boundary > retired_at:
                raise LifecycleRefused(
                    "--compromised-from is later than the key's retired_at; that would "
                    "accept reports retirement already refuses. Use an earlier boundary, "
                    "or omit it (unknown boundary refuses everything the key signed)"
                )
        entry["status"] = "compromised"
        entry.pop("retired_at", None)
        if boundary is not None:
            entry["compromised_from"] = _utc(boundary)

    return _mutate(path, key_id, now, change)


# ----------------------------------------------------------------------------- migration from the legacy forms


class MigrationRefused(ValueError):
    """Nothing was produced."""


def migrate_store(
    payload: Mapping[str, Any], issuers: Mapping[str, str], *, as_of: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Legacy or bare store to the ``entries`` form. The issuer of each key is an operator statement, never inferred.

    A flat ``revoked`` key becomes compromised with an unknown boundary, never retired: the legacy form does not say
    why it was revoked, and only the strictest reading is safe.
    """
    if "entries" in payload:
        raise MigrationRefused("already an entries store")
    try:
        source = TrustStore.from_dict(payload)
    except TrustStoreError as exc:
        raise MigrationRefused(f"the source does not validate: {exc}") from exc
    missing = sorted(set(source.keys) - set(issuers))
    if missing:
        raise MigrationRefused(f"no issuer stated for {missing}; issuers are never inferred")
    extra = sorted(set(issuers) - set(source.keys))
    if extra:
        raise MigrationRefused(f"issuer stated for unknown key_id(s) {extra}")
    for kid in sorted(source.keys):
        problem = issuer_name_problem(issuers[kid])
        if problem is not None:
            raise MigrationRefused(
                f"the issuer stated for {kid!r} {problem}; it is never normalised"
            )
    entries: dict[str, dict[str, Any]] = {}
    report: list[dict[str, Any]] = []
    for kid in sorted(source.keys):
        was = "revoked" if kid in source.revoked else "active"
        item: dict[str, Any] = {
            "issuer": issuers[kid],
            "public_key_pem": source.keys[kid],
            "status": "compromised" if was == "revoked" else "active",
            "issuer_source": OPERATOR_DECLARED,
        }
        pin = source.parameter_set_pins.get(kid)
        if pin is not None:
            item["parameter_set_pin"] = pin
        entries[kid] = item
        report.append(
            {
                "key_id": kid,
                "fingerprint": spki_fingerprint(source.keys[kid]),
                "from": was,
                "to": item["status"],
                "issuer": issuers[kid],
                "reason_code_change": (
                    "KEY_REVOKED -> KEY_COMPROMISED_NO_CHRONOLOGY" if was == "revoked" else None
                ),
                "new_refusal_possible": "ISSUER_MISMATCH",
                "issuer_binding": OPERATOR_DECLARED,
                "authenticated_binding": False,
            }
        )
    out = {"entries": entries, "as_of": as_of}
    try:
        migrated = TrustStore.from_dict(out)
    except TrustStoreError as exc:
        raise MigrationRefused(f"the result does not validate: {exc}") from exc
    if {k: spki_fingerprint(v) for k, v in migrated.keys.items()} != {
        k: spki_fingerprint(v) for k, v in source.keys.items()
    }:
        raise MigrationRefused("a key changed during migration")
    return out, report


def _write_new(path: str, data: bytes, mode: int) -> None:
    """A new file, durably, or nothing."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, mode)
        directory = os.open(os.path.dirname(os.path.realpath(path)), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise


def migrate(
    source: str, target: str, issuers: Mapping[str, str], *, now: datetime, dry_run: bool = False
) -> dict[str, Any]:
    """Write a new ``entries`` store. The source is left untouched; an existing target is refused."""
    real, mode = _resolve(source)
    try:
        payload = loads_strict(Path(real).read_bytes(), max_bytes=MAX_TRUST_STORE_BYTES)
    except (OSError, CanonicalError, RecursionError) as exc:
        raise TrustStoreError(f"trust-store {source!r} is unusable: {exc}") from exc
    if not isinstance(payload, dict):
        raise MigrationRefused("the source must be a JSON object")
    out, rows = migrate_store(payload, issuers, as_of=_utc(now))
    if os.path.lexists(target):
        raise MigrationRefused(f"{target!r} exists; migration never overwrites")
    side = os.path.realpath(target) + ISSUER_PROVENANCE_SUFFIX
    if os.path.lexists(side):
        raise MigrationRefused(f"{side!r} exists, from a pre-release version: remove it first")
    if not dry_run:
        _write_new(target, _dump(out).encode("utf-8"), mode)
    return {
        "scope": SCOPE,
        "source": source,
        "target": target,
        "dry_run": dry_run,
        "keys": rows,
        "issuer_binding": OPERATOR_DECLARED,
        "authenticated_binding": False,
        "notice": "The source is unchanged. Under the new store a report whose signed issuer differs from the "
        "stated issuer is refused (ISSUER_MISMATCH): check the stated issuers against your reports first. "
        "Each --issuer is your statement as a local operator, not proof that the key belongs to that issuer: no "
        "authenticated enrollment took place. confidential, high-assurance and secure-v1 refuse this store "
        "(ISSUER_ENROLLMENT_UNAUTHENTICATED). development accepts it and labels the result ISSUER_OPERATOR_DECLARED. "
        "Each entry records this as issuer_source, so published versions refuse the store: the source store stays the way "
        "back. See docs/MIGRATION_0.3.md.",
    }
