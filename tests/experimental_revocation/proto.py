"""EXPERIMENTAL PROTOTYPE of the owner-signed revocation list (draft v1). NOT SHIPPED.

Lives under ``tests/`` only. Nothing in ``src/regaudit_fhe`` imports it, no schema is registered
for it, and it changes no verification rule: it *produces inputs* for the existing
``TrustStore`` / ``TrustHistory`` / ``VerificationPolicy`` machinery. See
``docs/TRUST_REVOCATION_PROTOCOL_PROPOSAL.md``.

Honest limit, repeated in every result: a verifier that has no independently preserved
high-water mark cannot reliably detect a rollback of both the revocation data and its local state.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from regaudit_fhe._keys import spki_fingerprint
from regaudit_fhe._time import parse_rfc3339
from regaudit_fhe.canonical import (
    CanonicalError,
    canonical_bytes,
    decode_canonical_b64,
    loads_strict,
)
from regaudit_fhe.reports import verify_signature
from regaudit_fhe.trust import TrustStore
from regaudit_fhe.verification import TrustHistory

SCHEMA = "regaudit-fhe.revocation-list"
SIGN_DOMAIN = b"regaudit-fhe/revocation-list/v1/sign\x00"
DIGEST_DOMAIN = b"regaudit-fhe/revocation-list/v1/digest\x00"
STATUSES = ("retired", "compromised", "replaced")
MAX_ENTRIES = 10_000
MAX_BYTES = 4 * 1024 * 1024
SKEW = timedelta(minutes=5)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

ROLLBACK_LIMIT = (
    "A verifier with no independently preserved high-water mark cannot reliably detect a rollback of "
    "both the revocation data and its local state. A present mark detects replay of an older list, "
    "not an attacker who can also rewrite the mark."
)

TOP_MEMBERS = {
    "schema", "schema_version", "algorithm_version", "issuer", "authority", "epoch",
    "prev_list_digest", "issued_at", "valid_from", "valid_until", "entries", "signature",
}  # fmt: skip


class ShapeError(ValueError):
    """The document is not a well-formed draft-v1 revocation list."""


# ----------------------------------------------------------------------------- build / sign


def signed_body(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in doc.items() if k != "signature"}


def signing_input(doc: dict[str, Any]) -> bytes:
    return SIGN_DOMAIN + canonical_bytes(signed_body(doc))


def list_digest(doc: dict[str, Any]) -> str:
    return hashlib.sha256(DIGEST_DOMAIN + canonical_bytes(signed_body(doc))).hexdigest()


def sign_list(body: dict[str, Any], signer: Any) -> dict[str, Any]:
    """Attach the signature of ``signer`` (any object with ``sign(bytes) -> bytes``)."""
    import base64

    unsigned = {k: v for k, v in body.items() if k != "signature"}
    sig = signer.sign(SIGN_DOMAIN + canonical_bytes(unsigned))
    return {
        **unsigned,
        "signature": {"algorithm": "ed25519", "signature_b64": base64.b64encode(sig).decode()},
    }


def build_body(
    *,
    issuer: str,
    authority_key_id: str,
    authority_pem: str,
    epoch: int,
    prev_list_digest: str | None,
    issued_at: str,
    valid_from: str | None = None,
    valid_until: str,
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "algorithm_version": 1,
        "issuer": issuer,
        "authority": {
            "key_id": authority_key_id,
            "key_fingerprint": spki_fingerprint(authority_pem),
        },
        "epoch": epoch,
        "prev_list_digest": prev_list_digest,
        "issued_at": issued_at,
        "valid_from": valid_from or issued_at,
        "valid_until": valid_until,
        "entries": sorted(entries, key=lambda e: e["key_id"]),
    }


# ----------------------------------------------------------------------------- shape


def _t(value: Any, what: str) -> datetime:
    if not isinstance(value, str):
        raise ShapeError(f"{what} must be an RFC 3339 string")
    try:
        return parse_rfc3339(value)
    except ValueError as exc:
        raise ShapeError(f"{what}: {exc}") from exc


def _ident(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ShapeError(f"{what} must be a string of 1..256 characters")
    return value


def _fp(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _HEX64.match(value):
        raise ShapeError(f"{what} must be 64 lowercase hex characters")
    return value


def _exact(obj: Any, members: set[str], what: str, optional: frozenset[str] = frozenset()) -> None:
    if not isinstance(obj, dict):
        raise ShapeError(f"{what} must be an object")
    extra = set(obj) - members - optional
    missing = members - set(obj)
    if extra or missing:
        raise ShapeError(f"{what}: unknown {sorted(extra)} / missing {sorted(missing)}")


def validate_shape(doc: Any) -> None:
    _exact(doc, TOP_MEMBERS, "list")
    if doc["schema"] != SCHEMA:
        raise ShapeError("wrong schema")
    for name in ("schema_version", "algorithm_version", "epoch"):
        if type(doc[name]) is not int:
            raise ShapeError(f"{name} must be an integer")
    if doc["epoch"] < 1:
        raise ShapeError("epoch must be >= 1")
    _ident(doc["issuer"], "issuer")
    _exact(doc["authority"], {"key_id", "key_fingerprint"}, "authority")
    _ident(doc["authority"]["key_id"], "authority.key_id")
    _fp(doc["authority"]["key_fingerprint"], "authority.key_fingerprint")
    prev = doc["prev_list_digest"]
    if doc["epoch"] == 1:
        if prev is not None:
            raise ShapeError("epoch 1 must have prev_list_digest null")
    else:
        _fp(prev, "prev_list_digest")
    issued, vfrom, vuntil = (_t(doc[n], n) for n in ("issued_at", "valid_from", "valid_until"))
    if not (issued <= vfrom < vuntil):
        raise ShapeError("need issued_at <= valid_from < valid_until")
    _exact(doc["signature"], {"algorithm", "signature_b64"}, "signature")
    if doc["signature"]["algorithm"] != "ed25519":
        raise ShapeError("signature.algorithm must be ed25519")
    entries = doc["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ShapeError(f"entries must be a list of at most {MAX_ENTRIES}")
    last = None
    for i, e in enumerate(entries):
        _exact(e, {"key_id", "key_fingerprint", "status", "effective_from"}, f"entries[{i}]",
               frozenset({"successor"}))  # fmt: skip
        kid = _ident(e["key_id"], f"entries[{i}].key_id")
        if last is not None and kid <= last:
            raise ShapeError("entries must be strictly sorted by key_id (unique)")
        last = kid
        fp = _fp(e["key_fingerprint"], f"entries[{i}].key_fingerprint")
        if e["status"] not in STATUSES:
            raise ShapeError(f"entries[{i}].status must be one of {STATUSES}")
        if e["effective_from"] is None:
            if e["status"] != "compromised":
                raise ShapeError("only a compromised entry may have an unknown (null) boundary")
        else:
            _t(e["effective_from"], f"entries[{i}].effective_from")
        succ = e.get("successor")
        if e["status"] == "replaced" and succ is None:
            raise ShapeError("a replaced entry requires a successor")
        if succ is not None:
            _exact(succ, {"key_id", "key_fingerprint"}, f"entries[{i}].successor")
            skid = _ident(succ["key_id"], "successor.key_id")
            sfp = _fp(succ["key_fingerprint"], "successor.key_fingerprint")
            if skid == kid or sfp == fp:
                raise ShapeError("a key cannot be its own successor (key_id or fingerprint)")


# ----------------------------------------------------------------------------- state


@dataclass(frozen=True)
class Mark:
    """Verifier-side high-water mark for one (issuer, revocation key)."""

    issuer: str
    authority_fingerprint: str
    epoch: int
    digest: str
    issued_at: str
    valid_until: str
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)  # key_id -> entry


@dataclass(frozen=True)
class RevocationState:
    marks: dict[str, Mark] = field(default_factory=dict)

    @staticmethod
    def slot(issuer: str, fingerprint: str) -> str:
        return f"{issuer}\x00{fingerprint}"

    def get(self, issuer: str, fingerprint: str) -> Mark | None:
        return self.marks.get(self.slot(issuer, fingerprint))

    def with_mark(self, mark: Mark) -> RevocationState:
        marks = dict(self.marks)
        marks[self.slot(mark.issuer, mark.authority_fingerprint)] = mark
        return RevocationState(marks)

    def save(self, path: str) -> None:
        data = json.dumps(
            {s: m.__dict__ for s, m in sorted(self.marks.items())}, indent=2, sort_keys=True
        ).encode()
        target = Path(path)
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".revstate-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, target)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    @classmethod
    def load(cls, path: str) -> RevocationState:
        """A missing file is an EMPTY state (no mark): rollback is then undetectable."""
        try:
            raw = loads_strict(Path(path).read_bytes(), max_bytes=MAX_BYTES)
        except FileNotFoundError:
            return cls()
        return cls({s: Mark(**m) for s, m in raw.items()})


# ----------------------------------------------------------------------------- verification


@dataclass(frozen=True)
class Anchor:
    """Verifier-pinned revocation authority: never read from the list being verified."""

    issuer: str
    public_key_pem: str

    @property
    def fingerprint(self) -> str:
        return spki_fingerprint(self.public_key_pem)


@dataclass(frozen=True)
class ListResult:
    accepted: bool
    blocking: tuple[str, ...]
    notes: tuple[str, ...] = ()
    statement: dict[str, Any] | None = None
    digest: str | None = None
    rollback_detection: str = "none"
    limit: str = ROLLBACK_LIMIT

    @property
    def code(self) -> str | None:
        return self.blocking[0] if self.blocking else None


def _refuse(code: str, *notes: str, detection: str = "none") -> ListResult:
    return ListResult(False, (code,), tuple(notes), rollback_detection=detection)


def _monotone(old: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]]) -> str | None:
    for kid, o in old.items():
        n = new.get(kid)
        if n is None:
            return f"{kid}: entry removed"
        if n["key_fingerprint"] != o["key_fingerprint"]:
            return f"{kid}: fingerprint changed"
        if "successor" in o and n.get("successor") != o["successor"]:
            return f"{kid}: successor changed or removed"
        if o["status"] != "compromised" and n["status"] != "compromised":
            if n["effective_from"] != o["effective_from"]:
                return f"{kid}: effective_from changed"
            continue
        if o["status"] == "compromised":
            if n["status"] != "compromised":
                return f"{kid}: status moved backwards"
            if o["effective_from"] is None:
                if n["effective_from"] is not None:
                    return f"{kid}: unknown boundary became known"
            elif n["effective_from"] is not None and parse_rfc3339(
                n["effective_from"]
            ) > parse_rfc3339(o["effective_from"]):
                return f"{kid}: compromise boundary moved later"
            continue
        # retired/replaced -> compromised: must not re-open the closed interval
        if n["effective_from"] is not None and parse_rfc3339(n["effective_from"]) > parse_rfc3339(
            o["effective_from"]
        ):
            return f"{kid}: compromise boundary later than the retirement"
    return None


def _successor_cycle(entries: list[dict[str, Any]]) -> str | None:
    nxt = {e["key_id"]: e["successor"]["key_id"] for e in entries if "successor" in e}
    for start in nxt:
        seen = {start}
        cur = nxt[start]
        while cur in nxt:
            if cur in seen:
                return start
            seen.add(cur)
            cur = nxt[cur]
    return None


def verify_list(
    raw: str | bytes,
    anchor: Anchor,
    store: TrustStore | None,
    state: RevocationState,
    now: datetime,
    *,
    allow_gap: bool = True,
) -> ListResult:
    """Verify one list. Pure: never changes ``state`` (see :func:`commit`)."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    try:
        doc = loads_strict(raw, max_bytes=MAX_BYTES)
        validate_shape(doc)
    except (CanonicalError, RecursionError, ShapeError, UnicodeDecodeError) as exc:
        return _refuse("REVOCATION_MALFORMED", str(exc))
    if doc["schema_version"] != 1 or doc["algorithm_version"] != 1:
        return _refuse("REVOCATION_VERSION_UNSUPPORTED")
    if doc["issuer"] != anchor.issuer:
        return _refuse("REVOCATION_WRONG_ISSUER")
    if doc["authority"]["key_fingerprint"] != anchor.fingerprint:
        return _refuse("REVOCATION_AUTHORITY_MISMATCH")
    if store is not None and any(
        spki_fingerprint(p) == anchor.fingerprint for p in store.keys.values()
    ):
        # purpose separation: a report-signing key can never be the revocation key
        return _refuse("REVOCATION_KEY_IS_REPORT_KEY")
    try:
        sig_ok = verify_signature(
            anchor.public_key_pem, signing_input(doc), doc["signature"]["signature_b64"]
        )
        decode_canonical_b64(doc["signature"]["signature_b64"], length=64)
    except Exception:
        sig_ok = False
    if not sig_ok:
        return _refuse("REVOCATION_SIGNATURE_INVALID")
    issued, vfrom, vuntil = (
        parse_rfc3339(doc[n]) for n in ("issued_at", "valid_from", "valid_until")
    )
    if issued > now + SKEW or vfrom > now + SKEW:
        return _refuse("REVOCATION_NOT_YET_VALID")
    if now >= vuntil:
        return _refuse("REVOCATION_EXPIRED")
    entries = doc["entries"]
    for e in entries:
        if e["effective_from"] is not None and parse_rfc3339(e["effective_from"]) > issued + SKEW:
            return _refuse("REVOCATION_MALFORMED", f"{e['key_id']}: effective_from after issued_at")
    if _successor_cycle(entries):
        return _refuse("REVOCATION_MALFORMED", "successor cycle")
    if store is not None:
        for e in entries:
            local = store.entry(e["key_id"])
            if local is not None and spki_fingerprint(local.public_key_pem) != e["key_fingerprint"]:
                return _refuse("REVOCATION_KEY_MISMATCH", e["key_id"])
            succ = e.get("successor")
            if succ is not None:
                bound = store.entry(succ["key_id"])
                if (
                    bound is not None
                    and spki_fingerprint(bound.public_key_pem) != succ["key_fingerprint"]
                ):
                    return _refuse("REVOCATION_KEY_MISMATCH", "successor " + succ["key_id"])
    digest = list_digest(doc)
    mark = state.get(anchor.issuer, anchor.fingerprint)
    notes: list[str] = []
    if mark is None:
        notes.append("REVOCATION_NO_HIGH_WATER_MARK")
        detection = "none"
    else:
        detection = "high-water-mark-present"
        if doc["epoch"] < mark.epoch:
            return _refuse("REVOCATION_ROLLBACK", detection=detection)
        if doc["epoch"] == mark.epoch:
            if digest != mark.digest:
                return _refuse("REVOCATION_FORK", detection=detection)
            notes.append("REVOCATION_REPEAT")
        else:
            if doc["epoch"] == mark.epoch + 1 and doc["prev_list_digest"] != mark.digest:
                return _refuse("REVOCATION_FORK", detection=detection)
            if doc["epoch"] > mark.epoch + 1:
                if not allow_gap:
                    return _refuse("REVOCATION_EPOCH_GAP", detection=detection)
                notes.append("REVOCATION_EPOCH_GAP")
            problem = _monotone(mark.entries, {e["key_id"]: e for e in entries})
            if problem:
                return _refuse("REVOCATION_NOT_MONOTONE", problem, detection=detection)
    return ListResult(True, (), tuple(notes), doc, digest, detection)


def commit(state: RevocationState, anchor: Anchor, result: ListResult) -> RevocationState:
    """Advance the high-water mark after an accepted list (compare-and-set in a real verifier)."""
    if not result.accepted or result.statement is None or result.digest is None:
        return state
    doc = result.statement
    old = state.get(anchor.issuer, anchor.fingerprint)
    if old is not None and doc["epoch"] < old.epoch:
        return state
    return state.with_mark(
        Mark(
            issuer=anchor.issuer,
            authority_fingerprint=anchor.fingerprint,
            epoch=doc["epoch"],
            digest=result.digest,
            issued_at=doc["issued_at"],
            valid_until=doc["valid_until"],
            entries={e["key_id"]: e for e in doc["entries"]},
        )
    )


# ----------------------------------------------------------------------------- feeding the existing seams


def _z(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _entry_dict(store: TrustStore, kid: str) -> dict[str, Any]:
    e = store.entries[kid]
    out: dict[str, Any] = {
        "issuer": e.issuer,
        "public_key_pem": e.public_key_pem,
        "status": e.status,
    }
    for name in ("not_before", "retired_at", "compromised_from"):
        value = getattr(e, name)
        if value is not None:
            out[name] = _z(value)
    if e.deployments is not None:
        out["deployments"] = sorted(e.deployments)
    if e.primitives is not None:
        out["primitives"] = sorted(e.primitives)
    if e.parameter_set_pin is not None:
        out["parameter_set_pin"] = e.parameter_set_pin
    return out


def apply_to_store(store: TrustStore, result: ListResult) -> TrustStore:
    """The STRICTER of the local entry and the verified list entry; never loosens.

    ``replaced`` maps to ``retired`` (the store format has no successor member); the successor is
    evidence, never trust.
    """
    if not result.accepted or result.statement is None:
        raise ValueError("only an accepted list can be applied")
    if not store.entries:
        raise ValueError("only an 'entries' store can carry lifecycle state")
    entries = {kid: _entry_dict(store, kid) for kid in store.entries}
    for item in result.statement["entries"]:
        kid = item["key_id"]
        if kid not in entries:
            continue
        cur = entries[kid]
        eff = parse_rfc3339(item["effective_from"]) if item["effective_from"] else None
        if item["status"] == "compromised":
            bound = eff
            if cur["status"] == "compromised":
                old = cur.get("compromised_from")
                if old is None or bound is None:
                    bound = None
                else:
                    bound = min(bound, parse_rfc3339(old))
            elif cur["status"] == "retired" and bound is not None:
                bound = min(bound, parse_rfc3339(cur["retired_at"]))
            cur.pop("retired_at", None)
            cur.pop("compromised_from", None)
            cur["status"] = "compromised"
            if bound is not None:
                cur["compromised_from"] = _z(bound)
        else:
            assert eff is not None
            if cur["status"] == "compromised":
                continue
            if cur["status"] == "retired":
                eff = min(eff, parse_rfc3339(cur["retired_at"]))
            cur["status"] = "retired"
            cur["retired_at"] = _z(eff)
    payload: dict[str, Any] = {"entries": entries}
    if store.as_of is not None:
        payload["as_of"] = _z(store.as_of)
    return TrustStore.from_dict(payload)


def derive_trust_history(result: ListResult, now: datetime) -> TrustHistory | None:
    """The only producer of ``TrustHistory(authenticated=True)``: a list that just verified
    against the pinned revocation key and is inside its validity period."""
    if not result.accepted or result.statement is None:
        return None
    if now >= parse_rfc3339(result.statement["valid_until"]):
        return None
    return TrustHistory(as_of=parse_rfc3339(result.statement["issued_at"]), authenticated=True)


@dataclass(frozen=True)
class Outcome:
    status: str  # VERIFIED | NO_LIST | UNVERIFIED
    store: TrustStore
    history: TrustHistory | None
    result: ListResult | None
    state: RevocationState
    revocation_evidence: str
    limit: str = ROLLBACK_LIMIT


def evaluate(
    store: TrustStore,
    raw: str | bytes | None,
    anchor: Anchor,
    state: RevocationState,
    now: datetime,
    *,
    allow_gap: bool = True,
) -> Outcome:
    """Missing or unverifiable evidence NEVER means 'nothing revoked': the store is unchanged, no
    authenticated history exists, and the outcome says the evidence is unproven."""
    if raw is None:
        return Outcome("NO_LIST", store, None, None, state, "unproven")
    if not store.entries:
        refused = _refuse(
            "REVOCATION_STORE_UNSUPPORTED", "only an 'entries' store carries lifecycle state"
        )
        return Outcome("UNVERIFIED", store, None, refused, state, "unproven")
    result = verify_list(raw, anchor, store, state, now, allow_gap=allow_gap)
    if not result.accepted:
        return Outcome("UNVERIFIED", store, None, result, state, "unproven")
    new_state = commit(state, anchor, result)
    return Outcome(
        "VERIFIED",
        apply_to_store(store, result),
        derive_trust_history(result, now),
        result,
        new_state,
        "verified-as-of-" + result.statement["issued_at"],  # type: ignore[index]
    )


def resolve_successors(
    doc: dict[str, Any], key_id: str, fingerprint: str, max_depth: int = 16
) -> list[dict[str, Any]]:
    """Signed successor chain starting at (key_id, fingerprint); each hop is bound to a fingerprint.

    Evidence only: naming B as successor does not make B trusted.
    """
    by_id = {e["key_id"]: e for e in doc["entries"]}
    chain: list[dict[str, Any]] = []
    cur_id, cur_fp = key_id, fingerprint
    for _ in range(max_depth):
        entry = by_id.get(cur_id)
        if entry is None or entry["key_fingerprint"] != cur_fp or "successor" not in entry:
            break
        succ = entry["successor"]
        chain.append({"key_id": succ["key_id"], "key_fingerprint": succ["key_fingerprint"]})
        cur_id, cur_fp = succ["key_id"], succ["key_fingerprint"]
    return chain


__all__ = [n for n in dir() if not n.startswith("_")]
