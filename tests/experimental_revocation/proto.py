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
from dataclasses import dataclass, field, replace
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
    authority_generation: int = 1,
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
            "generation": authority_generation,
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
    _exact(doc["authority"], {"key_id", "key_fingerprint", "generation"}, "authority")
    _ident(doc["authority"]["key_id"], "authority.key_id")
    if type(doc["authority"]["generation"]) is not int or doc["authority"]["generation"] < 1:
        raise ShapeError("authority.generation must be an integer >= 1")
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
    seen_fps: set[str] = set()
    for i, e in enumerate(entries):
        _exact(e, {"key_id", "key_fingerprint", "status", "effective_from"}, f"entries[{i}]",
               frozenset({"successor"}))  # fmt: skip
        kid = _ident(e["key_id"], f"entries[{i}].key_id")
        if last is not None and kid <= last:
            raise ShapeError("entries must be strictly sorted by key_id (unique)")
        last = kid
        fp = _fp(e["key_fingerprint"], f"entries[{i}].key_fingerprint")
        if fp in seen_fps:
            raise ShapeError("one key fingerprint may appear once in a list")
        seen_fps.add(fp)
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
    accepted_at: str | None = None  # this verifier's clock; a signer can backdate issued_at, not this


@dataclass(frozen=True)
class RevocationState:
    """Verifier-persisted state: one mark per ISSUER (the epoch chain spans authority rotations),
    explicit local enrollments, and an archive of accepted lists (needed for recovery rebase)."""

    marks: dict[str, Mark] = field(default_factory=dict)
    enrollments: dict[str, Enrollment] = field(default_factory=dict)
    archive: dict[str, Mark] = field(default_factory=dict)  # list digest -> accepted list

    @staticmethod
    def slot(issuer: str) -> str:
        return issuer

    def get(self, issuer: str) -> Mark | None:
        return self.marks.get(self.slot(issuer))

    def with_mark(self, mark: Mark) -> RevocationState:
        marks = dict(self.marks)
        marks[self.slot(mark.issuer)] = mark
        archive = dict(self.archive)
        archive[mark.digest] = mark
        return replace(self, marks=marks, archive=archive)

    def with_enrollment(self, enrollment: Enrollment) -> RevocationState:
        enrollments = dict(self.enrollments)
        enrollments[enrollment.issuer] = enrollment
        return replace(self, enrollments=enrollments)

    def save(self, path: str) -> None:
        data = json.dumps(
            {
                "marks": {s: m.__dict__ for s, m in sorted(self.marks.items())},
                "archive": {s: m.__dict__ for s, m in sorted(self.archive.items())},
                "enrollments": {s: e.to_dict() for s, e in sorted(self.enrollments.items())},
            },
            indent=2,
            sort_keys=True,
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
        return cls(
            {s: Mark(**m) for s, m in raw["marks"].items()},
            {s: Enrollment.from_dict(e) for s, e in raw["enrollments"].items()},
            {s: Mark(**m) for s, m in raw["archive"].items()},
        )


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


def condemned(mark: Mark, compromised: dict[str, str | None]) -> bool:
    """The mark was signed by a key declared compromised, at or after the boundary or with an unknown one.

    Compares this verifier's acceptance time as well as the list's claim, since a thief writes ``issued_at``.
    """
    if mark.authority_fingerprint not in compromised:
        return False
    boundary = compromised[mark.authority_fingerprint]
    if boundary is None:
        return True
    limit = parse_rfc3339(boundary)
    times = [mark.issued_at] + ([mark.accepted_at] if mark.accepted_at else [])
    return any(parse_rfc3339(t) >= limit for t in times)


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


def _store_conflict(
    entries: list[dict[str, Any]], issuer: str, store: TrustStore
) -> tuple[str, str] | None:
    """A key is (key_id, fingerprint). The same fingerprint under another issuer is out of scope. The same
    key_id under another issuer with another fingerprint is an unrelated key: key_ids are not namespaced."""
    by_fp = {spki_fingerprint(p): k for k, p in store.keys.items()}

    def mine(entry: Any) -> bool:
        return entry.issuer is None or entry.issuer == issuer

    for e in entries:
        alias = store.entry(by_fp[e["key_fingerprint"]]) if e["key_fingerprint"] in by_fp else None
        if alias is not None and not mine(alias):
            return "REVOCATION_ISSUER_SCOPE", e["key_id"]  # cannot revoke another issuer's key
        local = store.entry(e["key_id"])
        if (
            local is not None
            and mine(local)
            and spki_fingerprint(local.public_key_pem) != e["key_fingerprint"]
        ):
            return "REVOCATION_KEY_MISMATCH", e["key_id"]
        succ = e.get("successor")
        if succ is not None:
            bound = store.entry(succ["key_id"])
            if (
                bound is not None
                and mine(bound)
                and spki_fingerprint(bound.public_key_pem) != succ["key_fingerprint"]
            ):
                return "REVOCATION_KEY_MISMATCH", "successor " + succ["key_id"]
    return None


def verify_list(
    raw: str | bytes,
    anchor: Anchor,
    store: TrustStore | None,
    state: RevocationState,
    now: datetime,
    *,
    allow_gap: bool = True,
    enrollment: Enrollment | None = None,
) -> ListResult:
    """Verify one list. Pure: never changes ``state`` (see :func:`commit`).

    With ``enrollment`` the list must also be signed by the CURRENT enrolled authority generation;
    lists from superseded or compromised authorities get distinct refusal codes.
    """
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
    if enrollment is not None:
        listed = doc["authority"]["key_fingerprint"]
        if listed in enrollment.compromised:
            return _refuse("REVOCATION_AUTHORITY_COMPROMISED")
        if listed in enrollment.superseded:
            return _refuse("REVOCATION_AUTHORITY_SUPERSEDED")
    if doc["authority"]["key_fingerprint"] != anchor.fingerprint:
        return _refuse("REVOCATION_AUTHORITY_MISMATCH")
    if enrollment is not None and doc["authority"]["generation"] != enrollment.generation:
        return _refuse("REVOCATION_AUTHORITY_MISMATCH", "generation")
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
    digest = list_digest(doc)
    mark = state.get(anchor.issuer)
    notes: list[str] = []
    if mark is None:
        notes.append("REVOCATION_NO_HIGH_WATER_MARK")
        detection = "none"
    else:
        detection = "high-water-mark-present"
        distrusted = enrollment is not None and condemned(mark, enrollment.compromised)
        if doc["epoch"] < mark.epoch:
            return _refuse("REVOCATION_ROLLBACK", detection=detection)
        if distrusted:
            # What a thief told this verifier must not make an honest list look contradictory. The epoch
            # floor stays, and joined key actions keep every tightening, so nothing loosens.
            if digest != mark.digest:
                notes.append("REVOCATION_MARK_CONDEMNED")
            else:
                notes.append("REVOCATION_REPEAT")
        elif doc["epoch"] == mark.epoch:
            if digest != mark.digest:
                return _refuse("REVOCATION_FORK", detection=detection)
            notes.append("REVOCATION_REPEAT")
        else:
            if issued < parse_rfc3339(mark.issued_at):
                return _refuse(
                    "REVOCATION_NOT_MONOTONE", "issued_at moved backwards", detection=detection
                )
            if doc["epoch"] == mark.epoch + 1 and doc["prev_list_digest"] != mark.digest:
                return _refuse("REVOCATION_FORK", detection=detection)
            if doc["epoch"] > mark.epoch + 1:
                if not allow_gap:
                    return _refuse("REVOCATION_EPOCH_GAP", detection=detection)
                notes.append("REVOCATION_EPOCH_GAP")
            problem = _monotone(mark.entries, {e["key_id"]: e for e in entries})
            if problem:
                return _refuse("REVOCATION_NOT_MONOTONE", problem, detection=detection)
    # After the epoch rules: a replayed old list is a rollback, whatever has since changed in the local store.
    if store is not None:
        problem_code = _store_conflict(entries, doc["issuer"], store)
        if problem_code is not None:
            return _refuse(problem_code[0], problem_code[1], detection=detection)
    return ListResult(True, (), tuple(notes), doc, digest, detection)


def commit(
    state: RevocationState, anchor: Anchor, result: ListResult, *, accepted_at: str | None = None
) -> RevocationState:
    """Advance the high-water mark after an accepted list (compare-and-set in a real verifier)."""
    if not result.accepted or result.statement is None or result.digest is None:
        return state
    doc = result.statement
    old = state.get(anchor.issuer)
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
            accepted_at=accepted_at,
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
    """The STRICTER of the local entry and the verified list entry; never loosens."""
    if not result.accepted or result.statement is None:
        raise ValueError("only an accepted list can be applied")
    return apply_entries(store, result.statement["entries"])


def apply_entries(store: TrustStore, listed: list[dict[str, Any]]) -> TrustStore:
    """Join listed key actions into a store, matching on the key fingerprint, not on key_id.

    ``replaced`` maps to ``retired`` (the store format has no successor member); the successor is
    evidence, never trust.
    """
    if not store.entries:
        raise ValueError("only an 'entries' store can carry lifecycle state")
    entries = {kid: _entry_dict(store, kid) for kid in store.entries}
    by_fp = {spki_fingerprint(e.public_key_pem): kid for kid, e in store.entries.items()}
    for item in listed:
        kid = by_fp.get(item["key_fingerprint"])
        if kid is None:
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
                known = cur.get("compromised_from")
                if known is not None and eff < parse_rfc3339(known):
                    cur["compromised_from"] = _z(eff)
                continue
            if cur["status"] == "retired":
                eff = min(eff, parse_rfc3339(cur["retired_at"]))
            cur["status"] = "retired"
            cur["retired_at"] = _z(eff)
    payload: dict[str, Any] = {"entries": entries}
    if store.as_of is not None:
        payload["as_of"] = _z(store.as_of)
    return TrustStore.from_dict(payload)


HISTORY_PROFILES = ("development", "confidential")


def derive_trust_history(
    result: ListResult,
    now: datetime,
    *,
    profile: str,
    owner_approved: bool = False,
) -> TrustHistory | None:
    """OPTIONAL, NOT APPROVED, LOWER PROFILES ONLY.

    A cumulative CURRENT list is not an authenticated history: it states what is revoked at
    ``issued_at`` and nothing about what was true earlier or about completeness. It is therefore
    never used for ``high-assurance`` (always ``None``), and for ``development``/``confidential`` only
    when the owner has explicitly approved the option (``owner_approved=True``). Default: ``None``.
    """
    if profile not in HISTORY_PROFILES or not owner_approved:
        return None
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
    profile: str = "confidential",
    owner_approved_history: bool = False,
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
        derive_trust_history(result, now, profile=profile, owner_approved=owner_approved_history),
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


# ----------------------------------------------------------------------------- authority: enrollment, routine transition, recovery

TRANSITION_SCHEMA = "regaudit-fhe.revocation-authority-transition"
RECOVERY_SCHEMA = "regaudit-fhe.revocation-authority-recovery"
TRANS_FROM_DOMAIN = b"regaudit-fhe/revocation-authority-transition/v1/sign-from\x00"
TRANS_TO_DOMAIN = b"regaudit-fhe/revocation-authority-transition/v1/sign-to\x00"
TRANS_DIGEST_DOMAIN = b"regaudit-fhe/revocation-authority-transition/v1/digest\x00"
REC_ANCHOR_DOMAIN = b"regaudit-fhe/revocation-authority-recovery/v1/sign-anchor\x00"
REC_TO_DOMAIN = b"regaudit-fhe/revocation-authority-recovery/v1/sign-new-authority\x00"
REC_DIGEST_DOMAIN = b"regaudit-fhe/revocation-authority-recovery/v1/digest\x00"

TRANS_MEMBERS = {
    "schema", "schema_version", "algorithm_version", "issuer", "from_authority", "to_authority",
    "issued_at", "valid_until", "signatures",
}  # fmt: skip
REC_MEMBERS = {
    "schema", "schema_version", "algorithm_version", "issuer", "recovery_anchor", "recovery_epoch",
    "declares_compromised", "new_authority", "rebase", "issued_at", "valid_until", "signatures",
}  # fmt: skip


@dataclass(frozen=True)
class Enrollment:
    """Explicit LOCAL enrollment of an owner's revocation authority (and optional recovery anchor).

    Created only by an operator (out of band); never learned from a list, a transition or the channel.
    """

    issuer: str
    authority_pem: str
    generation: int = 1
    recovery_pem: str | None = None
    recovery_epoch: int = 0
    recovery_digest: str | None = None
    compromised: dict[str, str | None] = field(default_factory=dict)  # fingerprint -> boundary
    superseded: tuple[str, ...] = ()
    accepted_transitions: tuple[dict[str, str], ...] = ()
    voided: tuple[str, ...] = ()

    @property
    def anchor(self) -> Anchor:
        return Anchor(self.issuer, self.authority_pem)

    @property
    def authority_fingerprint(self) -> str:
        return spki_fingerprint(self.authority_pem)

    def to_dict(self) -> dict[str, Any]:
        out = dict(self.__dict__)
        out["accepted_transitions"] = list(self.accepted_transitions)
        out["superseded"] = list(self.superseded)
        out["voided"] = list(self.voided)
        return out

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Enrollment:
        raw = dict(raw)
        raw["accepted_transitions"] = tuple(raw["accepted_transitions"])
        raw["superseded"] = tuple(raw["superseded"])
        raw["voided"] = tuple(raw["voided"])
        return cls(**raw)


def enroll(
    state: RevocationState,
    issuer: str,
    authority_pem: str,
    *,
    recovery_pem: str | None = None,
    store: TrustStore | None = None,
) -> RevocationState:
    """Operator action: enrol the owner's revocation authority (and recovery anchor) locally."""
    if issuer in state.enrollments:
        raise ValueError(
            "issuer already enrolled; re-enrollment is a separate, explicit operator act"
        )
    fps = {spki_fingerprint(authority_pem)}
    if recovery_pem is not None:
        rfp = spki_fingerprint(recovery_pem)
        if rfp in fps:
            raise ValueError("the recovery anchor must be a different key from the authority")
        fps.add(rfp)
    if store is not None and any(spki_fingerprint(p) in fps for p in store.keys.values()):
        raise ValueError("a report-signing key cannot be a revocation authority or recovery anchor")
    return state.with_enrollment(
        Enrollment(
            issuer,
            authority_pem.strip() + "\n",
            recovery_pem=recovery_pem and recovery_pem.strip() + "\n",
        )
    )


@dataclass(frozen=True)
class AuthResult:
    accepted: bool
    blocking: tuple[str, ...]
    notes: tuple[str, ...] = ()
    statement: dict[str, Any] | None = None
    digest: str | None = None
    enrollment: Enrollment | None = None  # the enrollment AFTER applying (not yet committed)
    voided: tuple[str, ...] = ()
    limit: str = ROLLBACK_LIMIT
    # On a refused recovery with a valid anchor signature: the compromise knowledge it carries anyway.
    declared: dict[str, str | None] | None = None

    @property
    def code(self) -> str | None:
        return self.blocking[0] if self.blocking else None


def _auth_refuse(code: str, *notes: str) -> AuthResult:
    return AuthResult(False, (code,), tuple(notes))


def _sig_doc(body: dict[str, Any], domain: bytes, signer: Any) -> dict[str, str]:
    import base64

    sig = signer.sign(domain + canonical_bytes(body))
    return {"algorithm": "ed25519", "signature_b64": base64.b64encode(sig).decode()}


def _sig_ok(pem: str, domain: bytes, body: dict[str, Any], sig: dict[str, str]) -> bool:
    try:
        decode_canonical_b64(sig["signature_b64"], length=64)
        return bool(verify_signature(pem, domain + canonical_bytes(body), sig["signature_b64"]))
    except Exception:
        return False


def _auth_ref(obj: Any, what: str, *, pem: bool) -> None:
    members = {"key_id", "key_fingerprint", "generation"} | ({"public_key_pem"} if pem else set())
    _exact(obj, members, what)
    _ident(obj["key_id"], f"{what}.key_id")
    _fp(obj["key_fingerprint"], f"{what}.key_fingerprint")
    if type(obj["generation"]) is not int or obj["generation"] < 1:
        raise ShapeError(f"{what}.generation must be an integer >= 1")
    if pem and (not isinstance(obj["public_key_pem"], str) or len(obj["public_key_pem"]) > 4096):
        raise ShapeError(f"{what}.public_key_pem must be a PEM string")


def _sigs(obj: Any, names: set[str]) -> None:
    _exact(obj, names, "signatures")
    for n in names:
        _exact(obj[n], {"algorithm", "signature_b64"}, f"signatures.{n}")
        if obj[n]["algorithm"] != "ed25519":
            raise ShapeError("signature.algorithm must be ed25519")


def validate_transition_shape(doc: Any) -> None:
    _exact(doc, TRANS_MEMBERS, "transition")
    if doc["schema"] != TRANSITION_SCHEMA:
        raise ShapeError("wrong schema")
    for n in ("schema_version", "algorithm_version"):
        if type(doc[n]) is not int:
            raise ShapeError(f"{n} must be an integer")
    _ident(doc["issuer"], "issuer")
    _auth_ref(doc["from_authority"], "from_authority", pem=False)
    _auth_ref(doc["to_authority"], "to_authority", pem=True)
    if not _t(doc["issued_at"], "issued_at") < _t(doc["valid_until"], "valid_until"):
        raise ShapeError("need issued_at < valid_until")
    _sigs(doc["signatures"], {"from", "to"})


def validate_recovery_shape(doc: Any) -> None:
    _exact(doc, REC_MEMBERS, "recovery")
    if doc["schema"] != RECOVERY_SCHEMA:
        raise ShapeError("wrong schema")
    for n in ("schema_version", "algorithm_version", "recovery_epoch"):
        if type(doc[n]) is not int:
            raise ShapeError(f"{n} must be an integer")
    if doc["recovery_epoch"] < 1:
        raise ShapeError("recovery_epoch must be >= 1")
    _ident(doc["issuer"], "issuer")
    _exact(doc["recovery_anchor"], {"key_id", "key_fingerprint"}, "recovery_anchor")
    _ident(doc["recovery_anchor"]["key_id"], "recovery_anchor.key_id")
    _fp(doc["recovery_anchor"]["key_fingerprint"], "recovery_anchor.key_fingerprint")
    declared = doc["declares_compromised"]
    if not isinstance(declared, list) or not declared or len(declared) > 64:
        raise ShapeError("declares_compromised must be a non-empty list (at most 64)")
    last = None
    for i, d in enumerate(declared):
        _exact(d, {"key_fingerprint", "compromised_from"}, f"declares_compromised[{i}]")
        fp = _fp(d["key_fingerprint"], "declared fingerprint")
        if last is not None and fp <= last:
            raise ShapeError("declares_compromised must be strictly sorted by fingerprint")
        last = fp
        if d["compromised_from"] is not None:
            _t(d["compromised_from"], "compromised_from")
    _auth_ref(doc["new_authority"], "new_authority", pem=True)
    if doc["rebase"] is not None:
        _exact(doc["rebase"], {"epoch", "list_digest"}, "rebase")
        if type(doc["rebase"]["epoch"]) is not int or doc["rebase"]["epoch"] < 1:
            raise ShapeError("rebase.epoch must be an integer >= 1")
        _fp(doc["rebase"]["list_digest"], "rebase.list_digest")
    if not _t(doc["issued_at"], "issued_at") < _t(doc["valid_until"], "valid_until"):
        raise ShapeError("need issued_at < valid_until")
    _sigs(doc["signatures"], {"anchor", "new_authority"})


def _without(doc: dict[str, Any], key: str = "signatures") -> dict[str, Any]:
    return {k: v for k, v in doc.items() if k != key}


def transition_digest(doc: dict[str, Any]) -> str:
    return hashlib.sha256(TRANS_DIGEST_DOMAIN + canonical_bytes(_without(doc))).hexdigest()


def recovery_digest(doc: dict[str, Any]) -> str:
    return hashlib.sha256(REC_DIGEST_DOMAIN + canonical_bytes(_without(doc))).hexdigest()


def build_transition_body(
    *, issuer: str, from_key_id: str, from_pem: str, from_generation: int, to_key_id: str,
    to_pem: str, to_generation: int | None = None, issued_at: str, valid_until: str,
) -> dict[str, Any]:  # fmt: skip
    return {
        "schema": TRANSITION_SCHEMA,
        "schema_version": 1,
        "algorithm_version": 1,
        "issuer": issuer,
        "from_authority": {
            "key_id": from_key_id,
            "key_fingerprint": spki_fingerprint(from_pem),
            "generation": from_generation,
        },
        "to_authority": {
            "key_id": to_key_id,
            "key_fingerprint": spki_fingerprint(to_pem),
            "generation": to_generation if to_generation is not None else from_generation + 1,
            "public_key_pem": to_pem,
        },
        "issued_at": issued_at,
        "valid_until": valid_until,
    }


def sign_transition(body: dict[str, Any], from_signer: Any, to_signer: Any) -> dict[str, Any]:
    body = _without(body)
    return {
        **body,
        "signatures": {
            "from": _sig_doc(body, TRANS_FROM_DOMAIN, from_signer),
            "to": _sig_doc(body, TRANS_TO_DOMAIN, to_signer),
        },
    }


def build_recovery_body(
    *, issuer: str, anchor_key_id: str, anchor_pem: str, recovery_epoch: int,
    declares: list[tuple[str, str | None]], new_key_id: str, new_pem: str, new_generation: int,
    rebase: dict[str, Any] | None = None, issued_at: str, valid_until: str,
) -> dict[str, Any]:  # fmt: skip
    return {
        "schema": RECOVERY_SCHEMA,
        "schema_version": 1,
        "algorithm_version": 1,
        "issuer": issuer,
        "recovery_anchor": {
            "key_id": anchor_key_id,
            "key_fingerprint": spki_fingerprint(anchor_pem),
        },
        "recovery_epoch": recovery_epoch,
        "declares_compromised": [
            {"key_fingerprint": fp, "compromised_from": c} for fp, c in sorted(declares)
        ],
        "new_authority": {
            "key_id": new_key_id,
            "key_fingerprint": spki_fingerprint(new_pem),
            "generation": new_generation,
            "public_key_pem": new_pem,
        },
        "rebase": rebase,
        "issued_at": issued_at,
        "valid_until": valid_until,
    }


def sign_recovery(body: dict[str, Any], anchor_signer: Any, new_signer: Any) -> dict[str, Any]:
    body = _without(body)
    return {
        **body,
        "signatures": {
            "anchor": _sig_doc(body, REC_ANCHOR_DOMAIN, anchor_signer),
            "new_authority": _sig_doc(body, REC_TO_DOMAIN, new_signer),
        },
    }


def _pem_matches(ref: dict[str, Any]) -> bool:
    try:
        return spki_fingerprint(ref["public_key_pem"]) == ref["key_fingerprint"]
    except Exception:
        return False


def _timed(doc: dict[str, Any], now: datetime) -> str | None:
    if parse_rfc3339(doc["issued_at"]) > now + SKEW:
        return "REVOCATION_NOT_YET_VALID"
    if now >= parse_rfc3339(doc["valid_until"]):
        return "REVOCATION_EXPIRED"
    return None


def _earlier(a: str | None, b: str | None) -> str | None:
    if a is None or b is None:
        return None
    return min(a, b, key=parse_rfc3339)


def _role_conflict_report(fp: str, store: TrustStore | None) -> bool:
    return store is not None and any(spki_fingerprint(p) == fp for p in store.keys.values())


def _role_conflict(fp: str, enr: Enrollment, store: TrustStore | None) -> bool:
    if enr.recovery_pem is not None and spki_fingerprint(enr.recovery_pem) == fp:
        return True
    return store is not None and any(spki_fingerprint(p) == fp for p in store.keys.values())


def verify_transition(
    raw: str | bytes, state: RevocationState, store: TrustStore | None, now: datetime
) -> AuthResult:
    """ROUTINE rotation: the current authority names its successor; the successor proves possession.

    Pure. Cannot be used for compromise recovery: a transition signed by a key already declared
    compromised is refused, and one accepted earlier is superseded by a later recovery statement.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    try:
        doc = loads_strict(raw, max_bytes=MAX_BYTES)
        validate_transition_shape(doc)
    except (CanonicalError, RecursionError, ShapeError, UnicodeDecodeError) as exc:
        return _auth_refuse("REVOCATION_MALFORMED", str(exc))
    if doc["schema_version"] != 1 or doc["algorithm_version"] != 1:
        return _auth_refuse("REVOCATION_VERSION_UNSUPPORTED")
    enr = state.enrollments.get(doc["issuer"])
    if enr is None:
        return _auth_refuse("REVOCATION_NOT_ENROLLED")
    frm, to = doc["from_authority"], doc["to_authority"]
    if frm["key_fingerprint"] in enr.compromised:
        return _auth_refuse(
            "REVOCATION_AUTHORITY_COMPROMISED",
            "a compromised authority cannot hand over; use recovery",
        )
    if frm["key_fingerprint"] in enr.superseded:
        return _auth_refuse("REVOCATION_AUTHORITY_SUPERSEDED")
    if frm["key_fingerprint"] != enr.authority_fingerprint:
        return _auth_refuse("REVOCATION_AUTHORITY_MISMATCH")
    if frm["generation"] != enr.generation or to["generation"] != frm["generation"] + 1:
        return _auth_refuse("REVOCATION_TRANSITION_GAP")
    if not _pem_matches(to):
        return _auth_refuse(
            "REVOCATION_MALFORMED", "to_authority fingerprint does not match its key"
        )
    to_fp = to["key_fingerprint"]
    if to_fp == frm["key_fingerprint"] or to_fp in enr.compromised or to_fp in enr.superseded:
        return _auth_refuse("REVOCATION_TRANSITION_CYCLE", "an authority key is never reused")
    if _role_conflict(to_fp, enr, store):
        return _auth_refuse(
            "REVOCATION_KEY_IS_REPORT_KEY", "new authority is a recovery anchor or report key"
        )
    body = _without(doc)
    if not (
        _sig_ok(enr.authority_pem, TRANS_FROM_DOMAIN, body, doc["signatures"]["from"])
        and _sig_ok(to["public_key_pem"], TRANS_TO_DOMAIN, body, doc["signatures"]["to"])
    ):
        return _auth_refuse("REVOCATION_SIGNATURE_INVALID")
    timing = _timed(doc, now)
    if timing:
        return _auth_refuse(timing)
    digest = transition_digest(doc)
    new = replace(
        enr,
        authority_pem=to["public_key_pem"].strip() + "\n",
        generation=to["generation"],
        superseded=(*enr.superseded, frm["key_fingerprint"]),
        accepted_transitions=(
            *enr.accepted_transitions,
            {
                "digest": digest,
                "signed_by": frm["key_fingerprint"],
                "issued_at": doc["issued_at"],
                "accepted_at": _z(now),
                "to": to_fp,
                "from_generation": frm["generation"],
            },
        ),
    )
    return AuthResult(True, (), (), doc, digest, new)


def apply_authority(state: RevocationState, result: AuthResult) -> RevocationState:
    """Commit an accepted transition or recovery (compare-and-set in a real verifier)."""
    if not result.accepted or result.enrollment is None or "REVOCATION_REPEAT" in result.notes:
        return state  # a repeated statement is public and replayable: it must change nothing
    new = state.with_enrollment(result.enrollment)
    if (
        result.statement is not None
        and result.statement.get("rebase")
        and "REVOCATION_REBASE_NOOP" not in result.notes
    ):
        base = state.archive.get(result.statement["rebase"]["list_digest"])
        if base is not None:
            marks = dict(new.marks)
            marks[RevocationState.slot(result.enrollment.issuer)] = base
            new = replace(new, marks=marks)
    return new


def verify_transition_chain(
    raws: list[str | bytes], state: RevocationState, store: TrustStore | None, now: datetime
) -> tuple[RevocationState, list[AuthResult]]:
    """Apply transitions in order; stops at the first refusal (gap, cycle, replay, ...)."""
    results: list[AuthResult] = []
    for raw in raws:
        res = verify_transition(raw, state, store, now)
        results.append(res)
        if not res.accepted:
            break
        state = apply_authority(state, res)
    return state, results


def verify_recovery(
    raw: str | bytes, state: RevocationState, store: TrustStore | None, now: datetime
) -> AuthResult:
    """COMPROMISE RECOVERY: signed by the separately enrolled recovery anchor, never by the authority."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    try:
        doc = loads_strict(raw, max_bytes=MAX_BYTES)
        validate_recovery_shape(doc)
    except (CanonicalError, RecursionError, ShapeError, UnicodeDecodeError) as exc:
        return _auth_refuse("REVOCATION_MALFORMED", str(exc))
    if doc["schema_version"] != 1 or doc["algorithm_version"] != 1:
        return _auth_refuse("REVOCATION_VERSION_UNSUPPORTED")
    enr = state.enrollments.get(doc["issuer"])
    if enr is None:
        return _auth_refuse("REVOCATION_NOT_ENROLLED")
    if enr.recovery_pem is None:
        return _auth_refuse(
            "REVOCATION_RECOVERY_ANCHOR_ABSENT",
            "no recovery anchor was enrolled: only operator re-enrollment can recover",
        )
    if doc["recovery_anchor"]["key_fingerprint"] != spki_fingerprint(enr.recovery_pem):
        return _auth_refuse("REVOCATION_RECOVERY_ANCHOR_MISMATCH")
    if _role_conflict_report(spki_fingerprint(enr.recovery_pem), store):
        return _auth_refuse("REVOCATION_KEY_IS_REPORT_KEY", "the recovery anchor is enrolled as a report key")
    new = doc["new_authority"]
    if not _pem_matches(new):
        return _auth_refuse(
            "REVOCATION_MALFORMED", "new_authority fingerprint does not match its key"
        )
    body = _without(doc)
    if not (
        _sig_ok(enr.recovery_pem, REC_ANCHOR_DOMAIN, body, doc["signatures"]["anchor"])
        and _sig_ok(new["public_key_pem"], REC_TO_DOMAIN, body, doc["signatures"]["new_authority"])
    ):
        return _auth_refuse("REVOCATION_SIGNATURE_INVALID")
    digest = recovery_digest(doc)
    if (
        doc["recovery_epoch"] == enr.recovery_epoch
        and digest == enr.recovery_digest
        and _timed(doc, now) is None
    ):
        return AuthResult(True, (), ("REVOCATION_REPEAT",), doc, digest, enr)

    declared = {d["key_fingerprint"]: d["compromised_from"] for d in doc["declares_compromised"]}
    issued = parse_rfc3339(doc["issued_at"])
    new_fp = new["key_fingerprint"]
    anchor_fp = spki_fingerprint(enr.recovery_pem)
    coherent = (
        all(b is None or parse_rfc3339(b) <= issued + SKEW for b in declared.values())
        and anchor_fp not in declared
        and new_fp not in declared
    )
    merged: dict[str, str | None] = dict(enr.compromised)
    for fp, boundary in declared.items():
        merged[fp] = _earlier(merged[fp], boundary) if fp in merged else boundary

    # Transitions taken from a key at or after its boundary are void, with every hop after the first. Keys they
    # installed are condemned: nobody but the thief knows those keys, so no statement can name them. Compared on
    # this verifier's own acceptance time as well, because the thief writes issued_at.
    voided_digests: list[str] = []
    base_generation = enr.generation
    for t in enr.accepted_transitions:
        if not voided_digests:
            if t["signed_by"] not in merged:
                continue
            limit = merged[t["signed_by"]]
            times = [t["issued_at"], t["accepted_at"]]
            if limit is not None and all(parse_rfc3339(x) < parse_rfc3339(limit) for x in times):
                continue
            base_generation = t["from_generation"]
        voided_digests.append(t["digest"])
        merged[t["to"]] = None
    def refuse(code: str, *notes: str) -> AuthResult:
        """Everything past the anchor signature is the anchor speaking. Whatever stops the authority change
        (a lost baseline, expiry, a generation) must not leave the verifier trusting a key it was told is stolen."""
        tell = merged if coherent and merged != enr.compromised else None
        return AuthResult(False, (code,), tuple(notes), declared=tell)

    timing = _timed(doc, now)
    if timing:
        return refuse(timing)
    if doc["recovery_epoch"] < enr.recovery_epoch:
        return refuse("REVOCATION_RECOVERY_REPLAY")
    if doc["recovery_epoch"] == enr.recovery_epoch:
        return refuse("REVOCATION_FORK", "same recovery_epoch, different statement")
    for boundary in declared.values():
        if boundary is not None and parse_rfc3339(boundary) > issued + SKEW:
            return refuse("REVOCATION_MALFORMED", "compromised_from after issued_at")

    if (
        new_fp in merged
        or new_fp in enr.superseded
        or new_fp == enr.authority_fingerprint
    ):
        return refuse("REVOCATION_TRANSITION_CYCLE", "the new authority must be a fresh key")
    if _role_conflict(new_fp, enr, store):
        return refuse("REVOCATION_KEY_IS_REPORT_KEY")
    if anchor_fp in declared:
        return refuse("REVOCATION_MALFORMED", "the recovery anchor cannot declare itself compromised")
    if new["generation"] <= base_generation:
        return refuse("REVOCATION_TRANSITION_GAP", "generation must increase")
    notes: tuple[str, ...] = ()
    if doc["rebase"] is not None:
        mark = state.get(doc["issuer"])
        if mark is not None and mark.epoch < doc["rebase"]["epoch"]:
            notes = ("REVOCATION_REBASE_NOOP",)  # this verifier never passed the baseline
        else:
            base = state.archive.get(doc["rebase"]["list_digest"])
            if base is None or base.epoch != doc["rebase"]["epoch"] or base.issuer != doc["issuer"]:
                return refuse("REVOCATION_RECOVERY_BASELINE_UNKNOWN")
    cur = enr.authority_fingerprint
    superseded = enr.superseded if cur in merged else (*enr.superseded, cur)
    updated = replace(
        enr,
        authority_pem=new["public_key_pem"].strip() + "\n",
        generation=new["generation"],
        compromised=merged,
        superseded=superseded,
        recovery_epoch=doc["recovery_epoch"],
        recovery_digest=digest,
        voided=(*enr.voided, *voided_digests),
    )
    return AuthResult(True, (), notes, doc, digest, updated, tuple(voided_digests))


def verify_list_enrolled(
    raw: str | bytes,
    issuer: str,
    store: TrustStore | None,
    state: RevocationState,
    now: datetime,
    **kw: Any,
) -> ListResult:
    """Verify a list against the CURRENT enrolled authority (nothing is pinned inside the list)."""
    enr = state.enrollments.get(issuer)
    if enr is None:
        return _refuse("REVOCATION_NOT_ENROLLED")
    return verify_list(raw, enr.anchor, store, state, now, enrollment=enr, **kw)


__all__ = [n for n in dir() if not n.startswith("_")]
