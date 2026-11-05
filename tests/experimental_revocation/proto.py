"""The product's document verifiers, plus what deliberately stays out of the product.

These tests started against a tests-only prototype. They now run against
``regaudit_fhe._revocation``. Only two things remain here, because they must not ship: the unapproved
list-derived history option (owner decision OD-7) and the whole-file state save, which has no compare-and-set.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from regaudit_fhe._revocation import *  # noqa: F403
from regaudit_fhe._revocation import Anchor as Anchor
from regaudit_fhe._revocation import (
    Enrollment,
    ListResult,
    Mark,
    _refuse,
    _sig_doc,  # noqa: F401
    _without,  # noqa: F401
    apply_to_store,
    commit,
    verify_list,
)
from regaudit_fhe._revocation import RevocationState as _ProductState
from regaudit_fhe._time import parse_rfc3339
from regaudit_fhe.canonical import canonical_bytes as canonical_bytes
from regaudit_fhe.canonical import loads_strict
from regaudit_fhe.trust import TrustStore
from regaudit_fhe.verification import TrustHistory


@dataclass(frozen=True)
class RevocationState(_ProductState):
    """Adds the whole-file save and load the early tests use. Not a product code path."""

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
        try:
            raw = loads_strict(Path(path).read_bytes(), max_bytes=MAX_BYTES)  # noqa: F405
        except FileNotFoundError:
            return cls()
        return cls(
            {s: Mark(**m) for s, m in raw["marks"].items()},
            {s: Enrollment.from_dict(e) for s, e in raw["enrollments"].items()},
            {s: Mark(**m) for s, m in raw["archive"].items()},
        )


HISTORY_PROFILES = ("development", "confidential")


def derive_trust_history(
    result: ListResult, now: datetime, *, profile: str, owner_approved: bool = False
) -> TrustHistory | None:
    """OPTIONAL, NOT APPROVED, LOWER PROFILES ONLY, AND NOT IN THE PRODUCT (OD-7)."""
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
    state: Any
    revocation_evidence: str
    limit: str = ROLLBACK_LIMIT  # noqa: F405


def evaluate(
    store: TrustStore,
    raw: str | bytes | None,
    anchor: Anchor,
    state: Any,
    now: datetime,
    *,
    allow_gap: bool = True,
    profile: str = "confidential",
    owner_approved_history: bool = False,
) -> Outcome:
    """The draft's one-call helper, kept so that the worked examples keep running on the real engine."""
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
    """Signed successor chain starting at (key_id, fingerprint). Evidence only."""
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
