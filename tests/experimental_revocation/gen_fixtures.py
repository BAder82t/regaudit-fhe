"""Deterministic fixture generator for the experimental revocation-list prototype (tests only).

Keys are derived from fixed labels so signatures (Ed25519 is deterministic) and canonical bytes are
reproducible and can be pinned as golden values. ``python -m tests.experimental_revocation.gen_fixtures
OUTDIR`` writes the vectors as JSON for inspection; nothing here is shipped.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import regaudit_fhe as rf
from regaudit_fhe._keys import spki_fingerprint
from regaudit_fhe.trust import TrustStore

from . import proto

UTC = timezone.utc
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
ISSUED = "2026-11-01T09:00:00Z"
UNTIL = "2026-11-08T09:00:00Z"


def det_signer(label: str, issuer: str, key_id: str) -> rf.Signer:
    priv = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
    return rf.Signer(issuer=issuer, key_id=key_id, private_key=priv, public_key=priv.public_key())


@dataclass
class World:
    issuer: str
    old: rf.Signer  # report key, to be retired/replaced/compromised
    new: rf.Signer  # report key, successor
    third: rf.Signer  # another report key
    rev: rf.Signer  # DEDICATED revocation key
    other_rev: rf.Signer  # an unrelated revocation key (impostor)

    @property
    def anchor(self) -> proto.Anchor:
        return proto.Anchor(self.issuer, self.rev.public_key_pem())

    def fp(self, s: rf.Signer) -> str:
        return spki_fingerprint(s.public_key_pem())

    def store(self, *signers: rf.Signer) -> TrustStore:
        who = signers or (self.old, self.new)
        return TrustStore.from_dict(
            {
                "entries": {
                    s.key_id: {
                        "issuer": self.issuer,
                        "public_key_pem": s.public_key_pem(),
                        "status": "active",
                    }
                    for s in who
                }
            }
        )

    def entry(
        self,
        s: rf.Signer,
        status: str,
        effective_from: str | None,
        successor: rf.Signer | None = None,
    ) -> dict[str, Any]:
        e: dict[str, Any] = {
            "key_id": s.key_id,
            "key_fingerprint": self.fp(s),
            "status": status,
            "effective_from": effective_from,
        }
        if successor is not None:
            e["successor"] = {"key_id": successor.key_id, "key_fingerprint": self.fp(successor)}
        return e

    def body(self, epoch: int, entries: list[dict[str, Any]], *, prev: str | None = None,
             issued_at: str = ISSUED, valid_until: str = UNTIL, signer: rf.Signer | None = None) -> dict[str, Any]:  # fmt: skip
        k = signer or self.rev
        return proto.build_body(
            issuer=self.issuer,
            authority_key_id=k.key_id,
            authority_pem=k.public_key_pem(),
            epoch=epoch,
            prev_list_digest=prev,
            issued_at=issued_at,
            valid_until=valid_until,
            entries=entries,
        )

    def signed(self, epoch: int, entries: list[dict[str, Any]], *, signer: rf.Signer | None = None, **kw: Any) -> dict[str, Any]:  # fmt: skip
        return proto.sign_list(self.body(epoch, entries, signer=signer, **kw), signer or self.rev)


def make_world(issuer: str = "acme") -> World:
    return World(
        issuer=issuer,
        old=det_signer("report-old", issuer, "acme-2026a"),
        new=det_signer("report-new", issuer, "acme-2026b"),
        third=det_signer("report-third", issuer, "acme-2026c"),
        rev=det_signer("revocation-key", issuer, "acme-rev-1"),
        other_rev=det_signer("revocation-impostor", issuer, "acme-rev-x"),
    )


def dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc, sort_keys=True)


def write_fixtures(out: Path) -> list[str]:
    """Write a small vector set (keys are synthetic, derived from fixed labels)."""
    w = make_world()
    out.mkdir(parents=True, exist_ok=True)
    e1 = [w.entry(w.old, "retired", "2026-10-01T00:00:00Z")]
    l1 = w.signed(1, e1)
    l2 = w.signed(
        2, [w.entry(w.old, "replaced", "2026-10-01T00:00:00Z", w.new)], prev=proto.list_digest(l1)
    )
    vectors = {
        "list-1-retired": l1,
        "list-2-replaced": l2,
        "list-compromised-unknown": w.signed(1, [w.entry(w.old, "compromised", None)]),
    }
    names = []
    for name, doc in vectors.items():
        (out / f"{name}.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        names.append(name)
    (out / "anchor.json").write_text(
        json.dumps({"issuer": w.issuer, "public_key_pem": w.rev.public_key_pem(),
                    "fingerprint": w.anchor.fingerprint}, indent=2) + "\n")  # fmt: skip
    return names


if __name__ == "__main__":  # pragma: no cover
    print(write_fixtures(Path(sys.argv[1])))
