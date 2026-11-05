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
TISSUED = "2026-11-01T08:00:00Z"
RISSUED = "2026-11-01T10:00:00Z"
TUNTIL = "2026-11-15T08:00:00Z"


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
    recovery: rf.Signer  # the separately enrolled RECOVERY ANCHOR (offline)
    auth2: rf.Signer  # next revocation authority (routine rotation target)
    auth3: rf.Signer  # authority after that
    evil: rf.Signer  # authority key chosen by an attacker who holds the old authority key

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
             issued_at: str = ISSUED, valid_until: str = UNTIL, signer: rf.Signer | None = None,
             generation: int = 1) -> dict[str, Any]:  # fmt: skip
        k = signer or self.rev
        return proto.build_body(
            issuer=self.issuer,
            authority_key_id=k.key_id,
            authority_pem=k.public_key_pem(),
            authority_generation=generation,
            epoch=epoch,
            prev_list_digest=prev,
            issued_at=issued_at,
            valid_until=valid_until,
            entries=entries,
        )

    def signed(self, epoch: int, entries: list[dict[str, Any]], *, signer: rf.Signer | None = None, **kw: Any) -> dict[str, Any]:  # fmt: skip
        return proto.sign_list(self.body(epoch, entries, signer=signer, **kw), signer or self.rev)

    def enrolled(
        self, *, recovery: bool = True, store: TrustStore | None = None
    ) -> proto.RevocationState:
        """Operator action: explicit local enrollment of the authority (and recovery anchor)."""
        return proto.enroll(
            proto.RevocationState(),
            self.issuer,
            self.rev.public_key_pem(),
            recovery_pem=self.recovery.public_key_pem() if recovery else None,
            store=store,
        )

    def transition(self, frm: rf.Signer, to: rf.Signer, *, from_gen: int = 1, to_gen: int | None = None,
                   issued_at: str = TISSUED, valid_until: str = TUNTIL, to_signer: rf.Signer | None = None,
                   from_signer: rf.Signer | None = None) -> dict[str, Any]:  # fmt: skip
        body = proto.build_transition_body(
            issuer=self.issuer, from_key_id=frm.key_id, from_pem=frm.public_key_pem(),
            from_generation=from_gen, to_key_id=to.key_id, to_pem=to.public_key_pem(),
            to_generation=to_gen, issued_at=issued_at, valid_until=valid_until,
        )  # fmt: skip
        return proto.sign_transition(body, from_signer or frm, to_signer or to)

    def recovery_stmt(self, new: rf.Signer, *, declares: list[tuple[str, str | None]] | None = None,
                      epoch: int = 1, new_gen: int = 2, rebase: dict[str, Any] | None = None,
                      issued_at: str = RISSUED, valid_until: str = TUNTIL,
                      anchor_signer: rf.Signer | None = None, new_signer: rf.Signer | None = None,
                      anchor: rf.Signer | None = None) -> dict[str, Any]:  # fmt: skip
        a = anchor or self.recovery
        body = proto.build_recovery_body(
            issuer=self.issuer, anchor_key_id=a.key_id, anchor_pem=a.public_key_pem(),
            recovery_epoch=epoch, declares=declares if declares is not None else [(self.fp(self.rev), None)],
            new_key_id=new.key_id, new_pem=new.public_key_pem(), new_generation=new_gen,
            rebase=rebase, issued_at=issued_at, valid_until=valid_until,
        )  # fmt: skip
        return proto.sign_recovery(body, anchor_signer or a, new_signer or new)


def make_world(issuer: str = "acme") -> World:
    return World(
        issuer=issuer,
        old=det_signer("report-old", issuer, "acme-2026a"),
        new=det_signer("report-new", issuer, "acme-2026b"),
        third=det_signer("report-third", issuer, "acme-2026c"),
        rev=det_signer("revocation-key", issuer, "acme-rev-1"),
        other_rev=det_signer("revocation-impostor", issuer, "acme-rev-x"),
        recovery=det_signer("recovery-anchor", issuer, "acme-recovery-1"),
        auth2=det_signer("revocation-key-2", issuer, "acme-rev-2"),
        auth3=det_signer("revocation-key-3", issuer, "acme-rev-3"),
        evil=det_signer("revocation-key-evil", issuer, "acme-rev-evil"),
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


def golden() -> dict[str, Any]:
    """Frozen golden vectors for the three statement kinds (deterministic keys, fixed times)."""
    import base64

    w = make_world()
    keys = {
        name: {"key_id": s.key_id, "public_key_pem": s.public_key_pem(), "fingerprint": spki_fingerprint(s.public_key_pem())}
        for name, s in (("revocation_authority_1", w.rev), ("revocation_authority_2", w.auth2),
                        ("recovery_anchor", w.recovery), ("report_key_old", w.old), ("report_key_new", w.new))
    }  # fmt: skip

    def sha(b: bytes) -> str:
        return hashlib.sha256(b).hexdigest()

    l1 = w.signed(1, [w.entry(w.old, "retired", "2026-10-01T00:00:00Z")])
    l2 = w.signed(
        2,
        [
            w.entry(w.old, "replaced", "2026-10-01T00:00:00Z", w.new),
            w.entry(w.third, "compromised", None),
        ],
        prev=proto.list_digest(l1),
    )
    tr = w.transition(w.rev, w.auth2)
    rc = w.recovery_stmt(w.auth2, declares=[(w.fp(w.rev), "2026-09-01T00:00:00Z")],
                         rebase={"epoch": 1, "list_digest": proto.list_digest(l1)})  # fmt: skip

    def sigbytes(doc: dict[str, Any], *path: str) -> str:
        cur: Any = doc
        for p in path:
            cur = cur[p]
        return base64.b64decode(cur["signature_b64"]).hex()

    return {
        "note": "FROZEN draft-v1 golden vectors (synthetic deterministic keys). Regenerate only with a version bump.",
        "keys": keys,
        "list_epoch1_retired": {
            "document": l1,
            "signing_input_sha256": sha(proto.signing_input(l1)),
            "digest": proto.list_digest(l1),
            "signature_hex": sigbytes(l1, "signature"),
        },
        "list_epoch2_replaced_and_compromised": {
            "document": l2,
            "signing_input_sha256": sha(proto.signing_input(l2)),
            "digest": proto.list_digest(l2),
            "signature_hex": sigbytes(l2, "signature"),
        },
        "authority_transition": {
            "document": tr,
            "signing_input_from_sha256": sha(
                proto.TRANS_FROM_DOMAIN + proto.canonical_bytes(proto._without(tr))
            ),
            "signing_input_to_sha256": sha(
                proto.TRANS_TO_DOMAIN + proto.canonical_bytes(proto._without(tr))
            ),
            "digest": proto.transition_digest(tr),
            "signature_from_hex": sigbytes(tr, "signatures", "from"),
            "signature_to_hex": sigbytes(tr, "signatures", "to"),
        },
        "authority_recovery": {
            "document": rc,
            "signing_input_anchor_sha256": sha(
                proto.REC_ANCHOR_DOMAIN + proto.canonical_bytes(proto._without(rc))
            ),
            "signing_input_new_authority_sha256": sha(
                proto.REC_TO_DOMAIN + proto.canonical_bytes(proto._without(rc))
            ),
            "digest": proto.recovery_digest(rc),
            "signature_anchor_hex": sigbytes(rc, "signatures", "anchor"),
            "signature_new_authority_hex": sigbytes(rc, "signatures", "new_authority"),
        },
    }


def golden_text() -> str:
    return json.dumps(golden(), indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":  # pragma: no cover
    print(write_fixtures(Path(sys.argv[1])))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(golden_text())
