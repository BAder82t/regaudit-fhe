"""Adversarial compatibility corpus for the draft-v1 revocation formats (tests only, deterministic).

``python -m tests.experimental_revocation.corpus`` rewrites ``tests/experimental_revocation/corpus/``.
Every case is a byte string plus the verifier preset it runs against and the exact expected outcome,
so a different implementation of the frozen spec can replay the same files.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from regaudit_fhe.trust import TrustStore

from . import proto
from .gen_fixtures import NOW, World, dump, make_world

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
E = "2026-09-01T00:00:00Z"
R = "2026-10-01T00:00:00Z"
ACCEPT = "ACCEPT"


def store(w: World, issuer: str | None = None) -> TrustStore:
    if issuer is None:
        return w.store(w.old, w.new, w.third)
    return TrustStore.from_dict(
        {
            "entries": {
                w.old.key_id: {
                    "issuer": issuer,
                    "public_key_pem": w.old.public_key_pem(),
                    "status": "active",
                }
            }
        }
    )


def _commit(w: World, state: proto.RevocationState, doc: dict[str, Any]) -> proto.RevocationState:
    res = proto.verify_list_enrolled(dump(doc), w.issuer, store(w), state, NOW)
    assert res.accepted, res.blocking
    return proto.commit(state, state.enrollments[w.issuer].anchor, res)


def _l(
    w: World, signer: Any, epoch: int, entries: list[dict[str, Any]], **kw: Any
) -> dict[str, Any]:
    return w.signed(epoch, entries, signer=signer, **kw)


def _base_entries(w: World) -> list[dict[str, Any]]:
    return [w.entry(w.old, "compromised", E), w.entry(w.third, "retired", R)]


def preset(name: str, w: World) -> proto.RevocationState:
    """Named verifier states (all built through the prototype's own operations)."""
    if name == "empty":
        return proto.RevocationState()
    if name == "enrolled":
        return w.enrolled()
    if name == "enrolled-no-recovery":
        return w.enrolled(recovery=False)
    if name == "epoch2":
        state = w.enrolled()
        l1 = _l(w, w.rev, 1, _base_entries(w))
        state = _commit(w, state, l1)
        return _commit(w, state, _l(w, w.rev, 2, _base_entries(w), prev=proto.list_digest(l1)))
    if name == "rotated":
        state = w.enrolled()
        res = proto.verify_transition(dump(w.transition(w.rev, w.auth2)), state, None, NOW)
        assert res.accepted
        return proto.apply_authority(state, res)
    if name == "recovered":
        state = w.enrolled()
        res = proto.verify_recovery(
            dump(w.recovery_stmt(w.auth2, declares=[(w.fp(w.rev), E)])), state, None, NOW
        )
        assert res.accepted
        return proto.apply_authority(state, res)
    raise KeyError(name)


Case = tuple[str, str, str, Callable[[World], Any], str]  # name, kind, preset, builder, expected


def _bad_sig(doc: dict[str, Any], path: tuple[str, ...], value: str) -> dict[str, Any]:
    d = copy.deepcopy(doc)
    cur = d
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value
    return d


def _wrong_issuer(w: World) -> dict[str, Any]:
    body = w.body(1, _base_entries(w))
    body["issuer"] = "globex"
    return proto.sign_list(body, w.rev)


def _version2(w: World) -> dict[str, Any]:
    body = w.body(1, _base_entries(w))
    body["schema_version"] = 2
    return proto.sign_list(body, w.rev)


def _dup_entries(w: World) -> dict[str, Any]:
    body = w.body(1, [])
    e = w.entry(w.old, "retired", R)
    body["entries"] = [e, copy.deepcopy(e)]
    return proto.sign_list(body, w.rev)


def _unsorted(w: World) -> dict[str, Any]:
    body = w.body(1, [])
    body["entries"] = [w.entry(w.third, "retired", R), w.entry(w.old, "retired", R)]
    return proto.sign_list(body, w.rev)


def _unknown_member(w: World) -> dict[str, Any]:
    body = w.body(1, _base_entries(w))
    body["extra"] = 1
    return proto.sign_list(body, w.rev)


def _dup_json_key(w: World) -> bytes:
    text = dump(_l(w, w.rev, 1, _base_entries(w)))
    return text.replace('"epoch": 1', '"epoch": 1, "epoch": 2').encode()


def _prev(w: World) -> str:
    return proto.list_digest(_l(w, w.rev, 1, _base_entries(w)))


def _prev2(w: World) -> str:
    return proto.list_digest(_l(w, w.rev, 2, _base_entries(w), prev=_prev(w)))


def _rotated_t12(w: World) -> dict[str, Any]:
    return w.transition(w.rev, w.auth2)


CASES: list[Case] = [
    ("list-valid-epoch1", "list", "enrolled", lambda w: _l(w, w.rev, 1, _base_entries(w)), ACCEPT),
    ("list-forged-issuer", "list", "enrolled", _wrong_issuer, "REVOCATION_WRONG_ISSUER"),
    ("list-wrong-authority", "list", "enrolled", lambda w: _l(w, w.other_rev, 1, _base_entries(w)), "REVOCATION_AUTHORITY_MISMATCH"),
    ("list-bad-signature", "list", "enrolled", lambda w: _bad_sig(_l(w, w.rev, 1, _base_entries(w)), ("signature", "signature_b64"), "A" * 88), "REVOCATION_SIGNATURE_INVALID"),
    ("list-truncated-signature", "list", "enrolled", lambda w: _bad_sig(_l(w, w.rev, 1, _base_entries(w)), ("signature", "signature_b64"), "AAAA"), "REVOCATION_SIGNATURE_INVALID"),
    ("list-tampered-entry", "list", "enrolled", lambda w: _tamper_entry(w), "REVOCATION_SIGNATURE_INVALID"),
    ("list-cross-issuer-revocation", "list-foreign", "enrolled", lambda w: _l(w, w.rev, 1, [w.entry(w.old, "compromised", None)]), "REVOCATION_ISSUER_SCOPE"),
    ("list-duplicate-entries", "list", "enrolled", _dup_entries, "REVOCATION_MALFORMED"),
    ("list-unsorted-entries", "list", "enrolled", _unsorted, "REVOCATION_MALFORMED"),
    ("list-unknown-member", "list", "enrolled", _unknown_member, "REVOCATION_MALFORMED"),
    ("list-duplicate-json-key", "list", "enrolled", _dup_json_key, "REVOCATION_MALFORMED"),
    ("list-version-2", "list", "enrolled", _version2, "REVOCATION_VERSION_UNSUPPORTED"),
    ("list-expired", "list", "enrolled", lambda w: _l(w, w.rev, 1, _base_entries(w), issued_at="2026-10-01T00:00:00Z", valid_until="2026-10-08T00:00:00Z"), "REVOCATION_EXPIRED"),
    ("list-not-enrolled", "list", "empty", lambda w: _l(w, w.rev, 1, _base_entries(w)), "REVOCATION_NOT_ENROLLED"),
    ("list-rollback-to-epoch1", "list", "epoch2", lambda w: _l(w, w.rev, 1, _base_entries(w)), "REVOCATION_ROLLBACK"),
    ("list-replay-epoch2", "list", "epoch2", lambda w: _l(w, w.rev, 2, _base_entries(w), prev=_prev(w)), ACCEPT),
    ("list-fork-epoch2", "list", "epoch2", lambda w: _l(w, w.rev, 2, [w.entry(w.old, "compromised", E)], prev=_prev(w)), "REVOCATION_FORK"),
    ("list-bad-chain-epoch3", "list", "epoch2", lambda w: _l(w, w.rev, 3, _base_entries(w), prev="b" * 64), "REVOCATION_FORK"),
    ("list-omits-revoked-key", "list", "epoch2", lambda w: _l(w, w.rev, 3, [w.entry(w.third, "retired", R)], prev=_prev2(w)), "REVOCATION_NOT_MONOTONE"),
    ("list-loosens-compromise", "list", "epoch2", lambda w: _l(w, w.rev, 3, [w.entry(w.old, "retired", E), w.entry(w.third, "retired", R)], prev=_prev2(w)), "REVOCATION_NOT_MONOTONE"),
    ("list-gap-epoch5", "list", "epoch2", lambda w: _l(w, w.rev, 5, _base_entries(w), prev="b" * 64), ACCEPT),
    ("list-by-superseded-authority", "list", "rotated", lambda w: _l(w, w.rev, 1, _base_entries(w)), "REVOCATION_AUTHORITY_SUPERSEDED"),
    ("list-by-compromised-authority", "list", "recovered", lambda w: _l(w, w.rev, 1, _base_entries(w)), "REVOCATION_AUTHORITY_COMPROMISED"),
    ("list-by-new-authority", "list", "rotated", lambda w: _l(w, w.auth2, 1, _base_entries(w), generation=2), ACCEPT),
    ("list-wrong-generation", "list", "rotated", lambda w: _l(w, w.auth2, 1, _base_entries(w), generation=1), "REVOCATION_AUTHORITY_MISMATCH"),
    ("transition-valid", "transition", "enrolled", _rotated_t12, ACCEPT),
    ("transition-no-possession-proof", "transition", "enrolled", lambda w: w.transition(w.rev, w.auth2, to_signer=w.evil), "REVOCATION_SIGNATURE_INVALID"),
    ("transition-impostor-from", "transition", "enrolled", lambda w: w.transition(w.rev, w.auth2, from_signer=w.other_rev), "REVOCATION_SIGNATURE_INVALID"),
    ("transition-generation-gap", "transition", "enrolled", lambda w: w.transition(w.rev, w.auth2, to_gen=3), "REVOCATION_TRANSITION_GAP"),
    ("transition-cycle-back-to-old", "transition", "rotated", lambda w: w.transition(w.auth2, w.rev, from_gen=2), "REVOCATION_TRANSITION_CYCLE"),
    ("transition-replay", "transition", "rotated", _rotated_t12, "REVOCATION_AUTHORITY_SUPERSEDED"),
    ("transition-by-compromised-authority", "transition", "recovered", lambda w: w.transition(w.rev, w.evil, from_gen=2, to_gen=3), "REVOCATION_AUTHORITY_COMPROMISED"),
    ("transition-to-recovery-anchor", "transition", "enrolled", lambda w: w.transition(w.rev, w.recovery), "REVOCATION_KEY_IS_REPORT_KEY"),
    ("recovery-valid", "recovery", "enrolled", lambda w: w.recovery_stmt(w.auth2, declares=[(w.fp(w.rev), E)]), ACCEPT),
    ("recovery-anchor-absent", "recovery", "enrolled-no-recovery", lambda w: w.recovery_stmt(w.auth2), "REVOCATION_RECOVERY_ANCHOR_ABSENT"),
    ("recovery-signed-by-authority", "recovery", "enrolled", lambda w: w.recovery_stmt(w.evil, anchor=w.rev), "REVOCATION_RECOVERY_ANCHOR_MISMATCH"),
    ("recovery-forged-anchor-signature", "recovery", "enrolled", lambda w: w.recovery_stmt(w.auth2, anchor_signer=w.rev), "REVOCATION_SIGNATURE_INVALID"),
    ("recovery-fork-same-epoch", "recovery", "recovered", lambda w: w.recovery_stmt(w.auth3, epoch=1, new_gen=3), "REVOCATION_FORK"),
    ("recovery-unknown-baseline", "recovery", "enrolled", lambda w: w.recovery_stmt(w.auth2, rebase={"epoch": 1, "list_digest": "e" * 64}), "REVOCATION_RECOVERY_BASELINE_UNKNOWN"),
    ("recovery-reuses-compromised-key", "recovery", "recovered", lambda w: w.recovery_stmt(w.rev, epoch=2, new_gen=3, declares=[(w.fp(w.auth2), None)]), "REVOCATION_TRANSITION_CYCLE"),
    ("recovery-declares-nothing", "recovery", "enrolled", lambda w: _empty_declares(w), "REVOCATION_MALFORMED"),
]  # fmt: skip


def _tamper_entry(w: World) -> dict[str, Any]:
    doc = _l(w, w.rev, 1, _base_entries(w))
    doc["entries"][0]["status"] = "retired"
    return doc


def _empty_declares(w: World) -> dict[str, Any]:
    doc = w.recovery_stmt(w.auth2)
    doc["declares_compromised"] = []
    return doc


def _bytes(value: Any) -> bytes:
    return value if isinstance(value, bytes) else (dump(value) + "\n").encode()


def build_all() -> dict[str, tuple[bytes, dict[str, str]]]:
    w = make_world()
    out: dict[str, tuple[bytes, dict[str, str]]] = {}
    for name, kind, pre, builder, expect in CASES:
        out[name] = (_bytes(builder(w)), {"kind": kind, "preset": pre, "expect": expect})
    return out


def write_corpus(directory: Path = CORPUS_DIR) -> list[str]:
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for name, (data, meta) in build_all().items():
        (directory / f"{name}.json").write_bytes(data)
        manifest[name] = {**meta, "file": f"{name}.json"}
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return sorted(manifest)


def run_case(
    w: World, kind: str, preset_name: str, data: bytes, *, foreign_store: bool = False
) -> tuple[bool, str | None, tuple[str, ...]]:
    """Return (accepted, first code, notes) for one corpus case."""
    state = preset(preset_name, w)
    if kind in ("list", "list-foreign"):
        foreign_store = foreign_store or kind == "list-foreign"
        res = proto.verify_list_enrolled(
            data, w.issuer, store(w, "globex" if foreign_store else None), state, NOW
        )
        return res.accepted, res.code, tuple(res.notes)
    if kind == "transition":
        ares = proto.verify_transition(data, state, store(w), NOW)
    else:
        ares = proto.verify_recovery(data, state, store(w), NOW)
    return ares.accepted, ares.code, tuple(ares.notes)


if __name__ == "__main__":  # pragma: no cover
    print(len(write_corpus()), "cases written")
