"""Verifier rules tightened by proposal v2 (wire formats unchanged, frozen corpus unchanged).

Each test failed against the draft-v1 prototype at f3e2a55. They are verifier rules, not format changes:
every document here is schema-valid draft v1.
"""

from __future__ import annotations

import pytest

from regaudit_fhe.trust import TrustStore

from . import proto
from .gen_fixtures import NOW, World, dump, make_world

R = "2026-10-01T00:00:00Z"
LATER = "2026-10-20T00:00:00Z"


@pytest.fixture
def w() -> World:
    return make_world()


def full(w: World) -> TrustStore:
    return w.store(w.old, w.new, w.third)


def ingest(w: World, state: proto.RevocationState, doc, store: TrustStore | None = None):
    res = proto.verify_list_enrolled(dump(doc), w.issuer, store or full(w), state, NOW)
    if res.accepted:
        state = proto.commit(state, state.enrollments[w.issuer].anchor, res)
    return res, state


def recover(w: World, state: proto.RevocationState, doc):
    res = proto.verify_recovery(dump(doc), state, None, NOW)
    return res, proto.apply_authority(state, res)


def test_replaying_a_recovery_statement_never_lowers_the_mark_again(w):
    """Draft v1 re-applied the rebase on a repeat, so anyone could lower the mark with a public document."""
    state = w.enrolled()
    l1 = w.signed(1, [])
    _, state = ingest(w, state, l1)
    _, state = ingest(
        w, state, w.signed(2, [w.entry(w.old, "compromised", None)], prev=proto.list_digest(l1))
    )
    rec = w.recovery_stmt(w.auth2, rebase={"epoch": 1, "list_digest": proto.list_digest(l1)})
    res, state = recover(w, state, rec)
    assert res.accepted and state.get(w.issuer).epoch == 1

    n2 = w.signed(2, [], signer=w.auth2, generation=2, prev=proto.list_digest(l1))
    _, state = ingest(w, state, n2)
    n3 = w.signed(
        3,
        [w.entry(w.new, "compromised", None)],
        signer=w.auth2,
        generation=2,
        prev=proto.list_digest(n2),
    )
    _, state = ingest(w, state, n3)
    assert state.get(w.issuer).epoch == 3

    res, replayed = recover(w, state, rec)
    assert res.accepted and "REVOCATION_REPEAT" in res.notes
    assert replayed.get(w.issuer).epoch == 3, "a repeat must be a strict no-op"
    assert ingest(w, replayed, n2)[0].code == "REVOCATION_ROLLBACK"


def test_rebase_is_a_noop_for_a_verifier_that_never_passed_the_baseline(w):
    """Draft v1 refused this clean verifier, leaving it on the compromised authority."""
    state = w.enrolled()
    l1 = w.signed(1, [])
    _, state = ingest(w, state, l1)
    l2 = w.signed(2, [], prev=proto.list_digest(l1))  # never seen by this verifier
    res, after = recover(
        w,
        state,
        w.recovery_stmt(w.auth2, rebase={"epoch": 2, "list_digest": proto.list_digest(l2)}),
    )
    assert res.accepted and "REVOCATION_REBASE_NOOP" in res.notes
    assert after.get(w.issuer).epoch == 1 and after.enrollments[w.issuer].generation == 2
    n3 = w.signed(3, [], signer=w.auth2, generation=2, prev=proto.list_digest(l2))
    assert ingest(w, after, n3)[0].accepted


def test_rebase_at_the_same_epoch_with_another_digest_stays_unknown(w):
    state = w.enrolled()
    l1 = w.signed(1, [])
    _, state = ingest(w, state, l1)
    res, _ = recover(
        w, state, w.recovery_stmt(w.auth2, rebase={"epoch": 1, "list_digest": "e" * 64})
    )
    assert res.code == "REVOCATION_RECOVERY_BASELINE_UNKNOWN"


def test_a_higher_epoch_with_an_earlier_issued_at_is_not_monotone(w):
    state = w.enrolled()
    l1 = w.signed(1, [])
    _, state = ingest(w, state, l1)
    back = w.signed(2, [], prev=proto.list_digest(l1), issued_at="2026-10-20T00:00:00Z")
    assert ingest(w, state, back)[0].code == "REVOCATION_NOT_MONOTONE"


def test_equal_issued_at_is_allowed_across_epochs(w):
    state = w.enrolled()
    l1 = w.signed(1, [])
    _, state = ingest(w, state, l1)
    assert ingest(w, state, w.signed(2, [], prev=proto.list_digest(l1)))[0].accepted


def test_one_fingerprint_may_appear_once_in_a_list(w):
    entries = [
        w.entry(w.old, "retired", R),
        {**w.entry(w.old, "compromised", None), "key_id": "zzz"},
    ]
    assert ingest(w, w.enrolled(), w.signed(1, entries))[0].code == "REVOCATION_MALFORMED"


def _alias(w: World, issuer: str | None = None) -> TrustStore:
    return TrustStore.from_dict(
        {
            "entries": {
                "local-alias": {
                    "issuer": issuer or w.issuer,
                    "public_key_pem": w.old.public_key_pem(),
                    "status": "active",
                }
            }
        }
    )


def test_a_listed_key_is_matched_by_fingerprint_under_a_local_alias(w):
    """Draft v1 matched by key_id only, so the compromised key stayed active under a local alias."""
    store = _alias(w)
    res, _ = ingest(w, w.enrolled(), w.signed(1, [w.entry(w.old, "compromised", None)]), store)
    assert res.accepted
    assert proto.apply_to_store(store, res).entries["local-alias"].status == "compromised"


def test_fingerprint_matching_does_not_open_a_cross_issuer_revocation(w):
    store = _alias(w, issuer="globex")
    res, _ = ingest(w, w.enrolled(), w.signed(1, [w.entry(w.old, "compromised", None)]), store)
    assert res.code == "REVOCATION_ISSUER_SCOPE"


def test_local_compromise_later_than_a_listed_retirement_takes_the_earlier_time(w):
    """compromised(C) joined with retired(R < C) is compromised(R): the stricter of both."""
    store = TrustStore.from_dict(
        {
            "entries": {
                w.old.key_id: {
                    "issuer": w.issuer,
                    "public_key_pem": w.old.public_key_pem(),
                    "status": "compromised",
                    "compromised_from": LATER,
                }
            }
        }
    )
    res, _ = ingest(w, w.enrolled(), w.signed(1, [w.entry(w.old, "retired", R)]), store)
    got = proto.apply_to_store(store, res).entries[w.old.key_id]
    assert got.status == "compromised"
    assert got.compromised_from == proto.parse_rfc3339(R)


def test_no_statement_can_name_a_new_recovery_anchor(w):
    """Changing the anchor is a re-enrollment ceremony. The formats have no member for it."""
    state = w.enrolled()
    rec = w.recovery_stmt(w.auth2)
    rec["new_recovery_anchor"] = {"key_fingerprint": w.fp(w.evil)}
    assert proto.verify_recovery(dump(rec), state, None, NOW).code == "REVOCATION_MALFORMED"
    tr = w.transition(w.rev, w.auth2)
    tr["new_recovery_anchor"] = {"key_fingerprint": w.fp(w.evil)}
    assert proto.verify_transition(dump(tr), state, None, NOW).code == "REVOCATION_MALFORMED"
