"""Tests of the EXPERIMENTAL owner-signed revocation-list prototype (tests-only, not shipped).

Synthetic, deterministic keys. These tests pin the proposed format's behaviour; they do not make
any claim about the published protocol, which has no revocation list.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import stat
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

import regaudit_fhe as rf
from regaudit_fhe.canonical import canonical_bytes
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import SIGN_DOMAIN as REPORT_SIGN_DOMAIN
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.verification import TimestampEvidence, VerificationPolicy, verify

from . import proto
from .gen_fixtures import ISSUED, NOW, UNTIL, World, dump, make_world, write_fixtures

R_OLD = "2026-10-01T00:00:00Z"


@pytest.fixture
def w() -> World:
    return make_world()


def run(w: World, doc, state=None, *, store="default", now=NOW, **kw):
    st = w.store() if store == "default" else store
    return proto.verify_list(
        dump(doc) if not isinstance(doc, (str, bytes)) else doc,
        w.anchor,
        st,
        state or proto.RevocationState(),
        now,
        **kw,
    )


def retired_list(w, epoch=1, **kw):
    return w.signed(epoch, [w.entry(w.old, "retired", R_OLD)], **kw)


# ============================================================================ golden / canonical


def test_golden_vectors_pin_canonical_bytes_digest_and_signature(w):
    doc = retired_list(w)
    assert (
        w.anchor.fingerprint == "79f7d84700712bb1dfac574b8269c976fe6deaaa6bb5dceb39922fc794415518"
    )
    assert hashlib.sha256(proto.signing_input(doc)).hexdigest() == (
        "b600722fffda841dc66a35f0d24dbc3c5aad0cfed68d627b24b0bdc7460360cc"
    )
    assert (
        proto.list_digest(doc) == "66651f87f1e008445444031df614ab16e55b634f95b7e4cd0d5056eaa999345c"
    )
    assert doc["signature"]["signature_b64"] == (
        "sOhC0J0zBG/usnpjYAZ6duAtwCY4L8Ni2BUKVzySfUJdApucGE3nAYZaNGQ3Kvzapmekca3WzHakOLwhjj0dDQ=="
    )


def test_signing_input_is_domain_prefix_plus_existing_canonical_bytes(w):
    doc = retired_list(w)
    body = proto.signed_body(doc)
    assert proto.signing_input(doc) == proto.SIGN_DOMAIN + canonical_bytes(body)
    assert "signature" not in body
    assert proto.SIGN_DOMAIN != REPORT_SIGN_DOMAIN and proto.SIGN_DOMAIN.endswith(b"\x00")
    assert proto.SIGN_DOMAIN != proto.DIGEST_DOMAIN


def test_canonical_bytes_independent_of_member_order_and_whitespace(w):
    doc = retired_list(w)
    shuffled = dict(reversed(list(doc.items())))
    assert proto.signing_input(shuffled) == proto.signing_input(doc)
    pretty = json.dumps(doc, indent=4)
    assert run(w, pretty).accepted
    assert run(w, json.dumps(shuffled, separators=(",", ":"))).accepted


def test_unicode_issuer_round_trips_through_signing():
    w = make_world("Bänk Ünïcode ✓")
    doc = retired_list(w)
    assert run(w, json.dumps(doc, ensure_ascii=False)).accepted
    assert run(w, json.dumps(doc, ensure_ascii=True)).accepted


def test_list_digest_changes_with_every_signed_member(w):
    base = retired_list(w)
    seen = {proto.list_digest(base)}
    for mutate in (
        lambda d: d.update(epoch=d["epoch"] + 1),
        lambda d: d.update(issued_at="2026-11-01T09:00:01Z"),
        lambda d: d["entries"][0].update(status="compromised"),
        lambda d: d.update(issuer="x"),
    ):
        d = copy.deepcopy(base)
        mutate(d)
        seen.add(proto.list_digest(d))
    assert len(seen) == 5
    d = copy.deepcopy(base)
    d["signature"]["signature_b64"] = "A" * 88
    assert proto.list_digest(d) == proto.list_digest(base)  # the signature is not self-covering


# ============================================================================ positive path


def test_valid_list_is_accepted_pure_and_reports_the_honest_limit(w):
    state = proto.RevocationState()
    res = run(w, retired_list(w), state)
    assert res.accepted and res.code is None
    assert "REVOCATION_NO_HIGH_WATER_MARK" in res.notes
    assert res.rollback_detection == "none"
    assert "cannot reliably detect a rollback of both" in res.limit
    assert state.marks == {}  # verification is pure; commit() is separate


# ============================================================================ tamper detection


def _leaves(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaves(v, (*path, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _leaves(v, (*path, i))
    else:
        yield path, obj


def _set(doc, path, value):
    cur = doc
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value


def _mutated(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if value is None:
        return "tampered"
    if isinstance(value, str):
        if len(value) == 64 and all(c in "0123456789abcdef" for c in value):
            return ("0" if value[0] != "0" else "1") + value[1:]
        if value.endswith("Z"):
            return value[:-1].replace("00", "01", 1) + "Z" if "00" in value else value + "x"
        return value + "x"
    raise AssertionError(value)


def _full_doc(w):
    """A list exercising every member: two entries, one replaced with a successor, epoch 2."""
    prev = proto.list_digest(retired_list(w))
    return w.signed(
        2,
        [
            w.entry(w.old, "replaced", R_OLD, w.new),
            w.entry(w.third, "compromised", "2026-09-01T00:00:00Z"),
        ],
        prev=prev,
    )


def test_every_leaf_field_is_tamper_evident(w):
    doc = _full_doc(w)
    assert run(w, doc, store=w.store(w.old, w.new, w.third)).accepted
    paths = [p for p, _ in _leaves(doc)]
    assert len(paths) == 23
    for path in paths:
        bad = copy.deepcopy(doc)
        _set(bad, path, _mutated(copy.deepcopy(dict(_leaves(doc))[path])))
        res = run(w, bad, store=w.store(w.old, w.new, w.third))
        assert not res.accepted, f"tamper of {path} accepted"


def test_removing_or_adding_any_member_is_refused(w):
    doc = _full_doc(w)
    st = w.store(w.old, w.new, w.third)
    for key in list(doc):
        bad = {k: v for k, v in doc.items() if k != key}
        assert not run(w, bad, store=st).accepted, key
    assert not run(w, {**doc, "extra": 1}, store=st).accepted
    for key in list(doc["entries"][0]):
        bad = copy.deepcopy(doc)
        del bad["entries"][0][key]
        assert not run(w, bad, store=st).accepted, key
    bad = copy.deepcopy(doc)
    bad["entries"][0]["extra"] = 1
    assert not run(w, bad, store=st).accepted
    bad = copy.deepcopy(doc)
    bad["entries"].reverse()
    assert not run(w, bad, store=st).accepted  # entry order is part of the signed form
    bad = copy.deepcopy(doc)
    bad["entries"] = bad["entries"][:1]
    assert run(w, bad, store=st).code == "REVOCATION_SIGNATURE_INVALID"  # dropping an entry


@pytest.mark.parametrize(
    "raw",
    [b"", b"{", b"[]", b"null", b'"x"', b"\xef\xbb\xbf{}", b'{"a":1,"a":2}', b'{"epoch": NaN}'],
)
def test_malformed_input_is_refused_not_raised(w, raw):
    res = run(w, raw)
    assert not res.accepted and res.code == "REVOCATION_MALFORMED"


def test_oversized_input_refused(w):
    assert run(w, b" " * (proto.MAX_BYTES + 1)).code == "REVOCATION_MALFORMED"


def test_deeply_nested_input_refused(w):
    assert run(w, "[" * 5000 + "]" * 5000).code == "REVOCATION_MALFORMED"


def test_unsupported_versions_are_refused_without_fallback(w):
    for name in ("schema_version", "algorithm_version"):
        body = w.body(1, [])
        body[name] = 2
        doc = proto.sign_list(body, w.rev)  # correctly signed, still refused
        assert run(w, doc).code == "REVOCATION_VERSION_UNSUPPORTED"


# ============================================================================ issuer / authority / purpose separation


def test_wrong_issuer_refused_even_when_correctly_signed(w):
    body = w.body(1, [])
    body["issuer"] = "someone-else"
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_WRONG_ISSUER"
    other_anchor = proto.Anchor("someone-else", w.rev.public_key_pem())
    res = proto.verify_list(
        dump(retired_list(w)), other_anchor, w.store(), proto.RevocationState(), NOW
    )
    assert res.code == "REVOCATION_WRONG_ISSUER"


def test_list_signed_by_an_unpinned_key_is_refused(w):
    doc = w.signed(
        1, [], signer=w.other_rev
    )  # self-consistent list from a different revocation key
    assert run(w, doc).code == "REVOCATION_AUTHORITY_MISMATCH"


def test_claiming_the_pinned_fingerprint_without_the_key_fails_signature(w):
    body = w.body(1, [])
    forged = proto.sign_list(body, w.other_rev)  # fingerprint in body is the pinned one
    assert run(w, forged).code == "REVOCATION_SIGNATURE_INVALID"


def test_a_report_signing_key_is_not_accepted_as_a_revocation_key(w):
    # (1) pinned as the anchor although it is enrolled as a report key: refused outright
    report_anchor = proto.Anchor(w.issuer, w.old.public_key_pem())
    doc = w.signed(1, [], signer=w.old)
    res = proto.verify_list(dump(doc), report_anchor, w.store(), proto.RevocationState(), NOW)
    assert res.code == "REVOCATION_KEY_IS_REPORT_KEY"
    # (2) a report key signing a list that names the real revocation key: bad signature
    forged = proto.sign_list(w.body(1, []), w.old)
    assert run(w, forged).code == "REVOCATION_SIGNATURE_INVALID"
    # (3) a report key signing a list that names itself: not the pinned authority
    assert run(w, w.signed(1, [], signer=w.new)).code == "REVOCATION_AUTHORITY_MISMATCH"


def test_enrolling_the_revocation_key_as_a_report_key_disables_it(w):
    """Purpose separation is enforced against the verifier's own store, whichever way it got there."""
    store = w.store(w.old, w.new, w.rev)
    assert run(w, retired_list(w), store=store).code == "REVOCATION_KEY_IS_REPORT_KEY"


def test_signature_over_other_domains_is_refused(w):
    body = w.body(1, [])
    for prefix in (
        b"",
        REPORT_SIGN_DOMAIN,
        proto.DIGEST_DOMAIN,
        b"regaudit-fhe/revocation-list/v2/sign\x00",
    ):
        sig = w.rev.sign(prefix + canonical_bytes(body))
        doc = {
            **body,
            "signature": {"algorithm": "ed25519", "signature_b64": base64.b64encode(sig).decode()},
        }
        assert run(w, doc).code == "REVOCATION_SIGNATURE_INVALID", prefix


def test_signature_encoding_must_be_canonical_base64(w):
    doc = retired_list(w)
    sig = doc["signature"]["signature_b64"]
    for bad in (sig[:-2], sig + "A", sig.replace("=", ""), "!" * 88):
        d = copy.deepcopy(doc)
        d["signature"]["signature_b64"] = bad
        assert not run(w, d).accepted


def test_fingerprint_mismatch_with_local_store_is_refused_never_merged(w):
    body = w.body(1, [w.entry(w.old, "compromised", None)])
    body["entries"][0]["key_fingerprint"] = w.fp(w.third)  # right key_id, wrong key
    doc = proto.sign_list(body, w.rev)
    res = run(w, doc)
    assert res.code == "REVOCATION_KEY_MISMATCH"
    out = proto.evaluate(w.store(), dump(doc), w.anchor, proto.RevocationState(), NOW)
    assert out.status == "UNVERIFIED" and out.store.entry(w.old.key_id).status == "active"  # type: ignore[union-attr]


def test_entry_for_a_key_the_store_does_not_hold_is_kept_as_evidence(w):
    res = run(w, retired_list(w), store=w.store(w.new))
    assert res.accepted  # old key not enrolled locally: nothing to match, nothing to apply


# ============================================================================ validity period


def test_expired_and_not_yet_valid_lists_are_refused(w):
    doc = retired_list(w)
    assert run(w, doc, now=NOW.replace(year=2027)).code == "REVOCATION_EXPIRED"
    until = proto.parse_rfc3339(UNTIL)
    assert run(w, doc, now=until).code == "REVOCATION_EXPIRED"  # boundary is exclusive
    assert run(w, doc, now=until - timedelta(seconds=1)).accepted
    issued = proto.parse_rfc3339(ISSUED)
    assert (
        run(w, doc, now=issued - proto.SKEW - timedelta(seconds=1)).code
        == "REVOCATION_NOT_YET_VALID"
    )
    assert run(w, doc, now=issued - proto.SKEW + timedelta(seconds=1)).accepted


def test_validity_ordering_is_enforced(w):
    body = w.body(1, [], valid_until=ISSUED)  # valid_until == issued_at
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_MALFORMED"
    body = w.body(1, [])
    body["valid_from"] = "2026-11-01T08:00:00Z"  # before issued_at
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_MALFORMED"


def test_effective_from_after_issuance_is_refused(w):
    doc = w.signed(1, [w.entry(w.old, "retired", "2026-11-02T00:00:00Z")])
    assert run(w, doc).code == "REVOCATION_MALFORMED"


def test_expired_list_gives_no_authenticated_history(w):
    res = run(w, retired_list(w))
    assert proto.derive_trust_history(res, NOW) is not None
    assert proto.derive_trust_history(res, proto.parse_rfc3339(UNTIL)) is None
    refused = run(w, retired_list(w), now=NOW.replace(year=2027))
    assert proto.derive_trust_history(refused, NOW) is None


# ============================================================================ epochs, rollback, fork, gaps


def _commit(w, doc, state=None, **kw):
    state = state or proto.RevocationState()
    res = run(w, doc, state, **kw)
    assert res.accepted, (res.blocking, res.notes)
    return proto.commit(state, w.anchor, res)


def test_epoch_chain_advances_and_rejects_replay_of_older_list(w):
    l1 = retired_list(w)
    state = _commit(w, l1)
    l2 = w.signed(2, [w.entry(w.old, "compromised", R_OLD)], prev=proto.list_digest(l1))
    state2 = _commit(w, l2, state)
    assert state2.get(w.issuer, w.anchor.fingerprint).epoch == 2  # type: ignore[union-attr]
    res = run(w, l1, state2)  # replay of an older, still-valid, authentic list
    assert res.code == "REVOCATION_ROLLBACK" and not res.accepted
    assert res.rollback_detection == "high-water-mark-present"


def test_same_epoch_same_content_is_a_repeat_not_a_fork(w):
    l1 = retired_list(w)
    state = _commit(w, l1)
    res = run(w, l1, state)
    assert res.accepted and "REVOCATION_REPEAT" in res.notes


def test_two_lists_with_the_same_epoch_and_different_content_are_a_fork(w):
    a = retired_list(w)
    b = w.signed(1, [w.entry(w.old, "compromised", None)])
    state = _commit(w, a)
    assert run(w, b, state).code == "REVOCATION_FORK"
    assert proto.list_digest(a) != proto.list_digest(b)


def test_next_epoch_must_chain_to_the_accepted_digest(w):
    l1 = retired_list(w)
    state = _commit(w, l1)
    bad = w.signed(2, [w.entry(w.old, "retired", R_OLD)], prev="a" * 64)
    assert run(w, bad, state).code == "REVOCATION_FORK"


def test_gap_is_allowed_with_a_note_only_if_monotone_and_can_be_forbidden(w):
    l1 = w.signed(1, [w.entry(w.old, "retired", R_OLD), w.entry(w.third, "retired", R_OLD)])
    state = _commit(w, l1, store=w.store(w.old, w.new, w.third))
    st3 = w.store(w.old, w.new, w.third)
    gap = w.signed(
        4, [w.entry(w.old, "retired", R_OLD), w.entry(w.third, "retired", R_OLD)], prev="b" * 64
    )
    ok = run(w, gap, state, store=st3)
    assert ok.accepted and "REVOCATION_EPOCH_GAP" in ok.notes
    assert run(w, gap, state, store=st3, allow_gap=False).code == "REVOCATION_EPOCH_GAP"
    dropping = w.signed(
        4, [w.entry(w.old, "retired", R_OLD)], prev="b" * 64
    )  # silently drops an entry
    assert run(w, dropping, state, store=st3).code == "REVOCATION_NOT_MONOTONE"


def test_refused_list_never_advances_the_mark(w):
    l1 = retired_list(w)
    state = _commit(w, l1)
    bad = copy.deepcopy(w.signed(2, [w.entry(w.old, "retired", R_OLD)], prev=proto.list_digest(l1)))
    bad["epoch"] = 3
    res = run(w, bad, state)
    assert not res.accepted
    assert proto.commit(state, w.anchor, res) is state


def test_commit_is_monotone_even_if_called_out_of_order(w):
    l1 = retired_list(w)
    l2 = w.signed(2, [w.entry(w.old, "retired", R_OLD)], prev=proto.list_digest(l1))
    s2 = _commit(w, l2)
    r1 = run(w, l1)  # accepted against an EMPTY state, committed late
    assert proto.commit(s2, w.anchor, r1).get(w.issuer, w.anchor.fingerprint).epoch == 2  # type: ignore[union-attr]


def test_marks_are_per_issuer_and_authority(w):
    other = make_world("globex")
    state = _commit(w, retired_list(w))
    res = proto.verify_list(dump(retired_list(other)), other.anchor, other.store(), state, NOW)
    assert res.accepted and "REVOCATION_NO_HIGH_WATER_MARK" in res.notes  # separate slot


# ============================================================================ monotone merge rules


def _two(w, first_entries, second_entries):
    l1 = w.signed(1, first_entries)
    state = _commit(w, l1, store=w.store(w.old, w.new, w.third))
    l2 = w.signed(2, second_entries, prev=proto.list_digest(l1))
    return run(w, l2, state, store=w.store(w.old, w.new, w.third))


E = "2026-09-01T00:00:00Z"
L = "2026-10-01T00:00:00Z"


@pytest.mark.parametrize(
    ("first", "second", "code"),
    [
        # entry removed
        (lambda w: [w.entry(w.old, "retired", L)], lambda w: [], "REVOCATION_NOT_MONOTONE"),
        # compromised back to retired
        (
            lambda w: [w.entry(w.old, "compromised", E)],
            lambda w: [w.entry(w.old, "retired", E)],
            "REVOCATION_NOT_MONOTONE",
        ),
        # retired -> compromised with a later boundary (re-opens a closed interval)
        (
            lambda w: [w.entry(w.old, "retired", E)],
            lambda w: [w.entry(w.old, "compromised", L)],
            "REVOCATION_NOT_MONOTONE",
        ),
        # compromise boundary moved later
        (
            lambda w: [w.entry(w.old, "compromised", E)],
            lambda w: [w.entry(w.old, "compromised", L)],
            "REVOCATION_NOT_MONOTONE",
        ),
        # unknown boundary became known (loosens)
        (
            lambda w: [w.entry(w.old, "compromised", None)],
            lambda w: [w.entry(w.old, "compromised", E)],
            "REVOCATION_NOT_MONOTONE",
        ),
        # retirement re-dated
        (
            lambda w: [w.entry(w.old, "retired", E)],
            lambda w: [w.entry(w.old, "retired", L)],
            "REVOCATION_NOT_MONOTONE",
        ),
        (
            lambda w: [w.entry(w.old, "retired", L)],
            lambda w: [w.entry(w.old, "retired", E)],
            "REVOCATION_NOT_MONOTONE",
        ),
        # successor changed
        (
            lambda w: [w.entry(w.old, "replaced", E, w.new)],
            lambda w: [w.entry(w.old, "replaced", E, w.third)],
            "REVOCATION_NOT_MONOTONE",
        ),
        # successor removed (replaced -> retired)
        (
            lambda w: [w.entry(w.old, "replaced", E, w.new)],
            lambda w: [w.entry(w.old, "retired", E)],
            "REVOCATION_NOT_MONOTONE",
        ),
    ],
)
def test_loosening_transitions_are_refused(w, first, second, code):
    assert _two(w, first(w), second(w)).code == code


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (
            lambda w: [w.entry(w.old, "retired", E)],
            lambda w: [w.entry(w.old, "retired", E), w.entry(w.third, "retired", L)],
        ),
        (lambda w: [w.entry(w.old, "retired", L)], lambda w: [w.entry(w.old, "compromised", E)]),
        (lambda w: [w.entry(w.old, "retired", L)], lambda w: [w.entry(w.old, "compromised", None)]),
        (lambda w: [w.entry(w.old, "retired", L)], lambda w: [w.entry(w.old, "compromised", L)]),
        (
            lambda w: [w.entry(w.old, "compromised", L)],
            lambda w: [w.entry(w.old, "compromised", E)],
        ),
        (
            lambda w: [w.entry(w.old, "compromised", E)],
            lambda w: [w.entry(w.old, "compromised", None)],
        ),
        (
            lambda w: [w.entry(w.old, "retired", E)],
            lambda w: [w.entry(w.old, "replaced", E, w.new)],
        ),  # successor added
    ],
)
def test_tightening_transitions_are_accepted(w, first, second):
    res = _two(w, first(w), second(w))
    assert res.accepted, (res.blocking, res.notes)


# ============================================================================ successor chains


def test_replaced_by_successor_chain_is_signed_and_fingerprint_bound(w):
    doc = w.signed(
        1,
        [
            w.entry(w.old, "replaced", E, w.new),
            w.entry(w.new, "replaced", L, w.third),
        ],
    )
    res = run(w, doc, store=w.store(w.old, w.new, w.third))
    assert res.accepted
    chain = proto.resolve_successors(res.statement, w.old.key_id, w.fp(w.old))  # type: ignore[arg-type]
    assert [c["key_id"] for c in chain] == [w.new.key_id, w.third.key_id]
    assert [c["key_fingerprint"] for c in chain] == [w.fp(w.new), w.fp(w.third)]
    # fingerprint binding: the same key_id with another fingerprint yields no chain
    assert proto.resolve_successors(res.statement, w.old.key_id, w.fp(w.third)) == []  # type: ignore[arg-type]
    assert proto.resolve_successors(res.statement, "ghost", w.fp(w.old)) == []  # type: ignore[arg-type]


def test_successor_cycles_and_self_succession_are_refused(w):
    cyc = w.signed(1, [w.entry(w.old, "replaced", E, w.new), w.entry(w.new, "replaced", E, w.old)])
    assert run(w, cyc, store=w.store(w.old, w.new)).code == "REVOCATION_MALFORMED"
    body = w.body(1, [w.entry(w.old, "replaced", E, w.new)])
    body["entries"][0]["successor"]["key_id"] = w.old.key_id
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_MALFORMED"
    body = w.body(1, [w.entry(w.old, "replaced", E, w.new)])
    body["entries"][0]["successor"]["key_fingerprint"] = w.fp(w.old)
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_MALFORMED"


def test_replaced_requires_a_successor_and_only_compromised_may_have_unknown_boundary(w):
    body = w.body(1, [w.entry(w.old, "replaced", E)])
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_MALFORMED"
    body = w.body(1, [w.entry(w.old, "retired", None)])
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_MALFORMED"
    assert run(w, w.signed(1, [w.entry(w.old, "compromised", None)])).accepted


def test_successor_fingerprint_must_match_the_enrolled_successor(w):
    body = w.body(1, [w.entry(w.old, "replaced", E, w.new)])
    body["entries"][0]["successor"]["key_fingerprint"] = w.fp(w.third)
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_KEY_MISMATCH"


def test_naming_a_successor_does_not_make_it_trusted_nor_replace_the_old_key(w):
    old_only = w.store(w.old)  # successor NOT enrolled
    doc = w.signed(1, [w.entry(w.old, "replaced", E, w.new)])
    out = proto.evaluate(old_only, dump(doc), w.anchor, proto.RevocationState(), NOW)
    assert out.status == "VERIFIED"
    assert out.store.entry(w.new.key_id) is None
    env = envelope_v2(
        "drift", _report(), signer=w.new, deployment_id="p", issued_at=NOW - timedelta(days=1)
    )
    res = verify(env, VerificationPolicy(trust_store=out.store, now=lambda: NOW))
    assert not res.accepted and "ISSUER_UNKNOWN" in res.blocking_reasons
    # and the replaced key itself is only "retired" in the store format
    assert out.store.entry(w.old.key_id).status == "retired"  # type: ignore[union-attr]


# ============================================================================ evaluate(): missing/unverifiable != nothing revoked


def _report():
    import numpy as np

    return rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))


def _tsa(gen):
    def verifier(digest, token):
        return TimestampEvidence(gen, timedelta(0)) if token == b"ok:" + digest else None

    return verifier


def test_missing_list_means_unproven_not_nothing_revoked(w):
    store = w.store()
    out = proto.evaluate(store, None, w.anchor, proto.RevocationState(), NOW)
    assert out.status == "NO_LIST" and out.revocation_evidence == "unproven"
    assert out.store is store and out.history is None and out.result is None
    assert "cannot reliably detect a rollback of both" in out.limit


def test_unverifiable_lists_change_nothing_and_give_no_history(w):
    store = w.store()
    good = retired_list(w)
    bads: list[Any] = [
        b"{",
        copy.deepcopy({**good, "epoch": 9}),
        w.signed(1, [], signer=w.other_rev),
        retired_list(w, valid_until="2026-11-01T10:00:00Z"),  # expired at NOW
    ]
    for bad in bads:
        raw = bad if isinstance(bad, bytes) else dump(bad)
        out = proto.evaluate(store, raw, w.anchor, proto.RevocationState(), NOW)
        assert out.status == "UNVERIFIED" and out.revocation_evidence == "unproven"
        assert out.store is store and out.history is None and out.state.marks == {}


def test_legacy_store_cannot_carry_lifecycle_state(w):
    legacy = rf.TrustStore.from_dict({"keys": {w.old.key_id: w.old.public_key_pem()}})
    out = proto.evaluate(legacy, dump(retired_list(w)), w.anchor, proto.RevocationState(), NOW)
    assert out.status == "UNVERIFIED" and out.result.code == "REVOCATION_STORE_UNSUPPORTED"  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="entries"):
        proto.apply_to_store(legacy, run(w, retired_list(w)))


def test_a_stale_mark_does_not_become_history_when_the_list_is_gone(w):
    state = _commit(w, retired_list(w))
    out = proto.evaluate(w.store(), None, w.anchor, state, NOW + timedelta(days=30))
    assert out.history is None and out.revocation_evidence == "unproven"


# ============================================================================ end to end through the UNCHANGED engine


def _signed_report(w, signer, when):
    env = envelope_v2("drift", _report(), signer=signer, deployment_id="p", issued_at=when)
    return env.with_timestamp(issuer="t", token=b"ok:" + env.sealed_digest(), issued_at=when), when


def test_verified_list_makes_authenticated_history_producible_for_the_existing_seam(w):
    """The existing engine, unchanged: a list-derived store + TrustHistory decide a historical report."""
    signed_at = proto.parse_rfc3339("2026-09-01T12:00:00Z")
    env, _ = _signed_report(w, w.old, signed_at)
    store = w.store()
    kw = {"timestamp_verifier": _tsa(signed_at)}

    # no list: the key is still locally active -> accepted (the verifier has no revocation evidence)
    assert verify(env, VerificationPolicy(trust_store=store, now=lambda: NOW, **kw)).accepted

    out = proto.evaluate(store, dump(retired_list(w)), w.anchor, proto.RevocationState(), NOW)
    assert out.status == "VERIFIED" and out.history is not None and out.history.authenticated
    pol = VerificationPolicy(
        trust_store=out.store, now=lambda: NOW, trust_history=out.history, **kw
    )
    ok = verify(env, pol)
    assert ok.accepted and ok.key_status == "retired" and ok.trust_history == "FRESH"

    # a report timestamped after the effective boundary is refused, list or no list for history
    late_at = proto.parse_rfc3339("2026-10-15T12:00:00Z")
    late, _ = _signed_report(w, w.old, late_at)
    res = verify(late, VerificationPolicy(trust_store=out.store, now=lambda: NOW,
                                          trust_history=out.history, timestamp_verifier=_tsa(late_at)))  # fmt: skip
    assert not res.accepted and "SIGNED_AFTER_RETIREMENT" in res.blocking_reasons

    # list unverifiable: store keeps the old key retired locally (if it was) but history is None
    local = proto.apply_to_store(store, run(w, retired_list(w)))
    bad = proto.evaluate(local, b"{", w.anchor, proto.RevocationState(), NOW)
    res = verify(
        env,
        VerificationPolicy(trust_store=bad.store, now=lambda: NOW, trust_history=bad.history, **kw),
    )
    assert not res.accepted and "TRUST_STORE_FRESHNESS_UNPROVEN" in res.blocking_reasons


def test_compromise_in_a_verified_list_is_never_rescued_by_chronology_missing(w):
    signed_at = proto.parse_rfc3339("2026-08-01T00:00:00Z")
    env, _ = _signed_report(w, w.old, signed_at)
    for boundary, expect in ((None, "KEY_COMPROMISED_NO_CHRONOLOGY"), ("2026-07-01T00:00:00Z", "SIGNED_AFTER_COMPROMISE"),
                             ("2026-09-01T00:00:00Z", None)):  # fmt: skip
        doc = w.signed(1, [w.entry(w.old, "compromised", boundary)])
        out = proto.evaluate(w.store(), dump(doc), w.anchor, proto.RevocationState(), NOW)
        res = verify(env, VerificationPolicy(trust_store=out.store, now=lambda: NOW,
                                             trust_history=out.history, timestamp_verifier=_tsa(signed_at)))  # fmt: skip
        assert res.accepted is (expect is None), (boundary, res.blocking_reasons)
        if expect:
            assert expect in res.blocking_reasons


def test_high_assurance_still_refuses_historical_acceptance_with_a_verified_list(w, tmp_path):
    signed_at = proto.parse_rfc3339("2026-09-01T12:00:00Z")
    env = envelope_v2(
        "drift", _report(), signer=w.old, deployment_id="p", audience=["reg"], issued_at=signed_at
    )
    env = env.with_timestamp(issuer="t", token=b"ok:" + env.sealed_digest(), issued_at=signed_at)
    out = proto.evaluate(w.store(), dump(retired_list(w)), w.anchor, proto.RevocationState(), NOW)
    pol = VerificationPolicy(
        profile="high-assurance", trust_store=out.store, now=lambda: NOW, trust_history=out.history,
        timestamp_verifier=_tsa(signed_at), max_age=timedelta(days=90), verifier_id="reg",
        replay_mode="record", replay_cache=SqliteReplayCache(tmp_path / "r.db"),
    )  # fmt: skip
    res = verify(env, pol)
    assert not res.accepted and "TRUST_STORE_FRESHNESS_UNPROVEN" in res.blocking_reasons


# ============================================================================ apply_to_store: stricter-of, never loosens


def _local(w, status, **extra):
    entry = {
        "issuer": w.issuer,
        "public_key_pem": w.old.public_key_pem(),
        "status": status,
        **extra,
    }
    return rf.TrustStore.from_dict({"entries": {w.old.key_id: entry}})


@pytest.mark.parametrize(
    ("local", "listed", "expected"),
    [
        (("active", {}), ("retired", L), ("retired", L, None)),
        (("active", {}), ("replaced", L), ("retired", L, None)),
        (("active", {}), ("compromised", E), ("compromised", None, E)),
        (("active", {}), ("compromised", None), ("compromised", None, None)),
        (("retired", {"retired_at": E}), ("retired", L), ("retired", E, None)),  # keeps earlier
        (("retired", {"retired_at": L}), ("retired", E), ("retired", E, None)),  # takes earlier
        (
            ("retired", {"retired_at": E}),
            ("compromised", L),
            ("compromised", None, E),
        ),  # no re-open
        (("retired", {"retired_at": L}), ("compromised", E), ("compromised", None, E)),
        (("retired", {"retired_at": L}), ("compromised", None), ("compromised", None, None)),
        (
            ("compromised", {"compromised_from": E}),
            ("retired", L),
            ("compromised", None, E),
        ),  # list can't loosen
        (("compromised", {"compromised_from": E}), ("compromised", L), ("compromised", None, E)),
        (("compromised", {"compromised_from": L}), ("compromised", E), ("compromised", None, E)),
        (
            ("compromised", {"compromised_from": E}),
            ("compromised", None),
            ("compromised", None, None),
        ),
        (
            ("compromised", {}),
            ("compromised", E),
            ("compromised", None, None),
        ),  # unknown stays unknown
    ],
)
def test_apply_is_the_stricter_of_local_and_list(w, local, listed, expected):
    store = _local(w, local[0], **local[1])
    status, eff = listed
    succ = w.new if status == "replaced" else None
    doc = w.signed(1, [w.entry(w.old, status, eff, succ)])
    res = run(w, doc, store=store)
    assert res.accepted, res.blocking
    got = proto.apply_to_store(store, res).entry(w.old.key_id)
    iso = lambda d: d.isoformat().replace("+00:00", "Z") if d else None  # noqa: E731
    assert (got.status, iso(got.retired_at), iso(got.compromised_from)) == expected  # type: ignore[union-attr]


def test_apply_keeps_unmentioned_entries_and_unrelated_fields_untouched(w):
    store = w.store(w.old, w.new)
    res = run(w, retired_list(w), store=store)
    new = proto.apply_to_store(store, res)
    assert new.entry(w.new.key_id) == store.entry(w.new.key_id)
    assert new.entry(w.old.key_id).public_key_pem == store.entry(w.old.key_id).public_key_pem  # type: ignore[union-attr]
    empty = run(w, w.signed(1, []), store=store)
    assert (
        proto.apply_to_store(store, empty).entries == store.entries
    )  # an empty list changes nothing


def test_apply_refuses_an_unaccepted_result(w):
    bad = run(w, b"{")
    with pytest.raises(ValueError, match="accepted"):
        proto.apply_to_store(w.store(), bad)


# ============================================================================ state file and the honest limit


def test_state_round_trips_with_mode_0600(w, tmp_path):
    path = str(tmp_path / "state.json")
    state = _commit(w, retired_list(w))
    state.save(path)
    again = proto.RevocationState.load(path)
    assert again == state
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]


def test_failed_save_leaves_the_previous_state_and_no_temp_file(w, tmp_path, monkeypatch):
    path = str(tmp_path / "state.json")
    _commit(w, retired_list(w)).save(path)
    before = Path(path).read_bytes()
    monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(OSError):
        proto.RevocationState().save(path)
    assert Path(path).read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]


def test_HONEST_LIMIT_deleting_or_lowering_the_state_defeats_rollback_detection(w, tmp_path):
    """This is a documented limitation, asserted so nobody mistakes the mark for more than it is."""
    l1 = retired_list(w)
    l2 = w.signed(2, [w.entry(w.old, "compromised", R_OLD)], prev=proto.list_digest(l1))
    path = str(tmp_path / "state.json")
    state = _commit(w, l2)
    state.save(path)
    assert run(w, l1, proto.RevocationState.load(path)).code == "REVOCATION_ROLLBACK"  # detected
    os.unlink(path)  # whoever can write the state can undo the protection
    fresh = proto.RevocationState.load(path)
    res = run(w, l1, fresh)
    assert (
        res.accepted and res.rollback_detection == "none"
    )  # the older, authentic list is accepted
    assert "cannot reliably detect a rollback of both" in res.limit
    # lowering the recorded epoch has the same effect
    state.save(path)
    raw = json.loads(Path(path).read_text())
    for mark in raw.values():
        mark["epoch"] = 1
        mark["digest"] = proto.list_digest(l1)
        mark["entries"] = {e["key_id"]: e for e in l1["entries"]}
    Path(path).write_text(json.dumps(raw))
    assert run(w, l1, proto.RevocationState.load(path)).accepted


# ============================================================================ draft JSON schema agrees with the prototype


SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs/proposals/revocation-list.v1/revocation-list.v1.schema.json"
)


def _schema_ok(doc) -> bool:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return not list(jsonschema.Draft202012Validator(schema).iter_errors(doc))


def test_draft_schema_accepts_valid_lists(w):
    assert _schema_ok(_full_doc(w))
    assert _schema_ok(retired_list(w))
    assert _schema_ok(w.signed(1, []))
    assert _schema_ok(w.signed(1, [w.entry(w.old, "compromised", None)]))


def test_draft_schema_and_prototype_agree_on_structural_tamper(w):
    base = _full_doc(w)
    mutations = [
        lambda d: d.update(epoch=0),
        lambda d: d.update(epoch="2"),
        lambda d: d.update(extra=1),
        lambda d: d.pop("valid_until"),
        lambda d: d.update(prev_list_digest=None),  # epoch 2 needs a digest
        lambda d: d.update(schema="other"),
        lambda d: d["entries"][0].update(status="revoked"),
        lambda d: d["entries"][0].update(key_fingerprint="XYZ"),
        lambda d: d["entries"][0].update(effective_from=None),  # replaced needs a boundary
        lambda d: d["entries"][0].pop("successor"),  # replaced needs a successor
        lambda d: d["entries"][0].update(extra=1),
        lambda d: d["signature"].update(algorithm="rsa"),
        lambda d: d["authority"].pop("key_id"),
        lambda d: d["entries"][0]["successor"].update(key_fingerprint="short"),
    ]
    for mutate in mutations:
        bad = copy.deepcopy(base)
        mutate(bad)
        assert not _schema_ok(bad)
        with pytest.raises(proto.ShapeError):
            proto.validate_shape(bad)


# ============================================================================ fixture generator


def test_fixture_generator_is_deterministic_and_its_vectors_verify(w, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    names = write_fixtures(a)
    write_fixtures(b)
    for name in [*names, "anchor"]:
        assert (a / f"{name}.json").read_bytes() == (b / f"{name}.json").read_bytes()
    anchor = json.loads((a / "anchor.json").read_text())
    assert anchor["fingerprint"] == w.anchor.fingerprint
    for name in names:
        raw = (a / f"{name}.json").read_text()
        res = proto.verify_list(raw, proto.Anchor(anchor["issuer"], anchor["public_key_pem"]),
                                w.store(), proto.RevocationState(), NOW)  # fmt: skip
        assert res.accepted, (name, res.blocking)


# ============================================================================ survivors added after mutation testing


def test_a_later_list_may_not_rebind_a_key_id_to_another_fingerprint(w):
    store = w.store(w.new)  # neither old nor third enrolled: the store check cannot catch this
    l1 = w.signed(1, [w.entry(w.old, "retired", E)])
    state = _commit(w, l1, store=store)
    swapped = w.entry(w.third, "retired", E)
    swapped["key_id"] = w.old.key_id  # same key_id, different key
    res = run(w, w.signed(2, [swapped], prev=proto.list_digest(l1)), state, store=store)
    assert res.code == "REVOCATION_NOT_MONOTONE" and "fingerprint changed" in res.notes[0]


def test_correctly_signed_but_unsorted_or_duplicate_entries_are_malformed(w):
    a, b = w.entry(w.old, "retired", E), w.entry(w.third, "retired", E)
    body = w.body(1, [])
    body["entries"] = [b, a]  # w.old.key_id < w.third.key_id, so this order is wrong
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_MALFORMED"
    body["entries"] = [a, copy.deepcopy(a)]
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_MALFORMED"


def test_epoch_one_has_no_predecessor_and_later_epochs_must_name_one(w):
    body = w.body(1, [], prev="a" * 64)
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_MALFORMED"
    body = w.body(2, [], prev=None)
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_MALFORMED"
    body = w.body(2, [], prev="not-hex")
    assert run(w, proto.sign_list(body, w.rev)).code == "REVOCATION_MALFORMED"
