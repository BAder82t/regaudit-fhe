"""Authority enrollment, ROUTINE rotation and COMPROMISE RECOVERY of the revocation authority.

Routine rotation (old authority hands over) and compromise recovery (an independently enrolled
recovery anchor replaces the authority) are separate mechanisms and are tested as separate cases.
Prototype only; synthetic deterministic keys.
"""

from __future__ import annotations

import copy
import json
from datetime import timedelta
from pathlib import Path

import pytest

from . import proto
from .gen_fixtures import NOW, World, dump, make_world


@pytest.fixture
def w() -> World:
    return make_world()


E = "2026-09-01T00:00:00Z"
R = "2026-10-01T00:00:00Z"


def vt(w, doc, state, **kw):
    return proto.verify_transition(dump(doc), state, kw.pop("store", None), kw.pop("now", NOW))


def vr(w, doc, state, **kw):
    return proto.verify_recovery(dump(doc), state, kw.pop("store", None), kw.pop("now", NOW))


def take(state, result):
    assert result.accepted, (result.blocking, result.notes)
    return proto.apply_authority(state, result)


def lst(w, signer, epoch, entries=(), *, gen=1, prev=None, **kw):
    return w.signed(epoch, list(entries), signer=signer, generation=gen, prev=prev, **kw)


def vlist(w, doc, state, store="default", **kw):
    st = w.store() if store == "default" else store
    return proto.verify_list_enrolled(dump(doc), w.issuer, st, state, NOW, **kw)


# ============================================================================ enrollment


def test_enrollment_is_explicit_local_and_refuses_unsafe_keys(w):
    state = w.enrolled()
    enr = state.enrollments[w.issuer]
    assert enr.generation == 1 and enr.authority_fingerprint == w.anchor.fingerprint
    with pytest.raises(ValueError, match="already enrolled"):
        proto.enroll(state, w.issuer, w.rev.public_key_pem())
    with pytest.raises(ValueError, match="different key"):
        proto.enroll(
            proto.RevocationState(),
            w.issuer,
            w.rev.public_key_pem(),
            recovery_pem=w.rev.public_key_pem(),
        )
    with pytest.raises(ValueError, match="report-signing"):
        proto.enroll(proto.RevocationState(), w.issuer, w.old.public_key_pem(), store=w.store())
    with pytest.raises(ValueError, match="report-signing"):
        proto.enroll(proto.RevocationState(), w.issuer, w.rev.public_key_pem(),
                     recovery_pem=w.new.public_key_pem(), store=w.store())  # fmt: skip


def test_nothing_is_enrolled_from_a_list_or_statement(w):
    empty = proto.RevocationState()
    assert vlist(w, lst(w, w.rev, 1), empty).code == "REVOCATION_NOT_ENROLLED"
    assert vt(w, w.transition(w.rev, w.auth2), empty).code == "REVOCATION_NOT_ENROLLED"
    assert vr(w, w.recovery_stmt(w.auth2), empty).code == "REVOCATION_NOT_ENROLLED"
    assert empty.enrollments == {}


def test_enrolled_list_verification_uses_the_enrolled_key_only(w):
    state = w.enrolled()
    assert vlist(w, lst(w, w.rev, 1), state).accepted
    assert vlist(w, lst(w, w.other_rev, 1), state).code == "REVOCATION_AUTHORITY_MISMATCH"


# ============================================================================ routine rotation


def test_routine_rotation_hands_over_and_the_epoch_chain_continues(w):
    state = w.enrolled()
    l1 = lst(w, w.rev, 1, [w.entry(w.old, "retired", R)])
    res1 = vlist(w, l1, state)
    state = proto.commit(state, state.enrollments[w.issuer].anchor, res1)
    state = take(state, vt(w, w.transition(w.rev, w.auth2), state))
    enr = state.enrollments[w.issuer]
    assert enr.generation == 2 and enr.authority_fingerprint == w.fp(w.auth2)
    assert enr.superseded == (w.fp(w.rev),) and enr.compromised == {}
    # old authority's lists are refused after the hand-over
    assert (
        vlist(
            w, lst(w, w.rev, 2, [w.entry(w.old, "retired", R)], prev=proto.list_digest(l1)), state
        ).code
        == "REVOCATION_AUTHORITY_SUPERSEDED"
    )
    # the new authority continues the same epoch chain (marks are per issuer, not per key)
    l2 = lst(w, w.auth2, 2, [w.entry(w.old, "retired", R)], gen=2, prev=proto.list_digest(l1))
    assert vlist(w, l2, state).accepted
    assert vlist(w, lst(w, w.auth2, 1, gen=2), state).code == "REVOCATION_FORK"  # no fresh chain
    # and must carry the new generation
    assert (
        vlist(
            w,
            lst(w, w.auth2, 2, [w.entry(w.old, "retired", R)], gen=1, prev=proto.list_digest(l1)),
            state,
        ).code
        == "REVOCATION_AUTHORITY_MISMATCH"
    )


def test_transition_requires_both_signatures_and_binds_roles(w):
    state = w.enrolled()
    good = w.transition(w.rev, w.auth2)
    assert vt(w, good, state).accepted
    # new key did not sign (proof of possession missing): signed by a third key
    assert (
        vt(w, w.transition(w.rev, w.auth2, to_signer=w.evil), state).code
        == "REVOCATION_SIGNATURE_INVALID"
    )
    # old key did not sign
    assert (
        vt(w, w.transition(w.rev, w.auth2, from_signer=w.evil), state).code
        == "REVOCATION_SIGNATURE_INVALID"
    )
    # signatures swapped between roles (domain separation)
    swapped = copy.deepcopy(good)
    swapped["signatures"]["from"], swapped["signatures"]["to"] = (
        good["signatures"]["to"],
        good["signatures"]["from"],
    )
    assert vt(w, swapped, state).code == "REVOCATION_SIGNATURE_INVALID"
    # a LIST signature cannot stand in for a transition signature
    body = proto._without(good)
    bad = copy.deepcopy(good)
    bad["signatures"]["from"] = proto._sig_doc(body, proto.SIGN_DOMAIN, w.rev)
    assert vt(w, bad, state).code == "REVOCATION_SIGNATURE_INVALID"


def _leaf_paths(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaf_paths(v, (*path, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _leaf_paths(v, (*path, i))
    else:
        yield path, obj


def _mutate_leaf(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if value is None:
        return "tampered"
    if len(value) == 64 and all(c in "0123456789abcdef" for c in value):
        return ("0" if value[0] != "0" else "1") + value[1:]
    return value + "x" if not value.endswith("Z") else value[:-1].replace("00", "01", 1) + "Z"


def _set(doc, path, value):
    cur = doc
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value


def test_every_leaf_of_a_transition_is_tamper_evident(w):
    state = w.enrolled()
    doc = w.transition(w.rev, w.auth2)
    leaves = dict(_leaf_paths(doc))
    assert len(leaves) == 17
    for path, value in leaves.items():
        bad = copy.deepcopy(doc)
        _set(bad, path, _mutate_leaf(value))
        assert not vt(w, bad, state).accepted, path


def test_every_leaf_of_a_recovery_statement_is_tamper_evident(w):
    state = w.enrolled()
    doc = w.recovery_stmt(
        w.auth2, declares=[(w.fp(w.rev), E)], rebase={"epoch": 1, "list_digest": "a" * 64}
    )
    leaves = dict(_leaf_paths(doc))
    assert len(leaves) == 21
    for path, value in leaves.items():
        bad = copy.deepcopy(doc)
        _set(bad, path, _mutate_leaf(value))
        assert not vr(w, bad, state).accepted, path


def test_transition_member_removal_addition_and_malformed_input(w):
    state = w.enrolled()
    doc = w.transition(w.rev, w.auth2)
    for key in list(doc):
        assert not vt(w, {k: v for k, v in doc.items() if k != key}, state).accepted, key
    assert vt(w, {**doc, "extra": 1}, state).code == "REVOCATION_MALFORMED"
    for raw in (b"", b"{", b"[]", b'{"a":1,"a":2}', b"\xef\xbb\xbf{}"):
        assert proto.verify_transition(raw, state, None, NOW).code == "REVOCATION_MALFORMED"
        assert proto.verify_recovery(raw, state, None, NOW).code == "REVOCATION_MALFORMED"
    bad = copy.deepcopy(doc)
    bad["to_authority"]["public_key_pem"] = w.evil.public_key_pem()  # fingerprint no longer matches
    assert vt(w, bad, state).code == "REVOCATION_MALFORMED"
    ver = copy.deepcopy(doc)
    ver["schema_version"] = 2
    assert vt(w, ver, state).code == "REVOCATION_VERSION_UNSUPPORTED"


def test_transition_generation_gaps_and_replay(w):
    state = w.enrolled()
    t12 = w.transition(w.rev, w.auth2)
    assert (
        vt(w, w.transition(w.rev, w.auth2, to_gen=3), state).code == "REVOCATION_TRANSITION_GAP"
    )  # skips 2
    assert (
        vt(w, w.transition(w.rev, w.auth2, from_gen=2), state).code == "REVOCATION_TRANSITION_GAP"
    )
    assert vt(w, w.transition(w.rev, w.auth2, to_gen=1), state).code == "REVOCATION_TRANSITION_GAP"
    state = take(state, vt(w, t12, state))
    assert (
        vt(w, t12, state).code == "REVOCATION_AUTHORITY_SUPERSEDED"
    )  # replay of an applied transition
    t23 = w.transition(w.auth2, w.auth3, from_gen=2)
    assert vt(w, t23, state).accepted


def test_transition_chains_gaps_cycles_and_order(w):
    state = w.enrolled()
    t12 = dump(w.transition(w.rev, w.auth2))
    t23 = dump(w.transition(w.auth2, w.auth3, from_gen=2))
    final, results = proto.verify_transition_chain([t12, t23], state, None, NOW)
    assert [r.accepted for r in results] == [True, True]
    assert final.enrollments[w.issuer].generation == 3
    assert final.enrollments[w.issuer].authority_fingerprint == w.fp(w.auth3)
    # gap: the verifier missed t12 and is shown only t23
    _, results = proto.verify_transition_chain([t23], state, None, NOW)
    assert results[0].code == "REVOCATION_AUTHORITY_MISMATCH"
    # out of order stops at the first refusal and applies nothing after it
    after, results = proto.verify_transition_chain([t23, t12], state, None, NOW)
    assert len(results) == 1 and not results[0].accepted and after is state
    # cycle: auth2 hands back to the original authority (key reuse)
    back = dump(w.transition(w.auth2, w.rev, from_gen=2))
    _, results = proto.verify_transition_chain([t12, back], state, None, NOW)
    assert [r.accepted for r in results] == [True, False]
    assert results[1].code == "REVOCATION_TRANSITION_CYCLE"
    # self-transition
    assert vt(w, w.transition(w.rev, w.rev, to_gen=2), state).code == "REVOCATION_TRANSITION_CYCLE"
    # duplicate record in a chain
    _, results = proto.verify_transition_chain([t12, t12], state, None, NOW)
    assert results[1].code == "REVOCATION_AUTHORITY_SUPERSEDED"
    # a hole in the middle (t12, then a transition whose from-generation is 3)
    hole = dump(w.transition(w.auth2, w.auth3, from_gen=3, to_gen=4))
    _, results = proto.verify_transition_chain([t12, hole], state, None, NOW)
    assert results[1].code == "REVOCATION_TRANSITION_GAP"


def test_transition_validity_period_and_role_conflicts(w):
    state = w.enrolled()
    assert vt(w, w.transition(w.rev, w.auth2, valid_until="2026-11-01T12:00:01Z"), state).accepted
    expired = w.transition(w.rev, w.auth2, valid_until="2026-11-01T12:00:00Z")  # exclusive bound
    assert vt(w, expired, state).code == "REVOCATION_EXPIRED"
    assert (
        vt(w, w.transition(w.rev, w.auth2), state, now=NOW + timedelta(days=30)).code
        == "REVOCATION_EXPIRED"
    )
    early = w.transition(w.rev, w.auth2, issued_at="2026-11-01T13:00:00Z")
    assert vt(w, early, state).code == "REVOCATION_NOT_YET_VALID"
    # the new authority may not be the recovery anchor or a report key
    assert vt(w, w.transition(w.rev, w.recovery), state).code == "REVOCATION_KEY_IS_REPORT_KEY"
    assert (
        vt(w, w.transition(w.rev, w.new), state, store=w.store()).code
        == "REVOCATION_KEY_IS_REPORT_KEY"
    )
    # unknown from-authority
    assert vt(w, w.transition(w.other_rev, w.auth2), state).code == "REVOCATION_AUTHORITY_MISMATCH"
    # claims the enrolled fingerprint but signed by someone else
    assert (
        vt(w, w.transition(w.rev, w.auth2, from_signer=w.other_rev), state).code
        == "REVOCATION_SIGNATURE_INVALID"
    )


def test_transition_for_another_issuer_is_not_accepted(w):
    state = w.enrolled()
    other = make_world("globex")
    assert vt(w, other.transition(other.rev, other.auth2), state).code == "REVOCATION_NOT_ENROLLED"
    forged = w.transition(w.rev, w.auth2)
    forged["issuer"] = "globex"
    assert vt(w, forged, state).code == "REVOCATION_NOT_ENROLLED"


# ============================================================================ compromise recovery


def _recovered(w, *, declares=None, epoch=1, rebase=None):
    state = w.enrolled()
    stmt = w.recovery_stmt(w.auth2, declares=declares, epoch=epoch, rebase=rebase)
    return take(state, vr(w, stmt, state)), stmt


def test_recovery_replaces_a_compromised_authority_via_the_independent_anchor(w):
    state, stmt = _recovered(w, declares=[(w.fp(w.rev), E)])
    enr = state.enrollments[w.issuer]
    assert enr.authority_fingerprint == w.fp(w.auth2) and enr.generation == 2
    assert enr.compromised == {w.fp(w.rev): E} and enr.recovery_epoch == 1
    assert enr.recovery_digest == proto.recovery_digest(stmt)
    # lists from the compromised authority are refused with a distinct code; the new one works
    assert vlist(w, lst(w, w.rev, 1), state).code == "REVOCATION_AUTHORITY_COMPROMISED"
    assert vlist(w, lst(w, w.auth2, 1, gen=2), state).accepted


def test_recovery_needs_an_enrolled_recovery_anchor(w):
    state = w.enrolled(recovery=False)
    res = vr(w, w.recovery_stmt(w.auth2), state)
    assert res.code == "REVOCATION_RECOVERY_ANCHOR_ABSENT" and "re-enrollment" in res.notes[0]
    # the compromised authority cannot stand in for an absent anchor
    self_signed = w.recovery_stmt(w.auth2, anchor=w.rev)
    assert vr(w, self_signed, state).code == "REVOCATION_RECOVERY_ANCHOR_ABSENT"
    assert state.enrollments[w.issuer].authority_fingerprint == w.anchor.fingerprint  # unchanged


def test_recovery_signed_by_the_authority_itself_is_refused(w):
    state = w.enrolled()
    # the (compromised) authority names itself as the anchor: wrong fingerprint
    assert (
        vr(w, w.recovery_stmt(w.evil, anchor=w.rev), state).code
        == "REVOCATION_RECOVERY_ANCHOR_MISMATCH"
    )
    # or claims the anchor's fingerprint but signs with the authority key
    forged = w.recovery_stmt(w.evil, anchor_signer=w.rev)
    assert vr(w, forged, state).code == "REVOCATION_SIGNATURE_INVALID"


def test_recovery_requires_possession_by_the_new_authority(w):
    state = w.enrolled()
    assert (
        vr(w, w.recovery_stmt(w.auth2, new_signer=w.evil), state).code
        == "REVOCATION_SIGNATURE_INVALID"
    )
    swapped = w.recovery_stmt(w.auth2)
    swapped["signatures"]["anchor"], swapped["signatures"]["new_authority"] = (
        swapped["signatures"]["new_authority"], swapped["signatures"]["anchor"])  # fmt: skip
    assert vr(w, swapped, state).code == "REVOCATION_SIGNATURE_INVALID"


def test_old_authority_signs_a_transition_after_it_was_declared_compromised(w):
    state, _ = _recovered(w, declares=[(w.fp(w.rev), E)])
    # the thief now uses the old authority key to hand over to his own key
    res = vt(w, w.transition(w.rev, w.evil, from_gen=1), state)
    assert res.code == "REVOCATION_AUTHORITY_COMPROMISED"
    # even with a generation that fits the current chain
    res = vt(w, w.transition(w.rev, w.evil, from_gen=2, to_gen=3), state)
    assert res.code == "REVOCATION_AUTHORITY_COMPROMISED"
    assert state.enrollments[w.issuer].authority_fingerprint == w.fp(w.auth2)


def test_transition_accepted_before_recovery_is_superseded_by_the_recovery_statement(w):
    """The thief hands the authority to his key BEFORE the compromise is known; recovery wins."""
    state = w.enrolled()
    evil_t = w.transition(w.rev, w.evil)
    state = take(state, vt(w, evil_t, state))
    assert state.enrollments[w.issuer].authority_fingerprint == w.fp(
        w.evil
    )  # honest limit: accepted
    rec = w.recovery_stmt(w.auth2, declares=[(w.fp(w.rev), E), (w.fp(w.evil), None)], new_gen=3)
    res = vr(w, rec, state)
    assert res.accepted and res.voided == (proto.transition_digest(evil_t),)
    state = take(state, res)
    enr = state.enrollments[w.issuer]
    assert enr.authority_fingerprint == w.fp(w.auth2) and enr.generation == 3
    assert set(enr.compromised) == {w.fp(w.rev), w.fp(w.evil)}
    assert enr.voided == (proto.transition_digest(evil_t),)
    assert vlist(w, lst(w, w.evil, 1, gen=2), state).code == "REVOCATION_AUTHORITY_COMPROMISED"
    assert (
        vt(w, w.transition(w.evil, w.auth3, from_gen=2), state).code
        == "REVOCATION_AUTHORITY_COMPROMISED"
    )


def test_only_transitions_at_or_after_the_boundary_are_voided(w):
    state = w.enrolled()
    early = w.transition(w.rev, w.auth2, issued_at="2026-10-01T00:00:00Z")  # before the boundary
    state = take(state, vt(w, early, state))
    rec = w.recovery_stmt(w.auth3, declares=[(w.fp(w.rev), "2026-10-15T00:00:00Z")], new_gen=3)
    assert vr(w, rec, state).voided == ()
    rec2 = w.recovery_stmt(w.auth3, declares=[(w.fp(w.rev), "2026-09-15T00:00:00Z")], new_gen=3)
    assert vr(w, rec2, state).voided == (proto.transition_digest(early),)
    rec3 = w.recovery_stmt(w.auth3, declares=[(w.fp(w.rev), None)], new_gen=3)  # unknown boundary
    assert vr(w, rec3, state).voided == (proto.transition_digest(early),)


def test_recovery_replay_fork_and_repeat(w):
    state, stmt = _recovered(w)
    assert vr(w, stmt, state).notes == ("REVOCATION_REPEAT",) and vr(w, stmt, state).accepted
    other = w.recovery_stmt(w.auth3, epoch=1, new_gen=3)
    assert vr(w, other, state).code == "REVOCATION_FORK"
    nxt = w.recovery_stmt(w.auth3, epoch=2, new_gen=3, declares=[(w.fp(w.auth2), None)])
    state2 = take(state, vr(w, nxt, state))
    assert (
        vr(w, stmt, state2).code == "REVOCATION_RECOVERY_REPLAY"
    )  # an old recovery cannot be replayed
    assert state2.enrollments[w.issuer].authority_fingerprint == w.fp(w.auth3)


def test_recovery_new_authority_must_be_fresh_and_generation_must_increase(w):
    state = w.enrolled()
    assert (
        vr(w, w.recovery_stmt(w.rev), state).code == "REVOCATION_TRANSITION_CYCLE"
    )  # same key as current
    assert vr(w, w.recovery_stmt(w.auth2, new_gen=1), state).code == "REVOCATION_TRANSITION_GAP"
    assert vr(w, w.recovery_stmt(w.recovery), state).code == "REVOCATION_KEY_IS_REPORT_KEY"
    assert (
        vr(w, w.recovery_stmt(w.new), state, store=w.store()).code == "REVOCATION_KEY_IS_REPORT_KEY"
    )
    st2, _ = _recovered(w)
    again = w.recovery_stmt(w.rev, epoch=2, new_gen=3, declares=[(w.fp(w.auth2), None)])
    assert (
        vr(w, again, st2).code == "REVOCATION_TRANSITION_CYCLE"
    )  # a compromised key never returns
    declaring_self = w.recovery_stmt(w.auth2, declares=[(w.fp(w.recovery), None)])
    assert vr(w, declaring_self, state).code == "REVOCATION_MALFORMED"
    future = w.recovery_stmt(w.auth2, declares=[(w.fp(w.rev), "2026-12-01T00:00:00Z")])
    assert vr(w, future, state).code == "REVOCATION_MALFORMED"


def test_recovery_statement_shape_rules(w):
    state = w.enrolled()
    doc = w.recovery_stmt(w.auth2)
    dup = copy.deepcopy(doc)
    dup["declares_compromised"] = dup["declares_compromised"] * 2  # duplicate record
    assert vr(w, dup, state).code == "REVOCATION_MALFORMED"
    empty = copy.deepcopy(doc)
    empty["declares_compromised"] = []
    assert vr(w, empty, state).code == "REVOCATION_MALFORMED"
    raw = dump(doc).replace('"recovery_epoch": 1', '"recovery_epoch": 1, "recovery_epoch": 2')
    assert proto.verify_recovery(raw, state, None, NOW).code == "REVOCATION_MALFORMED"
    assert (
        vr(w, w.recovery_stmt(w.auth2), state, now=NOW + timedelta(days=30)).code
        == "REVOCATION_EXPIRED"
    )
    assert (
        vr(w, w.recovery_stmt(w.auth2, issued_at="2026-11-01T13:00:00Z"), state).code
        == "REVOCATION_NOT_YET_VALID"
    )


def test_routine_and_recovery_statements_are_not_interchangeable(w):
    state = w.enrolled()
    assert (
        proto.verify_recovery(dump(w.transition(w.rev, w.auth2)), state, None, NOW).code
        == "REVOCATION_MALFORMED"
    )
    assert (
        proto.verify_transition(dump(w.recovery_stmt(w.auth2)), state, None, NOW).code
        == "REVOCATION_MALFORMED"
    )
    # a list is neither
    assert (
        proto.verify_transition(dump(lst(w, w.rev, 1)), state, None, NOW).code
        == "REVOCATION_MALFORMED"
    )
    # distinct signing domains
    domains = {proto.SIGN_DOMAIN, proto.TRANS_FROM_DOMAIN, proto.TRANS_TO_DOMAIN, proto.REC_ANCHOR_DOMAIN,
               proto.REC_TO_DOMAIN, proto.DIGEST_DOMAIN, proto.TRANS_DIGEST_DOMAIN, proto.REC_DIGEST_DOMAIN}  # fmt: skip
    assert len(domains) == 8 and all(d.endswith(b"\x00") for d in domains)


# ----- epoch poisoning and rebase


def _poisoned(w):
    """The thief (holding the authority key) published an epoch-1000 list full of spurious revocations."""
    state = w.enrolled()
    l1 = lst(w, w.rev, 1, [w.entry(w.old, "retired", R)])
    res = vlist(w, l1, state, store=w.store(w.old, w.new, w.third))
    state = proto.commit(state, state.enrollments[w.issuer].anchor, res)
    spurious = lst(w, w.rev, 1000, [w.entry(w.old, "retired", R), w.entry(w.third, "compromised", None)],
                   prev="c" * 64)  # fmt: skip
    res = vlist(w, spurious, state, store=w.store(w.old, w.new, w.third))
    assert res.accepted, res.blocking
    return proto.commit(state, state.enrollments[w.issuer].anchor, res), proto.list_digest(l1)


def test_epoch_poisoning_blocks_the_new_authority_without_a_rebase(w):
    state, _ = _poisoned(w)
    st3 = w.store(w.old, w.new, w.third)
    state = take(state, vr(w, w.recovery_stmt(w.auth2, declares=[(w.fp(w.rev), None)]), state))
    low = lst(w, w.auth2, 2, [w.entry(w.old, "retired", R)], gen=2, prev="d" * 64)
    assert (
        vlist(w, low, state, store=st3).code == "REVOCATION_ROLLBACK"
    )  # monotone mark stays at 1000


def test_recovery_with_rebase_restores_the_last_good_list_from_the_archive(w):
    state, good_digest = _poisoned(w)
    st3 = w.store(w.old, w.new, w.third)
    rec = w.recovery_stmt(
        w.auth2, declares=[(w.fp(w.rev), None)], rebase={"epoch": 1, "list_digest": good_digest}
    )
    state = take(state, vr(w, rec, state))
    assert state.marks[w.issuer].epoch == 1 and state.marks[w.issuer].digest == good_digest
    nxt = lst(w, w.auth2, 2, [w.entry(w.old, "retired", R)], gen=2, prev=good_digest)
    res = vlist(w, nxt, state, store=st3)
    assert res.accepted, (
        res.blocking
    )  # the spurious compromised entry for 'third' is not carried over


def test_rebase_to_an_unknown_baseline_is_refused_not_guessed(w):
    state, good_digest = _poisoned(w)
    unknown = w.recovery_stmt(
        w.auth2, declares=[(w.fp(w.rev), None)], rebase={"epoch": 1, "list_digest": "e" * 64}
    )
    assert vr(w, unknown, state).code == "REVOCATION_RECOVERY_BASELINE_UNKNOWN"
    wrong_epoch = w.recovery_stmt(
        w.auth2, declares=[(w.fp(w.rev), None)], rebase={"epoch": 2, "list_digest": good_digest}
    )
    assert vr(w, wrong_epoch, state).code == "REVOCATION_RECOVERY_BASELINE_UNKNOWN"


def test_recovery_never_loosens_the_local_trust_store(w):
    """Rebase restores the verifier's mark, not the store: tightening already applied stays."""
    state, _ = _poisoned(w)
    st3 = w.store(w.old, w.new, w.third)
    res = vlist(
        w,
        lst(
            w,
            w.rev,
            1000,
            [w.entry(w.old, "retired", R), w.entry(w.third, "compromised", None)],
            prev="c" * 64,
        ),
        state,
        store=st3,
    )
    tightened = proto.apply_to_store(st3, res)
    assert tightened.entry(w.third.key_id).status == "compromised"  # type: ignore[union-attr]
    # nothing in the recovery machinery returns a store; loosening is a manual operator act
    assert not hasattr(proto, "loosen_store")


def test_the_recovery_anchor_is_a_total_trust_root_documented_limit(w):
    """Whoever holds the recovery anchor key can replace the authority. This is the point of the
    anchor, and the reason it must be offline and enrolled out of band."""
    state = w.enrolled()
    res = vr(w, w.recovery_stmt(w.evil, declares=[(w.fp(w.rev), None)]), state)
    assert res.accepted  # signed by the genuine anchor key: indistinguishable from the owner


# ============================================================================ persistence and purity


def test_enrollment_state_round_trips_and_verification_is_pure(w, tmp_path):
    state, stmt = _recovered(w, declares=[(w.fp(w.rev), E)])
    path = str(tmp_path / "state.json")
    state.save(path)
    again = proto.RevocationState.load(path)
    assert again == state
    before = dict(again.enrollments)
    vr(w, stmt, again)
    vt(w, w.transition(w.auth2, w.auth3, from_gen=2), again)
    assert again.enrollments == before
    assert json.loads(Path(path).read_text())["enrollments"][w.issuer]["generation"] == 2


def test_deleting_the_state_forgets_enrollment_and_compromise_documented_limit(w, tmp_path):
    state, _ = _recovered(w)
    path = str(tmp_path / "state.json")
    state.save(path)
    Path(path).unlink()
    empty = proto.RevocationState.load(path)
    assert empty.enrollments == {}
    assert (
        vlist(w, lst(w, w.rev, 1), empty).code == "REVOCATION_NOT_ENROLLED"
    )  # fail-closed: nothing trusted


# ============================================================================ adversarial list cases with the enrolled authority


def test_forged_issuer_wrong_authority_and_cross_issuer_revocation(w):
    state = w.enrolled()
    body = w.body(1, [w.entry(w.old, "retired", R)])
    body["issuer"] = "globex"
    assert vlist(w, proto.sign_list(body, w.rev), state).code == "REVOCATION_WRONG_ISSUER"
    assert vlist(w, lst(w, w.other_rev, 1), state).code == "REVOCATION_AUTHORITY_MISMATCH"
    # an issuer cannot revoke a key enrolled under another issuer
    foreign = TrustStore_from(w, issuer="globex")
    res = vlist(w, lst(w, w.rev, 1, [w.entry(w.old, "compromised", None)]), state, store=foreign)
    assert res.code == "REVOCATION_ISSUER_SCOPE"


def TrustStore_from(w, *, issuer):
    from regaudit_fhe.trust import TrustStore

    return TrustStore.from_dict({"entries": {w.old.key_id: {"issuer": issuer,
        "public_key_pem": w.old.public_key_pem(), "status": "active"}}})  # fmt: skip


def test_omitted_previously_revoked_key_is_refused_even_when_correctly_signed(w):
    state = w.enrolled()
    st = w.store(w.old, w.new, w.third)
    l1 = lst(w, w.rev, 1, [w.entry(w.old, "compromised", E), w.entry(w.third, "retired", R)])
    state = proto.commit(state, state.enrollments[w.issuer].anchor, vlist(w, l1, state, store=st))
    silent = lst(
        w, w.rev, 2, [w.entry(w.third, "retired", R)], prev=proto.list_digest(l1)
    )  # old dropped
    res = vlist(w, silent, state, store=st)
    assert res.code == "REVOCATION_NOT_MONOTONE" and "entry removed" in res.notes[0]
    # honest limit: a verifier shown ONLY the list that omits it at first use cannot know
    fresh = w.enrolled()
    assert vlist(w, silent, fresh, store=st).accepted


def test_duplicate_records_and_conflicting_epochs(w):
    state = w.enrolled()
    a = w.entry(w.old, "retired", R)
    body = w.body(1, [])
    body["entries"] = [a, copy.deepcopy(a)]
    assert vlist(w, proto.sign_list(body, w.rev), state).code == "REVOCATION_MALFORMED"
    l1 = lst(w, w.rev, 1, [a])
    state = proto.commit(state, state.enrollments[w.issuer].anchor, vlist(w, l1, state))
    conflicting = lst(w, w.rev, 1, [w.entry(w.old, "compromised", None)])
    assert vlist(w, conflicting, state).code == "REVOCATION_FORK"
    same = lst(w, w.rev, 1, [a])
    assert vlist(w, same, state).notes == ("REVOCATION_REPEAT",)


def test_malformed_signature_encodings_on_every_statement_kind(w):
    state = w.enrolled()
    for doc, verify in (
        (lst(w, w.rev, 1), lambda d: vlist(w, d, state)),
        (w.transition(w.rev, w.auth2), lambda d: vt(w, d, state)),
        (w.recovery_stmt(w.auth2), lambda d: vr(w, d, state)),
    ):
        assert verify(doc).accepted
        sig_paths = [p for p, _ in _leaf_paths(doc) if p[-1] == "signature_b64"]
        assert sig_paths
        for path in sig_paths:
            for bad in (
                "",
                "A" * 88,
                "!" * 88,
                "A" * 87,
                dict(_leaf_paths(doc))[path][:-4] + "AAAA",
            ):
                d = copy.deepcopy(doc)
                _set(d, path, bad)
                assert not verify(d).accepted, (path, bad)


def test_recovery_cannot_declare_its_own_new_authority_compromised(w):
    state = w.enrolled()
    stmt = w.recovery_stmt(w.auth2, declares=[(w.fp(w.rev), None), (w.fp(w.auth2), None)])
    assert vr(w, stmt, state).code == "REVOCATION_TRANSITION_CYCLE"


def test_a_later_recovery_can_only_tighten_a_compromise_boundary(w):
    state = w.enrolled()
    state = take(state, vr(w, w.recovery_stmt(w.auth2, declares=[(w.fp(w.rev), E)]), state))
    boundaries = []
    for epoch, gen, signer, declared in (
        (2, 3, w.auth3, "2026-08-01T00:00:00Z"),  # earlier: tightens
        (3, 4, w.evil, "2026-09-20T00:00:00Z"),  # later: ignored
        (4, 5, w.other_rev, None),  # unknown: dominates
        (5, 6, w.new, "2026-07-01T00:00:00Z"),  # known after unknown: stays unknown
    ):
        stmt = w.recovery_stmt(signer, epoch=epoch, new_gen=gen, declares=[(w.fp(w.rev), declared)])
        state = take(state, vr(w, stmt, state))
        boundaries.append(state.enrollments[w.issuer].compromised[w.fp(w.rev)])
    assert boundaries == ["2026-08-01T00:00:00Z", "2026-08-01T00:00:00Z", None, None]


def test_recovery_supersedes_a_current_authority_that_was_not_declared_compromised(w):
    """Planned replacement through the anchor: the old authority is superseded, not compromised."""
    state = w.enrolled()
    stmt = w.recovery_stmt(w.auth2, declares=[(w.fp(w.other_rev), None)])
    state = take(state, vr(w, stmt, state))
    enr = state.enrollments[w.issuer]
    assert w.fp(w.rev) in enr.superseded and w.fp(w.rev) not in enr.compromised
    assert vlist(w, lst(w, w.rev, 1), state).code == "REVOCATION_AUTHORITY_SUPERSEDED"


def test_per_issuer_mark_survives_authority_rotation_and_get_takes_only_the_issuer(w):
    state = w.enrolled()
    l1 = lst(w, w.rev, 1, [w.entry(w.old, "retired", R)])
    state = proto.commit(state, state.enrollments[w.issuer].anchor, vlist(w, l1, state))
    state = take(state, vt(w, w.transition(w.rev, w.auth2), state))
    assert state.get(w.issuer).epoch == 1 and state.get(w.issuer).authority_fingerprint == w.fp(
        w.rev
    )
    l2 = lst(w, w.auth2, 2, [w.entry(w.old, "retired", R)], gen=2, prev=proto.list_digest(l1))
    state = proto.commit(state, state.enrollments[w.issuer].anchor, vlist(w, l2, state))
    assert state.get(w.issuer).epoch == 2 and state.get(w.issuer).authority_fingerprint == w.fp(
        w.auth2
    )
