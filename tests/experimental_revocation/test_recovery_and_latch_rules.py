"""Rules added after an independent adversarial read of the proposal. Each sequence was first run as a probe.

The common shape: K1 is the enrolled authority and is stolen, K2 is the new authority, and the verifier must end up
refusing what the thief says, without anyone lacking a key being able to stop it working.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from regaudit_fhe import _revocation_state as state_module
from regaudit_fhe.trust import TrustStore
from regaudit_fhe.verification import PolicyError

from . import proto
from . import trust_gate as tg
from .gen_fixtures import NOW, World, dump, make_world
from .test_state_and_gate import add, ctx, decide, l1, pin, policy, report, setup

R = "2026-10-01T00:00:00Z"


@pytest.fixture
def w() -> World:
    return make_world()


def full(w: World) -> TrustStore:
    return w.store(w.old, w.new, w.third)


def record(s, p) -> tg.Record:
    return tg.load(s, p)[0]


# ============================================================================ recovery that cannot complete still tells


def _gap_verifier(w: World):
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    second = w.signed(2, [], prev=proto.list_digest(first))
    add(w, s, p, w.signed(3, [], prev=proto.list_digest(second)))  # gap: epoch 2 never seen here
    rec = w.recovery_stmt(w.auth2, rebase={"epoch": 2, "list_digest": proto.list_digest(second)})
    return s, p, rec


def test_C23_a_refused_recovery_still_commits_what_it_declares(w, tmp_path):
    s, p, rec = _gap_verifier(w)
    assert tg.ingest_recovery(s, p, dump(rec), w.store(), NOW).code == (
        "REVOCATION_RECOVERY_BASELINE_UNKNOWN"
    )
    assert w.fp(w.rev) in record(s, p).state.enrollments[w.issuer].compromised
    thief = w.signed(9, [], prev="c" * 64)
    assert add(w, s, p, thief).code == "REVOCATION_AUTHORITY_COMPROMISED"
    d = decide(w, tmp_path, s, p)
    assert "REVOCATION_AUTHORITY_COMPROMISED" in d.result.blocking_reasons and not d.result.accepted


def test_C24_a_statement_past_its_validity_still_tells_a_long_offline_verifier(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w))
    rec = w.recovery_stmt(w.auth2)
    later = NOW + timedelta(days=60)
    assert tg.ingest_recovery(s, p, dump(rec), w.store(), later).code == "REVOCATION_EXPIRED"
    thief = w.signed(
        2,
        [],
        prev=proto.list_digest(l1(w)),
        issued_at="2026-12-31T00:00:00Z",
        valid_until="2027-02-01T00:00:00Z",
    )
    assert add(w, s, p, thief, now=later).code == "REVOCATION_AUTHORITY_COMPROMISED"


def test_C37_an_expired_statement_also_condemns_the_key_a_thief_installed(w):
    s, p = setup(w)
    assert tg.ingest_transition(s, p, dump(w.transition(w.rev, w.evil)), w.store(), NOW).accepted
    later = NOW + timedelta(days=60)
    out = tg.ingest_recovery(s, p, dump(w.recovery_stmt(w.auth2, new_gen=3)), w.store(), later)
    assert out.code == "REVOCATION_EXPIRED"
    assert w.fp(w.evil) in record(s, p).state.enrollments[w.issuer].compromised
    thief = w.signed(
        1,
        [],
        signer=w.evil,
        generation=2,
        issued_at="2026-12-31T00:00:00Z",
        valid_until="2027-02-01T00:00:00Z",
    )
    assert add(w, s, p, thief, now=later).code == "REVOCATION_AUTHORITY_COMPROMISED"


def test_C25_a_forged_anchor_signature_declares_nothing(w):
    s, p = setup(w)
    add(w, s, p, l1(w))
    forged = w.recovery_stmt(w.auth2, anchor_signer=w.evil)
    before = s.data[w.issuer]
    assert tg.ingest_recovery(s, p, dump(forged), w.store(), NOW).code == (
        "REVOCATION_SIGNATURE_INVALID"
    )
    assert s.data[w.issuer] == before


def test_C26_one_thief_hop_does_not_make_the_honest_recovery_refuse_itself(w):
    """The anchor cannot know what generation a thief took each verifier to."""
    s, p = setup(w)
    add(w, s, p, l1(w))
    assert tg.ingest_transition(s, p, dump(w.transition(w.rev, w.evil)), w.store(), NOW).accepted
    rec = w.recovery_stmt(w.auth2, new_gen=2)
    assert tg.ingest_recovery(s, p, dump(rec), w.store(), NOW).accepted
    enrollment = record(s, p).state.enrollments[w.issuer]
    assert enrollment.authority_fingerprint == w.fp(w.auth2) and enrollment.generation == 2


def test_C27_a_generation_that_does_not_clear_the_last_honest_one_is_still_refused(w):
    s, p = setup(w)
    add(w, s, p, l1(w))
    assert tg.ingest_transition(s, p, dump(w.transition(w.rev, w.evil)), w.store(), NOW).accepted
    rec = w.recovery_stmt(w.auth2, new_gen=1)
    assert tg.ingest_recovery(s, p, dump(rec), w.store(), NOW).code == "REVOCATION_TRANSITION_GAP"


def test_C28_a_key_the_owner_never_saw_is_condemned_with_the_transition_that_installed_it(w, tmp_path):
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    assert tg.ingest_transition(s, p, dump(w.transition(w.rev, w.evil)), w.store(), NOW).accepted
    by_evil = w.signed(2, [], signer=w.evil, generation=2, prev=proto.list_digest(first))
    assert add(w, s, p, by_evil).accepted
    # the statement can only name K1: nobody but the thief knows the key he installed
    assert tg.ingest_recovery(s, p, dump(w.recovery_stmt(w.auth2, new_gen=3)), w.store(), NOW).accepted
    compromised = record(s, p).state.enrollments[w.issuer].compromised
    assert compromised[w.fp(w.evil)] is None
    d = decide(w, tmp_path, s, p)
    assert "REVOCATION_AUTHORITY_COMPROMISED" in d.result.blocking_reasons and not d.result.accepted


def test_C29_every_hop_after_the_first_voided_transition_is_condemned(w):
    state = w.enrolled()
    hop1 = proto.verify_transition(dump(w.transition(w.rev, w.evil)), state, None, NOW)
    state = proto.apply_authority(state, hop1)
    hop2 = proto.verify_transition(
        dump(w.transition(w.evil, w.auth3, from_gen=2)), state, None, NOW
    )
    state = proto.apply_authority(state, hop2)
    res = proto.verify_recovery(dump(w.recovery_stmt(w.auth2, new_gen=2)), state, None, NOW)
    assert res.accepted and len(res.voided) == 2
    assert set(res.enrollment.compromised) == {w.fp(w.rev), w.fp(w.evil), w.fp(w.auth3)}  # type: ignore[union-attr]


def test_C30_a_new_authority_equal_to_a_condemned_key_is_refused(w):
    state = w.enrolled()
    state = proto.apply_authority(
        state, proto.verify_transition(dump(w.transition(w.rev, w.evil)), state, None, NOW)
    )
    res = proto.verify_recovery(dump(w.recovery_stmt(w.evil, new_gen=3)), state, None, NOW)
    assert res.code == "REVOCATION_TRANSITION_CYCLE"


def test_G26_a_backdated_list_from_a_stolen_key_does_not_survive_as_evidence(w, tmp_path):
    """The thief signs now and writes a time before the boundary. What counts is when this verifier took it."""
    s, p = setup(w)
    backdated = w.signed(1, [], issued_at="2026-11-01T05:59:00Z")
    assert add(w, s, p, backdated).accepted
    rec = w.recovery_stmt(w.auth2, declares=[(w.fp(w.rev), "2026-11-01T06:00:00Z")])
    assert tg.ingest_recovery(s, p, dump(rec), w.store(), NOW).accepted
    d = decide(w, tmp_path, s, p)
    assert "REVOCATION_AUTHORITY_COMPROMISED" in d.result.blocking_reasons


def test_C31_a_backdated_transition_from_a_stolen_key_is_voided(w):
    state = w.enrolled()
    backdated = w.transition(w.rev, w.evil, issued_at="2026-11-01T05:59:00Z")
    state = proto.apply_authority(state, proto.verify_transition(dump(backdated), state, None, NOW))
    rec = w.recovery_stmt(w.auth2, declares=[(w.fp(w.rev), "2026-11-01T06:00:00Z")], new_gen=3)
    res = proto.verify_recovery(dump(rec), state, None, NOW)
    assert res.voided == (proto.transition_digest(backdated),)


def test_C32_an_honest_list_after_recovery_does_not_latch_on_what_the_thief_said(w, tmp_path):
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    thief = w.signed(2, [w.entry(w.third, "compromised", None)], prev=proto.list_digest(first))
    assert add(w, s, p, thief).accepted
    assert tg.ingest_recovery(s, p, dump(w.recovery_stmt(w.auth2)), w.store(), NOW).accepted
    # K2 knows nothing of the thief's list, so it neither chains to it nor repeats its entry
    honest = w.signed(3, [], signer=w.auth2, generation=2, prev="d" * 64)
    out = add(w, s, p, honest)
    assert out.accepted and "REVOCATION_MARK_CONDEMNED" in out.notes
    rec = record(s, p)
    assert rec.contradiction is None and w.fp(w.third) in rec.effective  # the tightening stays
    assert decide(w, tmp_path, s, p).result.accepted


def test_C33_a_condemned_mark_still_stops_an_older_epoch(w):
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    add(w, s, p, w.signed(5, [], prev="c" * 64))
    assert tg.ingest_recovery(s, p, dump(w.recovery_stmt(w.auth2)), w.store(), NOW).accepted
    low = w.signed(3, [], signer=w.auth2, generation=2, prev="d" * 64)
    assert add(w, s, p, low).code == "REVOCATION_ROLLBACK"
    assert record(s, p).contradiction is None


def test_C34_a_same_epoch_list_replaces_a_condemned_mark(w):
    s, p = setup(w)
    add(w, s, p, l1(w))
    assert tg.ingest_recovery(s, p, dump(w.recovery_stmt(w.auth2)), w.store(), NOW).accepted
    out = add(w, s, p, w.signed(1, [], signer=w.auth2, generation=2))
    assert out.accepted and record(s, p).contradiction is None


def test_C35_recovery_forks_do_not_latch(w):
    s, p = setup(w)
    add(w, s, p, l1(w))
    assert tg.ingest_recovery(s, p, dump(w.recovery_stmt(w.auth2)), w.store(), NOW).accepted
    other = dump(w.recovery_stmt(w.auth3, new_gen=3))
    assert tg.ingest_recovery(s, p, other, w.store(), NOW).code == "REVOCATION_FORK"
    assert record(s, p).contradiction is None


def test_C36_an_anchor_later_added_as_a_report_key_stops_validating_recovery(w):
    state = w.enrolled()
    store = w.store(w.old, w.recovery)
    res = proto.verify_recovery(dump(w.recovery_stmt(w.auth2)), state, store, NOW)
    assert res.code == "REVOCATION_KEY_IS_REPORT_KEY"


# ============================================================================ no denial of service without a key


def _collision_store(w: World, issuer: str) -> TrustStore:
    """Another key enrolled under a key_id the list names."""
    return TrustStore.from_dict(
        {
            "entries": {
                w.old.key_id: {
                    "issuer": issuer,
                    "public_key_pem": w.third.public_key_pem(),
                    "status": "active",
                }
            }
        }
    )


def test_G28_replaying_an_old_list_after_a_local_store_change_stays_a_rollback(w, tmp_path):
    s, p = setup(w)
    first = l1(w, [w.entry(w.old, "retired", R)])
    add(w, s, p, first)
    add(w, s, p, w.signed(2, [w.entry(w.old, "retired", R)], prev=proto.list_digest(first)))
    for issuer in ("globex", w.issuer):
        store = _collision_store(w, issuer)
        assert tg.ingest_list(s, p, dump(first), store, NOW).code == "REVOCATION_ROLLBACK"
        assert record(s, p).contradiction is None


def test_L28_a_key_id_collision_with_another_issuer_is_unrelated(w):
    s, p = setup(w)
    store = _collision_store(w, "globex")
    out = tg.ingest_list(s, p, dump(l1(w, [w.entry(w.old, "retired", R)])), store, NOW)
    assert out.accepted
    # the other issuer's key, which merely shares the key_id, is not touched
    assert tg.overlay(store, w.issuer, record(s, p).effective).entries[w.old.key_id].status == "active"


def test_L29_a_same_issuer_key_mismatch_refuses_but_does_not_latch(w):
    s, p = setup(w)
    store = _collision_store(w, w.issuer)
    out = tg.ingest_list(s, p, dump(l1(w, [w.entry(w.old, "retired", R)])), store, NOW)
    assert out.code == "REVOCATION_KEY_MISMATCH" and record(s, p).contradiction is None


def test_G29_a_ceremony_adjudicates_a_fork_so_replaying_either_side_cannot_relatch(w):
    s, p = setup(w)
    good, bad = l1(w), w.signed(1, [w.entry(w.old, "retired", R)])
    add(w, s, p, good)
    assert add(w, s, p, bad).code == "REVOCATION_FORK"
    assert record(s, p).contradiction is not None
    p2 = pin(w, enrollment_id="enr-2", baseline_epoch=1, baseline_digest=proto.list_digest(good))
    tg.rebaseline(s, p2, now=NOW)
    assert add(w, s, p2, good).accepted
    assert add(w, s, p2, bad).code == "REVOCATION_FORK"
    assert record(s, p2).contradiction is None
    assert tg.gate(ctx(w, s, p2), w.issuer, NOW).ok


def test_G30_presented_evidence_is_compared_and_never_written(w, tmp_path):
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    assert tg.gate(ctx(w, s, p), w.issuer, NOW).ok  # binds the policy floor, its one write
    before = s.data[w.issuer]
    fork = dump(w.signed(1, [w.entry(w.old, "retired", R)]))
    for raw, code in ((fork, "REVOCATION_FORK"), (b"{", "REVOCATION_MALFORMED")):
        d = tg.verify_with_revocation(report(w), policy(w, tmp_path), ctx(w, s, p), presented=raw)
        assert code in d.result.blocking_reasons and not d.result.accepted
    newer = dump(w.signed(2, [w.entry(w.old, "compromised", None)], prev=proto.list_digest(first)))
    d = tg.verify_with_revocation(report(w), policy(w, tmp_path), ctx(w, s, p), presented=newer)
    assert d.result.accepted  # supplied with the artifact, so it is never trust history: not applied
    assert s.data[w.issuer] == before


# ============================================================================ restore, ceremony, record size


def test_S17_a_public_replay_after_a_restore_does_not_hide_the_lost_position(w):
    """The write counter alone can be walked back up with authentic old lists. The position cannot."""
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    second = w.signed(2, [], prev=proto.list_digest(first))
    third = w.signed(3, [], prev=proto.list_digest(second))
    fourth = w.signed(4, [], prev=proto.list_digest(third))
    backup = s.data[w.issuer]
    add(w, s, p, w.signed(5, [w.entry(w.old, "compromised", None)], prev="c" * 64))
    context = ctx(w, s, p)
    assert tg.gate(context, w.issuer, NOW).ok
    seen = tg.load(s, p)[0].seq
    s.data[w.issuer] = backup
    for old in (second, third, fourth):
        assert add(w, s, p, old).accepted
    assert tg.load(s, p)[0].seq >= seen  # seq has been walked back up past what the process saw
    assert tg.gate(context, w.issuer, NOW).code == "REVOCATION_STATE_ROLLBACK"


def test_S18_recovery_may_lower_the_position_for_a_process_that_remembers_it(w):
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    add(w, s, p, w.signed(5, [], prev="c" * 64))
    context = ctx(w, s, p)
    assert tg.gate(context, w.issuer, NOW).ok
    rec = w.recovery_stmt(w.auth2, rebase={"epoch": 1, "list_digest": proto.list_digest(first)})
    assert tg.ingest_recovery(s, p, dump(rec), w.store(), NOW).accepted
    assert tg.gate(context, w.issuer, NOW).code != "REVOCATION_STATE_ROLLBACK"


def test_S19_HONEST_LIMIT_the_staleness_bound_does_not_hold_against_a_stolen_authority_key(w, tmp_path):
    """Restored record, recovery withheld, K1 signs a fresh list days later. Stated in section 9.6."""
    fs = tg.FileCasStore(tmp_path)
    s, p = setup(w, fs)
    first = l1(w)
    add(w, s, p, first)
    backup = fs.path(w.issuer).read_bytes()
    assert tg.ingest_recovery(s, p, dump(w.recovery_stmt(w.auth2)), w.store(), NOW).accepted
    fs.path(w.issuer).write_bytes(backup)
    later = NOW + timedelta(days=10)
    thief = w.signed(
        2,
        [],
        prev=proto.list_digest(first),
        issued_at="2026-11-11T09:00:00Z",
        valid_until="2026-11-18T09:00:00Z",
    )
    assert add(w, s, p, thief, now=later).accepted
    assert tg.gate(ctx(w, s, p), w.issuer, later).ok


def test_S20_a_ceremony_cannot_lose_key_actions_by_accident(w):
    s, p = setup(w)
    add(w, s, p, l1(w, [w.entry(w.old, "compromised", None)]))
    s.data[w.issuer] = b"{"
    p2 = pin(w, enrollment_id="enr-2")
    with pytest.raises(tg.StateUnavailable, match="accept_loss"):
        tg.rebaseline(s, p2, now=NOW)
    tg.rebaseline(s, p2, now=NOW, accept_loss=True)
    assert record(s, p2).effective == {}


def test_S21_the_process_memory_is_per_enrollment(w):
    s, p = setup(w)
    add(w, s, p, l1(w))
    context = ctx(w, s, p)
    assert tg.gate(context, w.issuer, NOW).ok
    s.data[w.issuer] = b"{"
    p2 = pin(w, enrollment_id="enr-2", baseline_epoch=1, baseline_digest=proto.list_digest(l1(w)))
    tg.rebaseline(s, p2, now=NOW, accept_loss=True)
    context.pins[w.issuer] = p2
    assert tg.gate(context, w.issuer, NOW).code == "REVOCATION_DATA_ABSENT"  # not a state rollback


def test_S22_the_largest_legal_list_does_not_brick_the_verifier(w):
    s, p = setup(w)
    entries = [
        {
            "key_id": f"k{i:05d}",
            "key_fingerprint": f"{i:064x}",
            "status": "retired",
            "effective_from": R,
        }
        for i in range(9000)
    ]
    assert add(w, s, p, w.signed(1, entries)).accepted
    assert tg.gate(ctx(w, s, p), w.issuer, NOW).ok
    assert tg.ingest_recovery(s, p, dump(w.recovery_stmt(w.auth2)), w.store(), NOW).accepted


def test_S23_the_archive_is_pruned_oldest_first_to_stay_inside_the_limit(w, monkeypatch):
    s, p = setup(w)
    entries = [w.entry(w.old, "retired", R)]
    doc = w.signed(1, entries)
    add(w, s, p, doc)
    size = len(s.data[w.issuer])
    monkeypatch.setattr(state_module, "MAX_RECORD_BYTES", size + 900)
    digests = [proto.list_digest(doc)]
    for epoch in range(2, 8):
        doc = w.signed(epoch, entries, prev=digests[-1])
        digests.append(proto.list_digest(doc))
        assert add(w, s, p, doc).accepted
    rec = record(s, p)
    assert len(s.data[w.issuer]) <= state_module.MAX_RECORD_BYTES
    assert digests[0] not in rec.state.archive and digests[-1] in rec.state.archive
    assert rec.state.get(w.issuer).digest == digests[-1]


def test_S24_a_record_that_cannot_fit_refuses_the_document_and_stays_usable(w, monkeypatch):
    s, p = setup(w)
    add(w, s, p, l1(w))
    before = s.data[w.issuer]
    monkeypatch.setattr(state_module, "MAX_RECORD_BYTES", len(before) + 10)
    big = w.signed(
        2,
        [w.entry(w.old, "retired", R), w.entry(w.new, "retired", R), w.entry(w.third, "retired", R)],
        prev=proto.list_digest(l1(w)),
    )
    assert add(w, s, p, big).code == "REVOCATION_STATE_FULL"
    assert s.data[w.issuer] == before
    monkeypatch.undo()
    assert tg.gate(ctx(w, s, p), w.issuer, NOW).ok


def test_E18_a_ceremony_cannot_move_the_authority_backwards_or_drop_its_history(w):
    s, p = setup(w)
    add(w, s, p, l1(w))
    assert tg.ingest_recovery(s, p, dump(w.recovery_stmt(w.auth2)), w.store(), NOW).accepted
    behind = tg.Pin(w.issuer, w.auth2.public_key_pem(), "enr-2", baseline_epoch=0)
    with pytest.raises(ValueError, match="behind"):
        tg.rebaseline(s, behind, now=NOW)
    current = tg.Pin(
        w.issuer,
        w.auth2.public_key_pem(),
        "enr-2",
        recovery_pem=w.recovery.public_key_pem(),
        baseline_epoch=1,
        baseline_digest=proto.list_digest(l1(w)),
        authority_generation=2,
        recovery_epoch=1,
    )
    tg.rebaseline(s, current, now=NOW)
    assert w.fp(w.rev) in record(s, current).state.enrollments[w.issuer].compromised


def test_E19_a_ceremony_refuses_a_key_declared_compromised(w):
    s, p = setup(w)
    add(w, s, p, l1(w))
    assert tg.ingest_recovery(s, p, dump(w.recovery_stmt(w.auth2)), w.store(), NOW).accepted
    again = tg.Pin(
        w.issuer, w.rev.public_key_pem(), "enr-2", baseline_epoch=0, authority_generation=2, recovery_epoch=1
    )
    with pytest.raises(ValueError, match="compromised"):
        tg.rebaseline(s, again, now=NOW)


def test_E20_a_ceremony_runs_the_purpose_checks(w):
    s, _ = setup(w)
    bad = tg.Pin(w.issuer, w.old.public_key_pem(), "enr-2", baseline_epoch=0)
    with pytest.raises(ValueError, match="report-signing"):
        tg.rebaseline(s, bad, now=NOW, trust_store=w.store())


def test_E21_a_first_list_right_after_the_baseline_must_chain_to_it(w):
    first = l1(w)
    s, p = setup(w, baseline_epoch=1, baseline_digest=proto.list_digest(first))
    assert add(w, s, p, w.signed(2, [], prev="e" * 64)).code == "REVOCATION_FORK"
    s2, p2 = setup(w, baseline_epoch=1, baseline_digest=proto.list_digest(first))
    assert add(w, s2, p2, w.signed(2, [], prev=proto.list_digest(first))).accepted


# ============================================================================ the latch, through the store


def _latched(w, s, p, code):
    rec = record(s, p)
    return rec.contradiction is not None and rec.contradiction["code"] == code


@pytest.mark.parametrize(
    "case",
    ["chain-fork", "omitted-key", "issued-at-back", "same-epoch-fork"],
)
def test_M18_every_signed_contradiction_latches_through_the_store(w, tmp_path, case):
    s, p = setup(w)
    first = l1(w, [w.entry(w.old, "retired", R)])
    assert add(w, s, p, first).accepted
    prev = proto.list_digest(first)
    entries = [w.entry(w.old, "retired", R)]
    doc, code = {
        "chain-fork": (w.signed(2, entries, prev="e" * 64), "REVOCATION_FORK"),
        "omitted-key": (w.signed(2, [], prev=prev), "REVOCATION_NOT_MONOTONE"),
        "issued-at-back": (
            w.signed(2, entries, prev=prev, issued_at="2026-10-20T00:00:00Z"),
            "REVOCATION_NOT_MONOTONE",
        ),
        "same-epoch-fork": (w.signed(1, []), "REVOCATION_FORK"),
    }[case]
    assert add(w, s, p, doc).code == code
    assert _latched(w, s, p, code)
    assert "REVOCATION_CONTRADICTORY" in decide(w, tmp_path, s, p).result.blocking_reasons


def test_M19_a_repeat_and_a_refused_document_leave_the_record_bytes_unchanged(w):
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    before = s.data[w.issuer]
    assert "REVOCATION_REPEAT" in add(w, s, p, first).notes
    wrong_key = w.signed(2, [], signer=w.evil, prev=proto.list_digest(first))
    assert add(w, s, p, wrong_key).code == "REVOCATION_AUTHORITY_MISMATCH"
    assert s.data[w.issuer] == before


def test_M17_an_issuer_must_publish_a_later_compromise_of_a_retired_key_clamped(w):
    """A boundary after the retirement would re-open nothing, but it is refused, so tooling must clamp."""
    s, p = setup(w)
    first = l1(w, [w.entry(w.old, "retired", R)])
    add(w, s, p, first)
    unclamped = w.signed(
        2, [w.entry(w.old, "compromised", "2026-10-15T00:00:00Z")], prev=proto.list_digest(first)
    )
    clamped = w.signed(2, [w.entry(w.old, "compromised", R)], prev=proto.list_digest(first))
    s2, p2 = setup(w)
    add(w, s2, p2, first)
    assert add(w, s, p, unclamped).code == "REVOCATION_NOT_MONOTONE"
    assert add(w, s2, p2, clamped).accepted


# ============================================================================ configuration, disclosure, feed


def test_G27_signer_asserted_time_cannot_be_combined_with_a_revocation_mode(w, tmp_path):
    s, p = setup(w)
    pol = policy(w, tmp_path, profile="development", historical_acceptance="signer-asserted")
    with pytest.raises(PolicyError, match="signer-asserted"):
        tg.verify_with_revocation(report(w), pol, ctx(w, s, p))


def test_G31_an_unknown_key_still_gets_the_disclosure(w, tmp_path):
    s, p = setup(w)
    store = w.store(w.new)
    d = decide(w, tmp_path, s, p, store=store)
    assert "ISSUER_UNKNOWN" in d.result.blocking_reasons
    assert d.revocation["revocation_evidence"] == "unproven"
    assert "cannot reliably detect" in d.revocation["limit"]


def test_D05_a_feed_can_be_polled_repeatedly_and_in_any_order(w):
    s, p = setup(w)
    stated = [dump(w.transition(w.auth2, w.auth3, from_gen=2)), dump(w.transition(w.rev, w.auth2))]
    by3 = w.signed(1, [], signer=w.auth3, generation=3)
    for _ in range(3):  # the distribution point serves everything, every time
        out = tg.ingest_feed(s, p, recoveries=[], transitions=stated, raw_list=dump(by3), trust_store=w.store(), now=NOW)
        assert out.accepted, out
    # with no list to decide the result, a transition already passed is not a refusal
    again = tg.ingest_feed(s, p, recoveries=[], transitions=stated, raw_list=None, trust_store=w.store(), now=NOW)
    assert again.accepted, again
    enrollment = record(s, p).state.enrollments[w.issuer]
    assert enrollment.generation == 3 and record(s, p).contradiction is None


def test_D07_a_list_from_a_generation_not_reached_yet_does_not_latch(w):
    s, p = setup(w)
    by2 = w.signed(1, [], signer=w.auth2, generation=2)
    out = tg.ingest_feed(s, p, recoveries=[], transitions=[], raw_list=dump(by2), trust_store=w.store(), now=NOW)
    assert out.code == "REVOCATION_AUTHORITY_MISMATCH" and record(s, p).contradiction is None


def test_D01_a_failed_fetch_through_the_wrapper_is_unproven_not_nothing_revoked(w, tmp_path):
    s, p = setup(w)
    d = decide(w, tmp_path, s, p, profile="confidential", mode=tg.MODE_ADVISORY)
    assert d.revocation["revocation_evidence"] == "unproven"
    assert "REVOCATION_DATA_ABSENT" in d.result.reasons


def test_E11_no_pin_and_no_record_is_not_first_use(w, tmp_path):
    s = tg.MemoryCasStore()
    context = tg.RevocationContext(tg.MODE_REQUIRED, s, {})
    assert tg.gate(context, w.issuer, NOW).code == "REVOCATION_NOT_ENROLLED"
    assert s.data == {}


def test_E16_advisory_with_no_baseline_says_it_has_no_mark(w):
    s = tg.MemoryCasStore()
    p = tg.Pin(w.issuer, w.rev.public_key_pem(), "enr-1")
    tg.enroll(s, p, now=NOW)
    out = add(w, s, p, l1(w))
    assert out.accepted and "REVOCATION_NO_HIGH_WATER_MARK" in out.notes
