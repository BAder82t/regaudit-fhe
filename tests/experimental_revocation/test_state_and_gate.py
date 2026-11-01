"""Monotonic state store and verification-time gate: rows S*, G* and R* of the test matrix.

Runs the reference model in ``trust_gate.py`` around the unchanged engine. A test double stands in for the
independent compare-and-set service (none exists); ``FileCasStore`` is a real single-host file store.
"""

from __future__ import annotations

import threading
from datetime import timedelta
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.reports import TimestampAuthority
from regaudit_fhe.verification import PolicyError, TimestampEvidence, VerificationPolicy, verify

from . import proto
from . import trust_gate as tg
from .gen_fixtures import ISSUED, NOW, UNTIL, World, dump, make_world

R = "2026-10-01T00:00:00Z"
FRESH_NOW = NOW  # 3 h after ISSUED
STALE_NOW = NOW + timedelta(hours=22)  # 25 h after ISSUED, before UNTIL


@pytest.fixture
def w() -> World:
    return make_world()


def pin(w: World, **kw) -> tg.Pin:
    args = {"baseline_epoch": 0, "enrollment_id": "enr-1", **kw}
    return tg.Pin(w.issuer, w.rev.public_key_pem(), recovery_pem=w.recovery.public_key_pem(), **args)


def setup(w: World, store: tg.CasStore | None = None, **kw) -> tuple[tg.CasStore, tg.Pin]:
    s = store if store is not None else tg.MemoryCasStore()
    p = pin(w, **kw)
    tg.enroll(s, p, w.store(), now=NOW - timedelta(days=30))
    return s, p


def ctx(w: World, s: tg.CasStore, p: tg.Pin, mode: str = tg.MODE_REQUIRED, **kw):
    return tg.RevocationContext(mode, s, {w.issuer: p}, **kw)


def add(w: World, s: tg.CasStore, p: tg.Pin, doc, now=NOW) -> tg.Ingested:
    return tg.ingest_list(s, p, dump(doc), w.store(w.old, w.new, w.third), now)


def l1(w: World, entries=None):
    return w.signed(1, entries or [])


def report(w: World, signer=None, audience=("reg",)):
    rep = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    return envelope_v2(
        "drift",
        rep,
        signer=signer or w.old,
        deployment_id="p",
        audience=list(audience),
        issued_at=NOW - timedelta(hours=1),
    )


def policy(w: World, tmp_path: Path, profile="high-assurance", now=NOW, store=None, **kw):
    args = {
        "trust_store": store if store is not None else w.store(w.old, w.new, w.third),
        "now": lambda: now,
        "profile": profile,
    }
    if profile != "development":
        args.update(
            max_age=timedelta(days=90),
            replay_mode="record",
            verifier_id="reg",
            replay_cache=SqliteReplayCache(tmp_path / f"r-{profile}.db"),
        )
    args.update(kw)
    return VerificationPolicy(**args)


def decide(w, tmp_path, s, p, now=NOW, profile="high-assurance", mode=tg.MODE_REQUIRED, **kw):
    pol = policy(w, tmp_path, profile=profile, now=now, **kw)
    return tg.verify_with_revocation(report(w), pol, ctx(w, s, p, mode))


# ============================================================================ gate: fail closed


def test_G01_fresh_list_active_key_accepted_with_disclosure(w, tmp_path):
    s, p = setup(w)
    assert add(w, s, p, l1(w)).accepted
    d = decide(w, tmp_path, s, p)
    assert d.result.accepted and d.result.trust_status == "TRUSTED"
    assert d.revocation["revocation_evidence"] == "verified-as-of-" + ISSUED
    assert d.revocation["state_store_scope"] == "INDEPENDENT_CAS"
    assert "cannot reliably detect" in d.revocation["limit"]
    assert d.result.policy_id == "regaudit-fhe/high-assurance+revocation-required/v1"


def test_G02_no_list_ever_accepted_fails_closed(w, tmp_path):
    s, p = setup(w)
    d = decide(w, tmp_path, s, p)
    assert not d.result.accepted and "REVOCATION_DATA_ABSENT" in d.result.blocking_reasons
    assert d.revocation["revocation_evidence"] == "unproven"
    assert "cannot reliably detect" in d.revocation["limit"]
    assert d.revocation["state_store_scope"] == "INDEPENDENT_CAS"


def test_G03_list_past_valid_until_fails_closed(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w))
    d = decide(w, tmp_path, s, p, now=proto.parse_rfc3339(UNTIL))
    assert d.result.blocking_reasons[-1] == "REVOCATION_DATA_STALE" and not d.result.accepted


def test_G03_a_short_validity_ends_before_the_evidence_age_does(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, w.signed(1, [], valid_until="2026-11-01T13:00:00Z"))
    assert tg.gate(ctx(w, s, p), w.issuer, NOW).ok
    later = proto.parse_rfc3339("2026-11-01T13:00:00Z")  # 4 h after issued_at, exactly at valid_until
    assert tg.gate(ctx(w, s, p), w.issuer, later).code == "REVOCATION_DATA_STALE"


def test_G04_list_older_than_the_evidence_age_fails_closed_even_inside_its_validity(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w))
    assert proto.parse_rfc3339(UNTIL) > STALE_NOW
    d = decide(w, tmp_path, s, p, now=STALE_NOW)
    assert "REVOCATION_DATA_STALE" in d.result.blocking_reasons and not d.result.accepted


def test_G05_contradiction_latches_until_recovery_and_only_a_signature_can_cause_it(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w))
    fork = w.signed(1, [w.entry(w.old, "retired", R)])
    assert add(w, s, p, fork).code == "REVOCATION_FORK"
    d = decide(w, tmp_path, s, p)
    assert "REVOCATION_CONTRADICTORY" in d.result.blocking_reasons and not d.result.accepted
    assert add(w, s, p, l1(w)).code == "REVOCATION_CONTRADICTORY"  # no further list while latched
    t = dump(w.transition(w.rev, w.auth2))
    assert tg.ingest_transition(s, p, t, w.store(), NOW).code == "REVOCATION_CONTRADICTORY"
    rec = dump(w.recovery_stmt(w.auth2))
    assert tg.ingest_recovery(s, p, rec, w.store(), NOW).accepted
    assert "REVOCATION_CONTRADICTORY" not in decide(w, tmp_path, s, p).result.blocking_reasons


def test_G06_a_replayed_older_list_refused_does_not_latch_and_needs_no_key(w, tmp_path):
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    add(w, s, p, w.signed(2, [], prev=proto.list_digest(first)))
    assert add(w, s, p, first).code == "REVOCATION_ROLLBACK"
    assert decide(w, tmp_path, s, p).result.accepted  # the state is ahead of the attacker


def test_G07_a_presented_rolled_back_list_refuses_that_verification(w, tmp_path):
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    add(w, s, p, w.signed(2, [], prev=proto.list_digest(first)))
    d = tg.verify_with_revocation(
        report(w), policy(w, tmp_path), ctx(w, s, p), presented=dump(first)
    )
    assert not d.result.accepted and "REVOCATION_ROLLBACK" in d.result.blocking_reasons


@pytest.mark.parametrize("code", ["down", "corrupt", "torn"])
def test_G08_unusable_state_fails_closed_never_as_empty(w, tmp_path, code):
    s, p = setup(w)
    add(w, s, p, l1(w))
    if code == "down":
        s.down = True
    elif code == "corrupt":
        s.data[w.issuer] = b"{"
    else:
        s.data[w.issuer] = s.data[w.issuer][:-20]
    d = decide(w, tmp_path, s, p)
    assert "REVOCATION_STATE_UNAVAILABLE" in d.result.blocking_reasons and not d.result.accepted
    assert "REVOCATION_STATE_UNAVAILABLE" in tg.INFRASTRUCTURE_CODES


def test_G09_issuer_not_enrolled_fails_closed(w, tmp_path):
    s = tg.MemoryCasStore()
    d = tg.verify_with_revocation(
        report(w), policy(w, tmp_path), tg.RevocationContext(tg.MODE_REQUIRED, s, {})
    )
    assert "REVOCATION_NOT_ENROLLED" in d.result.blocking_reasons and not d.result.accepted


def test_G10_a_gate_refusal_does_not_burn_the_replay_identifier(w, tmp_path):
    s, p = setup(w)
    env = report(w)
    pol = policy(w, tmp_path)
    assert not tg.verify_with_revocation(env, pol, ctx(w, s, p)).result.accepted
    add(w, s, p, l1(w))
    ok = tg.verify_with_revocation(env, pol, ctx(w, s, p)).result
    assert ok.accepted and ok.consumption == "RECORDED_LOCAL"


def test_G11_the_issuer_comes_from_the_trust_store_not_the_report(w, tmp_path):
    """Issuer B is fresh and issuer A is not. A report under A's key claiming issuer B gets A's gate."""
    other = make_world("globex")
    s = tg.MemoryCasStore()
    pa, pb = pin(w), tg.Pin("globex", other.rev.public_key_pem(), "enr-b", baseline_epoch=0)
    tg.enroll(s, pa, now=NOW)
    tg.enroll(s, pb, now=NOW)
    store = rf.TrustStore.from_dict(
        {
            "entries": {
                w.old.key_id: {
                    "issuer": w.issuer,
                    "public_key_pem": w.old.public_key_pem(),
                    "status": "active",
                },
                other.new.key_id + "-g": {
                    "issuer": "globex",
                    "public_key_pem": other.new.public_key_pem(),
                    "status": "active",
                },
            }
        }
    )
    assert tg.ingest_list(s, pb, dump(other.signed(1, [])), store, NOW).accepted
    forged = rf.Signer(
        issuer="globex",
        key_id=w.old.key_id,
        private_key=w.old.private_key,
        public_key=w.old.public_key,
    )
    d = tg.verify_with_revocation(
        report(w, signer=forged),
        policy(w, tmp_path, store=store),
        tg.RevocationContext(tg.MODE_REQUIRED, s, {w.issuer: pa, "globex": pb}),
    )
    assert "REVOCATION_DATA_ABSENT" in d.result.blocking_reasons


def test_G12_marks_from_a_compromised_authority_stop_counting_after_recovery(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w))
    rec = dump(w.recovery_stmt(w.auth2))
    assert tg.ingest_recovery(s, p, rec, w.store(), NOW).accepted
    d = decide(w, tmp_path, s, p)
    assert "REVOCATION_AUTHORITY_COMPROMISED" in d.result.blocking_reasons
    fresh = w.signed(2, [], signer=w.auth2, generation=2, prev=proto.list_digest(l1(w)))
    assert add(w, s, p, fresh).accepted
    assert decide(w, tmp_path, s, p).result.accepted


def test_G13_a_mark_taken_before_a_known_compromise_boundary_stays_usable(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w), now=proto.parse_rfc3339("2026-11-01T09:10:00Z"))  # issued 09:00, taken 09:10
    rec = dump(w.recovery_stmt(w.auth2, declares=[(w.fp(w.rev), "2026-11-01T09:30:00Z")]))
    assert tg.ingest_recovery(s, p, rec, w.store(), NOW).accepted
    assert decide(w, tmp_path, s, p).result.accepted


def test_A11_routine_rotation_keeps_the_mark_usable_until_it_lapses(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w))
    assert tg.ingest_transition(s, p, dump(w.transition(w.rev, w.auth2)), w.store(), NOW).accepted
    assert decide(w, tmp_path, s, p).result.accepted
    assert "REVOCATION_DATA_STALE" in decide(w, tmp_path, s, p, now=STALE_NOW).result.blocking_reasons


def test_A10_a_long_offline_verifier_fails_closed_until_a_ceremony(w, tmp_path):
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    much_later = NOW + timedelta(days=60)
    transition = dump(w.transition(w.rev, w.auth2))
    assert tg.ingest_transition(s, p, transition, w.store(), much_later).code == "REVOCATION_EXPIRED"
    fresh_until = "2027-02-01T00:00:00Z"
    by_new = w.signed(
        2,
        [],
        signer=w.auth2,
        generation=2,
        prev=proto.list_digest(first),
        issued_at="2026-12-31T00:00:00Z",
        valid_until=fresh_until,
    )
    assert add(w, s, p, by_new, now=much_later).code == "REVOCATION_AUTHORITY_MISMATCH"
    assert tg.gate(ctx(w, s, p), w.issuer, much_later).code == "REVOCATION_DATA_STALE"
    p2 = tg.Pin(
        w.issuer,
        w.auth2.public_key_pem(),
        "enr-2",
        recovery_pem=w.recovery.public_key_pem(),
        baseline_epoch=1,
        baseline_digest=proto.list_digest(first),
        authority_generation=2,
    )
    tg.rebaseline(s, p2, now=much_later)
    assert add(w, s, p2, by_new, now=much_later).accepted  # the current authority's list, unchanged


def test_E17_a_ceremony_states_the_position_so_old_statements_cannot_move_the_authority_back(w):
    s, p = setup(w)
    add(w, s, p, l1(w))
    statement = w.recovery_stmt(w.auth2)  # installed auth2 at generation 2, long ago
    old = dump(statement)
    assert tg.ingest_recovery(s, p, old, w.store(), NOW).accepted
    digest = proto.recovery_digest(statement)
    cases = [
        (0, None, "REVOCATION_TRANSITION_GAP"),  # record lost, statement unknown to the ceremony
        (1, None, "REVOCATION_FORK"),  # the ceremony knows the epoch only
        (1, digest, None),  # the ceremony knows the statement: a true repeat, and a strict no-op
    ]
    for number, (epoch, known, code) in enumerate(cases):
        del s.data[w.issuer]
        p2 = tg.Pin(
            w.issuer,
            w.auth3.public_key_pem(),
            f"enr-{number + 2}",
            recovery_pem=w.recovery.public_key_pem(),
            baseline_epoch=0,
            authority_generation=3,
            recovery_epoch=epoch,
            recovery_digest=known,
        )
        tg.rebaseline(s, p2, now=NOW, accept_loss=True)
        before = tg.load(s, p2)[0].state.enrollments[w.issuer].authority_fingerprint
        out = tg.ingest_recovery(s, p2, old, w.store(), NOW)
        assert out.code == code
        after = tg.load(s, p2)[0].state.enrollments[w.issuer]
        assert after.generation == 3 and after.authority_fingerprint == before


def test_G14_clock_behind_the_state_floor_fails_closed(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w))
    d = decide(w, tmp_path, s, p, now=NOW - timedelta(days=1))
    assert "REVOCATION_CLOCK_REGRESSION" in d.result.blocking_reasons


def test_G15_a_listed_key_is_refused_by_the_engine_on_the_overlay_and_the_file_is_untouched(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w, [w.entry(w.old, "compromised", None)]))
    store = w.store(w.old, w.new, w.third)
    d = decide(w, tmp_path, s, p, store=store)
    assert "KEY_COMPROMISED_NO_CHRONOLOGY" in d.result.blocking_reasons
    assert store.entry(w.old.key_id).status == "active"  # type: ignore[union-attr]


def test_G16_a_key_enrolled_after_the_list_still_gets_the_listed_state(w, tmp_path):
    s, p = setup(w)
    assert tg.ingest_list(
        s, p, dump(l1(w, [w.entry(w.old, "compromised", None)])), w.store(w.new), NOW
    ).accepted
    d = decide(w, tmp_path, s, p, store=w.store(w.old, w.new))
    assert "KEY_COMPROMISED_NO_CHRONOLOGY" in d.result.blocking_reasons


def test_G17_hand_loosening_the_local_file_does_not_undo_listed_state(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w, [w.entry(w.old, "retired", R)]))
    active = w.store(w.old)  # the operator edited the file back to active
    assert "KEY_RETIRED_NO_CHRONOLOGY" in decide(w, tmp_path, s, p, store=active).result.blocking_reasons


def test_G18_advisory_mode_tightens_but_does_not_fail_closed(w, tmp_path):
    s, p = setup(w)
    d = decide(w, tmp_path, s, p, profile="confidential", mode=tg.MODE_ADVISORY)
    assert d.result.accepted and "REVOCATION_DATA_ABSENT" in d.result.reasons
    assert d.revocation["revocation_evidence"] == "unproven"
    add(w, s, p, l1(w, [w.entry(w.old, "compromised", None)]))
    d = decide(w, tmp_path, s, p, profile="confidential", mode=tg.MODE_ADVISORY)
    assert not d.result.accepted and "KEY_COMPROMISED_NO_CHRONOLOGY" in d.result.blocking_reasons


def test_G19_off_is_exactly_the_engine(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w, [w.entry(w.old, "compromised", None)]))
    env = report(w)
    pol = policy(w, tmp_path, profile="development")
    d = tg.verify_with_revocation(env, pol, ctx(w, s, p, tg.MODE_OFF))
    assert d.revocation is None and d.result.to_dict() == verify(env, pol).to_dict()
    assert d.result.accepted and d.result.policy_id == "regaudit-fhe/development/v1"


@pytest.mark.parametrize(
    ("change", "text"),
    [
        ({"mode": tg.MODE_ADVISORY}, "no advisory"),
        ({"baseline": None}, "baseline"),
        ({"store": "bare"}, "REVOCATION_STORE_UNSUPPORTED"),
        ({"independent": True}, "independent"),
        ({"not_durable": True}, "durable"),
    ],
)
def test_G20_unsafe_configurations_are_refused_at_startup(w, tmp_path, change, text):
    s: tg.CasStore = tg.FileCasStore(tmp_path)
    if change.get("not_durable"):
        s.durable = False  # type: ignore[misc]
    p = tg.Pin(w.issuer, w.rev.public_key_pem(), "enr-1", baseline_epoch=change.get("baseline", 0))
    store = None
    if change.get("store") == "bare":
        store = rf.TrustStore.from_dict({w.old.key_id: w.old.public_key_pem()})
    context = tg.RevocationContext(
        change.get("mode", tg.MODE_REQUIRED),
        s,
        {w.issuer: p},
        require_independent_store=change.get("independent", False),
    )
    with pytest.raises(PolicyError, match=text):
        tg.verify_with_revocation(report(w), policy(w, tmp_path, store=store), context)


# ============================================================================ state store: crash


@pytest.mark.parametrize(
    ("point", "epoch_after"),
    [("before-rename", 1), ("after-rename", 2)],
)
def test_S01_crash_mid_update_leaves_either_the_old_or_the_new_record_whole(
    w, tmp_path, point, epoch_after
):
    fs = tg.FileCasStore(tmp_path)
    s, p = setup(w, fs)
    first = l1(w)
    add(w, s, p, first)
    second = w.signed(2, [], prev=proto.list_digest(first))
    fs.crash_at = point
    with pytest.raises(tg.SimulatedCrash):
        add(w, s, p, second)
    fs.crash_at = None
    rec, _ = tg.load(fs, p)  # a leftover temp file is ignored
    assert rec.state.get(w.issuer).epoch == epoch_after
    retry = add(w, s, p, second)  # re-delivery converges in both cases
    assert retry.accepted and tg.load(fs, p)[0].state.get(w.issuer).epoch == 2


def test_S02_torn_record_is_refused_and_recovered_only_by_a_ceremony(w, tmp_path):
    fs = tg.FileCasStore(tmp_path)
    s, p = setup(w, fs)
    add(w, s, p, l1(w))
    path = fs.path(w.issuer)
    path.write_bytes(path.read_bytes()[:40])
    assert add(w, s, p, l1(w)).code == "REVOCATION_STATE_UNAVAILABLE"
    assert tg.gate(ctx(w, s, p), w.issuer, NOW).code == "REVOCATION_STATE_UNAVAILABLE"
    p2 = pin(w, enrollment_id="enr-2", baseline_epoch=1, baseline_digest=proto.list_digest(l1(w)))
    tg.rebaseline(fs, p2, now=NOW, accept_loss=True)
    assert add(w, s, p2, l1(w)).accepted
    assert tg.gate(ctx(w, s, p2), w.issuer, NOW).ok


# ============================================================================ state store: lost, restored


def test_S03_lost_state_with_a_surviving_pin_fails_closed_as_lost(w, tmp_path):
    fs = tg.FileCasStore(tmp_path)
    s, p = setup(w, fs)
    add(w, s, p, l1(w))
    fs.path(w.issuer).unlink()
    assert tg.gate(ctx(w, s, p), w.issuer, NOW).code == "REVOCATION_STATE_LOST"
    assert add(w, s, p, l1(w)).code == "REVOCATION_STATE_LOST"
    d = decide(w, tmp_path, s, p)
    assert "REVOCATION_STATE_LOST" in d.result.blocking_reasons and not d.result.accepted


def test_S04_a_process_that_remembers_the_counter_detects_a_restore(w, tmp_path):
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    backup = s.data[w.issuer]
    add(w, s, p, w.signed(2, [], prev=proto.list_digest(first)))
    context = ctx(w, s, p)
    assert tg.gate(context, w.issuer, NOW).ok
    s.data[w.issuer] = backup
    assert tg.gate(context, w.issuer, NOW).code == "REVOCATION_STATE_ROLLBACK"


def test_S04_a_restore_that_only_removes_a_latch_is_detected(w, tmp_path):
    """Same epoch, generation and recovery epoch: only the write counter shows it."""
    s, p = setup(w)
    add(w, s, p, l1(w))
    backup = s.data[w.issuer]
    context = ctx(w, s, p)
    add(w, s, p, w.signed(1, [w.entry(w.old, "retired", R)]))  # a signed fork latches
    assert tg.gate(context, w.issuer, NOW).code == "REVOCATION_CONTRADICTORY"
    s.data[w.issuer] = backup
    assert tg.gate(context, w.issuer, NOW).code == "REVOCATION_STATE_ROLLBACK"


def test_S02_an_edited_record_that_is_still_valid_json_is_refused(w, tmp_path):
    """The digest catches accidental damage that still parses. It is not authentication."""
    import json

    s, p = setup(w)
    add(w, s, p, l1(w))
    doc = json.loads(s.data[w.issuer])
    doc["record"]["seq"] += 5
    s.data[w.issuer] = json.dumps(doc, sort_keys=True).encode()
    assert tg.gate(ctx(w, s, p), w.issuer, NOW).code == "REVOCATION_STATE_UNAVAILABLE"


def test_S05_HONEST_LIMIT_restore_is_not_detected_by_a_fresh_process_and_is_bounded_by_validity(w, tmp_path):
    """A restored local file plus a replayed list is accepted, for at most the replayed list's lifetime."""
    fs = tg.FileCasStore(tmp_path)
    s, p = setup(w, fs)
    first = l1(w)
    add(w, s, p, first)
    backup = fs.path(w.issuer).read_bytes()
    second = w.signed(2, [], prev=proto.list_digest(first))
    third = w.signed(3, [w.entry(w.old, "compromised", None)], prev=proto.list_digest(second))
    add(w, s, p, second)
    add(w, s, p, third)
    fs.path(w.issuer).write_bytes(backup)

    fresh = ctx(w, s, p)  # new process, no memory of the counter
    assert tg.gate(fresh, w.issuer, NOW).ok  # undetected
    assert add(w, s, p, second).accepted  # older authentic list accepted again
    assert decide(w, tmp_path, s, p).result.accepted  # the compromise of w.old has been forgotten
    assert not tg.gate(fresh, w.issuer, STALE_NOW).ok  # ... only until the evidence age runs out
    assert tg.gate(fresh, w.issuer, STALE_NOW).code == "REVOCATION_DATA_STALE"
    assert add(w, s, p, third).accepted  # the moment the newer list arrives the state recovers
    assert not decide(w, tmp_path, s, p).result.accepted


def test_S06_restore_ceremony_with_a_fresh_baseline_refuses_older_lists(w, tmp_path):
    fs = tg.FileCasStore(tmp_path)
    s, p = setup(w, fs)
    first = l1(w)
    add(w, s, p, first)
    backup = fs.path(w.issuer).read_bytes()
    second = w.signed(2, [], prev=proto.list_digest(first))
    add(w, s, p, second)
    fs.path(w.issuer).write_bytes(backup)
    p2 = pin(w, enrollment_id="enr-2", baseline_epoch=2, baseline_digest=proto.list_digest(second))
    tg.rebaseline(fs, p2, now=NOW)
    assert add(w, s, p2, first).code == "REVOCATION_ROLLBACK"
    assert add(w, s, p2, second).accepted


def test_S07_the_ceremony_keeps_key_actions_unless_the_operator_clears_them(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w, [w.entry(w.old, "compromised", None)]))
    kept = tg.rebaseline(s, pin(w, enrollment_id="enr-2"), now=NOW)
    assert w.fp(w.old) in kept.effective
    cleared = tg.rebaseline(s, pin(w, enrollment_id="enr-3"), now=NOW, clear_effective=True)
    assert cleared.effective == {}
    assert cleared.seq > kept.seq


def test_E06_a_second_enrollment_needs_the_ceremony(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w))
    with pytest.raises(ValueError, match="already enrolled"):
        tg.enroll(s, pin(w, enrollment_id="enr-2"), now=NOW)
    assert tg.gate(ctx(w, s, p), w.issuer, NOW).ok


def test_S08_a_record_from_another_enrollment_is_refused(w, tmp_path):
    s, _ = setup(w)
    other = pin(w, enrollment_id="enr-other")
    assert tg.gate(ctx(w, s, other), w.issuer, NOW).code == "REVOCATION_STATE_UNAVAILABLE"


def test_E08_first_list_below_the_enrollment_baseline_is_a_rollback(w, tmp_path):
    first = l1(w)
    second = w.signed(2, [], prev=proto.list_digest(first))
    s, p = setup(w, baseline_epoch=2, baseline_digest=proto.list_digest(second))
    assert add(w, s, p, first).code == "REVOCATION_ROLLBACK"
    fork = w.signed(2, [w.entry(w.old, "retired", R)], prev=proto.list_digest(first))
    assert add(w, s, p, fork).code == "REVOCATION_FORK"


def test_E10_first_list_at_the_baseline_is_accepted(w, tmp_path):
    first = l1(w)
    second = w.signed(2, [], prev=proto.list_digest(first))
    s, p = setup(w, baseline_epoch=2, baseline_digest=proto.list_digest(second))
    assert add(w, s, p, second).accepted


# ============================================================================ state store: concurrent


def test_S09_lost_race_re_verifies_and_never_lowers_the_mark(w, tmp_path):
    """Writer A verified against epoch 1 and is about to write epoch 2; writer B gets epoch 3 in first."""
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    second = w.signed(2, [], prev=proto.list_digest(first))
    third = w.signed(3, [], prev=proto.list_digest(second))
    real_cas = s.cas
    fired = []

    def racing_cas(issuer, expected, new):
        if not fired:
            fired.append(1)
            assert add(w, s, p, third).accepted
        return real_cas(issuer, expected, new)

    s.cas = racing_cas  # type: ignore[method-assign]
    assert add(w, s, p, second).code == "REVOCATION_ROLLBACK"
    assert tg.load(s, p)[0].state.get(w.issuer).epoch == 3


def test_S10_endless_contention_is_a_refusal_not_a_blind_write(w, tmp_path):
    s, p = setup(w)
    s.cas = lambda *a: False  # type: ignore[method-assign]
    assert add(w, s, p, l1(w)).code == "REVOCATION_STATE_CONFLICT"


def test_S11_real_threads_on_the_file_store_end_at_the_highest_epoch(w, tmp_path):
    fs = tg.FileCasStore(tmp_path)
    _, p = setup(w, fs)
    docs = [l1(w)]
    for epoch in range(2, 9):
        docs.append(w.signed(epoch, [], prev=proto.list_digest(docs[-1])))
    outcomes: list[tg.Ingested] = []
    barrier = threading.Barrier(len(docs))

    def worker(doc):
        barrier.wait()
        outcomes.append(add(w, tg.FileCasStore(tmp_path), p, doc))

    threads = [threading.Thread(target=worker, args=(d,)) for d in reversed(docs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    rec, _ = tg.load(fs, p)
    mark = rec.state.get(w.issuer)
    # every list at or above the final mark's predecessor raced; the top list always wins
    assert mark.epoch == 8, outcomes
    assert {o.code for o in outcomes} <= {None, "REVOCATION_ROLLBACK", "REVOCATION_STATE_CONFLICT"}


def test_S12_two_verifiers_without_a_shared_store_can_disagree_and_nothing_claims_otherwise(w, tmp_path):
    a, pa = setup(w)
    b, pb = setup(w)
    first = l1(w)
    second = w.signed(2, [w.entry(w.old, "compromised", None)], prev=proto.list_digest(first))
    add(w, a, pa, first)
    add(w, a, pa, second)
    add(w, b, pb, first)
    assert not decide(w, tmp_path, a, pa).result.accepted
    b_result = decide(w, tmp_path, b, pb, replay_cache=SqliteReplayCache(tmp_path / "b.db"))
    assert b_result.result.accepted
    assert b_result.revocation["state_seq"] != tg.load(a, pa)[0].seq


def test_S13_two_verifiers_sharing_one_store_see_one_mark(w, tmp_path):
    s, p = setup(w)
    first = l1(w)
    add(w, s, p, first)
    c1, c2 = ctx(w, s, p), ctx(w, s, p)
    assert tg.gate(c1, w.issuer, NOW).evidence["epoch"] == 1
    add(w, s, p, w.signed(2, [], prev=proto.list_digest(first)))
    assert tg.gate(c2, w.issuer, NOW).evidence["epoch"] == 2


def test_S14_report_verification_never_writes_the_state(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w))
    before = s.data[w.issuer]
    assert decide(w, tmp_path, s, p).result.accepted
    assert s.data[w.issuer] == before


# ============================================================================ rebase and recovery through the store


def test_R01_rebase_lowers_the_mark_but_keeps_every_tightening(w, tmp_path):
    s, p = setup(w)
    good = l1(w)
    add(w, s, p, good)
    thief = w.signed(1000, [w.entry(w.third, "compromised", None)], prev="c" * 64)
    assert add(w, s, p, thief).accepted
    rec = w.recovery_stmt(w.auth2, rebase={"epoch": 1, "list_digest": proto.list_digest(good)})
    assert tg.ingest_recovery(s, p, dump(rec), w.store(), NOW).accepted
    after, _ = tg.load(s, p)
    assert after.state.get(w.issuer).epoch == 1
    assert w.fp(w.third) in after.effective  # denial of service persists until an operator ceremony


def test_R02_replaying_recovery_through_the_store_writes_nothing(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w))
    rec = dump(w.recovery_stmt(w.auth2, rebase={"epoch": 1, "list_digest": proto.list_digest(l1(w))}))
    tg.ingest_recovery(s, p, rec, w.store(), NOW)
    before = s.data[w.issuer]
    out = tg.ingest_recovery(s, p, rec, w.store(), NOW)
    assert out.accepted and "REVOCATION_REPEAT" in out.notes and s.data[w.issuer] == before


def test_R03_join_is_the_same_as_applying_lists_one_after_the_other(w):
    actions = [
        w.entry(w.old, "retired", "2026-10-05T00:00:00Z"),
        w.entry(w.old, "replaced", "2026-10-01T00:00:00Z", w.new),
        w.entry(w.old, "compromised", "2026-10-03T00:00:00Z"),
        w.entry(w.old, "compromised", "2026-09-01T00:00:00Z"),
        w.entry(w.old, "compromised", None),
    ]
    import itertools

    for pair in itertools.permutations(actions, 2):
        stepped = w.store(w.old)
        for a in pair:
            stepped = proto.apply_entries(stepped, [a])
        joined = proto.apply_entries(w.store(w.old), [tg.join_action(pair[0], pair[1])])
        s, j = stepped.entries[w.old.key_id], joined.entries[w.old.key_id]
        assert (s.status, s.retired_at, s.compromised_from) == (
            j.status,
            j.retired_at,
            j.compromised_from,
        ), pair


# ============================================================================ historical verification


def _tsa(gen):
    def verifier(digest, token):
        return TimestampEvidence(gen, timedelta(0)) if token == b"ok:" + digest else None

    return verifier


def _stamped(w, at):
    env = report(w)
    return env.with_timestamp(issuer="t", token=b"ok:" + env.sealed_digest(), issued_at=at)


@pytest.mark.parametrize(
    ("status", "boundary", "ts_at", "expected"),
    [
        ("retired", R, "2026-09-01T00:00:00+00:00", "TRUST_STORE_FRESHNESS_UNPROVEN"),
        ("retired", R, "2026-10-15T00:00:00+00:00", "SIGNED_AFTER_RETIREMENT"),
        ("retired", R, None, "KEY_RETIRED_NO_CHRONOLOGY"),
        ("compromised", R, "2026-09-01T00:00:00+00:00", "TRUST_STORE_FRESHNESS_UNPROVEN"),
        ("compromised", R, "2026-10-15T00:00:00+00:00", "SIGNED_AFTER_COMPROMISE"),
        ("compromised", R, None, "KEY_COMPROMISED_NO_CHRONOLOGY"),
        ("compromised", None, "2026-09-01T00:00:00+00:00", "KEY_COMPROMISED_NO_CHRONOLOGY"),
    ],
)
def test_H01_required_mode_never_accepts_history_from_a_list(w, tmp_path, status, boundary, ts_at, expected):
    s, p = setup(w)
    add(w, s, p, l1(w, [w.entry(w.old, status, boundary)]))
    kw = {}
    env = report(w)
    if ts_at is not None:
        when = proto.parse_rfc3339(ts_at)
        env = _stamped(w, when)
        kw["timestamp_verifier"] = _tsa(when)
    d = tg.verify_with_revocation(env, policy(w, tmp_path, **kw), ctx(w, s, p))
    assert not d.result.accepted and expected in d.result.blocking_reasons


def test_H02_claimed_issued_at_alone_never_rescues_a_retired_key(w, tmp_path):
    """The report claims a time long before the retirement; nothing authenticated says so."""
    s, p = setup(w)
    add(w, s, p, l1(w, [w.entry(w.old, "retired", R)]))
    rep = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    env = envelope_v2(
        "drift",
        rep,
        signer=w.old,
        deployment_id="p",
        audience=["reg"],
        issued_at=proto.parse_rfc3339("2026-09-01T00:00:00Z"),
    )
    for prof in ("confidential", "high-assurance"):
        d = tg.verify_with_revocation(env, policy(w, tmp_path, profile=prof), ctx(w, s, p))
        assert "KEY_RETIRED_NO_CHRONOLOGY" in d.result.blocking_reasons and not d.result.accepted


def test_H03_a_timestamp_without_a_pinned_verifier_is_not_chronology(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w, [w.entry(w.old, "retired", R)]))
    env = _stamped(w, proto.parse_rfc3339("2026-09-01T00:00:00Z"))
    d = tg.verify_with_revocation(env, policy(w, tmp_path), ctx(w, s, p))
    assert d.result.timestamp_status == "UNVERIFIED"
    assert "KEY_RETIRED_NO_CHRONOLOGY" in d.result.blocking_reasons


def test_H04_no_trust_history_is_derived_for_high_assurance_even_when_a_caller_supplies_one(w, tmp_path):
    from regaudit_fhe.verification import TrustHistory

    s, p = setup(w)
    add(w, s, p, l1(w, [w.entry(w.old, "retired", R)]))
    when = proto.parse_rfc3339("2026-09-01T00:00:00Z")
    pol = policy(
        w,
        tmp_path,
        timestamp_verifier=_tsa(when),
        trust_history=TrustHistory(as_of=NOW, authenticated=True),
    )
    d = tg.verify_with_revocation(_stamped(w, when), pol, ctx(w, s, p))
    assert "TRUST_STORE_FRESHNESS_UNPROVEN" in d.result.blocking_reasons


def test_G25_unreachable_state_under_advisory_runs_the_engine_on_the_local_store(w, tmp_path):
    s, p = setup(w)
    add(w, s, p, l1(w, [w.entry(w.old, "compromised", None)]))
    s.down = True
    d = decide(w, tmp_path, s, p, profile="confidential", mode=tg.MODE_ADVISORY)
    assert d.result.accepted and "REVOCATION_STATE_UNAVAILABLE" in d.result.reasons
    assert "REVOCATION_STATE_UNAVAILABLE" not in d.result.blocking_reasons
    assert d.revocation["revocation_evidence"] == "unproven"


def test_H08_a_report_v1_timestamp_block_is_never_chronology(w):
    """A verifier that would accept any token still gets nothing: a v1 token covers the body only."""
    rep = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    tsa = TimestampAuthority(issuer="t", sign_callable=lambda body: b"token")
    env = rf.envelope("drift", rep, signer=w.old, timestamp_authority=tsa)
    assert env.timestamp is not None
    entry = w.store(w.old).entries[w.old.key_id]
    assert entry.status == "active"
    store = rf.TrustStore.from_dict(
        {
            "entries": {
                w.old.key_id: {
                    "issuer": w.issuer,
                    "public_key_pem": w.old.public_key_pem(),
                    "status": "retired",
                    "retired_at": "2099-01-01T00:00:00Z",
                }
            }
        }
    )
    pol = VerificationPolicy(
        trust_store=store,
        now=lambda: NOW,
        timestamp_verifier=lambda digest, token: TimestampEvidence(NOW - timedelta(days=1)),
    )
    res = verify(env, pol)
    assert res.timestamp_status == "UNVERIFIED" and res.signed_not_after is None
    assert "KEY_RETIRED_NO_CHRONOLOGY" in res.blocking_reasons


def test_G21_an_old_signature_by_a_listed_compromised_key_is_refused_when_newly_presented(w, tmp_path):
    """Report signature valid and issuer once trusted: origin holds, current authorization does not."""
    env = report(w)
    pol = policy(w, tmp_path, replay_mode="check")
    assert verify(env, pol).accepted
    s, p = setup(w)
    add(w, s, p, l1(w, [w.entry(w.old, "compromised", None)]))
    d = tg.verify_with_revocation(env, pol, ctx(w, s, p))
    assert d.result.integrity_valid and not d.result.accepted


def test_list_digest_helper_is_stable_for_the_contradiction_record(w):
    s, p = setup(w)
    add(w, s, p, l1(w))
    fork = w.signed(1, [w.entry(w.old, "retired", R)])
    add(w, s, p, fork)
    assert tg.load(s, p)[0].contradiction == {
        "code": "REVOCATION_FORK",
        "digest": proto.list_digest(fork),
        "mark_digest": proto.list_digest(l1(w)),
    }
