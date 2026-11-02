"""Sequences from an independent adversarial read of the implementation. Each was first run as a probe against it.

Real code on the shipped file store unless a test says it uses the private algorithm path.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe import _revocation as rv
from regaudit_fhe import _revocation_gate as gate
from regaudit_fhe import _revocation_state as st
from regaudit_fhe import _revocation_tooling as tooling
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.trust import KeyEntry, TrustStore
from regaudit_fhe.verification import PolicyError, VerificationPolicy, verify

from .experimental_revocation.gen_fixtures import NOW, dump, make_world
from .test_revocation_tooling_and_cli import cli as run_cli
from .test_revocation_tooling_and_cli import ingest as cli_ingest
from .test_revocation_tooling_and_cli import op, sign_list  # noqa: F401

W = make_world()
STORE = W.store(W.old, W.new, W.third)
R = "2026-10-01T00:00:00Z"
K1, K2, K3, K4 = W.rev, W.auth2, W.auth3, W.evil


@pytest.fixture
def fs(tmp_path: Path) -> st.FileStateStore:
    d = tmp_path / "state"
    d.mkdir(mode=0o700)
    return st.FileStateStore(d)


def pin(**kw) -> st.Pin:
    args = {
        "enrollment_id": "enr-1",
        "recovery_pem": W.recovery.public_key_pem(),
        "baseline_epoch": 0,
    }
    args.update(kw)
    return st.Pin(W.issuer, K1.public_key_pem(), **args)


def enrolled(fs) -> st.Pin:
    p = pin()
    st.enroll(fs, p, STORE, now=NOW - timedelta(days=30))
    return p


def report(signer=None, audience=("reg",), issued_at=None):
    return envelope_v2(
        "drift",
        rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])),
        signer=signer or W.old,
        deployment_id="p",
        audience=list(audience),
        issued_at=issued_at or NOW - timedelta(hours=1),
    )


def policy(tmp_path: Path, store=STORE, now=NOW, **kw):
    args = {
        "profile": "confidential",
        "trust_store": store,
        "now": lambda: now,
        "max_age": timedelta(days=90),
        "replay_mode": "check",
        "verifier_id": "reg",
        "replay_cache": SqliteReplayCache(tmp_path / "replay.db"),
    }
    args.update(kw)
    return VerificationPolicy(**args)


def decide(fs, p, tmp_path, now=NOW, ctx=None, **kw):
    context = ctx or gate.RevocationContext(gate.MODE_REQUIRED, fs, {W.issuer: p})
    return gate.verify_with_revocation(report(), policy(tmp_path, now=now, **kw), context)


def tr(frm, to, frm_gen):
    return dump(W.transition(frm, to, from_gen=frm_gen))


def enr(fs, p):
    return st.load(fs, p)[0].state.enrollments[W.issuer]


def _rotated_after_recovery(fs):
    """K1 to K2 (rotation). R1 declares K1 and installs K3. K3 to K4 (rotation, after recovery)."""
    p = enrolled(fs)
    assert st.ingest_transition(fs, p, tr(K1, K2, 1), STORE, NOW).accepted
    r1 = dump(W.recovery_stmt(K3, new_gen=3, epoch=1))
    assert st.ingest_recovery(fs, p, r1, STORE, NOW).accepted
    assert st.ingest_transition(fs, p, tr(K3, K4, 3), STORE, NOW).accepted
    return p, r1


def test_replaying_an_expired_public_recovery_does_not_condemn_the_current_authority(fs):
    p, r1 = _rotated_after_recovery(fs)
    before = fs.path(W.issuer).read_bytes()
    out = st.ingest_recovery(fs, p, r1, STORE, NOW + timedelta(days=60))
    assert out.code == "REVOCATION_EXPIRED"
    assert fs.path(W.issuer).read_bytes() == before
    assert W.fp(K4) not in enr(fs, p).compromised


def test_replaying_an_older_recovery_does_not_condemn_a_key_rotated_to_since(fs):
    p, r1 = _rotated_after_recovery(fs)
    r2 = dump(W.recovery_stmt(W.other_rev, new_gen=9, epoch=2, declares=[(W.fp(K4), None)]))
    assert st.ingest_recovery(fs, p, r2, STORE, NOW).accepted
    before = fs.path(W.issuer).read_bytes()
    assert st.ingest_recovery(fs, p, r1, STORE, NOW).code == "REVOCATION_RECOVERY_REPLAY"
    assert fs.path(W.issuer).read_bytes() == before
    assert W.fp(W.other_rev) not in enr(fs, p).compromised


def test_an_older_statement_lands_its_declaration_and_voids_nothing(fs):
    """Statement 3 installs X, X rotates to K2, then statement 2 arrives late and declares X. K2 stays."""
    p = enrolled(fs)
    x = W.other_rev
    assert st.ingest_recovery(
        fs, p, dump(W.recovery_stmt(x, new_gen=5, epoch=3)), STORE, NOW
    ).accepted
    assert st.ingest_transition(fs, p, tr(x, K2, 5), STORE, NOW).accepted
    late = dump(W.recovery_stmt(K3, new_gen=9, epoch=2, declares=[(W.fp(x), None)]))
    assert st.ingest_recovery(fs, p, late, STORE, NOW).code == "REVOCATION_RECOVERY_REPLAY"
    state = enr(fs, p)
    assert W.fp(x) in state.compromised and W.fp(K2) not in state.compromised
    assert state.authority_fingerprint == W.fp(K2)


def test_a_legitimate_recovery_does_not_condemn_a_key_nobody_declared(fs):
    """R2 declares only K1 again. K4 came from a rotation by K3, which R1 installed honestly."""
    p, _ = _rotated_after_recovery(fs)
    r2 = dump(W.recovery_stmt(W.other_rev, new_gen=9, epoch=2))
    out = st.ingest_recovery(fs, p, r2, STORE, NOW)
    assert out.accepted
    state = enr(fs, p)
    assert W.fp(K4) not in state.compromised and W.fp(K4) in state.superseded


def test_a_mark_from_a_rotated_key_survives_a_later_recovery_that_did_not_declare_it(fs, tmp_path):
    p, _ = _rotated_after_recovery(fs)
    assert st.ingest_list(
        fs, p, dump(W.signed(1, [], signer=K4, generation=4)), STORE, NOW
    ).accepted
    assert st.ingest_recovery(
        fs, p, dump(W.recovery_stmt(W.other_rev, new_gen=9, epoch=2)), STORE, NOW
    ).accepted
    assert decide(fs, p, tmp_path).result.accepted  # usable until its deadline


def test_an_honest_feed_poll_carrying_old_recoveries_still_reaches_the_list(fs):
    p, r1 = _rotated_after_recovery(fs)
    r2 = dump(W.recovery_stmt(W.other_rev, new_gen=9, epoch=2))
    honest = dump(W.signed(1, [], signer=W.other_rev, generation=9))
    for _ in range(2):
        out = st.ingest_feed(
            fs, p, recoveries=[r1, r2], transitions=[tr(K1, K2, 1), tr(K3, K4, 3)], raw_list=honest,
            trust_store=STORE, now=NOW,
        )  # fmt: skip
        assert out.accepted, out
    assert st.load(fs, p)[0].state.get(W.issuer).epoch == 1


def test_a_junk_transition_in_a_feed_does_not_stop_the_poll(fs):
    p = enrolled(fs)
    honest = dump(W.signed(1, []))
    junk = dump(W.transition(W.evil, K2, from_gen=1))
    out = st.ingest_feed(
        fs, p, recoveries=[], transitions=[junk], raw_list=honest, trust_store=STORE, now=NOW
    )
    assert out.accepted, out


@pytest.mark.parametrize("bad", [5, None, ["x"], {"a": 1}])
def test_non_text_documents_are_refused_not_raised(fs, bad):
    p = enrolled(fs)
    assert st.ingest_list(fs, p, bad, STORE, NOW).code == "REVOCATION_MALFORMED"
    assert st.ingest_transition(fs, p, bad, STORE, NOW).code == "REVOCATION_MALFORMED"
    assert st.ingest_recovery(fs, p, bad, STORE, NOW).code == "REVOCATION_MALFORMED"
    out = st.ingest_feed(
        fs, p, recoveries=[bad], transitions=[], raw_list=None, trust_store=STORE, now=NOW
    )
    assert out.code == "REVOCATION_MALFORMED"


def test_a_fingerprint_with_a_trailing_newline_is_malformed(fs):
    p = enrolled(fs)
    entry = {**W.entry(W.old, "compromised", None), "key_fingerprint": W.fp(W.old) + "\n"}
    assert (
        st.ingest_list(fs, p, dump(W.signed(1, [entry])), STORE, NOW).code == "REVOCATION_MALFORMED"
    )
    with pytest.raises(tooling.ActionRefused):
        tooling.next_list(
            issuer=W.issuer, authority=K1, generation=1, previous=None,
            actions=[tooling.KeyAction("k", W.fp(W.old) + "\n", "compromised", None)],
            now=NOW, valid_for=timedelta(days=1),
        )  # fmt: skip


def test_an_explicit_null_successor_is_malformed(fs):
    p = enrolled(fs)
    entry = {**W.entry(W.old, "retired", R), "successor": None}
    assert (
        st.ingest_list(fs, p, dump(W.signed(1, [entry])), STORE, NOW).code == "REVOCATION_MALFORMED"
    )


def test_a_time_at_the_end_of_the_range_is_malformed_not_an_overflow(fs):
    p = enrolled(fs)
    doc = W.signed(1, [], issued_at="9999-12-31T23:59:00Z", valid_until="9999-12-31T23:59:30Z")
    assert st.ingest_list(fs, p, dump(doc), STORE, NOW).code == "REVOCATION_MALFORMED"
    rec = W.recovery_stmt(
        K2,
        issued_at="9999-12-31T23:59:00Z",
        valid_until="9999-12-31T23:59:30Z",
        declares=[(W.fp(K1), "2026-01-01T00:00:00Z")],
    )
    assert st.ingest_recovery(fs, p, dump(rec), STORE, NOW).code == "REVOCATION_MALFORMED"


# ------------------------------------------------------------------ configuration on the public path


def test_an_entry_without_an_issuer_is_refused_not_waved_through(fs, tmp_path):
    p = enrolled(fs)
    pem = W.old.public_key_pem()
    store = TrustStore(
        keys={W.old.key_id: pem}, entries={W.old.key_id: KeyEntry(W.old.key_id, pem, issuer=None)}
    )
    ctx = gate.RevocationContext(gate.MODE_REQUIRED, fs, {W.issuer: p})
    with pytest.raises(PolicyError, match="issuer"):
        gate.verify_with_revocation(report(), policy(tmp_path, store=store), ctx)


def test_mutating_the_context_cannot_widen_the_evidence_age_or_invent_a_mode(fs, tmp_path):
    p = enrolled(fs)
    ctx = gate.RevocationContext(gate.MODE_REQUIRED, fs, {W.issuer: p})
    ctx.max_evidence_age = timedelta(days=3650)
    with pytest.raises(PolicyError, match="max_evidence_age"):
        gate.verify_with_revocation(report(), policy(tmp_path), ctx)
    ctx = gate.RevocationContext(gate.MODE_REQUIRED, fs, {W.issuer: p})
    ctx.mode = "weird"
    with pytest.raises(PolicyError, match="mode"):
        gate.verify_with_revocation(report(), policy(tmp_path), ctx)


class _Sneaky(str):
    __slots__ = ()

    def __eq__(self, other):
        return False

    def __ne__(self, other):
        return True

    __hash__ = str.__hash__


def test_a_str_subclass_cannot_slip_past_the_high_assurance_refusal(fs, tmp_path):
    p = enrolled(fs)
    pol = policy(tmp_path)
    object.__setattr__(pol, "profile", _Sneaky("high-assurance"))
    ctx = gate.RevocationContext(gate.MODE_REQUIRED, fs, {W.issuer: p})
    with pytest.raises(PolicyError):
        gate.verify_with_revocation(report(), pol, ctx)


def test_the_private_algorithm_path_also_refuses_high_assurance_without_its_explicit_test_flag(
    fs, tmp_path
):
    p = enrolled(fs)
    pol = policy(tmp_path, profile="high-assurance")
    ctx = gate.RevocationContext(gate.MODE_REQUIRED, fs, {W.issuer: p})
    with pytest.raises(PolicyError, match="REVOCATION_HIGH_ASSURANCE_UNAVAILABLE"):
        gate._run_gate(report(), pol, ctx)


# ------------------------------------------------------------------ ceremonies


def test_a_ceremony_below_the_mark_needs_the_loss_stated(fs):
    p = enrolled(fs)
    first = W.signed(1, [])
    assert st.ingest_list(fs, p, dump(first), STORE, NOW).accepted
    assert st.ingest_list(
        fs, p, dump(W.signed(2, [], prev=rv.list_digest(first))), STORE, NOW
    ).accepted
    low = pin(enrollment_id="enr-2")
    with pytest.raises(ValueError, match="below"):
        st.rebaseline(fs, low, now=NOW)
    st.rebaseline(fs, low, now=NOW, accept_loss=True)


def test_a_ceremony_refuses_a_superseded_key(fs):
    p = enrolled(fs)
    assert st.ingest_transition(fs, p, tr(K1, K2, 1), STORE, NOW).accepted
    back = pin(enrollment_id="enr-2", authority_generation=2)
    with pytest.raises(ValueError, match="superseded"):
        st.rebaseline(fs, back, now=NOW)


# ------------------------------------------------------------------ record and pin hardening


def _rewrite(fs, mutate):
    import hashlib

    from regaudit_fhe.canonical import canonical_bytes

    path = fs.path(W.issuer)
    doc = json.loads(path.read_bytes())
    mutate(doc["record"])
    doc["digest"] = hashlib.sha256(st.RECORD_DOMAIN + canonical_bytes(doc["record"])).hexdigest()
    path.write_text(json.dumps(doc))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(clock_floor="nope"),
        lambda r: r.update(seq="many"),
        lambda r: r.update(effective={"a": 5}),
        lambda r: r.update(effective={"a": {"status": "weird"}}),
        lambda r: r.update(policy_floor={"mode": "weird", "max_evidence_age_us": 5}),
        lambda r: r.update(policy_floor=7),
        lambda r: r.update(contradiction=[1]),
        lambda r: r.update(adjudicated="abc"),
        lambda r: r["marks"][W.issuer].update(issued_at=5),
        lambda r: r["enrollments"][W.issuer].update(compromised={"a": 5}),
        lambda r: r["enrollments"][W.issuer].update(authority_pem=5),
    ],
)
def test_a_well_digested_record_with_wrong_types_is_unavailable_not_a_traceback(
    fs, tmp_path, mutate
):
    p = enrolled(fs)
    assert st.ingest_list(fs, p, dump(W.signed(1, [])), STORE, NOW).accepted
    _rewrite(fs, mutate)
    d = decide(fs, p, tmp_path)
    assert "REVOCATION_STATE_UNAVAILABLE" in d.result.blocking_reasons
    assert st.ingest_list(fs, p, dump(W.signed(2, [], prev="a" * 64)), STORE, NOW).code == (
        "REVOCATION_STATE_UNAVAILABLE"
    )


def test_a_group_writable_record_is_refused(fs, tmp_path):
    p = enrolled(fs)
    os.chmod(fs.path(W.issuer), 0o666)  # noqa: S103 - the point of the test
    d = decide(fs, p, tmp_path)
    assert "REVOCATION_STATE_UNAVAILABLE" in d.result.blocking_reasons


@pytest.mark.parametrize("kind", ["store", "pins"])
def test_a_fifo_is_refused_without_hanging(fs, tmp_path, kind):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    if kind == "pins":
        with pytest.raises(st.PinStoreError):
            st.load_pins(fifo)
    else:
        p = enrolled(fs)
        path = fs.path(W.issuer)
        path.unlink()
        os.mkfifo(path)
        assert st.ingest_list(fs, p, dump(W.signed(1, [])), STORE, NOW).code == (
            "REVOCATION_STATE_UNAVAILABLE"
        )


@pytest.mark.parametrize(
    "bad",
    [
        {"authority_pem": 5},
        {"issuer": ""},
        {"enrollment_id": ""},
        {"authority_generation": 0},
        {"recovery_digest": "zz"},
        {"baseline_epoch": 0, "baseline_digest": "a" * 64},
        {"baseline_epoch": 2, "baseline_digest": None},
    ],
)
def test_a_bad_pin_is_never_written_and_never_loads(tmp_path, bad):
    good = pin().to_dict()
    path = tmp_path / "pins.json"
    with pytest.raises(st.PinStoreError):
        st.save_pin(path, st.Pin(**{**good, **bad}))
    assert not path.exists()
    path.write_text(json.dumps({"pins": {str(good["issuer"]): {**good, **bad}}}))
    path.chmod(0o600)
    with pytest.raises(st.PinStoreError):
        st.load_pins(path)


# ------------------------------------------------------------------ tooling cannot wedge a publisher


def _next(previous, actions, **kw):
    args = {
        "issuer": W.issuer,
        "authority": K1,
        "generation": 1,
        "previous": previous,
        "actions": actions,
        "now": NOW,
        "valid_for": timedelta(days=1),
    }
    args.update(kw)
    return tooling.next_list(**args)


def test_a_successor_cycle_is_refused_before_signing():
    a = tooling.KeyAction(W.old.key_id, W.fp(W.old), "replaced", R, (W.new.key_id, W.fp(W.new)))
    b = tooling.KeyAction(W.new.key_id, W.fp(W.new), "replaced", R, (W.old.key_id, W.fp(W.old)))
    with pytest.raises(tooling.ActionRefused, match="cycle"):
        _next(None, [a, b])


def test_a_mistyped_fingerprint_is_refused_with_an_inventory():
    typo = tooling.KeyAction(W.old.key_id, "a" * 64, "compromised", None)
    with pytest.raises(tooling.ActionRefused, match="KEY_MISMATCH"):
        _next(None, [typo], trust_store=STORE)


def test_a_key_outside_the_inventory_needs_saying_so():
    unknown = tooling.KeyAction("not-enrolled", "b" * 64, "compromised", None)
    with pytest.raises(tooling.ActionRefused, match="inventory"):
        _next(None, [unknown], trust_store=STORE)
    assert _next(None, [unknown], trust_store=STORE, allow_unknown_keys=True).document


def test_another_issuers_key_is_refused():
    foreign = TrustStore.from_dict(
        {
            "entries": {
                W.old.key_id: {
                    "issuer": "globex",
                    "public_key_pem": W.old.public_key_pem(),
                    "status": "active",
                }
            }
        }
    )
    action = tooling.KeyAction(W.old.key_id, W.fp(W.old), "compromised", None)
    with pytest.raises(tooling.ActionRefused, match="ISSUER_SCOPE"):
        _next(None, [action], trust_store=foreign)


def test_an_oversized_list_is_refused_before_signing():
    actions = [
        tooling.KeyAction(f"k{'x' * 250}{i:05d}", f"{i:064x}", "compromised", R)
        for i in range(9900)
    ]
    with pytest.raises(tooling.ActionRefused, match="size"):
        _next(None, actions)


def test_the_generation_after_a_recovery_is_taken_from_the_statement():
    """A recovery may set a generation at or below the last list's, so the check needs the statement."""
    one = _next(None, []).document
    thief_gen = _next(one, [], authority=K2, generation=2).document
    statement = W.recovery_stmt(K3, new_gen=2)
    with pytest.raises(tooling.ActionRefused, match="same generation"):
        _next(thief_gen, [], authority=K3, generation=2)
    assert _next(thief_gen, [], authority=K3, generation=2, after_recovery=statement).document
    with pytest.raises(tooling.ActionRefused, match="does not install"):
        _next(thief_gen, [], authority=K4, generation=2, after_recovery=statement)


def test_cli_a_missing_publisher_state_needs_initial(op):  # noqa: F811
    cwd, _ = op
    argv = (
        "revocation", "sign-list", "--signing-key", "authority.pem", "--key-id", "authority", "--issuer", "acme",
        "--publisher-state", "typo.json", "--output", "l.json",
    )  # fmt: skip
    out = run_cli(*argv, cwd=cwd)
    assert out.returncode == 2 and "--initial" in out.stderr and not (cwd / "l.json").exists()
    assert run_cli(*argv, "--initial", cwd=cwd).returncode == 0
    again = run_cli(*argv, "--initial", cwd=cwd)
    assert again.returncode == 2 and "--initial" in again.stderr


def test_cli_actions_need_an_inventory_unless_waived(op):  # noqa: F811
    cwd, fps = op
    argv = (
        "revocation", "sign-list", "--signing-key", "authority.pem", "--key-id", "authority", "--issuer", "acme",
        "--publisher-state", "pub.json", "--output", "l.json", "--initial", "--compromise", f"report,{fps['report']}",
    )  # fmt: skip
    out = run_cli(*argv, cwd=cwd)
    assert out.returncode == 2 and "--trusted-keys" in out.stderr
    assert run_cli(*argv, "--allow-unknown-keys", cwd=cwd).returncode == 0


def test_cli_baseline_digest_at_epoch_zero_is_refused(op):  # noqa: F811
    cwd, fps = op
    out = run_cli(
        "revocation", "enroll", "--pins", "p2.json", "--state", "s2", "--issuer", "acme",
        "--authority-key", "authority.pub", "--authority-fingerprint", fps["authority"],
        "--baseline-epoch", "0", "--baseline-digest", "a" * 64, cwd=cwd,
    )  # fmt: skip
    assert out.returncode == 2 and not (cwd / "p2.json").exists()


def test_cli_enroll_with_a_bad_recovery_digest_leaves_the_pin_file_usable(op):  # noqa: F811
    cwd, fps = op
    out = run_cli(
        "revocation", "enroll", "--pins", "pins.json", "--state", "state", "--issuer", "other",
        "--authority-key", "authority2.pub", "--authority-fingerprint", fps["authority2"], "--baseline-epoch", "0",
        "--recovery-digest", "zz", cwd=cwd,
    )  # fmt: skip
    assert out.returncode == 2
    assert "acme" in st.load_pins(cwd / "pins.json")


def test_cli_bad_output_path_and_nested_previous_are_refused_not_tracebacks(op):  # noqa: F811
    cwd, fps = op
    out = run_cli(
        "revocation", "sign-transition", "--signing-key", "authority.pem", "--key-id", "authority", "--issuer", "acme",
        "--generation", "1", "--new-signing-key", "authority2.pem", "--new-key-id", "authority2",
        "--output", "no/such/dir/t.json", cwd=cwd,
    )  # fmt: skip
    assert out.returncode != 0 and "Traceback" not in out.stderr
    (cwd / "deep.json").write_text("[" * 100000)
    out = run_cli(
        "revocation", "sign-recovery", "--anchor-signing-key", "anchor.pem", "--anchor-key-id", "anchor",
        "--issuer", "acme", "--new-signing-key", "authority2.pem", "--new-key-id", "authority2", "--new-generation", "5",
        "--recovery-epoch", "1", "--declare", fps["authority"], "--previous", "deep.json", "--output", "r.json", cwd=cwd,
    )  # fmt: skip
    assert out.returncode == 2 and "Traceback" not in out.stderr


def test_cli_hostile_documents_are_refusals_not_infrastructure_failures(op):  # noqa: F811
    cwd, _ = op
    (cwd / "bin.json").write_bytes(b"\xff\xfe\x00")
    assert cli_ingest(cwd, "list", "bin.json").returncode == 1
    (cwd / "huge.json").write_bytes(b" " * (5 * 1024 * 1024))
    out = cli_ingest(cwd, "list", "huge.json")
    assert out.returncode == 1, out.stderr
    assert "REVOCATION_MALFORMED" in out.stdout
    other = W.transition(K1, K2)
    (cwd / "other.json").write_text(dump(other))
    assert cli_ingest(cwd, "transition", "other.json").returncode == 1


def test_cli_high_assurance_refusal_comes_before_touching_the_pins(op):  # noqa: F811
    cwd, _ = op
    (cwd / "pins.json").write_text("{")
    from .test_revocation_tooling_and_cli import verify_cli

    assert verify_cli(cwd, profile="high-assurance").returncode == 2


# ------------------------------------------------------------------ the floor


def test_a_gate_refusal_under_record_still_sets_the_floor(fs, tmp_path):
    """The gate runs the engine in check mode when it refuses. The floor must still bind to the record policy."""
    p = enrolled(fs)
    db = tmp_path / "floor.db"
    stale_issue = NOW - timedelta(hours=2)
    env = report(issued_at=stale_issue)
    ctx = gate.RevocationContext(gate.MODE_REQUIRED, fs, {W.issuer: p})
    pol = policy(
        tmp_path,
        max_age=timedelta(hours=1),
        replay_mode="record",
        replay_cache=SqliteReplayCache(db),
    )
    first = gate.verify_with_revocation(env, pol, ctx)
    assert "REPORT_TOO_OLD" in first.result.blocking_reasons
    assert SqliteReplayCache(db).max_age_floor() == timedelta(hours=1)
    assert st.ingest_list(fs, p, dump(W.signed(1, [])), STORE, NOW).accepted
    raised = policy(
        tmp_path,
        max_age=timedelta(days=1),
        replay_mode="record",
        replay_cache=SqliteReplayCache(db),
    )
    assert not gate.verify_with_revocation(env, raised, ctx).result.accepted


def test_a_stale_refusal_in_check_mode_stays_refused_when_raised(tmp_path):
    db = tmp_path / "check.db"
    env = report(issued_at=NOW - timedelta(hours=2))

    def run(age):
        return verify(
            env,
            policy(tmp_path, max_age=age, replay_mode="check", replay_cache=SqliteReplayCache(db)),
        )

    assert run(timedelta(hours=1)).blocking_reasons == ("REPORT_TOO_OLD",)
    assert run(timedelta(days=1)).blocking_reasons == ("REPORT_TOO_OLD",)
    assert SqliteReplayCache(db).max_age_floor() == timedelta(hours=1)


def test_a_read_only_store_in_check_mode_keeps_working(tmp_path):
    db = tmp_path / "ro.db"
    SqliteReplayCache(db)
    db.chmod(0o400)
    env = report()
    try:
        res = verify(env, policy(tmp_path, replay_mode="check", replay_cache=SqliteReplayCache(db)))
    finally:
        db.chmod(0o600)
    assert res.accepted and res.consumption == "CHECKED_NOT_CONSUMED"


def test_a_deleted_policy_record_is_corrupt_not_absent(tmp_path):
    db = tmp_path / "f.db"
    env = report()
    pol = policy(tmp_path, replay_mode="record", replay_cache=SqliteReplayCache(db))
    assert verify(env, pol).accepted
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM replay_meta")
    conn.commit()
    conn.close()
    other = report(issued_at=NOW - timedelta(minutes=30))
    res = verify(other, pol)
    assert not res.accepted and "REPLAY_STATE_UNAVAILABLE" in res.blocking_reasons


def test_module_reachable_without_a_shell():
    out = subprocess.run(
        [sys.executable, "-m", "regaudit_fhe.cli", "revocation", "--help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert out.returncode == 0
