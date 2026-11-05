"""Worked examples: scenario -> verdict under development / confidential / high-assurance.

Every row runs the REAL, UNCHANGED engine (`regaudit_fhe.verification.verify`). A list contributes only
(a) tightened store entries and (b) OPTIONALLY, for lower profiles and only with explicit owner approval
(not implemented in the product), a `TrustHistory`. `H` = high-assurance never accepts a historical
retired/compromised key. Claimed `issued_at` is never trusted except in development signer-asserted mode.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.verification import TimestampEvidence, VerificationPolicy, verify

from . import proto
from .gen_fixtures import NOW, dump, make_world

UTC = timezone.utc
SEP1 = datetime(2026, 9, 1, 12, tzinfo=UTC)
OCT15 = datetime(2026, 10, 15, 12, tzinfo=UTC)
R = "2026-10-01T00:00:00Z"
C = "2026-09-15T00:00:00Z"
PROFILES = ("development", "confidential", "high-assurance")
FRESH = "TRUST_STORE_FRESHNESS_UNPROVEN"
NOCHRON_R, NOCHRON_C = "KEY_RETIRED_NO_CHRONOLOGY", "KEY_COMPROMISED_NO_CHRONOLOGY"
AFTER_R, AFTER_C = "SIGNED_AFTER_RETIREMENT", "SIGNED_AFTER_COMPROMISE"
OK = None

# name -> (list entry builder or None, signer, timestamp, claimed issued_at, history option, dev signer-asserted)
# expected: (development, confidential, high-assurance); None = accepted, str = required blocking code
SCENARIOS = {
    "A active key, not listed": (None, "old", SEP1, SEP1, False, False, (OK, OK, OK)),
    "B retired R, TS before R, default (no list history)": (
        "retired",
        "old",
        SEP1,
        SEP1,
        False,
        False,
        (FRESH, FRESH, FRESH),
    ),
    "C retired R, TS before R, OPTIONAL owner-approved list history": (
        "retired",
        "old",
        SEP1,
        SEP1,
        True,
        False,
        (OK, OK, FRESH),
    ),
    "D retired R, TS after R (a NEW signature), option on": (
        "retired",
        "old",
        OCT15,
        OCT15,
        True,
        False,
        (AFTER_R, AFTER_R, AFTER_R),
    ),
    "E retired R, claimed issued_at before R, no TS": (
        "retired",
        "old",
        None,
        SEP1,
        False,
        False,
        (NOCHRON_R, NOCHRON_R, NOCHRON_R),
    ),
    "F retired R, claimed before R, no TS, development signer-asserted": (
        "retired",
        "old",
        None,
        SEP1,
        False,
        True,
        (OK, "n/a", "n/a"),
    ),
    "G retired R, backdated issued_at, TS after R, dev signer-asserted": (
        "retired",
        "old",
        OCT15,
        SEP1,
        False,
        True,
        (OK, "n/a", "n/a"),
    ),
    "H compromised C, TS before C, option on": (
        "compromised",
        "old",
        SEP1,
        SEP1,
        True,
        False,
        (OK, OK, FRESH),
    ),
    "I compromised C, TS before C, default": (
        "compromised",
        "old",
        SEP1,
        SEP1,
        False,
        False,
        (FRESH, FRESH, FRESH),
    ),
    "J compromised C, claimed before C, no TS (attacker backdates)": (
        "compromised",
        "old",
        None,
        SEP1,
        True,
        False,
        (NOCHRON_C, NOCHRON_C, NOCHRON_C),
    ),
    "K compromised C, TS after C": (
        "compromised",
        "old",
        OCT15,
        OCT15,
        True,
        False,
        (AFTER_C, AFTER_C, AFTER_C),
    ),
    "L compromised, unknown boundary, TS early, option on": (
        "compromised-unknown",
        "old",
        SEP1,
        SEP1,
        True,
        False,
        (NOCHRON_C, NOCHRON_C, NOCHRON_C),
    ),
    "M compromised C, dev signer-asserted never rescues it": (
        "compromised",
        "old",
        None,
        SEP1,
        False,
        True,
        (NOCHRON_C, "n/a", "n/a"),
    ),
    "N replaced A by B, report signed by enrolled B": (
        "replaced",
        "new",
        OCT15,
        OCT15,
        False,
        False,
        (OK, OK, OK),
    ),
    "O replaced A by B, B not enrolled": (
        "replaced-b-unenrolled",
        "new",
        OCT15,
        OCT15,
        False,
        False,
        ("ISSUER_UNKNOWN",) * 3,
    ),
}


def _report():
    return rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))


def _tsa(gen):
    def verifier(digest, token):
        return TimestampEvidence(gen, timedelta(0)) if token == b"ok:" + digest else None

    return verifier


def _entries(w, kind):
    if kind in ("retired",):
        return [w.entry(w.old, "retired", R)]
    if kind == "compromised":
        return [w.entry(w.old, "compromised", C)]
    if kind == "compromised-unknown":
        return [w.entry(w.old, "compromised", None)]
    return [w.entry(w.old, "replaced", R, w.new)]


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_worked_example(tmp_path, name, profile):
    kind, who, ts_at, issued, option, asserted, expected = SCENARIOS[name]
    want = expected[PROFILES.index(profile)]
    w = make_world()
    signer = w.old if who == "old" else w.new
    enrolled = (w.old,) if kind == "replaced-b-unenrolled" else (w.old, w.new)
    store = w.store(*enrolled)
    history = None
    if kind is not None:
        out = proto.evaluate(store, dump(w.signed(1, _entries(w, kind))), w.anchor,
                             proto.RevocationState(), NOW, profile=profile,
                             owner_approved_history=option)  # fmt: skip
        assert out.status == "VERIFIED"
        store, history = out.store, out.history
        if profile == "high-assurance" or not option:
            assert history is None  # a cumulative current list is not an authenticated history
    env = envelope_v2(
        "drift", _report(), signer=signer, deployment_id="p", audience=["reg"], issued_at=issued
    )
    kw = {}
    if ts_at is not None:
        env = env.with_timestamp(issuer="t", token=b"ok:" + env.sealed_digest(), issued_at=ts_at)
        kw["timestamp_verifier"] = _tsa(ts_at)
    args = {
        "trust_store": store,
        "now": lambda: NOW,
        "profile": profile,
        "trust_history": history,
        **kw,
    }
    if profile != "development":
        args.update(max_age=timedelta(days=90), replay_mode="record", verifier_id="reg",
                    replay_cache=SqliteReplayCache(tmp_path / "r.db"))  # fmt: skip
    if asserted:
        args["historical_acceptance"] = "signer-asserted"
        if profile != "development":
            with pytest.raises(Exception, match="development"):
                VerificationPolicy(**args)
            assert want == "n/a"
            return
    res = verify(env, VerificationPolicy(**args))
    if want is None:
        assert res.accepted, (name, profile, res.blocking_reasons)
    else:
        assert not res.accepted and want in res.blocking_reasons, (
            name,
            profile,
            res.blocking_reasons,
        )


def test_unverifiable_list_leaves_the_store_unchanged_and_says_unproven():
    w = make_world()
    store = w.store()
    out = proto.evaluate(store, b"{", w.anchor, proto.RevocationState(), NOW)
    assert (
        out.status == "UNVERIFIED" and out.store is store and out.revocation_evidence == "unproven"
    )
