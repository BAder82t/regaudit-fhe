"""The public gate on the real file store: modes, evidence-age cap, policy floor, disclosure, default-output compatibility.

Everything here is real code on a real local file. ``required`` under ``high-assurance`` is refused on this path;
its algorithm is exercised only by the private test path in ``tests/experimental_revocation/``, on a test double.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe import _revocation_gate as gate
from regaudit_fhe import _revocation_state as st
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.verification import PolicyError, VerificationPolicy, verify

from .experimental_revocation.gen_fixtures import NOW, dump, make_world

W = make_world()
STORE = W.store(W.old, W.new)
R = "2026-10-01T00:00:00Z"
RESULT_FIELDS = {
    "trust_status", "accepted", "valid", "integrity_valid", "issuer_trusted", "key_status",
    "chronology", "signed_not_after", "timestamp_status", "reasons", "blocking_reasons",
    "policy_id", "format", "replay_scope", "replay_durable", "consumption", "trust_history",
    "trust_store_as_of", "issuer", "key_id", "primitive", "issued_at", "regulations",
    "parameter_set_hash", "deployment_id", "audit_run_id",
}  # fmt: skip


def report(signer=None):
    return envelope_v2(
        "drift",
        rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])),
        signer=signer or W.old,
        deployment_id="p",
        audience=["reg"],
        issued_at=NOW - timedelta(hours=1),
    )


@pytest.fixture
def world(tmp_path: Path):
    d = tmp_path / "state"
    d.mkdir(mode=0o700)
    fs = st.FileStateStore(d)
    pin = st.Pin(
        W.issuer,
        W.rev.public_key_pem(),
        "enr-1",
        recovery_pem=W.recovery.public_key_pem(),
        baseline_epoch=0,
    )
    st.enroll(fs, pin, STORE, now=NOW - timedelta(days=30))
    return fs, pin, tmp_path


def policy(tmp_path: Path, profile="confidential", now=NOW, **kw):
    args = {"trust_store": STORE, "now": lambda: now, "profile": profile}
    if profile != "development":
        args.update(
            max_age=timedelta(days=90),
            replay_mode="check",
            verifier_id="reg",
            replay_cache=SqliteReplayCache(tmp_path / f"{profile}.db"),
        )
    args.update(kw)
    return VerificationPolicy(**args)


def decide(
    world,
    *,
    mode=gate.MODE_REQUIRED,
    now=NOW,
    age=gate.DEFAULT_MAX_EVIDENCE_AGE,
    profile="confidential",
):
    fs, pin, tmp = world
    ctx = gate.RevocationContext(mode, fs, {W.issuer: pin}, age)
    return gate.verify_with_revocation(report(), policy(tmp, profile=profile, now=now), ctx)


def ingest(world, doc, now=NOW):
    fs, pin, _ = world
    return st.ingest_list(fs, pin, dump(doc), STORE, now)


def test_required_accepts_with_fresh_data_and_discloses_the_local_file(world):
    assert ingest(world, W.signed(1, [])).accepted
    d = decide(world)
    assert d.result.accepted
    assert d.result.policy_id == "regaudit-fhe/confidential+revocation-required/v1"
    assert d.revocation["state_store_scope"] == "LOCAL_FILE"
    assert d.revocation["revocation_evidence"].startswith("verified-as-of-")


@pytest.mark.parametrize(
    ("setup", "code"),
    [
        ("absent", "REVOCATION_DATA_ABSENT"),
        ("stale", "REVOCATION_DATA_STALE"),
        ("contradictory", "REVOCATION_CONTRADICTORY"),
    ],
)
def test_required_fails_closed(world, setup, code):
    now = NOW
    if setup == "stale":
        ingest(world, W.signed(1, []))
        now = NOW + timedelta(hours=22)
    if setup == "contradictory":
        ingest(world, W.signed(1, []))
        ingest(world, W.signed(1, [W.entry(W.third, "retired", R)]))
    d = decide(world, now=now)
    assert not d.result.accepted and code in d.result.blocking_reasons
    assert d.result.integrity_valid  # origin still holds; current authorization does not


def test_a_listed_key_is_refused_with_a_valid_signature(world):
    ingest(world, W.signed(1, [W.entry(W.old, "compromised", None)]))
    d = decide(world)
    assert d.result.integrity_valid and not d.result.accepted
    assert "KEY_COMPROMISED_NO_CHRONOLOGY" in d.result.blocking_reasons


def test_advisory_tightens_and_does_not_fail_closed(world):
    d = decide(world, mode=gate.MODE_ADVISORY)
    assert d.result.accepted and "REVOCATION_DATA_ABSENT" in d.result.reasons
    assert d.revocation["revocation_evidence"] == "unproven"


# ------------------------------------------------------------------ evidence-age cap


@pytest.mark.parametrize(
    "bad",
    [
        timedelta(0),
        timedelta(seconds=-1),
        timedelta(hours=24, microseconds=1),
        timedelta.max,
        86400,
        None,
        float("inf"),
        float("nan"),
    ],
)
def test_evidence_age_outside_the_cap_is_refused(world, bad):
    fs, pin, _ = world
    with pytest.raises(PolicyError, match="max_evidence_age"):
        gate.RevocationContext(gate.MODE_REQUIRED, fs, {W.issuer: pin}, bad)


def test_evidence_age_at_the_cap_and_below_is_allowed(world):
    fs, pin, _ = world
    gate.RevocationContext(gate.MODE_REQUIRED, fs, {W.issuer: pin}, timedelta(hours=24))
    gate.RevocationContext(gate.MODE_REQUIRED, fs, {W.issuer: pin}, timedelta(seconds=1))


# ------------------------------------------------------------------ the same floor, on the gate


def test_raising_the_evidence_age_does_not_make_stale_data_acceptable(world):
    ingest(world, W.signed(1, []))
    later = NOW + timedelta(hours=2)  # 5 h after issue
    short = timedelta(hours=1)
    assert "REVOCATION_DATA_STALE" in decide(world, now=later, age=short).result.blocking_reasons
    raised = decide(world, now=later, age=timedelta(hours=24))
    assert not raised.result.accepted
    assert "REVOCATION_DATA_STALE" in raised.result.blocking_reasons
    assert "REVOCATION_POLICY_FLOOR_APPLIED" in raised.result.reasons


def test_control_an_unchanged_evidence_age_writes_once(world):
    fs, _, _ = world
    ingest(world, W.signed(1, []))
    assert decide(world).result.accepted
    before = fs.path(W.issuer).read_bytes()
    assert decide(world).result.accepted
    assert fs.path(W.issuer).read_bytes() == before


def test_a_record_that_served_required_refuses_advisory(world):
    ingest(world, W.signed(1, []))
    assert decide(world).result.accepted
    d = decide(world, mode=gate.MODE_ADVISORY)
    assert not d.result.accepted and "REVOCATION_POLICY_DOWNGRADE" in d.result.blocking_reasons


def test_advisory_can_be_tightened_to_required(world):
    ingest(world, W.signed(1, []))
    assert decide(world, mode=gate.MODE_ADVISORY).result.accepted
    assert decide(world).result.accepted


def test_the_floor_survives_a_new_context_and_a_ceremony_unless_reset_explicitly(world):
    fs, _, _ = world
    first = W.signed(1, [])
    ingest(world, first)
    assert decide(world).result.accepted
    from regaudit_fhe import _revocation as rv

    p2 = st.Pin(
        W.issuer,
        W.rev.public_key_pem(),
        "enr-2",
        recovery_pem=W.recovery.public_key_pem(),
        baseline_epoch=1,
        baseline_digest=rv.list_digest(first),
    )
    rec = st.rebaseline(fs, p2, now=NOW)
    assert rec.policy_floor["mode"] == gate.MODE_REQUIRED
    assert st.rebaseline(fs, p2, now=NOW, reset_policy_floor=True).policy_floor is None


def test_limit_off_reads_nothing_so_it_cannot_be_refused(world, tmp_path):
    """Owner ruling: off keeps its decisions. A record that served required does not change what off does."""
    ingest(world, W.signed(1, [W.entry(W.old, "compromised", None)]))
    assert not decide(world).result.accepted
    fs, pin, tmp = world
    ctx = gate.RevocationContext(gate.MODE_OFF, fs, {W.issuer: pin})
    d = gate.verify_with_revocation(report(), policy(tmp), ctx)
    assert d.result.accepted and d.revocation is None


# ------------------------------------------------------------------ high-assurance with revocation off


def test_high_assurance_off_keeps_decisions_and_policy_id_and_is_not_evaluated(world):
    fs, pin, tmp = world
    pol = policy(tmp, profile="high-assurance")
    direct = verify(report(), pol)
    d = gate.verify_with_revocation(
        report(), pol, gate.RevocationContext(gate.MODE_OFF, fs, {W.issuer: pin})
    )
    assert d.result.accepted is direct.accepted is True
    assert d.result.policy_id == "regaudit-fhe/high-assurance/v1"
    assert set(d.result.to_dict()) == RESULT_FIELDS
    section = gate.policy_evidence(d)
    assert section["policy_evidence_version"] == 1
    assert section["revocation"]["revocation_evaluation"] == "not_evaluated"
    assert section["revocation"]["satisfies_revocation_aware_high_assurance"] is False


def test_no_evidence_section_ever_claims_the_revocation_aware_profile(world):
    ingest(world, W.signed(1, []))
    section = gate.policy_evidence(decide(world))
    assert section["revocation"]["revocation_evaluation"] == "evaluated"
    assert section["revocation"]["satisfies_revocation_aware_high_assurance"] is False


def test_the_evidence_section_discloses_the_governance_limit():
    governance = gate.policy_evidence()["governance"]
    assert governance["independent_approver"] is False and governance["quorum"] is False
    assert "delegate" in governance["note"]


# ------------------------------------------------------------------ default output


def _cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=cwd,
        check=False,
    )


@pytest.fixture
def signed(tmp_path: Path) -> Path:
    (tmp_path / "in.json").write_text(json.dumps({"p": [0.2, 0.3, 0.5], "q": [0.25, 0.25, 0.5]}))
    key = json.loads(
        _cli(
            "keygen", "--key-id", "k", "--issuer", "acme", "--private-key", "k.pem",
            "--public-key", "k.pub", cwd=tmp_path,
        ).stdout
    )  # fmt: skip
    assert (
        _cli(
            "trust", "add", "--store", "t.json", "--key-id", "k", "--issuer", "acme",
            "--public-key", "k.pub", "--fingerprint", key["fingerprint_sha256"], cwd=tmp_path,
        ).returncode == 0
    )  # fmt: skip
    assert (
        _cli(
            "audit", "drift", "-i", "in.json", "-o", "r.json", "--signing-key", "k.pem", "--key-id", "k",
            "--issuer", "acme", "--deployment-id", "p", cwd=tmp_path,
        ).returncode == 0
    )  # fmt: skip
    return tmp_path


def test_default_cli_output_has_exactly_the_published_fields(signed):
    proc = _cli("verify", "-i", "r.json", "--trusted-keys", "t.json", cwd=signed)
    assert proc.returncode == 0 and proc.stderr == ""
    assert set(json.loads(proc.stdout)) == RESULT_FIELDS | {"trusted_issuer"}


def test_the_evidence_section_appears_only_when_asked_for(signed):
    proc = _cli(
        "verify", "-i", "r.json", "--trusted-keys", "t.json", "--policy-evidence", cwd=signed
    )
    payload = json.loads(proc.stdout)
    assert proc.returncode == 0
    assert set(payload) == RESULT_FIELDS | {
        "trusted_issuer",
        "policy_evidence",
        "response_format",
        "revocation_evaluation",
        "issuer_binding",
    }
    assert payload["policy_evidence"]["revocation"]["revocation_evaluation"] == "not_evaluated"


def test_http_verify_output_has_exactly_the_published_fields(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from regaudit_fhe.server import ServerConfig, build_app
    from tests._asgi import client_for

    config = ServerConfig(
        api_keys={},
        dev_mode=True,
        max_body_bytes=1 << 20,
        rate_limit_per_min=600,
        request_timeout_s=10.0,
        cors_origins=(),
        trust_store=STORE,
        profile="development",
    )
    client = client_for(build_app(config=config), base_url="http://127.0.0.1:8000")
    env = envelope_v2(
        "drift",
        rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])),
        signer=W.old,
        deployment_id="p",
    )
    response = client.post("/v1/verify", json={"envelope": env.to_dict()})
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == RESULT_FIELDS and body["policy_id"] == "regaudit-fhe/development/v1"
