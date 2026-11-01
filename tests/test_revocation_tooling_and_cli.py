"""Issuer tooling that refuses hazards before signing, and the operator CLI end to end in real processes."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from regaudit_fhe import _revocation as rv
from regaudit_fhe import _revocation_tooling as tooling
from regaudit_fhe._trust_lifecycle import MigrationRefused, migrate
from regaudit_fhe.trust import TrustStore

from .experimental_revocation.gen_fixtures import NOW, dump, make_world

W = make_world()
R = "2026-10-01T00:00:00Z"
LATER = "2026-10-15T00:00:00Z"
DAY = timedelta(days=1)


def action(signer, status, when=R, successor=None):
    return tooling.KeyAction(
        signer.key_id,
        W.fp(signer),
        status,
        when,
        (successor.key_id, W.fp(successor)) if successor else None,
    )


def nxt(previous, actions, **kw):
    args = {
        "issuer": W.issuer,
        "authority": W.rev,
        "generation": 1,
        "previous": previous,
        "actions": actions,
        "now": NOW,
        "valid_for": DAY,
    }
    args.update(kw)
    return tooling.next_list(**args)


def verifier_accepts(*docs) -> list[rv.ListResult]:
    state = rv.RevocationState()
    state = rv.enroll(state, W.issuer, W.rev.public_key_pem())
    out = []
    for doc in docs:
        res = rv.verify_list_enrolled(dump(doc), W.issuer, W.store(W.old, W.new, W.third), state, NOW)
        out.append(res)
        if res.accepted:
            state = rv.commit(state, state.enrollments[W.issuer].anchor, res)
    return out


def test_a_retired_key_compromised_later_is_clamped_and_the_verifier_does_not_latch():
    one = nxt(None, [action(W.old, "retired", R)])
    two = nxt(one.document, [action(W.old, "compromised", LATER)])
    assert two.clamped and R in two.clamped[0]
    assert two.document["entries"][0]["effective_from"] == R
    assert all(r.accepted for r in verifier_accepts(one.document, two.document))


def test_control_without_the_clamp_the_verifier_refuses_that_form():
    one = nxt(None, [action(W.old, "retired", R)])
    body = rv.build_body(
        issuer=W.issuer,
        authority_key_id=W.rev.key_id,
        authority_pem=W.rev.public_key_pem(),
        epoch=2,
        prev_list_digest=one.digest,
        issued_at="2026-11-01T12:00:00Z",
        valid_until="2026-11-02T12:00:00Z",
        entries=[W.entry(W.old, "compromised", LATER)],
    )
    results = verifier_accepts(one.document, rv.sign_list(body, W.rev))
    assert results[1].code == "REVOCATION_NOT_MONOTONE"


def test_lists_are_cumulative_chained_and_accepted():
    one = nxt(None, [action(W.old, "retired", R)])
    two = nxt(one.document, [action(W.new, "compromised", None)])
    three = nxt(two.document, [])  # a heartbeat
    assert three.document["epoch"] == 3 and len(three.document["entries"]) == 2
    assert three.document["prev_list_digest"] == two.digest
    assert all(r.accepted for r in verifier_accepts(one.document, two.document, three.document))


def _refused(previous, actions, match, **kw):
    with pytest.raises(tooling.ActionRefused, match=match):
        nxt(previous, actions, **kw)


def test_hazardous_actions_are_refused_before_signing():
    first = nxt(None, [action(W.old, "retired", R), action(W.new, "compromised", R)]).document
    unknown = nxt(None, [action(W.old, "compromised", None)]).document
    _refused(None, [action(W.old, "retired", "2026-12-01T00:00:00Z")], "future-dated")
    _refused(None, [action(W.old, "retired", None)], "unknown boundary")
    _refused(None, [action(W.old, "replaced", R)], "successor")
    _refused(None, [action(W.old, "replaced", R, W.old)], "own successor")
    _refused(None, [action(W.old, "weird", R)], "status")
    _refused(None, [action(W.old, "retired", R), action(W.old, "compromised", R)], "two actions")
    _refused(None, [action(W.rev, "retired", R)], "own signer")
    _refused(first, [action(W.old, "retired", "2026-09-01T00:00:00Z")], "fixed once published")
    _refused(first, [action(W.new, "retired", R)], "cannot move back")
    _refused(first, [action(W.new, "compromised", LATER)], "only move earlier")
    _refused(unknown, [action(W.old, "compromised", R)], "cannot become known")
    rebound = tooling.KeyAction(W.old.key_id, W.fp(W.third), "compromised", None)
    _refused(first, [rebound], "another fingerprint")
    alias = tooling.KeyAction("alias", W.fp(W.old), "compromised", None)
    _refused(first, [alias], "two key_ids")
    _refused(None, [], "validity", valid_for=timedelta(days=31))
    _refused(None, [], "validity", valid_for=timedelta(0))
    _refused(None, [], "report key", trust_store=W.store(W.rev))
    _refused(None, [], "recovery anchor", recovery_anchor_pem=W.rev.public_key_pem())
    foreign = dict(first, issuer="globex")
    _refused(foreign, [], "another issuer")


def test_replacing_keeps_the_successor_and_refuses_changing_it():
    one = nxt(None, [action(W.old, "replaced", R, W.new)]).document
    _refused(one, [action(W.old, "replaced", R, W.third)], "successor cannot change")
    assert nxt(one, [action(W.old, "compromised", None)]).document["entries"][0]["successor"]


def test_a_crash_after_persist_leads_to_a_gap_and_never_a_fork(tmp_path):
    state = tmp_path / "publisher.json"
    one = nxt(None, []).document
    tooling.persist_before_release(state, one)
    assert tooling.load_publisher_state(state) == one
    # released: one. Then two is persisted and the process dies before anyone sees it.
    two = nxt(tooling.load_publisher_state(state), [action(W.old, "retired", R)]).document
    tooling.persist_before_release(state, two)
    three = nxt(tooling.load_publisher_state(state), []).document
    results = verifier_accepts(one, three)
    assert three["epoch"] == 3 and all(r.accepted for r in results)
    assert "REVOCATION_EPOCH_GAP" in results[1].notes


def test_transition_tooling_refuses_hazards():
    def sign(**kw):
        args = {"issuer": W.issuer, "from_signer": W.rev, "from_generation": 1, "to_signer": W.auth2, "now": NOW}
        args.update(kw)
        return tooling.sign_transition_statement(**args)

    doc = sign()
    state = rv.enroll(rv.RevocationState(), W.issuer, W.rev.public_key_pem())
    assert rv.verify_transition(dump(doc), state, None, NOW).accepted
    with pytest.raises(tooling.ActionRefused, match="current authority"):
        sign(to_signer=W.rev)
    with pytest.raises(tooling.ActionRefused, match="recovery anchor"):
        sign(recovery_anchor_pem=W.auth2.public_key_pem())
    with pytest.raises(tooling.ActionRefused, match="report key"):
        sign(trust_store=W.store(W.auth2))


def test_recovery_tooling_refuses_hazards_and_keeps_declarations_cumulative():
    def sign(**kw):
        args = {
            "issuer": W.issuer,
            "anchor": W.recovery,
            "new_authority": W.auth2,
            "new_generation": 5,
            "recovery_epoch": 1,
            "declares": [(W.fp(W.rev), None)],
            "now": NOW,
        }
        args.update(kw)
        return tooling.sign_recovery_statement(**args)

    doc = sign()
    state = rv.enroll(
        rv.RevocationState(), W.issuer, W.rev.public_key_pem(), recovery_pem=W.recovery.public_key_pem()
    )
    assert rv.verify_recovery(dump(doc), state, None, NOW).accepted
    for kw, text in (
        ({"new_authority": W.recovery}, "recovery anchor"),
        ({"declares": []}, "at least one"),
        ({"declares": [(W.fp(W.recovery), None)]}, "anchor"),
        ({"declares": [(W.fp(W.auth2), None)]}, "its own new authority"),
        ({"declares": [(W.fp(W.rev), "2026-12-01T00:00:00Z")]}, "future-dated"),
        ({"declares": [("zz", None)]}, "malformed"),
        ({"declares": [(W.fp(W.rev), None), (W.fp(W.rev), None)]}, "twice"),
        ({"previous": doc, "recovery_epoch": 1, "new_authority": W.auth3}, "newer"),
        ({"previous": doc, "recovery_epoch": 2, "new_authority": W.auth3, "new_generation": 5}, "exceed"),
        ({"previous": doc, "recovery_epoch": 2, "new_generation": 6}, "fresh"),
        (
            {
                "previous": doc,
                "recovery_epoch": 2,
                "new_authority": W.auth3,
                "new_generation": 6,
                "declares": [(W.fp(W.auth2), None)],
            },
            "cumulative",
        ),
    ):
        with pytest.raises(tooling.ActionRefused, match=text):
            sign(**kw)


# ------------------------------------------------------------------ migration of files


def test_migrate_writes_a_new_file_and_leaves_the_source(tmp_path):
    src = tmp_path / "old.json"
    pem = W.old.public_key_pem()
    src.write_text(json.dumps({"keys": {"k": pem}, "revoked": ["k"]}))
    src.chmod(0o640)
    before = src.read_bytes()
    dst = tmp_path / "new.json"
    dry = migrate(str(src), str(dst), {"k": "acme"}, now=NOW, dry_run=True)
    assert dry["dry_run"] and not dst.exists()
    out = migrate(str(src), str(dst), {"k": "acme"}, now=NOW)
    assert src.read_bytes() == before and dst.stat().st_mode & 0o777 == 0o640
    assert TrustStore.from_json(dst).entries["k"].status == "compromised"
    assert out["keys"][0]["reason_code_change"]
    with pytest.raises(MigrationRefused, match="never overwrites"):
        migrate(str(src), str(dst), {"k": "acme"}, now=NOW)


# ------------------------------------------------------------------ the CLI, in real processes


def cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_fhe.cli", *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=cwd,
        check=False,
    )


@pytest.fixture
def op(tmp_path: Path):
    """A report key, an authority, an anchor; an enrolled verifier; a signed report."""
    fps = {}
    for name in ("report", "authority", "anchor", "authority2"):
        out = cli(
            "keygen", "--key-id", name, "--issuer", "acme", "--private-key", f"{name}.pem",
            "--public-key", f"{name}.pub", cwd=tmp_path,
        )  # fmt: skip
        assert out.returncode == 0, out.stderr
        fps[name] = json.loads(out.stdout)["fingerprint_sha256"]
    assert cli(
        "trust", "add", "--store", "t.json", "--key-id", "report", "--issuer", "acme",
        "--public-key", "report.pub", "--fingerprint", fps["report"], cwd=tmp_path,
    ).returncode == 0  # fmt: skip
    (tmp_path / "in.json").write_text(json.dumps({"p": [0.2, 0.3, 0.5], "q": [0.25, 0.25, 0.5]}))
    assert cli(
        "audit", "drift", "-i", "in.json", "-o", "r.json", "--signing-key", "report.pem", "--key-id", "report",
        "--issuer", "acme", "--deployment-id", "p", "--audience", "reg", cwd=tmp_path,
    ).returncode == 0  # fmt: skip
    enroll = cli(
        "revocation", "enroll", "--pins", "pins.json", "--state", "state", "--issuer", "acme",
        "--authority-key", "authority.pub", "--authority-fingerprint", fps["authority"],
        "--anchor-key", "anchor.pub", "--anchor-fingerprint", fps["anchor"],
        "--baseline-epoch", "0", "--trusted-keys", "t.json", cwd=tmp_path,
    )  # fmt: skip
    assert enroll.returncode == 0, enroll.stderr
    return tmp_path, fps


def sign_list(cwd: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    first = () if (cwd / "publisher.json").exists() else ("--initial",)
    return cli(
        "revocation", "sign-list", "--signing-key", "authority.pem", "--key-id", "authority", "--issuer", "acme",
        "--publisher-state", "publisher.json", "--output", "list.json", "--trusted-keys", "t.json",
        *first, *extra, cwd=cwd,
    )  # fmt: skip


def ingest(cwd: Path, kind="list", doc="list.json") -> subprocess.CompletedProcess[str]:
    return cli(
        "revocation", "ingest", kind, doc, "--pins", "pins.json", "--state", "state", "--issuer", "acme",
        "--trusted-keys", "t.json", cwd=cwd,
    )  # fmt: skip


def verify_cli(cwd: Path, *extra: str, profile="confidential", mode="required") -> subprocess.CompletedProcess[str]:
    args = [
        "verify", "-i", "r.json", "--trusted-keys", "t.json", "--profile", profile, "--max-age-seconds", "3600",
        "--replay-mode", "check", "--replay-db", "replay.db", "--verifier-id", "reg",
    ]  # fmt: skip
    if mode is not None:
        args += ["--revocation-mode", mode, "--revocation-pins", "pins.json", "--revocation-state", "state"]
    return cli(*args, *extra, cwd=cwd)


def test_cli_end_to_end_required_with_exit_codes(op):
    cwd, fps = op
    absent = verify_cli(cwd)  # no list yet: refused by policy
    assert absent.returncode == 1
    assert "REVOCATION_DATA_ABSENT" in json.loads(absent.stdout)["blocking_reasons"]

    assert sign_list(cwd).returncode == 0
    accepted = ingest(cwd)
    assert accepted.returncode == 0, accepted.stdout
    ok = verify_cli(cwd)
    assert ok.returncode == 0, ok.stdout
    payload = json.loads(ok.stdout)
    assert payload["policy_id"] == "regaudit-fhe/confidential+revocation-required/v1"
    assert payload["policy_evidence"]["revocation"]["status"] == "VERIFIED_AS_OF"
    assert payload["policy_evidence"]["revocation"]["state_store_scope"] == "LOCAL_FILE"

    assert ingest(cwd).returncode == 0  # a repeat
    status = json.loads(
        cli(
            "revocation", "status", "--pins", "pins.json", "--state", "state", "--issuer", "acme", cwd=cwd
        ).stdout
    )  # fmt: skip
    assert status["mark"]["epoch"] == 1 and status["policy_floor"]["mode"] == "required"

    assert sign_list(cwd, "--compromise", f"report,{fps['report']}").returncode == 0
    assert ingest(cwd).returncode == 0
    refused = verify_cli(cwd)
    assert refused.returncode == 1
    body = json.loads(refused.stdout)
    assert "KEY_COMPROMISED_NO_CHRONOLOGY" in body["blocking_reasons"] and body["integrity_valid"]


def test_cli_high_assurance_is_refused_as_a_configuration_error(op):
    cwd, _ = op
    out = verify_cli(cwd, profile="high-assurance")
    assert out.returncode == 2 and "REVOCATION_HIGH_ASSURANCE_UNAVAILABLE" in out.stderr
    advisory = verify_cli(cwd, profile="high-assurance", mode="advisory")
    assert advisory.returncode == 2


def test_cli_high_assurance_off_says_nothing_new_by_default(op):
    cwd, _ = op
    out = verify_cli(cwd, profile="high-assurance", mode=None)
    assert out.returncode == 0, out.stdout + out.stderr
    payload = json.loads(out.stdout)
    assert payload["policy_id"] == "regaudit-fhe/high-assurance/v1"
    assert "policy_evidence" not in payload
    asked = verify_cli(cwd, "--policy-evidence", profile="high-assurance", mode=None)
    assert json.loads(asked.stdout)["policy_evidence"]["revocation"]["status"] == "NOT_EVALUATED"


@pytest.mark.parametrize("value", ["0", "-1", "86401", "nan", "inf", "1e300"])
def test_cli_evidence_age_outside_the_cap_is_a_configuration_error(op, value):
    cwd, _ = op
    out = verify_cli(cwd, f"--revocation-evidence-age-seconds={value}")
    assert out.returncode == 2, (value, out.stdout, out.stderr)


def test_cli_infrastructure_failures_exit_3(op):
    cwd, _ = op
    (cwd / "state").rename(cwd / "state-gone")
    gone = verify_cli(cwd)
    assert gone.returncode == 3 and gone.stdout == ""
    (cwd / "state-gone").rename(cwd / "state")
    (cwd / "pins.json").write_text("{")
    assert verify_cli(cwd).returncode == 3


def test_cli_missing_arguments_are_a_usage_error(op):
    cwd, _ = op
    out = cli("verify", "-i", "r.json", "--trusted-keys", "t.json", "--revocation-mode", "required", cwd=cwd)
    assert out.returncode == 2


def test_cli_enrollment_refuses_a_wrong_fingerprint_and_a_report_key(op):
    cwd, fps = op
    wrong = cli(
        "revocation", "enroll", "--pins", "p2.json", "--state", "s2", "--issuer", "acme",
        "--authority-key", "authority.pub", "--authority-fingerprint", "0" * 64, "--baseline-epoch", "0", cwd=cwd,
    )  # fmt: skip
    assert wrong.returncode == 2 and "fingerprint mismatch" in wrong.stderr
    report_key = cli(
        "revocation", "enroll", "--pins", "p2.json", "--state", "s2", "--issuer", "acme",
        "--authority-key", "report.pub", "--authority-fingerprint", fps["report"], "--baseline-epoch", "0",
        "--trusted-keys", "t.json", cwd=cwd,
    )  # fmt: skip
    assert report_key.returncode == 2 and "report-signing" in report_key.stderr
    again = cli(
        "revocation", "enroll", "--pins", "pins.json", "--state", "state", "--issuer", "acme",
        "--authority-key", "authority.pub", "--authority-fingerprint", fps["authority"], "--baseline-epoch", "0", cwd=cwd,
    )  # fmt: skip
    assert again.returncode == 2 and "already enrolled" in again.stderr


def test_cli_trust_add_refuses_an_enrolled_authority_or_anchor(op):
    cwd, fps = op
    for name in ("authority", "anchor"):
        out = cli(
            "trust", "add", "--store", "t.json", "--key-id", name, "--issuer", "acme", "--public-key", f"{name}.pub",
            "--fingerprint", fps[name], "--revocation-pins", "pins.json", cwd=cwd,
        )  # fmt: skip
        assert out.returncode == 2 and "enrolled" in out.stderr


def test_cli_sign_list_clamps_and_says_so(op):
    cwd, fps = op
    assert sign_list(cwd, "--retire", f"report,{fps['report']},{R}").returncode == 0
    out = sign_list(cwd, "--compromise", f"report,{fps['report']},{LATER}")
    assert out.returncode == 0 and "clamped" in out.stderr
    assert json.loads((cwd / "list.json").read_text())["entries"][0]["effective_from"] == R


def test_cli_sign_list_refuses_and_releases_nothing(op):
    cwd, fps = op
    out = sign_list(cwd, "--retire", f"report,{fps['report']},2099-01-01T00:00:00Z")
    assert out.returncode == 2 and not (cwd / "list.json").exists()
    assert not (cwd / "publisher.json").exists()


def test_cli_concurrent_publishers_never_fork(op):
    """Real processes on one publisher state: each gets its own epoch."""
    cwd, _ = op
    assert sign_list(cwd).returncode == 0
    argv = [
        sys.executable, "-m", "regaudit_fhe.cli", "revocation", "sign-list", "--signing-key", "authority.pem",
        "--key-id", "authority", "--issuer", "acme", "--publisher-state", "publisher.json",
    ]  # fmt: skip
    procs = [
        subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            [*argv, "--output", f"list{i}.json"], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        for i in range(5)
    ]
    epochs = []
    for proc in procs:
        out, err = proc.communicate(timeout=180)
        assert proc.returncode == 0, err
        epochs.append(json.loads(out)["epoch"])
    assert sorted(epochs) == [2, 3, 4, 5, 6]


def test_rotation_mistakes_are_refused_before_signing():
    one = nxt(None, []).document
    _refused(one, [], "same generation", authority=W.auth2)
    _refused(one, [], "new generation", generation=2)
    two = nxt(one, [], authority=W.auth2, generation=2).document
    _refused(two, [], "below the previous", authority=W.auth3, generation=1)


def test_cli_rotation_and_recovery_end_to_end(op):
    cwd, fps = op
    assert sign_list(cwd).returncode == 0
    assert ingest(cwd).returncode == 0
    rotate = cli(
        "revocation", "sign-transition", "--signing-key", "authority.pem", "--key-id", "authority", "--issuer", "acme",
        "--generation", "1", "--new-signing-key", "authority2.pem", "--new-key-id", "authority2",
        "--trusted-keys", "t.json", "--output", "transition.json", cwd=cwd,
    )  # fmt: skip
    assert rotate.returncode == 0, rotate.stderr
    assert ingest(cwd, "transition", "transition.json").returncode == 0
    # the old authority's next list is now refused
    assert sign_list(cwd).returncode == 0
    assert ingest(cwd).returncode == 1

    for name in ("authority3",):
        out = cli(
            "keygen", "--key-id", name, "--issuer", "acme", "--private-key", f"{name}.pem",
            "--public-key", f"{name}.pub", cwd=cwd,
        )  # fmt: skip
        assert out.returncode == 0
    recover = cli(
        "revocation", "sign-recovery", "--anchor-signing-key", "anchor.pem", "--anchor-key-id", "anchor",
        "--issuer", "acme", "--new-signing-key", "authority3.pem", "--new-key-id", "authority3",
        "--new-generation", "9", "--recovery-epoch", "1", "--declare", fps["authority2"],
        "--output", "recovery.json", cwd=cwd,
    )  # fmt: skip
    assert recover.returncode == 0, recover.stderr
    assert ingest(cwd, "recovery", "recovery.json").returncode == 0
    assert ingest(cwd, "recovery", "recovery.json").returncode == 0  # a repeat, a strict no-op
    status = json.loads(
        cli("revocation", "status", "--pins", "pins.json", "--state", "state", "--issuer", "acme", cwd=cwd).stdout
    )
    assert status["generation"] == 9 and fps["authority2"] in status["compromised_authorities"]


def test_cli_rebaseline_after_a_lost_record(op):
    cwd, fps = op
    for path in (cwd / "state").glob("*.state"):
        path.unlink()
    assert verify_cli(cwd).returncode == 3
    args = (
        "revocation", "rebaseline", "--pins", "pins.json", "--state", "state", "--issuer", "acme",
        "--authority-key", "authority.pub", "--authority-fingerprint", fps["authority"],
        "--anchor-key", "anchor.pub", "--anchor-fingerprint", fps["anchor"], "--baseline-epoch", "0",
    )  # fmt: skip
    refused = cli(*args, cwd=cwd)
    assert refused.returncode == 3 and "accept_loss" in refused.stderr
    assert cli(*args, "--accept-loss", cwd=cwd).returncode == 0
    assert verify_cli(cwd).returncode == 1  # absent, not lost


def test_cli_trust_migrate(tmp_path):
    pem = W.old.public_key_pem()
    (tmp_path / "old.json").write_text(json.dumps({"k": pem}))
    refused = cli("trust", "migrate", "--source", "old.json", "--target", "new.json", cwd=tmp_path)
    assert refused.returncode == 2 and "never inferred" in refused.stderr
    out = cli(
        "trust", "migrate", "--source", "old.json", "--target", "new.json", "--issuer", "k=acme", cwd=tmp_path
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    assert TrustStore.from_json(tmp_path / "new.json").entries["k"].issuer == "acme"
