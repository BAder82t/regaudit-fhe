"""The five statements that explain a result: each is derived from what the real engine returned, and the verdict and
reason codes are the engine's own, unchanged by them."""

from __future__ import annotations

import copy
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest
from helpers import client_for, make_portal, post_bytes, signed_report
from regaudit_portal import statuses as statuses_module
from regaudit_portal.config import load_portal
from regaudit_portal.explain import DEMONSTRATION_LABEL, FHE_NOTICE, declarations

import regaudit_fhe as rf
from regaudit_fhe.report_v2 import envelope_v2, parse_envelope_strict
from regaudit_fhe.reports import ParameterSet
from regaudit_fhe.verification import CONSUMPTION_NOT_CHECKED, CONSUMPTION_RECORDED_LOCAL, verify

GOLDEN = Path(__file__).parent / "golden" / "sample_results_before_statuses.json"
NAMES = ("signature", "issuer_trust", "freshness", "replay", "encryption_claims")


def dated_report(
    signer: rf.Signer, issued_at: datetime, parameter_set: ParameterSet | None = None
) -> bytes:
    report = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    env = envelope_v2(
        "drift",
        report,
        signer=signer,
        deployment_id="synthetic-test",
        audience=["demo-verifier"],
        parameter_set=parameter_set,
        issued_at=issued_at,
        audit_run_id=str(uuid.uuid4()),
    )
    return json.dumps(env.to_dict()).encode()


@pytest.fixture
def setup(tmp_path):
    config, signer = make_portal(tmp_path / "p")
    return config, signer, client_for(config)


def run(client, raw):
    response = client.post("/api/verify", content=raw, headers={"content-type": "application/json"})
    assert response.status_code == 200, response.text
    return response.json()


# ----------------------------------------------------------------------------- the original result is unchanged


def test_the_bundled_samples_are_unchanged_except_for_the_added_statuses(welcome_client):
    golden = json.loads(GOLDEN.read_text())
    assert set(golden) == {
        "trusted",
        "untrusted-signer",
        "modified",
        "plaintext-backend",
        "declares-encrypted-backend",
    }
    for sample_id, before in golden.items():
        after = welcome_client.post(f"/api/samples/{sample_id}/verify").json()
        after.pop("checked_at")
        statuses = after.pop("statuses")
        assert statuses["schema"] == statuses_module.SCHEMA
        assert after == before, (
            sample_id
        )  # every existing member, byte for byte in value, is as it was


@pytest.fixture
def welcome_client():
    from fastapi.testclient import TestClient
    from regaudit_portal.app import build_app

    return TestClient(build_app(None, port=8765), base_url="http://127.0.0.1:8765")


# ----------------------------------------------------------------------------- the samples


def test_each_sample_has_the_five_statements_labelled_as_a_demonstration(welcome_client):
    for sample in welcome_client.get("/api/status").json()["samples"]:
        body = welcome_client.post(f"/api/samples/{sample['id']}/verify").json()
        s = body["statuses"]
        assert [n for n in NAMES if n in s] == list(NAMES)
        assert (
            s["trust_mode"] == "demonstration" and s["demonstration_label"] == DEMONSTRATION_LABEL
        )
        assert s["verdict"] == body["verification"]["trust_status"]
        assert s["fhe_notice"] == FHE_NOTICE
        for name in NAMES:
            assert s[name]["trust_mode"] == "demonstration"
            assert s[name]["demonstration_label"] == DEMONSTRATION_LABEL
            assert s[name]["derived_from"] and s[name]["text"]
            assert "administrator" not in s[name]["text"].replace(
                "administrator's own", ""
            )  # demonstration words


def test_the_trusted_sample_reads_passed_and_says_what_was_not_checked(welcome_client):
    s = welcome_client.post("/api/samples/trusted/verify").json()["statuses"]
    assert s["signature"]["state"] == "passed"
    assert s["issuer_trust"]["state"] == "established"
    # The demonstration policy sets no maximum age and keeps no replay record: those are "not checked", with the reason.
    assert s["freshness"]["state"] == "not_checked" and "no maximum age" in s["freshness"]["text"]
    assert s["replay"]["state"] == "not_checked" and "no record" in s["replay"]["text"]


# ----------------------------------------------------------------------------- crafted reports, real engine


def test_trusted_customer_report_passes_and_records_nothing_in_check_mode(setup):
    _config, signer, client = setup
    body = run(client, signed_report(signer))
    s = body["statuses"]
    assert body["trust_mode"] == "customer" and s["trust_mode"] == "customer"
    assert "demonstration_label" not in s and "demonstration_label" not in s["signature"]
    assert s["verdict"] == "TRUSTED"
    assert s["signature"]["state"] == "passed"
    assert s["issuer_trust"]["state"] == "established"
    assert s["freshness"]["state"] == "within_limit"
    assert s["freshness"]["details"]["max_age_seconds"] == 30 * 86400
    assert s["freshness"]["details"]["time_source"] == "signer_stated"
    assert "only what the signer stated" in s["freshness"]["limit"]
    assert s["replay"]["state"] == "checked_not_seen"
    assert "own record file" in s["replay"]["limit"]
    assert s["encryption_claims"]["state"] == "plaintext_stated"
    assert s["encryption_claims"]["limit"] == FHE_NOTICE
    assert s["encryption_claims"]["details"]["encryption_verified"] is False


def test_a_tampered_report_fails_the_signature_and_leaves_the_issuer_not_established(setup):
    _config, signer, client = setup
    changed = json.loads(signed_report(signer))
    changed["deployment_id"] = "changed-after-signing"
    body = run(client, json.dumps(changed).encode())
    s = body["statuses"]
    assert "HASH_MISMATCH" in body["verification"]["blocking_reasons"]
    assert s["signature"]["state"] == "failed"
    assert s["issuer_trust"]["state"] == "not_established"
    assert s["replay"]["state"] == "not_checked" and "last" in s["replay"]["text"]


def test_an_unknown_issuer_is_not_checked_for_signature_and_not_established(setup):
    _, _, client = setup
    stranger = rf.Signer.generate(issuer="Northwind Test Issuer", key_id="k-other")
    body = run(client, signed_report(stranger))
    s = body["statuses"]
    assert body["verification"]["blocking_reasons"] == ["ISSUER_UNKNOWN"]
    assert s["signature"]["state"] == "not_checked" and "no enrolled key" in s["signature"]["text"]
    assert s["issuer_trust"]["state"] == "not_established"
    assert (
        s["freshness"]["details"]["time_source"] == "not_established"
    )  # the engine withholds chronology here
    assert (
        s["freshness"]["state"] == "within_limit"
    )  # the age rule is still evaluated by the engine


def test_a_wrong_issuer_name_is_not_established_although_the_signature_passes(setup):
    _config, signer, client = setup
    renamed = rf.Signer("Another Issuer", signer.key_id, signer.private_key, signer.public_key)
    body = run(client, signed_report(renamed))
    s = body["statuses"]
    assert "ISSUER_MISMATCH" in body["verification"]["blocking_reasons"]
    assert s["signature"]["state"] == "passed"
    assert s["issuer_trust"]["state"] == "not_established"


@pytest.mark.parametrize(
    ("offset", "code", "state"),
    [
        (timedelta(days=-45), "REPORT_TOO_OLD", "too_old"),
        (timedelta(days=2), "REPORT_FROM_FUTURE", "from_future"),
    ],
)
def test_an_over_age_or_future_report_fails_freshness_only_through_the_engines_reason(
    setup, offset, code, state
):
    _config, signer, client = setup
    body = run(client, dated_report(signer, datetime.now(timezone.utc) + offset))
    s = body["statuses"]
    assert body["verification"]["blocking_reasons"] == [code]
    assert s["freshness"]["state"] == state
    assert s["signature"]["state"] == "passed" and s["issuer_trust"]["state"] == "established"
    assert s["freshness"]["details"]["max_age_seconds"] == 30 * 86400


def test_a_repeat_in_record_mode_is_recorded_then_detected(tmp_path):
    config, signer = make_portal(tmp_path / "r")
    settings = json.loads(config.read_text())
    settings["replay_mode"] = "record"
    config.write_text(json.dumps(settings))
    client = client_for(config)
    raw = signed_report(signer)
    first = run(client, raw)
    second = run(client, raw)
    assert first["statuses"]["replay"]["state"] == "recorded"
    assert first["statuses"]["replay"]["details"]["consumption"] == CONSUMPTION_RECORDED_LOCAL
    assert second["verification"]["blocking_reasons"] == ["REPLAY_DETECTED"]
    assert second["statuses"]["replay"]["state"] == "repeat_detected"
    assert second["statuses"]["signature"]["state"] == "passed"


def test_plaintext_and_encrypted_claims_are_stated_by_the_signer_and_never_verified(setup):
    _config, signer, client = setup
    plain = run(client, signed_report(signer))["statuses"]["encryption_claims"]
    claimed = ParameterSet(backend="tenseal-ckks", poly_modulus_degree=8192, security_bits=192)
    encrypted = run(client, signed_report(signer, parameter_set=claimed))["statuses"][
        "encryption_claims"
    ]
    odd = ParameterSet(backend="made-up-backend", poly_modulus_degree=8192, security_bits=192)
    unknown = run(client, signed_report(signer, parameter_set=odd))["statuses"]["encryption_claims"]
    assert plain["state"] == "plaintext_stated"
    assert (
        encrypted["state"] == "declared_by_signer"
        and encrypted["details"]["backend"] == "tenseal-ckks"
    )
    assert unknown["state"] == "declared_by_signer" and "does not recognize" in unknown["text"]
    for entry in (plain, encrypted, unknown):
        assert entry["details"]["encryption_verified"] is False and entry["limit"] == FHE_NOTICE


def test_the_verdict_and_reason_codes_equal_the_exact_engine_called_directly(setup):
    config, signer, client = setup
    raw = signed_report(signer)
    body = run(client, raw)
    portal = load_portal(config)
    direct = verify(parse_envelope_strict(json.loads(raw)), portal.policy).to_dict()
    assert body["verification"] == direct


# ----------------------------------------------------------------------------- derivation, not constants


def engine_result(client, raw) -> dict:
    return run(client, raw)["verification"]


def test_the_statements_are_a_function_of_the_engine_result(setup):
    config, signer, client = setup
    body = run(client, signed_report(signer))
    policy = load_portal(config).policy
    again = statuses_module.build(
        body["verification"],
        body["encryption_declarations"],
        policy,
        trust_mode="customer",
        demonstration=False,
    )
    assert again == body["statuses"]


@pytest.mark.parametrize(
    ("change", "name", "state"),
    [
        (
            {"integrity_valid": False, "blocking_reasons": ["SIGNATURE_INVALID"]},
            "signature",
            "failed",
        ),
        (
            {"integrity_valid": False, "blocking_reasons": ["ISSUER_UNKNOWN"]},
            "signature",
            "not_checked",
        ),
        ({"issuer_trusted": False}, "issuer_trust", "not_established"),
        ({"blocking_reasons": ["REPORT_TOO_OLD"]}, "freshness", "too_old"),
        ({"blocking_reasons": ["REPORT_FROM_FUTURE"]}, "freshness", "from_future"),
        ({"blocking_reasons": ["MALFORMED_ENVELOPE"]}, "freshness", "not_checked"),
        ({"consumption": CONSUMPTION_RECORDED_LOCAL}, "replay", "recorded"),
        ({"consumption": CONSUMPTION_NOT_CHECKED}, "replay", "not_checked"),
        ({"blocking_reasons": ["REPLAY_DETECTED"]}, "replay", "repeat_detected"),
        (
            {"reasons": ["REPLAY_STATE_UNAVAILABLE"], "consumption": CONSUMPTION_NOT_CHECKED},
            "replay",
            "state_unavailable",
        ),
    ],
)
def test_changing_one_engine_field_changes_exactly_the_statement_that_depends_on_it(
    setup, change, name, state
):
    config, signer, client = setup
    body = run(client, signed_report(signer))
    policy = load_portal(config).policy
    altered = copy.deepcopy(body["verification"])
    altered.update(change)
    if "blocking_reasons" in change:
        altered["reasons"] = list(dict.fromkeys([*altered["reasons"], *change["blocking_reasons"]]))
    built = statuses_module.build(
        altered, body["encryption_declarations"], policy, trust_mode="customer", demonstration=False
    )
    assert built[name]["state"] == state
    unchanged = {
        n for n in NAMES if n != name and built[n]["state"] == body["statuses"][n]["state"]
    }
    assert name not in unchanged


def test_a_withdrawn_key_is_never_called_established_when_the_engine_blocked_it():
    base = {
        "trust_status": "INVALID",
        "issuer_trusted": True,
        "key_status": "revoked",
        "blocking_reasons": ["KEY_REVOKED"],
        "integrity_valid": True,
    }
    assert statuses_module._issuer(base)["state"] == "not_established"
    accepted = {**base, "trust_status": "TRUSTED", "blocking_reasons": []}
    assert statuses_module._issuer(accepted)["state"] == "established_with_limit"


def test_a_report_with_no_max_age_policy_says_freshness_was_not_checked(setup):
    _, signer, client = setup
    body = run(client, signed_report(signer))
    facts = statuses_module.PolicyFacts("development", None, timedelta(minutes=5), "off")
    s = statuses_module._freshness(body["verification"], facts)
    assert s["state"] == "not_checked" and "no maximum age" in s["text"]


def test_text_from_the_report_reaches_the_statements_only_neutralised(setup):
    _config, _signer, client = setup
    hostile = "Evil ‮<b>x</b>​"
    body = run(client, signed_report(rf.Signer.generate(issuer=hostile, key_id="k1")))
    blob = json.dumps(body["statuses"], ensure_ascii=False)
    assert "‮" not in blob and "​" not in blob
    assert "Evil" not in blob  # the issuer name is not interpolated into any statement


def test_the_saved_result_keeps_its_meaning_and_the_statuses_are_an_extra_member(setup):
    _config, signer, client = setup
    body = run(client, signed_report(signer))
    saved = {k: v for k, v in body.items() if k != "statuses"}
    assert set(saved) >= {
        "verification",
        "explanation",
        "encryption_declarations",
        "engine",
        "fhe_notice",
    }
    assert body["statuses"]["note"].startswith("These statements explain the verdict")


def test_declarations_helper_is_what_the_encryption_statement_uses(setup):
    _config, signer, client = setup
    raw = signed_report(signer)
    body = run(client, raw)
    env = parse_envelope_strict(json.loads(raw))
    assert body["encryption_declarations"] == declarations(
        env, body["verification"]["trust_status"]
    )
    assert post_bytes(client, raw).status_code == 200
