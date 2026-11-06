"""Each sentence the setup pages say about a profile is checked here against the published engine, with the exact policy
the portal builds from a configuration. If the engine did something else, the explanation would be wrong, and a test
here fails instead.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest
from helpers import make_portal
from regaudit_portal import config as config_module
from regaudit_portal import profiles
from regaudit_portal.config import load_portal

import regaudit_fhe as rf
from regaudit_fhe.report_v2 import envelope_v2, parse_envelope_strict
from regaudit_fhe.reports import envelope
from regaudit_fhe.trust import TrustStore
from regaudit_fhe.verification import PROFILES as ENGINE_PROFILES
from regaudit_fhe.verification import PolicyError, VerificationPolicy, verify

ISSUER = "Northwind Test Issuer"
VERIFIER = "northwind-verifier"


@pytest.fixture(params=profiles.PROFILE_NAMES)
def profile(request):
    return request.param


@pytest.fixture
def portal_for(tmp_path):
    """The policy the portal itself builds from a configuration with this profile, and the key it trusts."""
    made = {}

    def build(profile: str, replay_mode: str = "check"):
        key = (profile, replay_mode)
        if key not in made:
            root = tmp_path / f"{profile}-{replay_mode}"
            config, signer = make_portal(
                root, issuer=ISSUER, profile=profile, verifier_id=VERIFIER, key_id="nw-1"
            )
            raw = json.loads(config.read_text())
            raw["replay_mode"] = replay_mode
            config.write_text(json.dumps(raw))
            made[key] = (load_portal(config), signer)
        return made[key]

    return build


def _v2(signer, *, audience=(VERIFIER,), issued_at=None):
    report = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    env = envelope_v2(
        "drift",
        report,
        signer=signer,
        deployment_id="profile-test",
        audience=list(audience) if audience is not None else None,
        issued_at=issued_at or datetime.now(timezone.utc),
        audit_run_id=str(uuid.uuid4()),
    )
    return parse_envelope_strict(json.dumps(env.to_dict()))


def _v1(signer):
    report = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
    return parse_envelope_strict(json.dumps(envelope("drift", report, signer=signer).to_dict()))


def _broken(cache):
    def fails(*_args, **_kwargs):
        raise RuntimeError("the replay file cannot be used")

    cache.seen = fails
    cache.record = fails


# ----------------------------------------------------------------------------- only the three fixed profiles


def test_the_profiles_offered_are_exactly_the_three_the_engine_and_the_configuration_know():
    assert set(profiles.PROFILE_NAMES) == set(ENGINE_PROFILES)
    assert profiles.PROFILE_NAMES == config_module._PROFILES
    assert [p["name"] for p in profiles.guide()["profiles"]] == list(profiles.PROFILE_NAMES)
    with pytest.raises(KeyError):
        profiles.explain("custom")


def test_every_profile_has_a_title_a_summary_and_at_least_one_thing_it_does():
    for name in profiles.PROFILE_NAMES:
        shown = profiles.explain(name)
        assert shown["title"] and shown["summary"] and shown["does"], name


# ----------------------------------------------------------------------------- what all three do (COMMON)


def test_in_every_profile_a_report_from_an_enrolled_key_addressed_to_this_verifier_is_accepted(
    portal_for, profile
):
    portal, signer = portal_for(profile)
    assert verify(_v2(signer), portal.policy).trust_status == "TRUSTED"


def test_in_every_profile_a_key_that_is_not_in_the_trust_list_is_refused(portal_for, profile):
    portal, _ = portal_for(profile)
    stranger = rf.Signer.generate(issuer=ISSUER, key_id="nw-1")
    result = verify(_v2(stranger), portal.policy)
    assert result.trust_status == "INVALID"


def test_in_every_profile_a_report_naming_another_issuer_for_the_key_is_refused(
    portal_for, profile
):
    portal, signer = portal_for(profile)
    other = rf.Signer("Someone Else", signer.key_id, signer.private_key, signer.public_key)
    result = verify(_v2(other), portal.policy)
    assert "ISSUER_MISMATCH" in result.blocking_reasons


def test_in_every_profile_a_report_older_than_the_maximum_age_is_refused(portal_for, profile):
    portal, signer = portal_for(profile)
    old = _v2(signer, issued_at=datetime.now(timezone.utc) - timedelta(days=31))
    assert verify(old, portal.policy).blocking_reasons == ("REPORT_TOO_OLD",)


def test_in_every_profile_a_report_more_than_five_minutes_in_the_future_is_refused(
    portal_for, profile
):
    portal, signer = portal_for(profile)
    ahead = _v2(signer, issued_at=datetime.now(timezone.utc) + timedelta(minutes=6))
    assert verify(ahead, portal.policy).blocking_reasons == ("REPORT_FROM_FUTURE",)
    near = _v2(signer, issued_at=datetime.now(timezone.utc) + timedelta(minutes=4))
    assert verify(near, portal.policy).trust_status == "TRUSTED"


@pytest.mark.parametrize("status", ["retired", "compromised"])
def test_in_every_profile_a_key_marked_retired_or_compromised_is_refused(tmp_path, profile, status):
    entry = {"status": status}
    if status == "retired":
        entry["retired_at"] = "2099-01-01T00:00:00Z"  # retired in the future: still refused
    config, signer = make_portal(
        tmp_path / "p", issuer=ISSUER, profile=profile, verifier_id=VERIFIER, entry=entry
    )
    result = verify(_v2(signer), load_portal(config).policy)
    assert result.trust_status == "INVALID" and result.blocking_reasons


def test_the_text_for_every_profile_says_what_the_common_checks_are():
    for said in (
        "signed by a key in your trust list",
        "names the issuer the trust list gives for that key",
        "has not changed since it was signed",
        "older than your maximum report age",
        "more than five minutes in the future",
        "retired or compromised is refused",
    ):
        assert said in profiles.COMMON, said


# ----------------------------------------------------------------------------- confidential


def test_confidential_refuses_a_report_addressed_to_others_and_accepts_one_addressed_to_nobody(
    portal_for,
):
    portal, signer = portal_for("confidential")
    assert verify(_v2(signer, audience=("someone-else",)), portal.policy).blocking_reasons == (
        "AUDIENCE_MISMATCH",
    )
    assert verify(_v2(signer, audience=None), portal.policy).trust_status == "TRUSTED"


@pytest.mark.parametrize("profile_name", ["confidential", "high-assurance"])
@pytest.mark.parametrize("mode", ["check", "record"])
def test_confidential_and_high_assurance_refuse_when_the_replay_file_cannot_be_used(
    portal_for, profile_name, mode
):
    portal, signer = portal_for(profile_name, mode)
    _broken(portal.policy.replay_cache)
    assert verify(_v2(signer), portal.policy).blocking_reasons == ("REPLAY_STATE_UNAVAILABLE",)


def test_confidential_refuses_a_v1_report_because_it_has_no_run_identifier(portal_for):
    portal, signer = portal_for("confidential")
    result = verify(_v1(signer), portal.policy)
    assert result.blocking_reasons == ("REPLAY_ID_MISSING",)


@pytest.mark.parametrize("profile_name", ["confidential", "high-assurance"])
def test_confidential_and_high_assurance_need_a_trust_list_a_maximum_age_and_a_replay_file_on_disk(
    profile_name,
):
    signer = rf.Signer.generate(issuer=ISSUER, key_id="nw-1")
    store = TrustStore.from_dict(
        {"entries": {"nw-1": {"issuer": ISSUER, "public_key_pem": signer.public_key_pem(), "status": "active"}}}
    )  # fmt: skip
    with pytest.raises(PolicyError, match="requires a trust store"):
        VerificationPolicy(profile=profile_name, verifier_id=VERIFIER)
    with pytest.raises(PolicyError, match="requires max_age"):
        VerificationPolicy(profile=profile_name, trust_store=store, verifier_id=VERIFIER)
    with pytest.raises(PolicyError, match="requires replay checking"):
        VerificationPolicy(
            profile=profile_name, trust_store=store, verifier_id=VERIFIER, max_age=timedelta(days=1)
        )


def test_the_portal_always_provides_what_the_engine_requires(portal_for, profile):
    portal, _ = portal_for(profile)
    policy = portal.policy
    assert policy.trust_store is not None and policy.max_age is not None
    assert policy.replay_mode in ("check", "record") and policy.replay_cache is not None
    assert getattr(policy.replay_cache, "durable", False) is True
    assert policy.verifier_id == VERIFIER and policy.check_provenance is True
    assert policy.allow_self_signed is False and policy.timestamp_verifier is None


# ----------------------------------------------------------------------------- high-assurance


def test_high_assurance_refuses_a_report_that_names_no_recipient(portal_for):
    portal, signer = portal_for("high-assurance")
    assert verify(_v2(signer, audience=None), portal.policy).blocking_reasons == (
        "AUDIENCE_MISMATCH",
    )
    assert verify(_v2(signer), portal.policy).trust_status == "TRUSTED"


def test_high_assurance_refuses_every_v1_report_for_its_format(portal_for):
    portal, signer = portal_for("high-assurance")
    assert "LEGACY_V1_FORMAT" in verify(_v1(signer), portal.policy).blocking_reasons


def test_high_assurance_does_not_add_what_its_text_says_0_2_1_does_not_have(portal_for):
    """No authenticated trust list, no shared replay record and no required timestamp: the policy has none of them."""
    portal, signer = portal_for("high-assurance")
    policy = portal.policy
    assert policy.trust_history is None and policy.require_verified_timestamp is False
    assert policy.replay_cache.scope == "LOCAL_PERSISTENT"
    result = verify(_v2(signer), policy)
    assert result.trust_status == "TRUSTED" and result.trust_history == "UNPROVEN"
    assert result.timestamp_status == "ABSENT" and result.replay_scope == "LOCAL_PERSISTENT"


# ----------------------------------------------------------------------------- development


def test_development_does_not_refuse_when_the_replay_file_cannot_be_used_and_notes_it(portal_for):
    portal, signer = portal_for("development")
    _broken(portal.policy.replay_cache)
    result = verify(_v2(signer), portal.policy)
    assert result.trust_status == "TRUSTED"
    assert "REPLAY_STATE_UNAVAILABLE" in result.reasons and not result.blocking_reasons


def test_development_does_not_refuse_a_v1_report_for_lacking_a_run_identifier(portal_for):
    portal, signer = portal_for("development")
    result = verify(_v1(signer), portal.policy)
    assert (
        "REPLAY_ID_MISSING" in result.reasons and "REPLAY_ID_MISSING" not in result.blocking_reasons
    )


def test_development_still_needs_the_verifier_id_in_a_named_audience(portal_for):
    portal, signer = portal_for("development")
    assert verify(_v2(signer, audience=("someone-else",)), portal.policy).blocking_reasons == (
        "AUDIENCE_MISMATCH",
    )
    assert verify(_v2(signer, audience=None), portal.policy).trust_status == "TRUSTED"


def test_only_development_allows_the_engines_development_options(tmp_path, profile):
    config, _ = make_portal(tmp_path / "p", issuer=ISSUER, profile=profile, verifier_id=VERIFIER)
    raw = json.loads(config.read_text())
    raw["allow_self_signed"] = True
    config.write_text(json.dumps(raw))
    if profile == "development":
        load_portal(config)
    else:
        with pytest.raises(config_module.ConfigProblem, match="development-only"):
            load_portal(config)


def test_every_result_under_development_says_not_to_rely_on_it(tmp_path):
    from helpers import client_for, post_bytes, signed_report

    config, signer = make_portal(
        tmp_path / "p", issuer=ISSUER, profile="development", verifier_id=VERIFIER
    )
    body = post_bytes(client_for(config), signed_report(signer, audience=(VERIFIER,))).json()
    warnings = {w["code"]: w["message"] for w in body["explanation"]["warnings"]}
    assert "Do not rely on this result" in warnings["DEVELOPMENT_PROFILE"]
    assert (
        "Every result on this portal then says not to rely on it."
        in profiles.explain("development")["does"]
    )


# ----------------------------------------------------------------------------- replay modes


def test_check_mode_records_nothing_and_refuses_a_report_recorded_earlier(portal_for):
    portal, signer = portal_for("confidential", "check")
    env = _v2(signer)
    first, second = verify(env, portal.policy), verify(env, portal.policy)
    assert first.trust_status == second.trust_status == "TRUSTED"
    assert first.consumption == "CHECKED_NOT_CONSUMED"
    portal.policy.replay_cache.record(
        signer.key_id, env.audit_run_id, now=datetime.now(timezone.utc), retain=timedelta(days=31)
    )
    assert verify(env, portal.policy).blocking_reasons == ("REPLAY_DETECTED",)


def test_record_mode_records_an_accepted_report_and_refuses_it_the_second_time(portal_for):
    portal, signer = portal_for("confidential", "record")
    env = _v2(signer)
    assert verify(env, portal.policy).consumption == "RECORDED_LOCAL"
    assert verify(env, portal.policy).blocking_reasons == ("REPLAY_DETECTED",)


def test_the_replay_texts_name_both_modes_and_only_those():
    assert [m["name"] for m in profiles.guide()["replay_modes"]] == ["check", "record"]
    assert "nothing new is recorded" in profiles.replay_text("check")
    assert "refused as a repeat" in profiles.replay_text("record")


def test_no_profile_summary_invites_reliance_and_each_says_where_it_stands():
    for name in profiles.PROFILE_NAMES:
        summary = profiles.explain(name)["summary"]
        assert "rely on" not in summary.replace("Do not rely on", ""), name
    assert profiles.explain("confidential")["summary"].startswith("Between the other two")
    assert profiles.explain("high-assurance")["summary"].startswith("The strictest of the three")
