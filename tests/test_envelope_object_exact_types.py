"""An envelope object is untrusted input to ``verify_report``. Under a strict profile every field must be what a JSON parser
would have produced, before any of them is compared.

A ``str`` subclass serialises to its real characters, so the signature still verifies, while its ``!=`` can say what it likes. An
envelope subclass or an instance attribute can replace what is signed. ``object.__setattr__`` and other malicious code in the verifier's
process are outside the guarantee, and not tested here.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe import _revocation_gate as gate
from regaudit_fhe import _revocation_state as st
from regaudit_fhe.replay import SqliteReplayCache, replay_file_status
from regaudit_fhe.report_v2 import (
    AuditEnvelopeV2,
    envelope_v2,
    parse_envelope,
    parse_envelope_strict,
)
from regaudit_fhe.reports import AuditEnvelope
from regaudit_fhe.verification import VerificationPolicy, verify

STRICT = ("confidential", "high-assurance", "secure-v1")
T = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
BOB = rf.Signer.generate(issuer="bob-lab", key_id="bob-1")
FORGED = rf.Signer(issuer="alice-bank", key_id="bob-1", private_key=BOB.private_key, public_key=BOB.public_key)
PEM = BOB.public_key_pem()
RESULT = rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6]))
RUN = "3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6b1"


def _pin_hash() -> str:
    return v2(BOB).parameter_set_hash


def v2(who=BOB, **kw) -> AuditEnvelopeV2:
    args = {"deployment_id": "p", "audience": ("reg",), "issued_at": T, "audit_run_id": RUN, **kw}
    return envelope_v2("drift", RESULT, signer=who, **args)


def store(**entry) -> rf.TrustStore:
    return rf.TrustStore.from_dict(
        {"entries": {"bob-1": {"issuer": "bob-lab", "public_key_pem": PEM, "status": "active", **entry}}}
    )


def strict(profile: str, tmp_path: Path, trust=None) -> VerificationPolicy:
    return VerificationPolicy(
        profile=profile, trust_store=trust or store(), now=lambda: T, max_age=timedelta(hours=1), verifier_id="reg",
        replay_mode="record", replay_cache=SqliteReplayCache(tmp_path / f"{profile}.db"),
    )  # fmt: skip


class Agreeable(str):
    """Serialises as itself, and says it equals whatever it is compared with."""

    __slots__ = ()

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

    __hash__ = str.__hash__


class AlwaysIn(list):
    def __contains__(self, item):
        return True


class Quiet(dict):
    """A dict that says the receipt's digest and signature are whatever is asked."""

    def get(self, key, default=None):
        return super().get(key, default)


class Int(int):
    pass


class Float(float):
    pass


# name -> build the hostile object from an honest forged signature
FIELD_ATTACKS = {
    "issuer": lambda e: dataclasses.replace(e, issuer=Agreeable(e.issuer)),
    "key_id": lambda e: dataclasses.replace(e, key_id=Agreeable(e.key_id)),
    "public_key_fingerprint": lambda e: dataclasses.replace(e, public_key_fingerprint=Agreeable(e.public_key_fingerprint)),
    "deployment_id": lambda e: dataclasses.replace(e, deployment_id=Agreeable(e.deployment_id)),
    "primitive": lambda e: dataclasses.replace(e, primitive=Agreeable(e.primitive)),
    "parameter_set_hash": lambda e: dataclasses.replace(e, parameter_set_hash=Agreeable(e.parameter_set_hash)),
    "audit_run_id": lambda e: dataclasses.replace(e, audit_run_id=Agreeable(e.audit_run_id)),
    "issued_at": lambda e: dataclasses.replace(e, issued_at=Agreeable(e.issued_at)),
    "schema": lambda e: dataclasses.replace(e, schema=Agreeable(e.schema)),
    "backend": lambda e: dataclasses.replace(e, backend=Agreeable(e.backend)),
    "audience": lambda e: dataclasses.replace(e, audience=AlwaysIn(e.audience)),
    "audience item": lambda e: dataclasses.replace(e, audience=[Agreeable("someone-else")]),
    "regulations": lambda e: dataclasses.replace(e, regulations=AlwaysIn(e.regulations)),
    "receipt": lambda e: dataclasses.replace(e, receipt=Quiet(e.receipt)),
    "receipt digest": lambda e: dataclasses.replace(e, receipt={**e.receipt, "sha256": Agreeable("0" * 64)}),
    "receipt key": lambda e: dataclasses.replace(e, receipt={**e.receipt, "public_key_pem": Agreeable(PEM)}),
    "parameter_set": lambda e: dataclasses.replace(e, parameter_set=Quiet(e.parameter_set)),
    "parameter_set value": lambda e: dataclasses.replace(
        e, parameter_set={**e.parameter_set, "backend": Agreeable(e.parameter_set["backend"])}
    ),
    "result": lambda e: dataclasses.replace(e, result=Quiet(e.result)),
    "depth_budget value": lambda e: dataclasses.replace(
        e, depth_budget={k: Int(v) for k, v in e.depth_budget.items()}
    ),
    "trust_policy_version": lambda e: dataclasses.replace(e, trust_policy_version=Int(e.trust_policy_version)),
    "result float": lambda e: dataclasses.replace(e, result={**e.result, "planted": Float(1.5)}),
    "timestamps": lambda e: dataclasses.replace(e, timestamps=AlwaysIn(e.timestamps)),
}


def test_the_finding_a_substituted_issuer_through_a_str_subclass_is_refused(tmp_path):
    hostile = dataclasses.replace(v2(FORGED), issuer=Agreeable("alice-bank"))
    for profile in STRICT:
        res = verify(hostile, strict(profile, tmp_path))
        assert not res.accepted and not res.issuer_trusted
        assert res.blocking_reasons == ("MALFORMED_ENVELOPE",)  # the object check, not the issuer check
        assert res.consumption == "NOT_CHECKED"
        assert res.issuer == ""  # nothing from the object is repeated


@pytest.mark.parametrize("name", sorted(FIELD_ATTACKS))
@pytest.mark.parametrize("profile", STRICT)
def test_no_field_may_be_a_substituted_type(name, profile, tmp_path):
    hostile = FIELD_ATTACKS[name](v2(BOB))
    res = verify(hostile, strict(profile, tmp_path))
    assert not res.accepted and res.blocking_reasons == ("MALFORMED_ENVELOPE",), name
    assert replay_file_status(tmp_path / f"{profile}.db")["rows"] == 0  # refused before the replay store is touched


@pytest.mark.parametrize("profile", STRICT)
def test_an_issuer_scope_cannot_be_answered_by_the_object(profile, tmp_path):
    trust = store(deployments=["other"], primitives=["fairness"], parameter_set_pin="0" * 64)
    hostile = dataclasses.replace(
        v2(BOB), deployment_id=Agreeable("p"), primitive=Agreeable("drift"), parameter_set_hash=Agreeable(_pin_hash())
    )
    assert verify(hostile, strict(profile, tmp_path, trust)).blocking_reasons == ("MALFORMED_ENVELOPE",)


class ReplacesWhatIsSigned(AuditEnvelopeV2):
    """Presents an honest body to the signature check and another identity to the reader."""

    def signed_body(self):
        return honest_body()


def honest_body():
    return v2(BOB).signed_body()


@pytest.mark.parametrize("profile", STRICT)
def test_an_envelope_subclass_is_refused(profile, tmp_path):
    fields = {f.name: getattr(v2(BOB), f.name) for f in dataclasses.fields(AuditEnvelopeV2)}
    hostile = ReplacesWhatIsSigned(**{**fields, "issuer": "alice-bank"})
    assert verify(hostile, strict(profile, tmp_path)).blocking_reasons == ("MALFORMED_ENVELOPE",)


@pytest.mark.parametrize("profile", STRICT)
def test_an_instance_attribute_cannot_replace_a_method(profile, tmp_path):
    hostile = v2(FORGED)
    honest = v2(BOB)
    hostile.__dict__["signing_input"] = honest.signing_input
    assert verify(hostile, strict(profile, tmp_path)).blocking_reasons == ("MALFORMED_ENVELOPE",)


@pytest.mark.parametrize("profile", STRICT)
def test_a_v1_object_is_held_to_the_same_rule(profile, tmp_path):
    env = rf.envelope("drift", RESULT, signer=FORGED)
    for hostile in (
        dataclasses.replace(env, issuer=Agreeable("alice-bank")),
        dataclasses.replace(env, receipt={**env.receipt, "key_id": Agreeable("bob-1")}),
        dataclasses.replace(env, regulations=AlwaysIn(env.regulations)),
    ):
        assert verify(hostile, strict(profile, tmp_path)).blocking_reasons == ("MALFORMED_ENVELOPE",)
    class Sub(AuditEnvelope):
        pass

    fields = {f.name: getattr(env, f.name) for f in dataclasses.fields(AuditEnvelope)}
    assert verify(Sub(**fields), strict(profile, tmp_path)).blocking_reasons == ("MALFORMED_ENVELOPE",)


@pytest.mark.parametrize("profile", ["confidential", "secure-v1"])
def test_a_revocation_mode_reaches_the_same_refusal(profile, tmp_path):
    hostile = dataclasses.replace(v2(FORGED), issuer=Agreeable("alice-bank"))
    ctx = gate.RevocationContext(gate.MODE_ADVISORY, st.FileStateStore(tmp_path / "state"), {})
    decision = gate.verify_with_revocation(hostile, strict(profile, tmp_path), ctx)
    assert not decision.result.accepted and decision.result.blocking_reasons == ("MALFORMED_ENVELOPE",)


def test_verify_trusted_was_already_safe_because_it_reparses():
    hostile = dataclasses.replace(v2(FORGED), issuer=Agreeable("alice-bank"))
    res = rf.verify_trusted(hostile, store())
    assert not res.trusted


# ------------------------------------------------------------------ what keeps working


@pytest.mark.parametrize("profile", STRICT)
def test_control_an_honest_object_from_the_builder_is_accepted(profile, tmp_path):
    res = verify(v2(BOB), strict(profile, tmp_path))
    assert res.accepted and res.issuer == "bob-lab"


@pytest.mark.parametrize("profile", STRICT)
def test_control_a_parsed_object_is_accepted_and_the_issuer_guard_still_decides(profile, tmp_path):
    text = json.dumps(v2(BOB).to_dict())
    assert verify(parse_envelope(text), strict(profile, tmp_path)).accepted
    forged = parse_envelope_strict(json.dumps(v2(FORGED, audit_run_id=RUN[:-1] + "2").to_dict()))
    assert verify(forged, strict(profile, tmp_path)).blocking_reasons == ("ISSUER_MISMATCH",)


@pytest.mark.parametrize("profile", STRICT)
def test_control_a_timestamped_object_is_accepted(profile, tmp_path):
    env = v2(BOB).with_timestamp(issuer="t", token=b"x", issued_at=T)
    assert verify(env, strict(profile, tmp_path)).accepted


@pytest.mark.parametrize("profile", STRICT)
def test_control_a_builder_v1_object_gets_its_usual_refusal(profile, tmp_path):
    env = rf.envelope("drift", RESULT, signer=BOB)
    assert "MALFORMED_ENVELOPE" not in verify(env, strict(profile, tmp_path)).blocking_reasons


def test_limit_development_is_not_covered():
    """The owner's ruling is for strict profiles. development and the lenient paths are unchanged, and verify_trusted reparses."""
    hostile = dataclasses.replace(v2(FORGED), issuer=Agreeable("alice-bank"))
    res = verify(hostile, VerificationPolicy(trust_store=store(), now=lambda: T))
    assert res.accepted and res.issuer == "alice-bank"
