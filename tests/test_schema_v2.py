"""The report.v2 JSON Schema agrees with the strict parser."""

from __future__ import annotations

import copy
from datetime import datetime, timezone

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe.report_v2 import AuditEnvelopeV2, EnvelopeFormatError, envelope_v2

ISSUED = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _env(**kw) -> AuditEnvelopeV2:
    report = rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )
    signer = rf.Signer.generate(issuer="acme", key_id="k1")
    return envelope_v2(
        "fairness", report, signer=signer, deployment_id="prod", issued_at=ISSUED, **kw
    )


def test_v2_schema_is_listed_and_loadable():
    assert "envelope.v2" in rf.list_schemas()
    schema = rf.load_schema("envelope.v2")
    assert schema["properties"]["schema"]["const"] == "regaudit-fhe.report.v2"
    assert "$id" in schema and "title" in schema


def test_v1_schema_is_unchanged_and_still_v1():
    assert rf.load_schema("envelope")["properties"]["schema"]["const"] == "regaudit-fhe.report.v1"


def test_real_v2_envelope_passes_the_schema():
    env = _env(
        audience=["reg"],
        model_commitment={"name": "m", "sha256": "a" * 64},
        dataset_commitment={"name": "d", "sha256": "b" * 64},
    ).with_timestamp(issuer="t", token=b"tok", issued_at=ISSUED)
    rf.validate_envelope_v2(env.to_dict())
    rf.validate_envelope_v2(_env().to_dict())  # optional fields absent


def test_v2_envelope_does_not_validate_against_the_v1_schema_and_vice_versa():
    with pytest.raises(rf.SchemaError):
        rf.validate_envelope(_env().to_dict())
    signer = rf.Signer.generate(issuer="acme", key_id="k1")
    v1 = rf.envelope(
        "fairness",
        rf.audit_fairness(
            np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([0.0, 1.0])
        ),
        signer=signer,
    )
    with pytest.raises(rf.SchemaError):
        rf.validate_envelope_v2(v1.to_dict())


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.update(extra=1),
        lambda d: d["receipt"].update(key_id="k1"),
        lambda d: d.pop("key_id"),
        lambda d: d.pop("deployment_id"),
        lambda d: d.update(audit_run_id="3F2B1C4E-5A6D-4E7F-8091-A2B3C4D5E6F7"),
        lambda d: d.update(public_key_fingerprint="A" * 64),
        lambda d: d.update(audience=[]),
        lambda d: d.update(audience=["a", "a"]),
        lambda d: d.update(trust_policy_version=-1),
        lambda d: d.update(model_commitment={"name": "m"}),
        lambda d: d.update(schema="regaudit-fhe.report.v1"),
        lambda d: d.update(issued_at="2026-10-01 12:00:00+00:00"),
        lambda d: d.update(timestamps=[{"issuer": "t"}]),
    ],
)
def test_schema_and_parser_refuse_the_same_defects(mutation):
    data = copy.deepcopy(_env().to_dict())
    rf.validate_envelope_v2(data)  # control
    mutation(data)
    with pytest.raises(rf.SchemaError):
        rf.validate_envelope_v2(data)
    with pytest.raises(EnvelopeFormatError):
        AuditEnvelopeV2.from_dict(data)
