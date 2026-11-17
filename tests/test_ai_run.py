"""``ai_run`` evidence: an issuer's signed statement about one AI evaluation run.

The verifier checks the signature, the trust relationship and that the statement is internally consistent.
It does not check that the model, the dataset or the metric exist or are true.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone

import pytest

import regaudit_fhe as rf
from regaudit_fhe.ai_run import (
    CLAIM_KINDS,
    PRIMITIVE,
    ai_run_envelope,
    validate_result,
)
from regaudit_fhe.report_v2 import AuditEnvelopeV2, EnvelopeFormatError, parse_envelope_strict
from regaudit_fhe.trust import TrustStore

ISSUED = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
MODEL = "a" * 64
DATA = "b" * 64


def _signer():
    return rf.Signer.generate(issuer="eval-lab", key_id="lab-1")


def _store(signer, **over):
    entry = {"issuer": signer.issuer, "public_key_pem": signer.public_key_pem(), "status": "active"}
    entry.update(over)
    return TrustStore.from_dict({"entries": {signer.key_id: entry}})


def _kwargs(**over):
    base = dict(
        deployment_id="lab-prod",
        issued_at=ISSUED,
        subject={"name": "model-x", "sha256": MODEL},
        inputs=[{"role": "evaluation_dataset", "name": "holdout", "sha256": DATA}],
        claims=[
            {
                "kind": "evaluation_metric",
                "metric": "accuracy",
                "value": 0.93,
                "unit": "fraction",
                "method": "top-1 on the holdout set, one run",
                "dataset": "holdout",
            }
        ],
        environment={"framework": "torch 2.5"},
    )
    base.update(over)
    return base


def _env(signer=None, **over) -> AuditEnvelopeV2:
    return ai_run_envelope(signer=signer or _signer(), **_kwargs(**over))


def test_primitive_name_and_claim_kinds():
    assert PRIMITIVE == "ai_run"
    assert CLAIM_KINDS == ("evaluation_metric",)


def test_builds_a_signed_v2_envelope_with_no_regulation_mapping():
    env = _env()
    assert env.primitive == "ai_run"
    assert env.regulations == []  # evidence supports nothing by name; no regulation is claimed
    assert env.model_commitment == {"name": "model-x", "sha256": MODEL}
    assert env.result["claims"][0]["value"] == 0.93


def test_round_trips_through_the_strict_parser():
    env = _env()
    again = parse_envelope_strict(json.dumps(env.to_dict()))
    assert isinstance(again, AuditEnvelopeV2)
    assert again.to_dict() == env.to_dict()


def test_a_trusted_issuer_is_accepted_and_only_as_attribution():
    s = _signer()
    out = rf.verify_trusted(json.dumps(_env(s).to_dict()), _store(s, primitives=["ai_run"]))
    assert out.trusted
    assert out.result.primitive == "ai_run"


def test_a_stranger_is_not_trusted():
    out = rf.verify_trusted(json.dumps(_env().to_dict()), _store(_signer()))
    assert not out.trusted


def test_changed_value_after_signing_is_not_trusted():
    s = _signer()
    doc = _env(s).to_dict()
    doc["result"]["claims"][0]["value"] = 0.99
    out = rf.verify_trusted(json.dumps(doc), _store(s, primitives=["ai_run"]))
    assert not out.trusted


def test_an_entry_scoped_to_other_primitives_cannot_issue_ai_run():
    s = _signer()
    out = rf.verify_trusted(json.dumps(_env(s).to_dict()), _store(s, primitives=["fairness"]))
    assert not out.trusted


def test_an_unscoped_entry_cannot_issue_ai_run():
    # An entry with no primitive scope means "every audit primitive". It must not silently
    # extend to issuer statements, which are a different kind of claim.
    s = _signer()
    out = rf.verify_trusted(json.dumps(_env(s).to_dict()), _store(s))
    assert not out.trusted
    assert "PRIMITIVE_NOT_ALLOWED" in out.reasons


def test_an_entry_scoped_to_ai_run_is_accepted():
    s = _signer()
    out = rf.verify_trusted(json.dumps(_env(s).to_dict()), _store(s, primitives=["ai_run"]))
    assert out.trusted


# ---- the result is a closed vocabulary --------------------------------------------------------------


def _result():
    return copy.deepcopy(_env().result)


def test_valid_result_passes():
    assert validate_result(_result())["ai_run_version"] == "regaudit-fhe.ai-run.v1"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(extra=1),
        lambda r: r.pop("claims"),
        lambda r: r.update(claims=[]),
        lambda r: r.update(ai_run_version="other"),
        lambda r: r.update(statement="the verifier checked this"),
        lambda r: r["subject"].update(sha256="short"),
        lambda r: r["subject"].update(sha256=MODEL.upper()),
        lambda r: r["subject"].update(extra="x"),
        lambda r: r["inputs"][0].update(role="secret_role"),
        lambda r: r["inputs"][0].update(sha256="z" * 64),
        lambda r: r["claims"][0].update(kind="certification"),
        lambda r: r["claims"][0].update(extra="x"),
        lambda r: r["claims"][0].update(value=float("nan")),
        lambda r: r["claims"][0].update(value=float("inf")),
        lambda r: r["claims"][0].update(value=True),
        lambda r: r["claims"][0].update(value="0.9"),
        lambda r: r["claims"][0].update(metric=""),
        lambda r: r["claims"][0].update(metric="m" * 200),
        lambda r: r["claims"][0].update(method="m" * 5000),
        lambda r: r["claims"][0].update(dataset="nonexistent"),
        lambda r: r["claims"].append(copy.deepcopy(r["claims"][0])),  # duplicate metric+dataset
        lambda r: r["inputs"].append(copy.deepcopy(r["inputs"][0])),  # duplicate input name
        lambda r: r["environment"].update({"k": 1}),
        lambda r: r.update(environment={f"k{i}": "v" for i in range(40)}),
        lambda r: r.update(claims=[{**r["claims"][0], "metric": f"m{i}"} for i in range(70)]),
    ],
)
def test_malformed_results_are_refused(mutate):
    r = _result()
    mutate(r)
    with pytest.raises(EnvelopeFormatError):
        validate_result(r)


def test_claim_dataset_must_be_an_evaluation_dataset():
    r = _result()
    r["inputs"][0]["role"] = "configuration"
    with pytest.raises(EnvelopeFormatError):
        validate_result(r)


def test_model_commitment_must_match_the_subject():
    doc = _env().to_dict()
    doc["model_commitment"] = {"name": "model-x", "sha256": "c" * 64}
    with pytest.raises(EnvelopeFormatError):
        parse_envelope_strict(json.dumps(doc))


def test_ai_run_cannot_carry_dp_or_regulations_claims():
    doc = _env().to_dict()
    doc["dp"] = {"epsilon": 1}
    with pytest.raises(EnvelopeFormatError):
        parse_envelope_strict(json.dumps(doc))


def test_unknown_claim_kind_is_refused_when_built():
    with pytest.raises(EnvelopeFormatError):
        _env(claims=[{**_kwargs()["claims"][0], "kind": "safety_certification"}])


def test_existing_primitives_are_unchanged():
    from regaudit_fhe.schemas import PRIMITIVES

    assert "ai_run" not in PRIMITIVES
    assert len(PRIMITIVES) == 6
