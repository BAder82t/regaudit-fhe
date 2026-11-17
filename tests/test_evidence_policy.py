"""Buyer-side policy checks over verified ``ai_run`` evidence. Policy is separate from trust."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

import regaudit_fhe as rf
from regaudit_fhe.ai_run import ai_run_envelope
from regaudit_fhe.evidence_policy import (
    EvidencePolicy,
    PolicyFormatError,
    evaluate_evidence,
    parse_policy,
)
from regaudit_fhe.trust import TrustStore

ISSUED = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
NOW = ISSUED + timedelta(days=10)
MODEL = "a" * 64
DATA = "b" * 64


def _signer(issuer="eval-lab", key_id="lab-1"):
    return rf.Signer.generate(issuer=issuer, key_id=key_id)


def _store(*signers):
    return TrustStore.from_dict(
        {
            "entries": {
                s.key_id: {
                    "issuer": s.issuer,
                    "public_key_pem": s.public_key_pem(),
                    "status": "active",
                    "primitives": ["ai_run", "fairness"],
                }
                for s in signers
            }
        }
    )


def _report(signer, value=0.93, unit="fraction", metric="accuracy", issued=ISSUED):
    env = ai_run_envelope(
        signer=signer,
        deployment_id="lab-prod",
        issued_at=issued,
        subject={"name": "model-x", "sha256": MODEL},
        inputs=[{"role": "evaluation_dataset", "name": "holdout", "sha256": DATA}],
        claims=[
            {
                "kind": "evaluation_metric",
                "metric": metric,
                "value": value,
                "unit": unit,
                "method": "top-1, one run",
                "dataset": "holdout",
            }
        ],
    )
    return json.dumps(env.to_dict())


def _policy(**over):
    base = {
        "policy_version": 1,
        "require": [
            {
                "kind": "evaluation_metric",
                "metric": "accuracy",
                "comparison": ">=",
                "threshold": 0.9,
            }
        ],
    }
    base.update(over)
    return parse_policy(base)


def _run(report, policy, store, **kw):
    return evaluate_evidence(report, store, policy, now=NOW, **kw)


def test_accept_when_trusted_and_every_rule_holds():
    s = _signer()
    d = _run(_report(s), _policy(), _store(s))
    assert d.accepted and d.reasons == ()


def test_reject_when_the_issuer_is_not_trusted():
    d = _run(_report(_signer()), _policy(), _store(_signer(key_id="other")))
    assert not d.accepted and "NOT_TRUSTED" in d.reasons


def test_reject_when_threshold_not_met():
    s = _signer()
    d = _run(_report(s, value=0.8), _policy(), _store(s))
    assert not d.accepted and d.reasons == ("RULE_0_THRESHOLD_NOT_MET",)


@pytest.mark.parametrize(
    "cmp,thr,value,ok",
    [
        (">=", 0.9, 0.9, True),
        (">", 0.9, 0.9, False),
        ("<=", 0.1, 0.1, True),
        ("<", 0.1, 0.1, False),
        ("==", 0.5, 0.5, True),
        ("==", 0.5, 0.6, False),
    ],
)
def test_comparison_directions(cmp, thr, value, ok):
    s = _signer()
    p = _policy(
        require=[
            {"kind": "evaluation_metric", "metric": "accuracy", "comparison": cmp, "threshold": thr}
        ]
    )
    assert _run(_report(s, value=value), p, _store(s)).accepted is ok


def test_missing_metric_is_a_failed_rule():
    s = _signer()
    d = _run(_report(s, metric="f1"), _policy(), _store(s))
    assert d.reasons == ("RULE_0_CLAIM_MISSING",)


def test_unit_mismatch():
    s = _signer()
    p = _policy(
        require=[
            {
                "kind": "evaluation_metric",
                "metric": "accuracy",
                "unit": "percent",
                "comparison": ">=",
                "threshold": 90,
            }
        ]
    )
    assert _run(_report(s), p, _store(s)).reasons == ("RULE_0_UNIT_MISMATCH",)


def test_dataset_digest_must_match_when_given():
    s = _signer()
    rule = {"kind": "evaluation_metric", "metric": "accuracy", "comparison": ">=", "threshold": 0.9}
    ok = _policy(require=[{**rule, "dataset_sha256": DATA}])
    bad = _policy(require=[{**rule, "dataset_sha256": "c" * 64}])
    assert _run(_report(s), ok, _store(s)).accepted
    assert _run(_report(s), bad, _store(s)).reasons == ("RULE_0_CLAIM_MISSING",)


def test_issuer_allow_list():
    s = _signer()
    assert _run(_report(s), _policy(allowed_issuers=["eval-lab"]), _store(s)).accepted
    d = _run(_report(s), _policy(allowed_issuers=["someone-else"]), _store(s))
    assert d.reasons == ("ISSUER_NOT_ALLOWED",)


def test_key_allow_list():
    s = _signer()
    assert _run(_report(s), _policy(allowed_key_ids=["lab-1"]), _store(s)).accepted
    assert _run(_report(s), _policy(allowed_key_ids=["lab-2"]), _store(s)).reasons == (
        "KEY_NOT_ALLOWED",
    )


def test_max_age():
    s = _signer()
    assert _run(_report(s), _policy(max_age_days=30), _store(s)).accepted
    assert _run(_report(s), _policy(max_age_days=5), _store(s)).reasons == ("TOO_OLD",)


def test_future_dated_evidence_is_refused():
    s = _signer()
    r = _report(s, issued=NOW + timedelta(days=2))
    assert "FUTURE_DATED" in _run(r, _policy(max_age_days=30), _store(s)).reasons


def test_subject_digest_equality():
    s = _signer()
    assert _run(_report(s), _policy(subject_sha256=MODEL), _store(s)).accepted
    assert _run(_report(s), _policy(subject_sha256="c" * 64), _store(s)).reasons == (
        "SUBJECT_MISMATCH",
    )


def test_several_failures_give_one_code_each():
    s = _signer()
    p = _policy(
        allowed_issuers=["x"],
        require=[
            {
                "kind": "evaluation_metric",
                "metric": "accuracy",
                "comparison": ">=",
                "threshold": 0.99,
            },
            {"kind": "evaluation_metric", "metric": "f1", "comparison": ">=", "threshold": 0.5},
        ],
    )
    d = _run(_report(s), p, _store(s))
    assert d.reasons == ("ISSUER_NOT_ALLOWED", "RULE_0_THRESHOLD_NOT_MET", "RULE_1_CLAIM_MISSING")


def test_a_report_of_another_primitive_is_refused():
    s = _signer()
    import numpy as np

    env = rf.envelope_v2(
        "fairness",
        rf.audit_fairness(
            np.array([1.0, 0.0, 1.0, 0.0]),
            np.array([1.0, 0.0, 0.0, 0.0]),
            np.array([1.0, 1.0, 0.0, 0.0]),
            np.array([0.0, 0.0, 1.0, 1.0]),
        ),
        signer=s,
        deployment_id="d",
        issued_at=ISSUED,
    )
    d = _run(json.dumps(env.to_dict()), _policy(), _store(s))
    assert not d.accepted and "WRONG_PRIMITIVE" in d.reasons


def test_malformed_report_is_a_rejection_not_an_exception():
    d = _run("{not json", _policy(), _store(_signer()))
    assert not d.accepted and "NOT_TRUSTED" in d.reasons


def test_a_policy_cannot_enrol_an_issuer():
    # allowed_issuers is a filter over trusted issuers; it never adds trust.
    s = _signer()
    d = _run(_report(s), _policy(allowed_issuers=["eval-lab"]), _store(_signer(key_id="other")))
    assert not d.accepted and "NOT_TRUSTED" in d.reasons


# ---- the policy file is strict ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"policy_version": 2, "require": []},
        {"policy_version": 1},
        {"policy_version": 1, "require": []},
        {
            "policy_version": 1,
            "require": [
                {"kind": "evaluation_metric", "metric": "a", "comparison": "~", "threshold": 1}
            ],
        },
        {
            "policy_version": 1,
            "require": [
                {"kind": "evaluation_metric", "metric": "a", "comparison": ">=", "threshold": "1"}
            ],
        },
        {
            "policy_version": 1,
            "require": [
                {"kind": "evaluation_metric", "metric": "a", "comparison": ">=", "threshold": True}
            ],
        },
        {
            "policy_version": 1,
            "require": [
                {
                    "kind": "evaluation_metric",
                    "metric": "a",
                    "comparison": ">=",
                    "threshold": float("nan"),
                }
            ],
        },
        {
            "policy_version": 1,
            "require": [{"kind": "other", "metric": "a", "comparison": ">=", "threshold": 1}],
        },
        {
            "policy_version": 1,
            "require": [
                {
                    "kind": "evaluation_metric",
                    "metric": "a",
                    "comparison": ">=",
                    "threshold": 1,
                    "x": 1,
                }
            ],
        },
        {
            "policy_version": 1,
            "unknown": 1,
            "require": [
                {"kind": "evaluation_metric", "metric": "a", "comparison": ">=", "threshold": 1}
            ],
        },
        {
            "policy_version": 1,
            "allowed_issuers": [],
            "require": [
                {"kind": "evaluation_metric", "metric": "a", "comparison": ">=", "threshold": 1}
            ],
        },
        {
            "policy_version": 1,
            "max_age_days": 0,
            "require": [
                {"kind": "evaluation_metric", "metric": "a", "comparison": ">=", "threshold": 1}
            ],
        },
        {
            "policy_version": 1,
            "subject_sha256": "short",
            "require": [
                {"kind": "evaluation_metric", "metric": "a", "comparison": ">=", "threshold": 1}
            ],
        },
    ],
)
def test_bad_policies_are_refused_never_defaulted(doc):
    with pytest.raises(PolicyFormatError):
        parse_policy(doc)


def test_policy_text_with_duplicate_keys_is_refused():
    with pytest.raises(PolicyFormatError):
        parse_policy('{"policy_version": 1, "policy_version": 1, "require": []}')


def test_policy_parses_from_text():
    p = parse_policy(
        json.dumps(
            {
                "policy_version": 1,
                "require": [
                    {"kind": "evaluation_metric", "metric": "a", "comparison": ">=", "threshold": 1}
                ],
            }
        )
    )
    assert isinstance(p, EvidencePolicy)


def test_policy_must_be_an_evidence_policy_object():
    with pytest.raises(TypeError):
        evaluate_evidence("{}", _store(_signer()), {"policy_version": 1}, now=NOW)  # type: ignore[arg-type]
