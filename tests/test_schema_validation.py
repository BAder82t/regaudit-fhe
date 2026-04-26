"""JSON Schema validation tests."""

from __future__ import annotations

import json

import pytest

import regaudit_fhe as rf


# --------------------------------------------------------------------------
# 1. Bundled schemas load + enumerate
# --------------------------------------------------------------------------


def test_bundle_includes_thirteen_schemas():
    names = rf.list_schemas()
    assert "envelope" in names
    for primitive in ("fairness", "provenance", "concordance",
                      "calibration", "drift", "disagreement"):
        assert f"{primitive}.input" in names
        assert f"{primitive}.output" in names


def test_each_schema_has_id_and_title():
    for name in rf.list_schemas():
        schema = rf.load_schema(name)
        assert "$id" in schema, f"{name} missing $id"
        assert "$schema" in schema, f"{name} missing $schema"
        assert schema["$schema"].startswith(
            "https://json-schema.org/draft/2020-12/schema")
        assert "title" in schema, f"{name} missing title"


def test_unknown_schema_raises():
    with pytest.raises(KeyError):
        rf.load_schema("not.a.schema")


# --------------------------------------------------------------------------
# 2. Valid inputs pass
# --------------------------------------------------------------------------


VALID_INPUTS = {
    "fairness": {
        "y_true": [1, 0, 1, 0],
        "y_pred": [1, 0, 0, 0],
        "group_a": [1, 1, 0, 0],
        "group_b": [0, 0, 1, 1],
        "threshold": 0.1,
    },
    "provenance": {
        "attributions": [0.5, 0.7, 0.2, 0.9],
        "row_ids": [0, 1, 2, 3],
        "n_buckets": 4, "k": 2,
    },
    "concordance": {
        "risk":  [0.1, 0.5, 0.9],
        "time":  [10.0, 20.0, 30.0],
        "event": [1, 1, 0],
    },
    "calibration": {
        "scores": [0.1, 0.5, 0.9],
        "quantiles": [0.5, 0.5, 0.5],
    },
    "drift": {
        "p": [1.0, 2.0, 3.0, 4.0],
        "q": [2.0, 2.0, 3.0, 3.0],
        "drift_threshold": 0.005,
    },
    "disagreement": {
        "model_polynomials": [[0, 1, 0, 0], [0, 0.9, 0, 0], [0, 1.1, 0, 0]],
        "test_input": [-0.4, 0.0, 0.4],
        "threshold": 0.05,
    },
}


@pytest.mark.parametrize("primitive,payload",
                         list(VALID_INPUTS.items()))
def test_valid_input_passes_validation(primitive, payload):
    rf.validate_input(primitive, payload)


# --------------------------------------------------------------------------
# 3. Invalid inputs are rejected
# --------------------------------------------------------------------------


def test_unknown_field_rejected_by_additional_properties():
    payload = dict(VALID_INPUTS["fairness"])
    payload["evil_extra_field"] = 1
    with pytest.raises(rf.SchemaError, match="Additional properties"):
        rf.validate_input("fairness", payload)


def test_missing_required_field_rejected():
    payload = dict(VALID_INPUTS["fairness"])
    payload.pop("y_pred")
    with pytest.raises(rf.SchemaError, match="'y_pred' is a required property"):
        rf.validate_input("fairness", payload)


def test_non_binary_label_rejected():
    payload = dict(VALID_INPUTS["fairness"])
    payload["y_true"] = [1, 2, 3, 4]
    with pytest.raises(rf.SchemaError):
        rf.validate_input("fairness", payload)


def test_threshold_out_of_range_rejected():
    payload = dict(VALID_INPUTS["fairness"])
    payload["threshold"] = 5.0
    with pytest.raises(rf.SchemaError):
        rf.validate_input("fairness", payload)


def test_disagreement_short_polynomial_rejected_by_schema():
    payload = dict(VALID_INPUTS["disagreement"])
    payload["model_polynomials"] = [[0, 1, 0]] * 3
    with pytest.raises(rf.SchemaError):
        rf.validate_input("disagreement", payload)


def test_disagreement_too_few_models_rejected_by_schema():
    payload = dict(VALID_INPUTS["disagreement"])
    payload["model_polynomials"] = [[0, 1, 0, 0]] * 2
    with pytest.raises(rf.SchemaError):
        rf.validate_input("disagreement", payload)


def test_provenance_negative_row_id_rejected():
    payload = dict(VALID_INPUTS["provenance"])
    payload["row_ids"] = [-1, 1, 2, 3]
    with pytest.raises(rf.SchemaError):
        rf.validate_input("provenance", payload)


def test_calibration_score_array_must_be_nonempty():
    payload = dict(VALID_INPUTS["calibration"])
    payload["scores"] = []
    with pytest.raises(rf.SchemaError):
        rf.validate_input("calibration", payload)


# --------------------------------------------------------------------------
# 4. Envelope schema
# --------------------------------------------------------------------------


def _real_envelope_dict():
    import numpy as np
    y = np.array([1.0, 0.0, 1.0, 0.0])
    report = rf.audit_fairness(y, y, y, 1.0 - y)
    signer = rf.Signer.generate(issuer="acme", key_id="k1")
    params = rf.ParameterSet(backend="tenseal-ckks",
                             poly_modulus_degree=32768,
                             multiplicative_depth=6,
                             coeff_mod_bit_sizes=(60, 40, 40, 40, 40, 40, 40, 60),
                             scaling_factor_bits=40,
                             backend_version="0.3.16")
    env = rf.envelope("fairness", report, signer=signer,
                       parameter_set=params,
                       input_commitments=rf.commitments_for(
                           {"y_true": y}))
    return env.to_dict()


def test_real_envelope_passes_envelope_schema():
    rf.validate_envelope(_real_envelope_dict())


def test_envelope_with_unknown_primitive_rejected():
    body = _real_envelope_dict()
    body["primitive"] = "totally-fake"
    with pytest.raises(rf.SchemaError):
        rf.validate_envelope(body)


def test_envelope_with_bad_sha256_format_rejected():
    body = _real_envelope_dict()
    body["receipt"]["sha256"] = "not-hex"
    with pytest.raises(rf.SchemaError):
        rf.validate_envelope(body)


def test_envelope_with_wrong_signature_alg_rejected():
    body = _real_envelope_dict()
    body["receipt"]["signature_alg"] = "RSA"
    with pytest.raises(rf.SchemaError):
        rf.validate_envelope(body)


def test_envelope_with_extra_top_level_field_rejected():
    body = _real_envelope_dict()
    body["evil_field"] = "yes"
    with pytest.raises(rf.SchemaError):
        rf.validate_envelope(body)


def test_envelope_with_security_below_128_rejected():
    body = _real_envelope_dict()
    body["parameter_set"]["security_bits"] = 64
    with pytest.raises(rf.SchemaError):
        rf.validate_envelope(body)


def test_envelope_with_depth_above_six_rejected():
    body = _real_envelope_dict()
    body["depth_budget"]["consumed"] = 9
    with pytest.raises(rf.SchemaError):
        rf.validate_envelope(body)


# --------------------------------------------------------------------------
# 5. CLI _audit_dispatch enforces the schema
# --------------------------------------------------------------------------


def test_cli_dispatch_rejects_invalid_input():
    from regaudit_fhe.cli import _audit_dispatch
    with pytest.raises(rf.SchemaError):
        _audit_dispatch("fairness", {"y_true": [1, 2, 3]})


# --------------------------------------------------------------------------
# 6. Output schemas validate primitive outputs
# --------------------------------------------------------------------------


def test_fairness_output_passes_output_schema():
    import numpy as np
    y = np.array([1.0, 0.0, 1.0, 0.0])
    report = rf.audit_fairness(y, y, y, 1.0 - y)
    rf.validate_output("fairness", rf.reports.report_to_dict(report))


def test_drift_output_passes_output_schema():
    import numpy as np
    p = np.array([1.0, 2.0, 3.0, 4.0])
    q = np.array([2.0, 2.0, 3.0, 3.0])
    report = rf.audit_drift(p, q)
    rf.validate_output("drift", rf.reports.report_to_dict(report))
