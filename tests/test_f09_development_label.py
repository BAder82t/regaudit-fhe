"""In ``development`` and on the lenient paths a store without issuers keeps its verdict and the output says so (F-09).

Dropping this behaviour means dropping this file and the commit that adds it: the refusal under the other policies does not
depend on it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import warnings

import pytest

import regaudit_fhe as rf
from regaudit_fhe.reports import verify_envelope, verify_receipt
from regaudit_fhe.trust import KeyEntry
from regaudit_fhe.verification import VerificationPolicy, verify

from .test_f09_issuer_substitution import ALICE, BOB, FORGED, STORES, UNBOUND, _cli, policy, report


def test_the_real_cli_on_development_says_so(tmp_path):
    out = _cli(tmp_path, "legacy", "development")
    assert out.returncode == 0 and json.loads(out.stdout)["reasons"] == ["ISSUER_UNBOUND"]
    assert "states no issuer" in out.stderr


def test_an_entry_built_without_an_issuer_gets_the_note(tmp_path):
    entry = KeyEntry(
        key_id="bob-1", public_key_pem=BOB.public_key_pem(), status="active", issuer=None
    )
    store = rf.TrustStore(keys={"bob-1": BOB.public_key_pem()}, entries={"bob-1": entry})
    res = verify(report(FORGED), VerificationPolicy(trust_store=store))
    assert res.accepted and "ISSUER_UNBOUND" in res.reasons


def test_migrating_removes_the_note(tmp_path):
    from regaudit_fhe.report_v2 import parse_envelope

    from .test_f09_store_migration import ISSUER, KEY_ID, NOW, PEM, VECTORS, migrate, store_from

    source = {"keys": {KEY_ID: PEM}}
    assert migrate(tmp_path, source, f"{KEY_ID}={ISSUER}").returncode == 0
    env = parse_envelope(json.dumps(VECTORS["0.2.1"]["reports"]["v2-audience"]))
    before = verify(
        env, VerificationPolicy(trust_store=rf.TrustStore.from_dict(source), now=lambda: NOW)
    )
    after = verify(env, VerificationPolicy(trust_store=store_from(tmp_path), now=lambda: NOW))
    assert "ISSUER_UNBOUND" in before.reasons and "ISSUER_UNBOUND" not in after.reasons
    assert before.accepted and after.accepted


@pytest.mark.parametrize("form", UNBOUND)
def test_development_keeps_the_verdict_and_says_the_name_was_not_checked(form, tmp_path):
    res = verify(report(FORGED), policy("development", STORES[form], tmp_path))
    assert res.accepted and res.trust_status == "TRUSTED" and res.issuer_trusted
    assert res.reasons == ("ISSUER_UNBOUND",)
    assert res.blocking_reasons == ()


def test_the_note_is_not_on_an_entries_store(tmp_path):
    assert verify(report(ALICE), policy("development", STORES["entries"], tmp_path)).reasons == ()


@pytest.mark.parametrize(
    ("form", "who", "expected"),
    [
        ("legacy", FORGED, "not_bound"),
        ("entries", ALICE, "store_entry"),
        ("entries", FORGED, "not_established"),
    ],
)
def test_the_versioned_response_states_the_binding(form, who, expected, tmp_path):
    (tmp_path / "r.json").write_text(json.dumps(report(who).to_dict()))
    (tmp_path / "t.json").write_text(json.dumps(STORES[form]))
    out = subprocess.run(
        [sys.executable, "-m", "regaudit_fhe.cli", "verify", "-i", "r.json", "--trusted-keys", "t.json",
         "--response-format", "v2"],
        capture_output=True, text=True, timeout=120, cwd=tmp_path, check=False,
    )  # fmt: skip
    assert json.loads(out.stdout)["issuer_binding"] == expected


def test_the_default_response_has_no_new_field(tmp_path):
    body = verify(report(FORGED), policy("development", STORES["legacy"], tmp_path)).to_dict()
    assert "issuer_binding" not in body


def test_the_legacy_verifier_says_whether_the_name_was_compared():
    env = report(FORGED, "v1")
    with pytest.warns(DeprecationWarning, match="states no issuer"):
        plain = verify_envelope(env, trusted_keys=STORES["bare"])
    with pytest.warns(DeprecationWarning, match="states no issuer"):
        legacy = verify_envelope(env, trust_store=rf.TrustStore.from_dict(STORES["legacy"]))
    assert plain.trust_status == legacy.trust_status == "TRUSTED"
    assert not plain.issuer_bound and not legacy.issuer_bound
    assert "issuer_bound" not in plain.to_dict() and "issuer_bound" not in repr(plain)
    honest = verify_envelope(
        report(ALICE, "v1"), trust_store=rf.TrustStore.from_dict(STORES["entries"])
    )
    assert honest.trust_status == "TRUSTED" and honest.issuer_bound


def test_verify_receipt_keeps_its_contract_and_carries_no_label():
    """It returns a bare bool and promises not to warn when given trust material. A stated limit of the label."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert verify_receipt(report(FORGED, "v1"), trusted_keys=STORES["bare"]) is True


def test_verify_receipt_says_near_the_api_what_its_bool_is_not():
    doc = " ".join(verify_receipt.__doc__.split())
    assert "not an issuer-attribution result and not a revocation result" in doc
    assert "When tenant identity matters" in doc and "verify_trusted" in doc


def test_control_no_warning_when_nothing_was_claimed_about_an_issuer():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert verify_envelope(report(ALICE, "v1")).trust_status == "SELF_SIGNED_ONLY"
        verify_envelope(report(ALICE, "v1"), trust_store=rf.TrustStore.from_dict(STORES["entries"]))
