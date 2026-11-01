"""The opt-in response format: an explicit revocation_evaluation, on the CLI and on POST /v1/verify.

Real processes for the CLI, the real ASGI app for HTTP. The default must stay exactly what it was.
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
from regaudit_fhe import _verification_response as vr
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2, parse_envelope_strict
from regaudit_fhe.verification import VerificationPolicy, verify

from .experimental_revocation.gen_fixtures import NOW, dump, make_world

W = make_world()
STORE = W.store(W.old, W.new)
ADDED = {"response_format", "revocation_evaluation", "policy_evidence"}


def env():
    return envelope_v2(
        "drift",
        rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])),
        signer=W.old,
        deployment_id="p",
        audience=["reg"],
        issued_at=NOW - timedelta(hours=1),
    )


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
def signed(tmp_path: Path) -> Path:
    (tmp_path / "r.json").write_text(env().to_json())
    (tmp_path / "t.json").write_text(
        json.dumps(
            {
                "entries": {
                    W.old.key_id: {
                        "issuer": W.issuer,
                        "public_key_pem": W.old.public_key_pem(),
                        "status": "active",
                    }
                }
            }
        )
    )
    return tmp_path


def test_cli_default_is_byte_identical_to_the_engine_dict_and_v2_only_adds(signed):
    base = ("verify", "-i", "r.json", "--trusted-keys", "t.json")
    default = cli(*base, cwd=signed)
    explicit = cli(*base, "--response-format", "v1", cwd=signed)
    assert default.stdout == explicit.stdout and default.returncode == 0 and default.stderr == ""
    payload = json.loads(default.stdout)
    assert list(payload) == [*list(verify_keys()), "trusted_issuer"]
    v2 = cli(*base, "--response-format", "v2", cwd=signed)
    body = json.loads(v2.stdout)
    assert v2.returncode == 0 and set(body) == set(payload) | ADDED
    assert {k: body[k] for k in payload} == payload
    assert body["response_format"] == "regaudit-fhe.verification-response.v2"
    assert body["revocation_evaluation"] == "not_evaluated"
    assert body["trust_status"] == "TRUSTED"  # TRUSTED keeps its meaning, and the status says what is not covered


def verify_keys():
    pol = VerificationPolicy(trust_store=STORE, now=lambda: NOW)
    return verify(parse_envelope_strict(env().to_json()), pol).to_dict()


def test_cli_refused_report_in_v2_keeps_its_exit_code(signed):
    (signed / "empty.json").write_text(json.dumps({"entries": {"other": {
        "issuer": W.issuer, "public_key_pem": W.new.public_key_pem(), "status": "active"}}}))  # fmt: skip
    out = cli("verify", "-i", "r.json", "--trusted-keys", "empty.json", "--response-format", "v2", cwd=signed)
    body = json.loads(out.stdout)
    assert out.returncode == 1 and body["revocation_evaluation"] == "not_evaluated"
    assert body["trust_status"] == "INVALID"


def _client(**overrides):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from regaudit_fhe.server import ServerConfig, build_app
    from tests._asgi import client_for

    base = dict(
        api_keys={},
        dev_mode=True,
        max_body_bytes=1 << 20,
        rate_limit_per_min=600,
        request_timeout_s=10.0,
        cors_origins=(),
        trust_store=STORE,
        profile="development",
    )
    base.update(overrides)
    return client_for(build_app(config=ServerConfig(**base)), base_url="http://127.0.0.1:8000")


def test_http_default_is_byte_identical_and_v2_only_adds():
    client = _client()
    body = {"envelope": env().to_dict()}
    default = client.post("/v1/verify", json=body)
    assert default.status_code == 200
    # byte for byte what the app serialises for the engine's dict, with the same keys in the same order
    payload = default.json()
    assert list(payload) == list(verify_keys())
    assert default.content == client.post("/v1/verify?response_format=v1", json=body).content
    assert default.content == client.post("/v1/verify?unrelated=1", json=body).content
    v2 = client.post("/v1/verify?response_format=v2", json=body)
    out = v2.json()
    assert v2.status_code == 200 and set(out) == set(payload) | ADDED
    assert {k: out[k] for k in payload} == payload
    assert out["revocation_evaluation"] == "not_evaluated"
    assert out["policy_evidence"]["revocation"]["mode"] == "off"


def test_http_unknown_format_is_refused_before_the_body_is_read():
    client = _client()
    out = client.post("/v1/verify?response_format=v3", json={"envelope": {}})
    assert out.status_code == 422 and "response_format" in out.text


def test_http_openapi_document_does_not_change():
    assert "response_format" not in _client().get("/openapi.json").text


# ------------------------------------------------------------------ the three values


@pytest.fixture
def world(tmp_path: Path):
    d = tmp_path / "state"
    d.mkdir(mode=0o700)
    fs = st.FileStateStore(d)
    pin = st.Pin(W.issuer, W.rev.public_key_pem(), "enr-1", baseline_epoch=0)
    st.enroll(fs, pin, STORE, now=NOW - timedelta(days=30))
    return fs, pin, tmp_path


def decide(world, mode):
    fs, pin, tmp = world
    pol = VerificationPolicy(
        profile="confidential",
        trust_store=STORE,
        now=lambda: NOW,
        max_age=timedelta(days=90),
        replay_mode="check",
        verifier_id="reg",
        replay_cache=SqliteReplayCache(tmp / "replay.db"),
    )
    return gate.verify_with_revocation(
        env(), pol, gate.RevocationContext(mode, fs, {W.issuer: pin})
    )


def test_off_is_not_evaluated(world):
    assert gate.response_v2(decide(world, gate.MODE_OFF))["revocation_evaluation"] == "not_evaluated"


def test_fresh_data_is_evaluated_and_evaluated_is_not_a_promise(world):
    fs, pin, _ = world
    assert st.ingest_list(fs, pin, dump(W.signed(1, [W.entry(W.old, "compromised", None)])), STORE, NOW).accepted
    body = gate.response_v2(decide(world, gate.MODE_REQUIRED))
    assert body["revocation_evaluation"] == "evaluated"
    assert body["trust_status"] == "INVALID"  # evaluated, and the answer was no


@pytest.mark.parametrize("cause", ["absent", "lost", "contradictory"])
def test_required_but_unavailable_is_never_trusted(world, cause):
    fs, pin, _ = world
    if cause == "lost":
        fs.path(W.issuer).unlink()
    if cause == "contradictory":
        st.ingest_list(fs, pin, dump(W.signed(1, [])), STORE, NOW)
        st.ingest_list(fs, pin, dump(W.signed(1, [W.entry(W.new, "retired", "2026-10-01T00:00:00Z")])), STORE, NOW)
    body = gate.response_v2(decide(world, gate.MODE_REQUIRED))
    assert body["revocation_evaluation"] == "required_but_unavailable"
    assert body["trust_status"] == "INVALID" and body["accepted"] is False and body["valid"] is False
    assert body["integrity_valid"] is True


def test_advisory_with_no_data_is_not_evaluated_not_unavailable(world):
    body = gate.response_v2(decide(world, gate.MODE_ADVISORY))
    assert body["revocation_evaluation"] == "not_evaluated" and body["trust_status"] == "TRUSTED"


def test_the_builder_refuses_to_represent_unavailable_as_trusted():
    fake = {"accepted": True, "valid": True, "trust_status": "TRUSTED"}
    with pytest.raises(RuntimeError, match="never"):
        vr.response_v2(fake, {"gate": "REVOCATION_DATA_ABSENT", "mode": "required"})


def test_cli_required_but_unavailable_is_shown_on_exit_3(signed):
    pin = st.Pin(W.issuer, W.rev.public_key_pem(), "enr-1", baseline_epoch=0)
    st.save_pin(signed / "pins.json", pin)
    out = cli(
        "verify", "-i", "r.json", "--trusted-keys", "t.json", "--revocation-mode", "required",
        "--revocation-pins", "pins.json", "--revocation-state", "no-such-dir", cwd=signed,
    )  # fmt: skip
    body = json.loads(out.stdout)
    assert out.returncode == 3 and body["revocation_evaluation"] == "required_but_unavailable"
    assert body["trust_status"] == "INVALID"


def test_policy_id_is_not_reused_for_an_assurance_it_does_not_provide(world):
    off = decide(world, gate.MODE_OFF).result
    required = decide(world, gate.MODE_REQUIRED).result
    assert off.policy_id == "regaudit-fhe/confidential/v1"
    assert required.policy_id == "regaudit-fhe/confidential+revocation-required/v1"
