"""P3-04: the HTTP side of the claim labels (needs the server extra: fastapi and httpx).

The command-line side is in ``test_claim_labels.py``. These tests live in their own module so that a scope with no
server extra (the ``release-gate`` job installs only ``[dev]``) can exclude the whole module, instead of a mandatory
test skipping inside a module that the scope still requires.
"""

from __future__ import annotations

import json

import pytest

from tests import _claims_corpus as corpus

NOT_ESTABLISHED = "Encrypted execution not established."


def _client(**overrides: object):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from regaudit_fhe.server import ServerConfig, build_app
    from tests._asgi import client_for

    base: dict[str, object] = dict(
        api_keys={}, dev_mode=True, max_body_bytes=1 << 20, rate_limit_per_min=600,
        request_timeout_s=10.0, cors_origins=(), trust_store=corpus.store(), profile="development",
    )  # fmt: skip
    base.update(overrides)
    return client_for(build_app(config=ServerConfig(**base)), base_url="http://127.0.0.1:8000")  # type: ignore[arg-type]


def test_http_default_has_no_claim_keys_and_v2_has_the_assessment() -> None:
    client = _client()
    env = json.loads(corpus.texts()["valid_fhe_declared_v2"])
    default = client.post("/v1/verify", json={"envelope": env}).json()
    assert "claim_assessment" not in default
    v2 = client.post("/v1/verify?response_format=v2", json={"envelope": env}).json()
    assert v2["claim_assessment"]["statement"] == NOT_ESTABLISHED
    assert v2["claim_assessment"]["execution_mode"]["declared_in_report"] == "fhe_declared"
    assert {k: v2[k] for k in default} == default


def test_version_does_not_suggest_an_encrypted_audit_path() -> None:
    body = _client().get("/version").json()
    assert {"library_version", "python", "tenseal"} <= set(body)  # existing keys stay
    assert body["server_execution"].startswith("plaintext-only")
    assert "not evidence" in body["server_execution"]
    assert "encrypted audit" not in json.dumps(body).lower()


def test_the_help_and_api_description_do_not_promise_an_encrypted_backend() -> None:
    from regaudit_fhe.cli import build_parser

    help_text = build_parser().format_help()
    assert "optional TenSEAL CKKS backend" not in help_text
    desc = _client().get("/openapi.json").json()["info"]["description"]
    assert "optional TenSEAL CKKS backend" not in desc and "plaintext" in desc
