"""Deterministic canonical test vectors for ``regaudit-fhe.report.v2``.

Run ``python tests/vectors/report_v2/generate.py`` to (re)write ``vectors.json``.
``tests/test_report_v2_vectors.py`` regenerates them in memory and compares byte
for byte, so any change to canonicalisation, signing or the sealed digest fails
a test and forces a deliberate regeneration and format-version decision.

The signing key below is derived from a public constant. It is a TEST KEY ONLY,
is not a secret and must never be trusted anywhere.

Float formatting follows Python's shortest round-trip ``repr`` (for example
``1e-07``). Another implementation must reproduce these bytes exactly, or
adopt RFC 8785, before it can claim v2 compatibility.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import regaudit_fhe as rf
from regaudit_fhe.canonical import canonical_bytes
from regaudit_fhe.report_v2 import (
    SCHEMA_V2,
    SIGN_DOMAIN,
    AuditEnvelopeV2,
    public_key_fingerprint,
    sign_body_v2,
)
from regaudit_fhe.reports import ParameterSet

HERE = Path(__file__).parent
KEY_ID = "vector-key-1"
ISSUER = "vector-issuer"
RUN_ID = "3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f7"
SEED = hashlib.sha256(b"regaudit-fhe/test-vector/ed25519-seed/1").digest()
PARAMS = ParameterSet(library_version="0.0.8")


def signer(seed: bytes = SEED, key_id: str = KEY_ID) -> rf.Signer:
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return rf.Signer(issuer=ISSUER, key_id=key_id, private_key=priv, public_key=priv.public_key())


def minimal_body(s: rf.Signer) -> dict[str, Any]:
    return {
        "schema": SCHEMA_V2,
        "schema_version": SCHEMA_V2,
        "algorithm_version": "0.0.8",
        "primitive": "fairness",
        "backend": "plaintext",
        "parameter_set": PARAMS.to_dict(),
        "parameter_set_hash": PARAMS.hash(),
        "regulations": ["NYC_LL144"],
        "result": {"breach": False, "disparity": 0.25},
        "input_commitments": [],
        "depth_budget": {"declared": 6, "consumed": 2},
        "issued_at": "2026-10-01T12:00:00+00:00",
        "issuer": s.issuer,
        "key_id": s.key_id,
        "public_key_fingerprint": public_key_fingerprint(s.public_key_pem()),
        "deployment_id": "prod-eu-1",
        "audit_run_id": RUN_ID,
        "trust_policy_version": 1,
    }


def full_body(s: rf.Signer) -> dict[str, Any]:
    body = minimal_body(s)
    body.update(
        regulations=["NYC_LL144", "EU_AI_ACT_ART10"],
        result={
            "breach": True,
            "count": 4,
            "disparity": 0.25,
            "nested": {"é": [1, 2.5, None, "ü"]},
            "tiny": 1e-07,
        },
        input_commitments=[{"name": "y_true", "sha256": hashlib.sha256(b"y_true").hexdigest()}],
        audience=["regulator-a", "regulator-b"],
        model_commitment={"name": "model", "sha256": hashlib.sha256(b"model").hexdigest()},
        dataset_commitment={"name": "dataset", "sha256": hashlib.sha256(b"dataset").hexdigest()},
        dp={"mechanism": "laplace", "epsilon": 1.0},
    )
    return body


def _record(env: AuditEnvelopeV2) -> dict[str, Any]:
    return {
        "envelope": env.to_dict(),
        "canonical_signed_body_hex": canonical_bytes(env.signed_body()).hex(),
        "signing_input_sha256": hashlib.sha256(env.signing_input()).hexdigest(),
        "signature_b64": env.receipt["signature_b64"],
        "sealed_digest_hex": env.sealed_digest().hex(),
    }


def _text(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True)


def build_vectors() -> dict[str, Any]:
    s = signer()
    full = sign_body_v2(full_body(s), s).with_timestamp(
        issuer="vector-tsa",
        token=b"vector-token",
        issued_at=__import__("datetime").datetime(
            2026, 10, 2, tzinfo=__import__("datetime").timezone.utc
        ),
    )
    minimal = sign_body_v2(minimal_body(s), s)
    positive = [{"name": "full", **_record(full)}, {"name": "minimal", **_record(minimal)}]
    base = full.to_dict()

    def mutated(fn) -> dict[str, Any]:
        data = copy.deepcopy(base)
        fn(data)
        return data

    parse: list[dict[str, Any]] = []

    def add_parse(
        name: str,
        expect: str,
        *,
        text: str | None = None,
        obj: Any = None,
        raw_b64: str | None = None,
    ) -> None:
        entry: dict[str, Any] = {"name": name, "expect": expect}
        if raw_b64 is not None:
            entry["input_b64"] = raw_b64
        elif text is not None:
            entry["input_text"] = text
        else:
            entry["input_object"] = obj
        parse.append(entry)

    ok_text = _text(base)
    add_parse(
        "duplicate_top_level_key",
        "canonical:duplicate",
        text=ok_text[:-1] + ', "issuer": "mallory"}',
    )
    nested_dup = _text(mutated(lambda d: d.update(result={"a": 1})))
    add_parse(
        "duplicate_nested_key",
        "canonical:duplicate",
        text=nested_dup.replace('"a": 1', '"a": 1, "a": 2'),
    )
    add_parse(
        "nan_in_result",
        "canonical",
        text=_text(mutated(lambda d: d.update(result={"x": 1}))).replace('"x": 1', '"x": NaN'),
    )
    add_parse(
        "overflowing_float",
        "canonical",
        text=_text(mutated(lambda d: d.update(result={"x": 1}))).replace('"x": 1', '"x": 1e999'),
    )
    add_parse(
        "utf8_bom",
        "canonical",
        raw_b64=base64.b64encode(b"\xef\xbb\xbf" + ok_text.encode()).decode(),
    )
    add_parse(
        "invalid_utf8", "canonical", raw_b64=base64.b64encode(ok_text.encode() + b"\xff").decode()
    )
    add_parse(
        "lone_surrogate_escape",
        "canonical",
        text=_text(mutated(lambda d: d.update(result={"x": "a"}))).replace(
            '"x": "a"', '"x": "\\ud800"'
        ),
    )
    deep = "[" * 70 + "]" * 70
    add_parse(
        "excessive_nesting",
        "canonical",
        text=_text(mutated(lambda d: d.update(result={"x": 1}))).replace('"x": 1', '"x": ' + deep),
    )
    add_parse(
        "unknown_top_level_field", "format:UNKNOWN_FIELD", obj=mutated(lambda d: d.update(extra=1))
    )
    add_parse(
        "receipt_carries_key_id",
        "format:UNKNOWN_FIELD",
        obj=mutated(lambda d: d["receipt"].update(key_id=KEY_ID)),
    )
    add_parse("missing_key_id", "format:MISSING_FIELD", obj=mutated(lambda d: d.pop("key_id")))
    add_parse(
        "uppercase_uuid",
        "format:BAD_VALUE",
        obj=mutated(lambda d: d.update(audit_run_id=RUN_ID.upper())),
    )
    add_parse(
        "naive_issued_at",
        "format:BAD_VALUE",
        obj=mutated(lambda d: d.update(issued_at="2026-10-01T12:00:00")),
    )
    add_parse("empty_audience", "format:BAD_VALUE", obj=mutated(lambda d: d.update(audience=[])))
    add_parse(
        "unknown_schema",
        "format:BAD_SCHEMA",
        obj=mutated(lambda d: d.update(schema="regaudit-fhe.report.v9")),
    )

    def noncanonical_sig(d: dict[str, Any]) -> None:
        sig = d["receipt"]["signature_b64"]
        body, pad = sig.rstrip("="), sig[len(sig.rstrip("=")) :]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        mask = 0b1111 if pad == "==" else 0b11
        d["receipt"]["signature_b64"] = body[:-1] + alphabet[alphabet.index(body[-1]) ^ mask] + pad

    add_parse("noncanonical_signature_base64", "format:BAD_VALUE", obj=mutated(noncanonical_sig))

    verify: list[dict[str, Any]] = []

    def add_verify(name: str, reason: str, obj: Any, **extra: Any) -> None:
        verify.append({"name": name, "expect_reason": reason, "envelope": obj, **extra})

    add_verify(
        "tampered_result", "HASH_MISMATCH", mutated(lambda d: d["result"].update(disparity=0.0))
    )
    add_verify(
        "tampered_audience", "HASH_MISMATCH", mutated(lambda d: d.update(audience=["regulator-z"]))
    )
    add_verify("swapped_key_id", "ISSUER_UNKNOWN", mutated(lambda d: d.update(key_id="other-key")))
    # Signed over the bare canonical body: valid under v1 conventions, never under v2 domain separation.
    bare_body = full_body(s)
    unsigned = AuditEnvelopeV2.from_dict({**bare_body, "receipt": full.receipt})
    bare_sig = base64.b64encode(s.sign(canonical_bytes(unsigned.signed_body()))).decode()
    bare = unsigned.to_dict()
    bare["receipt"] = {**full.receipt, "signature_b64": bare_sig}
    add_verify("signature_without_domain_separation", "SIGNATURE_INVALID", bare)
    other = signer(hashlib.sha256(b"regaudit-fhe/test-vector/other-seed").digest())
    forged = sign_body_v2(full_body(s), other).to_dict()
    add_verify("signed_by_a_different_key", "SIGNATURE_INVALID", forged)
    wrong_fp = full_body(s)
    wrong_fp["public_key_fingerprint"] = "0" * 64
    add_verify(
        "wrong_signed_fingerprint", "FINGERPRINT_MISMATCH", sign_body_v2(wrong_fp, s).to_dict()
    )
    wrong_issuer = full_body(s)
    wrong_issuer["issuer"] = "someone-else"
    add_verify("wrong_signed_issuer", "ISSUER_MISMATCH", sign_body_v2(wrong_issuer, s).to_dict())
    wrong_dep = full_body(s)
    wrong_dep["deployment_id"] = "prod-us-1"
    add_verify(
        "deployment_outside_registered_scope",
        "DEPLOYMENT_NOT_ALLOWED",
        sign_body_v2(wrong_dep, s).to_dict(),
        trust_override={"deployments": ["prod-eu-1"]},
    )
    relabelled = copy.deepcopy(base)
    relabelled["schema"] = relabelled["schema_version"] = "regaudit-fhe.report.v1"
    add_verify("v2_relabelled_as_v1", "HASH_MISMATCH", relabelled)
    # A genuine token over the *minimal* envelope, attached to the *full* one.
    stolen = full.to_dict()
    stolen["timestamps"] = [
        {
            "issuer": "vector-tsa",
            "token_b64": base64.b64encode(b"ok:" + minimal.sealed_digest()).decode(),
            "issued_at": "2026-10-02T00:00:00+00:00",
        }
    ]
    add_verify(
        "timestamp_token_over_a_different_artifact",
        "TIMESTAMP_FAILED",
        stolen,
        pinned_timestamp_verifier=True,
    )

    v1_as_v2 = {
        "schema": SCHEMA_V2,
        "schema_version": SCHEMA_V2,
        "algorithm_version": "0.0.8",
        "primitive": "fairness",
        "backend": "plaintext",
    }
    add_parse("truncated_v2_missing_signed_identity", "format:MISSING_FIELD", obj=v1_as_v2)

    return {
        "description": (
            "Canonical regaudit-fhe.report.v2 vectors. TEST KEY ONLY - derived from a public "
            "constant; never trust it. Regenerate with tests/vectors/report_v2/generate.py."
        ),
        "key": {
            "key_id": KEY_ID,
            "issuer": ISSUER,
            "seed_derivation": "sha256(b'regaudit-fhe/test-vector/ed25519-seed/1')",
            "public_key_pem": signer().public_key_pem(),
            "public_key_fingerprint": public_key_fingerprint(signer().public_key_pem()),
        },
        "domains": {"sign": SIGN_DOMAIN.hex()},
        "positive": positive,
        "parse_refusals": parse,
        "verify_refusals": verify,
    }


def render() -> str:
    return json.dumps(build_vectors(), indent=2, sort_keys=True) + "\n"


def main() -> None:
    (HERE / "vectors.json").write_text(render(), encoding="utf-8")
    print(f"wrote {HERE / 'vectors.json'}")


if __name__ == "__main__":
    main()
