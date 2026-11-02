# Report format and JSON schemas

What a signed report contains and the schemas that describe it. The exact rules are in [TRUST_SPEC.md](TRUST_SPEC.md).

## Audit envelope

An audit result is wrapped into a regulator-facing, signed JSON envelope.
`regaudit_fhe.envelope(...)` (and `regaudit-fhe audit`) produce `report.v1`;
`regaudit_fhe.envelope_v2(...)` produces `report.v2`. An abridged `report.v2`:

```json
{
  "schema": "regaudit-fhe.report.v2",
  "schema_version": "regaudit-fhe.report.v2",
  "algorithm_version": "0.2.1",
  "primitive": "fairness",
  "backend": "plaintext",
  "parameter_set": { "...": "..." },
  "parameter_set_hash": "6b8aedc173e2c94e…",
  "regulations": ["NYC_LL144"],
  "result": { "breach": false, "disparity": 0.25 },
  "input_commitments": [{ "name": "y_true", "sha256": "a5c4…" }],
  "depth_budget": { "declared": 6, "consumed": 2 },
  "issued_at": "2026-10-01T12:00:00+00:00",
  "issuer": "acme-bank",
  "key_id": "acme-2026-04",
  "public_key_fingerprint": "f5a124b4…",
  "deployment_id": "prod-eu-1",
  "audit_run_id": "3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f7",
  "trust_policy_version": 1,
  "audience": ["regulator-a"],
  "receipt": {
    "sha256": "26af001f…",
    "signature_alg": "Ed25519",
    "signature_b64": "lVI6L7um…",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----…"
  },
  "timestamps": []
}
```

Everything above `receipt` is **signed** (`audience`, `model_commitment`,
`dataset_commitment` and `dp` are optional and omitted when absent). The signature is
over a domain-separated encoding of the strict canonical JSON of that body, and the
receipt's `public_key_pem` is a convenience only: a verifier checks the signature
against the key **it** registered, never the embedded one. `timestamps` sit outside
the signature and bind a *sealed digest* of the signed body plus the signature. The
canonical test vectors under [`tests/vectors/report_v2/`](../tests/vectors/report_v2/)
pin the exact bytes. The `"consumed": 2` in this example is a value the test vector
passes; a report from the CLI says 6.

`report.v1` keeps its original canonical bytes and fields: `key_id` and the public
key live in the unsigned receipt, so a v1 report cannot bind its issuer key,
deployment or run identity. It remains verifiable, with weaker historical guarantees
documented in [docs/TRUST_SPEC.md](TRUST_SPEC.md) (Appendix C). Unsigned
SHA-256 receipts are useful for tamper evidence only.

## JSON schemas

Every primitive input, primitive output, and the audit envelope itself
ships with a Draft-2020-12 JSON Schema under [`schemas/`](../schemas/) (the copy inside the installed package is `src/regaudit_fhe/schemas/`; a test keeps the two byte-identical).
Auditors and integrators can pin specific schema versions and reject
payloads that do not conform.

```bash
regaudit-fhe schema --list
regaudit-fhe schema fairness.input
regaudit-fhe schema envelope        # report.v1
regaudit-fhe schema envelope.v2     # report.v2
```

The CLI and HTTP server validate every request body against the
matching schema before invoking the audit primitive; failures return
HTTP 422 / CLI exit-code 2 with a structured pointer to the offending
field. Programmatic access:

```python
import regaudit_fhe as rf

rf.list_schemas()  # all 14 names
rf.load_schema("fairness.input")  # raw schema dict
rf.validate_input("fairness", payload)  # raises rf.SchemaError on bad input
rf.validate_envelope(env_dict)  # check a report.v1 envelope
rf.validate_envelope_v2(env_dict)  # check a report.v2 envelope
```
