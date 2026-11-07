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

## What `parameter_set` and `security_bits` mean

`parameter_set` is what the producer declared about the encryption parameters. It is signed, and a valid signature
only shows that the issuer's key signed those bytes. Nothing in the library checks the declaration, and `verify`
does not read `security_bits`.

**`security_bits` is not a measured cryptographic security level.** A valid signature does not substantiate it. It comes
from one of three places: the default of `128`, when no `parameter_set` is passed; the number behind the
`security_level` name given to `CKKSParams`; or, in versions before 0.3.0, an argument passed to
`parameter_set_from_ckks_context` or `parameter_set_from_openfhe_context`.

| Where the report came from | What it signs | How to read it |
|---|---|---|
| `regaudit-fhe audit`, the HTTP server, `envelope(...)` or `envelope_v2(...)` without a `parameter_set` | `backend: "plaintext"`, `poly_modulus_degree: 0`, an empty chain and `security_bits: 128` | **The signed parameter set describes no encryption.** For `regaudit-fhe audit` and the HTTP server nothing was encrypted. For `envelope(...)` or `envelope_v2(...)` the same values are signed even when the calculation ran on an encrypted backend, because the default parameter set says plaintext. The `128` is a field default, and both schemas require at least 128, so the field cannot say anything else. It is not 128-bit cryptographic protection. |
| `CKKSParams` with `HEStd_128_classic` | `128` | The chain was compared with the 128-bit limit for `N`, and in 0.3.0 and later a real context was built and the ring dimension and chain were read back from it. The TenSEAL backend builds its context at SEAL's default 128-bit level and is shown to refuse above that limit. The report still cannot show that the producer used that context. |
| `CKKSParams` with `HEStd_192_classic` or `HEStd_256_classic`, before 0.3.0 | `192` or `256` | **May exceed what the parameters support.** TenSEAL gives no way to ask for these levels, and at `N = 2^14` the default 360-bit chain is above the SEAL limits for them (305 and 237 bits). Do not rely on the number. From 0.3.0 `CKKSParams` refuses these levels. |
| `parameter_set_from_ckks_context`, before 0.3.0 | The caller's level, a fixed default chain, and `poly_modulus_degree` from the wrapper object | Not read from the context. From 0.3.0 the ring dimension, chain and scale are read from the context, and the level must be the one the backend is shown to enforce. |
| `parameter_set_from_openfhe_context`, before 0.3.0 | The caller's level, twice the batch size as `poly_modulus_degree`, and an empty chain | Not read from the context. From 0.3.0 the ring dimension is read from the context and the chain is still signed empty. The level is the 128 the builder requests. **Not run against a real OpenFHE.** |

Reports signed before 0.3.0 with a `192` or `256`, or by the two functions above, cannot be told from correct ones by
looking at the report. The signed numbers are whatever the producer's code wrote.

Verifying a report does not show that FHE execution occurred. `backend` is also a declaration. See
[SIGN_AND_VERIFY.md](SIGN_AND_VERIFY.md) for what a `TRUSTED` verdict does and does not say.

**Reading existing reports.** A report that signs `backend: "plaintext"` with `security_bits: 128` makes no claim of
encryption, whatever the number says, and it does not show that none took place. Every published version from 0.0.2 to 0.2.1 signs it this way
by default, so show such a report as "no encryption claimed", and never as "128-bit". The published schemas are not
changed by this note, and correcting the field itself would need a new schema version.

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
