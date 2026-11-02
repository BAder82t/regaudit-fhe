# Issuer attribution limitation in v0.2.1

When a verifier uses the legacy `{"keys": ...}` trust-store format, a valid signature from an enrolled key may be accepted even if the signed report declares a different issuer. This can produce a `TRUSTED` result with `issuer_trusted: true` despite the issuer mismatch.

The issue affects issuer attribution, not the cryptographic validity of the signature. It is particularly relevant when a trust store contains keys belonging to multiple organizations or tenants and an application relies on the report's `issuer` field for authorization or audit attribution.

**Mitigation:** Use the issuer-bound `entries` trust-store format and verify that each enrolled key is associated with its intended issuer. Until the correction is released, do not rely on the reported issuer identity for tenant isolation when using a legacy trust store.

The legacy-store behavior has been reproduced in v0.2.1 using the CLI under `development`, `confidential`, and `high-assurance` policies.

The older bare `{key_id: PEM}` trust-store form has the same limitation. This was reproduced through the library.

**Caller-built objects:** `verify_report` in 0.1.0, 0.1.1, 0.2.0 and 0.2.1 can also give `TRUSTED` with `issuer_trusted: true` for the wrong issuer, on any trust-store form, when Python code builds the envelope object itself and sets its `issuer` to a `str` subclass that overrides comparison. This needs that object to be passed to `verify_report` in the same process. A report read from JSON, by `parse_envelope`, the CLI or the HTTP server, has a plain string and is not affected. On 0.2.0 and 0.2.1, `verify_trusted` refuses the same object. Until the correction is released, parse reports from their JSON text and do not pass envelope objects received from untrusted code to `verify_report`. No patch release is planned for this.
