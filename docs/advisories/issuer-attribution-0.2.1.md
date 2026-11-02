# Issuer attribution limitation in v0.2.1

When a verifier uses the legacy `{"keys": ...}` trust-store format, a valid signature from an enrolled key may be accepted even if the signed report declares a different issuer. This can produce a `TRUSTED` result with `issuer_trusted: true` despite the issuer mismatch.

The issue affects issuer attribution, not the cryptographic validity of the signature. It is particularly relevant when a trust store contains keys belonging to multiple organizations or tenants and an application relies on the report's `issuer` field for authorization or audit attribution.

**Mitigation:** Use the issuer-bound `entries` trust-store format and verify that each enrolled key is associated with its intended issuer. Until the correction is released, do not rely on the reported issuer identity for tenant isolation when using a legacy trust store.

The legacy-store behavior has been reproduced in v0.2.1 using the CLI under `development`, `confidential`, and `high-assurance` policies.

The older bare `{key_id: PEM}` trust-store form has the same limitation. This was reproduced through the library.
