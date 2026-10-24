# Changelog

## Unreleased — Phase 1 trust hardening

### Changed (deliberate, security-motivated default changes)

- **`POST /v1/verify` now fails closed.** Without a configured trust store
  (`REGAUDIT_FHE_TRUST_STORE` / `regaudit-fhe serve --trust-store`) it returns
  503 instead of verifying the envelope against its own embedded key. A
  previously accepted self-signed report is now refused by this endpoint. This
  is an intentional correction, not a regression.
- `/v1/verify` responses keep `valid`, `primitive`, `issued_at` and
  `regulations` and add `trust_status`, `integrity_valid` and
  `timestamp_status`. `valid` is true only when `trust_status` is `TRUSTED`.
- A trust store that is configured but missing, unreadable or malformed aborts
  server startup (`TrustStoreError`); it never falls back to self-verification.
- `verify_envelope` / `verify_receipt` verify the signature against the
  *registered* key when trust material is supplied, never the embedded one.
- `VerificationOutcome.issuer_trusted` is now `False` when no trust material
  was supplied (it used to be `True`). `valid` keeps its v1 integrity meaning
  for callers without trust material.
- An attached timestamp with no `tsa_verifier` is reported `UNVERIFIED` and
  `timestamp_valid` is `False` (it used to be `True`).
- `verify_receipt(trusted_keys={})` now fails closed (an empty mapping is trust
  material that trusts nobody) instead of taking the self-signed path.
- `/v1/verify` answers 422 for a malformed envelope body instead of 500.

### Added

- `VerificationOutcome.trust_status` (`TRUSTED` / `SELF_SIGNED_ONLY` /
  `INVALID`), `timestamp_status` (`ABSENT` / `UNVERIFIED` / `VERIFIED` /
  `FAILED`), `revoked`, `pin_ok`.
- `verify_envelope(..., trust_store=, require_verified_timestamp=)` and
  `verify_receipt(..., trust_store=)`; a `TrustStore` passed as `trusted_keys`
  now keeps its revocation set and parameter-set pins.
- `verify_envelope_or_raise(..., require_verified_timestamp=)` and the
  `TimestampUnverified` exception.
- `regaudit-fhe serve --trust-store PATH` and `--allow-self-signed`
  (development only: refused under non-`development` profiles via
  `REGAUDIT_FHE_PROFILE`, and on non-loopback binds; never yields `TRUSTED`).

### Unchanged

- The v1 canonical signing format (`regaudit-fhe.report.v1`); existing reports
  still parse and verify cryptographically. No `report.v2` fields are added.
- The `timestamp` block remains outside the signed body.

### Remaining trust limitations

- No replay protection, freshness window or audit-run binding.
- Revocation has no time semantics; `issued_at` is signer-asserted.
- `/v1/audit/*` signs with an ephemeral issuer key, so its envelopes can only
  verify as `SELF_SIGNED_ONLY`.
- `verify_receipt` with a plain `trusted_keys` mapping cannot enforce
  revocation or pins; use a `TrustStore`.
- `--allow-self-signed` bind-host enforcement lives in the `serve` CLI. An app
  from `build_app()` served directly (e.g. `uvicorn` on `0.0.0.0`) is not
  host-checked; it still can never report `TRUSTED`.
- A timestamp with no `tsa_verifier` leaves the trust decision unchanged unless
  `require_verified_timestamp` is set (the server default is off).
