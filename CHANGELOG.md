# Changelog

## 0.1.1 — defensive patch (candidate, NOT PUBLISHED)

Four defensive fixes found by an AI-assisted security review of 0.1.0, plus container hygiene. This is
not an audit and gives no production assurance. No change to signing formats, schemas, `report.v1` /
`report.v2` verification results for well-formed reports, trust semantics or crypto backends: reports
signed by 0.1.0 verify the same under 0.1.1. The only change visible in a freshly signed report is
`algorithm_version` (`"0.1.1"`).

### Fixed

- **A non-finite audit result is no longer signed.** `envelope()` raised no error when a schema-valid but
  overflowing input (for example coefficients of `1e308` on `/v1/audit/disagreement`) produced `NaN` or
  `Infinity`. `report.v1` signed the literal `NaN` while the HTTP layer delivered `null`, so the delivered
  report failed its own verification (`HASH_MISMATCH`) and `breach` read `false` because `NaN > threshold`
  is false. `envelope()` now raises `ValueError` for a non-finite result or `dp` block; `POST /v1/audit/*`
  answers HTTP 422 and `regaudit-fhe audit` exits 2. Library callers that previously signed a non-finite
  result now get `ValueError`; such a report could not survive a JSON round trip.
- **`POST /v1/verify` answers 422 instead of 500 when a report's `primitive` is not a string.** A
  `report.v1` with a JSON array or object as `primitive` raised `TypeError` in the verifier when the
  matching trust-store entry restricts `primitives`. The verifier now refuses it (`PRIMITIVE_NOT_ALLOWED`)
  and the endpoint answers `422 {"detail": "malformed envelope"}`. A non-string `primitive` that previously
  produced an HTTP 200 verdict (for example `null` or a number) now also answers 422 on this endpoint.
- **`POST /v1/audit/{primitive}` parses its body strictly**, as `/v1/verify` already did: a duplicate key,
  `NaN`/`Infinity` literal, byte-order mark, trailing data, empty body or non-object body is refused with
  HTTP 422 (`request body is not strict JSON` or `request body must be an object`). The body is still read
  and size-limited before authentication. Previously the last duplicate key won silently. The OpenAPI
  request body for this route is now a generic object.

### Changed

- The runtime Docker stage removes `pip` (nothing is installed after the build) and `.dockerignore` excludes
  environment files, key material and coverage output from the build context.
- `SECURITY.md` named `0.0.7` as the current version; it now names `0.1.1`.

## 0.1.0 — release candidate (NOT PUBLISHED)

Everything under the "0.1.0 —" headings below ships in this release. **0.1.0 is a Pre-Alpha release
with deliberate, behaviour-changing security defaults; read "Changed (breaking, deliberate)" in the
Phase 3A section and `docs/rc/RC_COMPATIBILITY_ASSESSMENT.md` before upgrading from 0.0.x.**

### Fixed

- **The JSON schemas are now included in the wheel and the sdist.** Every earlier release (0.0.2 to
  0.0.8) shipped without `schemas/*.schema.json`, so after a clean install `regaudit-fhe audit …`,
  `regaudit-fhe schema …` and any `load_schema` / `validate_*` call raised `FileNotFoundError`.
  The suite did not notice because it ran from a checkout where the loader found the files through
  its working-directory and repository-root fallbacks.
- **The schema loader reads only the installed package's `schemas/` directory.** It no longer falls
  back to `./schemas` or a repository-root `schemas/`. Callers who relied on a `schemas/` directory
  next to the working directory must stop; that directory could previously decide which schema
  validated a payload.

### Changed

- **Dependency floors were raised since 0.0.8:** `cryptography>=50.0.2` (was `>=42`), `tenseal>=0.3.16`
  (was `>=0.3.14`), `fastapi>=0.143.0` (was `>=0.115`), `uvicorn[standard]>=0.54.0` (was `>=0.30`),
  `pydantic>=2.14.0` (was `>=2`), plus higher floors for the development tools. The `dev` extra now
  also lists `setuptools>=70.1`. The suite passes with the runtime dependencies pinned at their floors.
- **The Docker base image moved from `python:3.12-slim-bookworm` to `python:3.14-slim-bookworm`.**
- `regaudit-fhe schema --list` and `/v1/schemas` now include `envelope.v2` (14 names, was 13).
- The `server` module no longer re-exports `VerifyRequest`, `verify_receipt`, `AuditEnvelope` or
  `BaseModel` (the request model was removed deliberately; the others were incidental imports).

- **`GET /readyz` now answers HTTP 503 (same JSON body, `"ready": false`) when the schema bundle cannot be
  loaded**, instead of 200. A probe that looks only at the status code now sees "not ready". `/healthz`
  is unchanged (200 while the process lives). If you scrape the old behaviour, read the `ready` field.

### Security fixes found by the AI-agent reviews of this candidate

- **The request-body limit now counts the bytes actually received on every route**, so a chunked body (no
  `Content-Length`) can no longer exceed it; the connection is answered with HTTP 413 as soon as the limit is
  passed, before authentication or parsing. Previously only `Content-Length` was checked, `/v1/audit/*` read and
  parsed an arbitrarily large chunked body before authenticating, and a 400 MiB chunked request raised the server's
  memory use by about 2.8 GB. Measured after the fix on a real uvicorn server: 200 MiB offered, response 413,
  memory unchanged.
- **Trust-store files are parsed with the strict JSON policy** (`loads_strict`): duplicate keys, `NaN`/`Infinity`,
  a BOM or invalid UTF-8 are now refused with `TrustStoreError`. Previously a duplicated key silently won, so a
  duplicate `"revoked"` entry could empty the revocation list and a duplicate key id could re-activate a
  compromised key. **Compatibility:** a trust store with such content (or a BOM) that loaded before is now refused.
- **A trust store in the legacy `keys`/`revoked`/`parameter_set_pins` form now refuses unknown top-level members.**
  A misspelt `"revokd": [...]` used to load with an empty revocation list, so a key meant to be revoked verified as
  `TRUSTED` (found by the adversarial review, reproduced on a real server). **Compatibility:** a legacy store with any
  other top-level member is now refused; the `entries` form already refused unknown members.
- Schema files and `regaudit-fhe audit --input` are read as UTF-8 regardless of the locale (two schemas contain
  non-ASCII text; under an ASCII locale loading them raised `UnicodeDecodeError`).
- An `OverflowError` inside a primitive (a huge integer) answers 422 like other inconsistent input.
- Inconsistent audit inputs that the schema cannot express (for example arrays of unequal length) answer HTTP 422
  instead of 500; the detail is logged server-side only.
- `regaudit-fhe verify --help` now says that `--allow-self-signed` outside the development profile exits 2 (it
  said 3, but the code returned 2).

### Release process

- The publishing workflow was rewritten **and renamed from `publish.yml` to `pypi-release.yml`** (the PyPI trusted
  publisher must be changed to the new file name, which also stops older commits that still contain the
  old, unguarded `publish.yml` from presenting the trusted name): the only trigger is a strict `vX.Y.Z` tag push (no `workflow_dispatch`);
  a `guard` job requires an annotated tag on the event commit that is reachable from the default branch;
  the tag, the source versions and the built wheel/sdist metadata must agree
  (`scripts/check_release_metadata.py`); the built wheel is installed and tested on Python 3.10-3.13 from
  outside the checkout before anything is signed; the digests recorded at build time are re-checked
  before upload; PyPI upload is confined to one job in the protected `pypi` environment; the default
  token has no permissions; third-party actions are pinned to commit SHAs. A `release-rehearsal` workflow
  runs the same build-and-test without publishing. `docs/RELEASE_PROCESS.md` lists what GitHub and PyPI
  settings must additionally be configured by the owner. None of this has been run on GitHub Actions.
- The build backend requirement is now bounded: `setuptools>=70.1,<85`.
- The sdist now ships `tests/` (helpers and data), `scripts/`, `schemas/` and `CHANGELOG.md`, so it can run the test suite against an installed wheel; `scripts/check_release_metadata.py` refuses an sdist that cannot, and a wheel or sdist with unexpected members or another project name.

### Known limitations carried into this release

- **The HTTP server is not hardened for direct exposure to untrusted clients.** There are no per-input
  resource caps on the audit primitives (for example the `provenance` bucket count grows memory with its square,
  and the request timeout answers 504 but does not cancel the worker), `X-Request-ID` has no length limit, a chunked 413 is logged as an unhandled exception and a client that disconnects mid-body on `/v1/verify` logs a traceback, `/readyz` checks one schema and caches the first successful load, the
  trust store is read once at start-up (revocation needs a restart), and the replay database is created with
  the process's default file mode. Run it behind a reverse proxy that enforces size, rate and time limits on
  every route.
- `verify_receipt(env)` without `strict=True` or trust material returns `True` for any envelope whose
  signature matches its own embedded key (documented; use `verify_envelope`/`verify_report` with a trust store).
- `/docs`, `/openapi.json`, `/healthz`, `/readyz` and `/version` are served without authentication by design (see `docs/DEPLOYMENT.md`).
- setuptools warns that the table-form `project.license` and the license classifiers stop being supported
  on 2027-02-18, and the sdist archive is not byte-reproducible (the wheel is).
- `requirements-dev.txt` is stale and not authoritative (see `docs/SUPPLY_CHAIN.md`).

### Tests

- `tests/test_installed_distribution.py` builds the sdist and wheel (and a wheel from the sdist),
  checks all 14 schemas are present, unpacks the wheel and runs it from a directory outside the
  repository (v1 and v2 sign/verify, schema validation). It also checks that the top-level
  `schemas/` copy (used by the Dockerfile) stays byte-identical to the packaged one. It needs
  `setuptools>=70.1`, which is now in the `dev` extra.

### Release notes

- `requirements-dev.txt` is a legacy convenience file, not an authoritative lockfile (see
  `docs/SUPPLY_CHAIN.md`).

## 0.1.0 — post-merge security maintenance

Follow-up to the security-maintenance change, from a retrospective (AI-assisted, static)
review. No change to the authentication design, the trust schema or any dependency *in that follow-up*; relative to the published 0.0.8 the dependency floors did change (see "Changed" under 0.1.0 above).

### Security

- **Explicit HMAC keys are validated.** `build_app(salt=...)` and
  `make_auth_dependency(salt=...)` now raise `ValueError` for a key shorter than 16 bytes
  (including empty) and `TypeError` for a non-bytes key. An invalid key is never replaced
  silently, and error messages never contain key material. Omitting `salt` (the default,
  and what `regaudit-fhe serve` does) still generates `os.urandom(32)`.
  **Compatibility:** an embedder passing a key under 16 bytes must now pass a longer,
  unpredictable one (`os.urandom(32)`). No shipped example, test or doc did so. Length is
  only a floor; it does not make a predictable key secure.
- **Structured logs keep one record on one line.** `json.dumps(ensure_ascii=False)` left
  U+0085, U+2028 and U+2029 unescaped, so Unicode-aware line splitters could see a forged
  second record in attacker-influenced text. They are now escaped (`\u0085` etc.); the JSON
  is equivalent and `\n` / `\r` were already escaped.

### Tests

- The FastAPI-dependent regressions moved to `tests/test_server_security_maintenance.py`.
  Only a missing FastAPI skips that module; a broken `regaudit_fhe.server` import now fails.
  The `_OnceFlag` and examples tests in `tests/test_security_maintenance.py` run in a
  `[dev]`-only environment (previously a module-level skip silently dropped them).

## 0.1.0 — security maintenance (CodeQL findings)

Confined to confirmed code-scanning findings; independent of any Phase 3B work and of
the trust schema. The full inventory and evidence are in
[docs/CODEQL_TRIAGE.md](docs/CODEQL_TRIAGE.md).

### Security

- **`/readyz` no longer returns exception text.** A failed schema load used to put
  `str(exc)` (which can contain file-system paths) in the response to an unauthenticated
  probe. It now reports `schema bundle unavailable`; the detail is written to the server
  log (`readyz_schema_unavailable`, fields `error_type` and `error`).
- **API bearer-token comparison uses HMAC-SHA256** keyed by the per-process random secret,
  instead of `SHA-256(salt + token)`. The digest is only ever used for a constant-time
  comparison; the comparison logic is unchanged.
  **Migration:** none is needed. The digests are computed at start-up from the configured
  keys, kept only in process memory, and never stored or transmitted, and the key is
  `os.urandom(32)` per process. The one derived value that leaves the process is the
  opaque 12-character `key_id` in logs and rate-limit buckets; its value changes with
  this release (it already changed on every restart). An embedder that pins a fixed
  `salt=` in `build_app` will see its `key_id` values change once.
- **The one-time "no trust material" warning from `verify_receipt` is now exactly-once.**
  A bare module-level flag mutated through `global` is replaced by a lock-guarded
  once-flag. The previous race was benign (at worst a duplicate warning).

### Changed

- The examples (`signed_envelope.py`, `regulator_verify_signature.py`,
  `openfhe_fairness_roundtrip.py`) print and assert `trust_status` / `sha256_valid` /
  `signature_valid` instead of the deprecated `valid` and the boolean `issuer_trusted`.

## 0.1.0 — Phase 3A: `report.v2` trust core

Candidate trust-core implementation of the approved parts of
`docs/TRUST_SPEC.md`. **Not production readiness.** Trust-anchor distribution
(O8), any timestamp authority (O9), shared replay infrastructure and
high-assurance historical acceptance are deliberately not implemented.

### Contract decisions applied after owner review

- **`RECORDED_LOCAL`** is a defined consumption state (never global replay
  protection, exactly-once execution or proof the operation completed). Every
  replay-checked result discloses `replay_durable` (`false` for the in-memory
  cache, which is lost on restart; `true` for the sqlite cache).
- **Retirement boundary is now strict**, like compromise: a timestamp whose
  latest possible time (`genTime + accuracy`) equals `retired_at` is refused,
  as is a signer-asserted `issued_at` equal to it (development only). This
  tightens the earlier candidate, which accepted equality for retirement. A
  valid timestamp still does not establish that trust history is complete (O8).
- **Unix sockets** are refused for the development self-signed option only
  (uvicorn reports no server address for them); normal trusted verification over
  a Unix socket is unaffected. The development option now also requires a known
  loopback peer.
- **`regaudit-fhe verify --trusted-keys`**: omitted is a usage error (`2`);
  supplied, even as an empty value, but unusable is infrastructure failure (`3`).
- `report.v1` is refused under `confidential` / `high-assurance` for now.
- A required timestamp is satisfied only by authenticated evidence.
- **Directly constructed `TrustStore(...)`** is held to the loaders' rules: Ed25519
  keys only and no key under two ids (previously only the loaders checked).
- **Canonical base64 on the `report.v1` path too:** a v1 signature or timestamp
  token that is not canonical base64 (trailing bits, whitespace, stray characters)
  no longer verifies.
- A replay store that fails **while verifying**, outside the development profile,
  is infrastructure failure (`verify` exit `3`, HTTP `503`), not a policy refusal.

### Added

- **`regaudit-fhe.report.v2`** (`envelope_v2`, `AuditEnvelopeV2`, `parse_envelope`,
  `docs`/JSON Schema `envelope.v2`). The signed body carries `issuer`, `key_id`,
  `public_key_fingerprint`, `deployment_id`, `audit_run_id`, optional `audience`
  and optional `model_commitment` / `dataset_commitment`, under a
  **domain-separated** Ed25519 signature. Unknown fields are refused everywhere.
  Timestamps are a list outside the signed body and bind the **sealed digest**
  (signed body + signature + key identity).
- **Strict canonical JSON policy** (`regaudit_fhe.canonical`): duplicate keys,
  `NaN`/`Infinity`, overflowing numbers, BOM, invalid UTF-8, lone surrogates,
  non-string keys, excessive depth and oversized input are refused. `report.v1`
  keeps its original lenient canonical bytes.
- **Shared verification engine** (`VerificationPolicy`, `verify_report`,
  `VerificationResult`): one policy for the library, CLI, HTTP server and
  `build_app()`. Results expose `trust_status`, `accepted`, `integrity_valid`,
  `issuer_trusted`, `key_status`, `chronology`, `signed_not_after`,
  `timestamp_status`, `reasons`, `blocking_reasons`, `replay_scope`,
  `consumption` and `trust_history`. `accepted` is the authoritative decision.
- **Key lifecycle** in a locally provisioned trust store (`entries` form):
  `active` / `retired` / `compromised`, validity bounds, deployment and
  primitive scope, parameter-set pin. One public key may be registered under one
  `key_id` only; keys must be Ed25519.
- **Chronology rules**: retired and compromised keys are accepted historically
  only with authenticated chronology (a caller-pinned `TimestampVerifier` over
  the sealed digest) **and** a fresh, authenticated `TrustHistory`. No mechanism
  in this release authenticates a trust history, so by default these reports are
  refused. An unknown compromise boundary refuses everything the key signed.
- **Local replay detection** (`InMemoryReplayCache`, `SqliteReplayCache`), with
  honest scope labels and `RECORDED_LOCAL`. Fails closed when full or broken
  outside the development profile. See the limits below.
- `regaudit-fhe verify` options: `--allow-self-signed`, `--profile`,
  `--verifier-id`, `--max-age-seconds`, `--replay-db`, `--replay-mode`,
  `--refuse-legacy-v1`.
- `build_app` is documented as a supported embedding entry point and listed in
  `regaudit_fhe.server.__all__`.
- Canonical test vectors with golden values (`tests/vectors/report_v2/`) and
  `scripts/mutation_check_phase3a.py`.

### Changed (breaking, deliberate)

- **`regaudit-fhe verify` exit codes**: `0` accepted, `1` refused by policy
  (including `SELF_SIGNED_ONLY`), `2` invalid input, usage or incompatible options
  (e.g. `--allow-self-signed` with a non-development profile, or a production
  profile without its required options), `3` a specified trust or replay resource
  that is unavailable or unusable. Two behaviours change:
  a consistent self-signed report used to exit `0` and now exits `1`; a
  malformed or empty `--trusted-keys` file used to exit `2` (and a missing path or a directory exited `1`
  with a traceback) and every unusable trust file now exits `3`. Running without `--trusted-keys` and without `--allow-self-signed` is a
  usage error (`2`). `serve` keeps `2` for "refusing to start".
- `regaudit-fhe verify` output gains the authoritative fields above and keeps
  `valid` (now an alias of `accepted`) and `trusted_issuer`.
- **`require_verified_timestamp` now requires a `VERIFIED` timestamp** (an absent
  timestamp no longer satisfies it) and needs a pinned `timestamp_verifier`.
  `report.v1` timestamps cover the body only, so they can never be `VERIFIED`.
- `ServerConfig.tsa_verifier` (Phase 1 candidate, unreleased) is replaced by
  `timestamp_verifier` with the v2 interface.
- `/v1/verify` reads the request body itself: strict JSON, exactly
  `{"envelope": ...}`, the size limit applies to chunked uploads too, 422 for any
  malformed input, and verification runs off the event loop.
- **`valid` is deprecated** on `VerificationOutcome` and `VerificationResult`
  (a `DeprecationWarning`), preserved through the first v2 release, with removal
  deferred to a later, explicitly breaking release.
- A trust store may no longer register the same public key under two `key_id`s,
  and every key must parse as Ed25519. Phase 1 helpers treat any non-`active`
  entry as revoked.
- **Removed/moved names:** `regaudit_fhe.server.PROFILES` now lives in
  `regaudit_fhe.verification` (importing it from `server` raises `ImportError`),
  and the `server.VerifyRequest` model is gone.
- **Stricter `/v1/verify` body:** exactly `{"envelope": ...}`; any extra key is a
  422, and the OpenAPI request model is no longer generated.
- **Non-development profiles are enforced when the app is built.**
  `confidential` and `high-assurance` now require a trust store, `max_age`, a
  persistent replay cache and a replay mode (and `high-assurance` a
  `verifier_id`); a deployment configured with less now fails at `build_app()` /
  startup with `PolicyError` instead of running with weaker checks.
- **`report.v1` is refused under `confidential` and `high-assurance`**
  (`REPLAY_ID_MISSING`): replay checking is mandatory there and a v1 report has no
  `audit_run_id`. (`docs/TRUST_SPEC.md` §7 and §6 can be read differently; see
  Appendix C.2.)
- `TrustStore` is now immutable after construction (its mappings are read-only
  views and `revoked` a `frozenset`), copies what it is given, and refuses a
  direct construction whose `keys`/`revoked`/`parameter_set_pins` disagree with
  its `entries`.
- Development-only self-signed verification now also requires, on every
  request, a loopback TCP server socket **and** a known loopback client (Unix
  sockets are refused for this option), and refuses any forwarding header unless an explicit trusted-proxy policy vouches for it.

### Security hardening found by independent review during this phase

Same key under two ids bypassing a compromised status; non-canonical base64
changing the sealed digest; loose RFC 3339 timestamps; replay-store input
guards; X-Forwarded-For parsing across multiple header lines; IPv4-mapped
loopback; replay retention that could be shorter than report freshness;
chronology reported for unauthenticated issuers; blocking replay I/O on the
event loop; non-finite `--max-age-seconds`; unbounded trust-store and report
files.

### Remaining limitations

- No trust-anchor distribution or anchor-signed bundles (**O8**): an
  *authenticated* `TrustHistory` cannot be produced by this library, so
  historical acceptance of retired/compromised keys is refused unless a caller
  injects one. `high-assurance` never accepts historical keys.
- No timestamp authority or default roots (**O9**); only a caller-pinned
  verifier interface.
- Replay detection is **local** only. `RECORDED_LOCAL` means "recorded in this
  verifier's store at verification time"; it is not coupled to any downstream
  operation and is not a crash-safe exactly-once guarantee. Any caller holding
  `audit:verify` can consume an `audit_run_id` first when `record` mode is on.
  Independent verifiers without a shared store can each accept a report once.
- `report.v2` is produced by the library API only; `regaudit-fhe audit` and
  `/v1/audit/*` still emit `report.v1` signed by an ephemeral key.
- Float formatting follows Python's `repr`; a non-Python verifier needs RFC 8785
  (or byte-identical formatting) before claiming v2 compatibility.
- A header-less local reverse proxy cannot be distinguished from a direct local
  client, so the development self-signed option must not be enabled behind one.
  Under uvicorn a Unix-socket request reports no server address; the development
  option refuses it by decision (normal verification is unaffected).
- `BodySizeLimitMiddleware` still checks `Content-Length` only for the other
  endpoints (only `/v1/verify` now bounds chunked uploads).
- Phase 3A does not address the larger confidential-computation limitations
  (evaluator/decryption-key separation, OpenFHE behavioural verification,
  differential-privacy enforcement).

## 0.1.0 — Phase 1 trust hardening (partly superseded by Phase 3A above)

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

### Documentation

- `valid` is documented as not a provenance claim; a verified timestamp is
  documented as not proof of non-revocation; the `build_app()` entry-point
  contract is documented. The target design is in `docs/TRUST_SPEC.md`
  (specification only).

### Unchanged

- The v1 canonical signing format (`regaudit-fhe.report.v1`); existing reports
  still parse and verify cryptographically. (Phase 1 added no `report.v2` fields;
  Phase 3A, above, introduces `report.v2` without changing v1.)
- The `timestamp` block remains outside the signed body.

### Remaining trust limitations

- At Phase 1 there was no replay protection, freshness window or audit-run
  binding; Phase 3A adds a freshness window, a signed `audit_run_id` and *local*
  replay detection for `report.v2` only (see above).
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
