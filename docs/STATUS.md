# Project status

What is checked automatically, what is not provided, and what the current release ships.

## Production / regulator readiness — what is and isn't validated

**In short:** the library is ready to *evaluate and integrate*. It is not a finished
compliance product, and the verification core is a candidate. The tables below say
exactly what is checked automatically, what is only partly done, and what is not provided.

> The release gate in [DEVELOPMENT.md](DEVELOPMENT.md#verify-a-fresh-clone) guarantees the package builds, imports,
> exposes the documented CLI / API, and passes its test suite. That
> is **not** the same as being validated for regulated production use.
> The matrix below is the honest current state.

| Property                                | Status                                                                              |
| --------------------------------------- | ----------------------------------------------------------------------------------- |
| Python syntax + imports                 | Verified by CI on every push.                                                       |
| pytest suite (800+ tests)               | Verified by CI on every push (Linux py3.10–3.13 + macOS py3.12 / 3.13).             |
| Coverage gate                           | `--cov-fail-under=80` enforced in CI; currently about 89%.                          |
| Type checking                           | `mypy` gates CI: zero errors across the source tree.                                 |
| Static security                         | `bandit` (medium+) gates CI; CodeQL (security-and-quality) runs on push and weekly. |
| Lint                                    | `ruff check` gates CI with E/F/W/B/S/UP/I/SIM/RUF/A rule set.                       |
| Real CKKS encrypted backend (TenSEAL)   | Shipped under `[fhe]`; equivalence-tested.                                          |
| OpenFHE CKKS backend (experimental)     | Shipped under `[openfhe]`; registry-selectable; equivalence-tested for 5/6          |
|                                         | primitives (concordance pending rectangular `mm_pt`). Not the verified reference.   |
| External key custody (KMS / HSM)        | `CallableKeyProvider` keeps the signing key off-host; fails closed on bad sig.      |
| Differential-privacy output noise       | Optional `regaudit_fhe.dp` (Laplace / Gaussian); signed `dp` block. Sensitivity is  |
|                                         | the deployer's responsibility — the library calibrates, it does not bound.          |
| Generated API reference                 | `pdoc` HTML built in CI (`docs.yml`); see [docs/API.md](API.md).               |
| Signed audit envelope (Ed25519)         | `report.v1` and `report.v2`; canonical-JSON + tamper tests.                         |
| `report.v2` signed identity (candidate) | Issuer, key id + fingerprint, deployment, run id, audience signed under a           |
|                                         | domain-separated signature; strict parser; golden test vectors.                     |
| Shared verification policy (candidate)  | One engine for library, CLI, HTTP and `build_app()`: `TRUSTED` / `SELF_SIGNED_ONLY` |
|                                         | / `INVALID`, key lifecycle and scope, strict chronology, freshness, audience.       |
| Trust store + typed verifier failures   | `TrustStore` (flat and `entries` forms) + typed `EnvelopeVerificationError`s.       |
| CLI exit codes                          | `verify`: 0 accepted / 1 refused / 2 usage / 3 resource unusable; process-tested.   |
| Local replay detection                  | In-memory and sqlite caches; `RECORDED_LOCAL`, durability disclosed. Local only.    |
| Mutation-sensitivity check              | `scripts/mutation_check_phase3a.py`: trust-core tests catch deliberate bugs.        |
| JSON Schemas                            | Shipped; validated on every CLI / API request.                                      |
| Hardened HTTP server                    | Constant-time bearer compare, opaque key_id in logs, `DEV_MODE` non-loopback bind   |
|                                         | refusal, scopes, rate limit, CORS, audit log.                                       |
| Concurrency-safe depth state            | `ContextVar`-backed `last_depth` / `last_depths`; cross-thread / asyncio isolated.  |
| Reproducible wheel                      | CI builds twice with pinned `SOURCE_DATE_EPOCH`, asserts SHA-256 stable.            |
| Sigstore-signed wheel + sdist           | Keyless OIDC bundles attached to every GitHub Release.                              |
| Real benchmarks at N=2^14, N=2^15       | Shipped; reproducible from `benchmarks/bench_fhe.py`.                               |

**Not provided or not validated**

| Property                                | Status                                                                              |
| --------------------------------------- | ----------------------------------------------------------------------------------- |
| Trust-anchor distribution, signed trust-store bundles | Not implemented. A trust store is a local file; its completeness and freshness   |
|                                         | cannot be authenticated, so historical acceptance of retired/compromised keys is refused. |
| Timestamp authority                     | None bundled. Required timestamps need a verifier you pin; none is trusted by default. |
| Global / shared replay protection       | Not provided. Replay detection is local and not coupled to any operation.           |
| High-assurance historical verification  | Not implemented.                                                                    |
| Evaluator / key-holder separation       | The encrypted path still encrypts, evaluates and decrypts in one process.           |
| External security audit                 | Not performed. Reviews of the trust core were internal.                             |
| `report.v2` from the HTTP audit         | Not yet: `/v1/audit/*` emits `report.v1` (ephemeral key). The CLI emits `report.v2` with `audit --signing-key`. |
| Post-quantum authentication             | Not provided (Ed25519).                                                             |

`regaudit-fhe` is a dependency you can bring into a compliance
workflow today; it is not, by itself, a finished compliance product.
[COMPLIANCE.md](../COMPLIANCE.md) lists what each primitive does NOT
prove, regulation by regulation.

## Maturity and status

> **Description:** *Depth-tracked regulatory audit primitives for
> privacy-preserving AI audits.*
>
> **Backends:** TenSEAL CKKS is the verified reference backend
> (`regaudit_fhe.fhe`). An **experimental** OpenFHE CKKS backend
> (`regaudit_fhe.fhe.openfhe`) is also selectable through the backend
> registry; it covers every primitive except encrypted concordance
> (which needs rectangular `mm_pt`). See
> [docs/roadmap/openfhe_backend.md](roadmap/openfhe_backend.md)
> for the design note.

The current release ships:

- the plaintext SlotVec model with strict depth-budget enforcement,
- a TenSEAL CKKS backend that mirrors the SlotVec algebra and passes
  end-to-end ciphertext / plaintext equivalence tests,
- a pluggable backend registry (`regaudit_fhe.fhe.get_backend` /
  `available_backends`) with an experimental OpenFHE CKKS backend that
  runs the same circuits via the Halevi–Shoup diagonal method,
- the Ed25519-signed audit envelope with canonical-JSON rules,
  parameter-set hashing, and input commitments,
- a typed verifier surface — `TrustStore` (key_id → PEM, revocation,
  parameter-set pinning, and the `entries` form with key status, validity and
  issuer / deployment / primitive scope) plus `verify_envelope_or_raise`
  raising `UntrustedIssuer` / `RevokedIssuer` / `WrongParameterSet` /
  `HashMismatch` / `InvalidSignature` / `TimestampInvalid` for regulator-side
  use,
- a **candidate `report.v2` trust core**: a signed issuer / key / deployment /
  audit-run identity, strict canonical JSON, a shared `VerificationPolicy`
  (`verify_report`) with explicit `trust_status` and `accepted` outcomes,
  fail-closed key-lifecycle and chronology rules, local replay detection with
  disclosed durability, and `regaudit-fhe verify` exit codes 0/1/2/3. It is
  verified by process-level, golden-vector and mutation-sensitivity tests, and it
  explicitly refuses configurations it cannot support (see the table above),
- a key-custody seam — `CallableKeyProvider` keeps the Ed25519 signing
  key in a KMS/HSM, so only a public PEM and a sign-callable enter the
  audit host,
- an optional differential-privacy output-perturbation layer
  (`regaudit_fhe.dp`: Laplace / Gaussian mechanisms, a basic-composition
  accountant, and a signed `dp` disclosure block in the envelope),
- JSON Schemas for every input, output, and the envelope itself,
- the hardened HTTP audit server with constant-time bearer-token
  compare, opaque hashed key_id in logs, scopes, body-size limit,
  rate limiting, structured logs, CORS controls, and a `DEV_MODE`
  non-loopback bind guard,
- concurrency-safe depth recording via `ContextVar` so concurrent
  encrypted requests cannot race on the depth state,
- supply-chain controls: Trusted-Publisher PyPI release, Sigstore
  keyless signing of the wheel + sdist, reproducible-build CI gate
  (pinned `SOURCE_DATE_EPOCH`, two builds, identical SHA),
  CycloneDX SBOM, `pip-audit`, CodeQL, weekly Dependabot.

Contributions are not accepted — see [CONTRIBUTING.md](../CONTRIBUTING.md).
