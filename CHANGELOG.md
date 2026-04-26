# Changelog

All notable changes to **regaudit-fhe** are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project follows [Semantic Versioning](https://semver.org/).

## [0.0.4] - 2026-04-27
### Fixed
- README quick-start install line said `[fhe]` "adds OpenFHE"; the
  `[fhe]` extra installs **TenSEAL**. Reworded the line to match
  reality.
- Example `openfhe_fairness_roundtrip.py` now prints
  ``backend: tenseal-ckks (open-source)`` instead of the placeholder
  ``backend: openfhe`` so the demo summary tells the truth about
  which backend executed.
- `_slot.py` module docstring updated: the optional encrypted
  backend is TenSEAL CKKS (`regaudit_fhe.fhe`), not OpenFHE.
- `docs/specs/01_egf_imss.md` reference deployment line: TenSEAL is
  the active backend; OpenFHE deployment lives in the closed-source
  roadmap.

## [0.0.3] - 2026-04-27
### Removed
- `src/regaudit_fhe/backends/` (the empty `OpenFHE` skeleton).
  It was a leftover from earlier scaffolding that contradicted
  v0.0.2's claim of a working CKKS backend. The real, exercised CKKS
  backend lives at `regaudit_fhe.fhe` (TenSEAL); the OpenFHE-specific
  variant is part of the closed-source companion product roadmap, not
  the open-source repo.

### Changed
- Documentation and changelog rewording to make the active backend
  unambiguous: **TenSEAL CKKS today, no OpenFHE in this repo**.

## [0.0.2] - 2026-04-27
### Added
- TenSEAL CKKS encrypted backend under the `[fhe]` extra, exposed as
  `regaudit_fhe.fhe` with end-to-end ciphertext / plaintext
  equivalence tests. (The misleading `regaudit_fhe.backends.openfhe`
  skeleton was retired in v0.0.3.)
- Validated `CKKSParams` parameter set (128-bit security, modulus-chain
  depth, scale stability, rotation-key minimality, precision-loss
  bounds) plus `build_d6_context_from_params`.
- Ed25519-signed audit envelope: canonical JSON, parameter-set hash,
  input commitments, optional RFC-3161 timestamp authority.
- `docs/THREAT_MODEL.md` — formal threat / leakage model, per-primitive
  public-surface tables, regulator-side verification checklist.
- `docs/COMPLIANCE.md` — binding scope statement covering 16
  regulations with what-we-do-NOT-prove columns.
- 13 JSON Schemas (Draft 2020-12) for every primitive input / output
  and the audit envelope; CLI `regaudit-fhe schema` subcommand and
  HTTP `/v1/schemas` endpoint.
- Hardened HTTP server: bearer-token auth + scopes, body-size limit,
  in-process token-bucket rate limiter, per-request timeout, JSON
  access logs that never echo audit payloads, CORS allow-list,
  `/healthz`, `/readyz` (with privacy-boundary warning), `/version`.
- `Dockerfile` (multi-stage, non-root UID 10001) and
  `docs/DEPLOYMENT.md` with Kubernetes reference manifests and a
  production checklist.
- Five new examples: `openfhe_fairness_roundtrip`, `signed_envelope`,
  `server_client`, `regulator_verify_signature`, `benchmark_reproduce`.
- Real CKKS benchmarks at `N = 2^14` and `N = 2^15`; results in
  `benchmarks/results/SUMMARY.md` + per-ring JSON.
- Adversarial / edge-case test suite (NaN/Inf rejection, empty
  arrays, single-group cases, extreme thresholds), envelope
  robustness tests (tampering, schema mismatch, key swap), and
  Hypothesis property-based tests for FHE↔plaintext equivalence,
  canonical-JSON byte stability, and commitment uniqueness.
- Supply-chain controls: weekly Dependabot, `pip-audit`, CycloneDX
  SBOM generation, pinned `requirements-dev.txt`, Sigstore-attested
  PyPI Trusted-Publisher release workflow, `docs/SUPPLY_CHAIN.md`.

### Changed
- Project description repositioned to "Depth-tracked regulatory audit
  primitives for future FHE-CKKS execution." to match maturity.
- Drift primitive switched from sign-poly-based W1 (~25 % relative
  error) to Cramer-von-Mises CDF L2² (depth 1, exact under encryption).

## [0.0.1] - 2026-04-26
### Added
- Six audit primitives, each evaluable inside a CKKS multiplicative-depth
  budget of six without bootstrapping:
  - `audit_fairness` (group-fairness disparities, depth 4)
  - `audit_provenance` (top-K training-data provenance, depth 3)
  - `audit_concordance` (Harrell C-index, depth 4)
  - `audit_calibration` (conformal prediction sets, depth 3)
  - `audit_drift` (Cramer-von-Mises CDF L2 distance, depth 1)
  - `audit_disagreement` (cross-model disagreement, depth 5)
- Plaintext SlotVec model with strict depth-budget enforcement.
- Audit envelope schema (`regaudit-fhe.report.v1`) with SHA-256 receipts
  and regulation-tag mapping for NYC LL144, EU AI Act §10/§15, Colorado
  AI Act, FDA SaMD PCCP, FDA AI-SaMD UQ, OCC SR 11-7, ISO/IEC 23053,
  Basel III, GDPR §22, HIPAA, 21 CFR Part 11, and UNECE WP.29.
- Command-line interface: `regaudit-fhe audit ...`, `... verify ...`,
  `... serve ...`.
- Optional HTTP server (`[server]` extra) backed by FastAPI.
- Initial scaffold for an OpenFHE-specific backend (later removed in
  v0.0.3 because it never carried a working implementation; the real
  CKKS backend ships under `regaudit_fhe.fhe`).
- Per-primitive technical specifications under `docs/specs/`.
- Four end-to-end examples covering local audits, regulator submissions,
  receipt verification, and a pure-CLI workflow.
- 15 pytest cases covering oracle agreement, depth-budget enforcement,
  envelope serialisation, and tamper detection.
