# Changelog

All notable changes to **regaudit-fhe** are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project follows [Semantic Versioning](https://semver.org/).

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
- OpenFHE backend skeleton (`[fhe]` extra) documenting the integration
  surface.
- Per-primitive technical specifications under `docs/specs/`.
- Four end-to-end examples covering local audits, regulator submissions,
  receipt verification, and a pure-CLI workflow.
- 15 pytest cases covering oracle agreement, depth-budget enforcement,
  envelope serialisation, and tamper detection.
