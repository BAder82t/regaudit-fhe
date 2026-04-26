# Compliance scope and limits

> **Read this before citing `regaudit-fhe` in any compliance, audit,
> conformity, or filing context.** It states what the library produces
> and — equally important — what it does NOT produce.

---

## What the library is

`regaudit-fhe` produces **technical evidence**: numerical scalars,
boolean breach indicators, decryption-error bounds, depth-budget
attestations, and Ed25519-signed audit envelopes. The artefacts are
designed to fit into compliance workflows but **do not constitute
compliance, certification, conformity assessment, or regulatory
acceptance** by themselves.

A regulator, auditor, conformity-assessment body, or licensed
attorney decides whether a given audit envelope satisfies a given
regulatory requirement. The library cannot make that decision and
does not attempt to.

---

## Mapping primitives to regulations

The table below is the binding scope statement. Anything not listed is
out of scope. Items in the **What the library does NOT prove** column
must be addressed by other parts of the deployment (legal review,
governance, validation studies, regulator submissions, etc.).

| Regulation                              | Requirement area                              | What `regaudit-fhe` computes                                          | What it does NOT prove                                                 |
| --------------------------------------- | --------------------------------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **NYC Local Law 144**                   | Bias audit for HR-AI tools.                   | Encrypted demographic-parity, equal-opportunity, and predictive-parity disparity scalars between two protected groups. | Legal compliance with LL144. Independent-auditor designation. Public bias-audit posting requirements. Notice-to-candidate obligations. |
| **EU AI Act, Article 10**               | Data and data-governance.                     | Encrypted top-K training-data-provenance histogram; input-commitment hashes binding the audit to a specific dataset. | Conformity assessment. Lawful basis for training-data processing. Demonstrated representativeness or relevance of the training set. |
| **EU AI Act, Article 15**               | Accuracy, robustness, post-market monitoring. | Encrypted drift, calibration, fairness, and disagreement scalars; signed audit envelopes for evidentiary record-keeping. | Robustness testing. Accuracy benchmarks against the regulator's reference dataset. The Article 17 quality-management system. |
| **EU AI Act, Article 17**               | Quality management system.                    | Schema- and signature-pinned audit-trail envelopes that a QMS can ingest. | The QMS process itself. Document-control. Change-management. Training records. |
| **Colorado AI Act**                     | Algorithmic-decision impact assessment.       | The same encrypted disparity scalars as NYC LL144. | Impact assessment under §6-1-1701 et seq. Consumer disclosures. Risk-management programme. |
| **CFPB algorithmic-discrimination guidance** | Adverse-action consistency.              | Encrypted disparity scalars at decision boundary.  | Reg B / ECOA compliance. Adverse-action notice content. Reasons-for-denial accuracy. |
| **FDA SaMD Predetermined Change-Control Plan (PCCP)** | Post-market AI/ML monitoring. | Encrypted concordance (C-index), calibration, drift, and disagreement primitives at fixed CKKS parameters. | FDA acceptance of a specific PCCP submission. Clinical validation. Substantial-equivalence determinations. SaMD risk classification. |
| **FDA AI-SaMD UQ guidance**             | Distribution-free uncertainty quantification. | Encrypted conformal-prediction-set bitmask. | Validation of the calibration set. Coverage-guarantee proofs in the regulatory submission. |
| **EMA AI guidance**                     | Survival-AI performance attestation.          | Encrypted concordance audit primitive. | Marketing authorisation. Pharmacovigilance reporting. Real-world-evidence study design. |
| **OCC Supervisory Letter SR 11-7**      | Model risk management.                        | Encrypted cross-model disagreement (champion-vs-challenger).         | Independent model validation. Effective challenge. Internal audit findings. The SR 11-7 attestation itself. |
| **HIPAA**                               | PHI minimum necessary.                        | The library never decrypts PHI server-side; PHI stays encrypted under CKKS for the entire audit run. | A HIPAA Security Rule risk assessment. Business-associate agreements. Breach-notification programme. |
| **GDPR, Article 22**                    | Algorithmic-decision review.                  | Encrypted attribution-bucket histograms feeding a human review process. | The right-to-explanation as interpreted in your jurisdiction. Lawful basis under Article 6. Data-protection impact assessment. |
| **21 CFR Part 11**                      | FDA training-data audit trail.                | Append-only signed envelope chain (in the closed-source companion product); SHA-256 receipts in the open-source library. | Validated electronic-signature programme under §11.10. Computer-system-validation lifecycle. |
| **ISO/IEC 23053**                       | Trustworthy AI framework.                     | Calibrated UQ + concordance + drift primitives that map to several ISO 23053 controls. | ISO 23053 certification. Management-system audit. |
| **UNECE WP.29**                         | UQ for autonomous-vehicle AI.                 | Encrypted conformal-prediction-set bitmask. | Type-approval of the AV system. Cybersecurity Management System (CSMS) audit under R155. |
| **Basel III model risk**                | Distribution-shift evidence for credit models. | Encrypted drift primitive over input-feature histograms. | The Basel III internal-models approval. Capital-floor calculation. Backtesting framework. |

---

## What "audit" means in this library

Inside `regaudit-fhe`, **audit** is an engineering term: an encrypted
numerical computation that produces signed evidence. It is **not**:

- A statutory audit under company-law definitions.
- A regulatory inspection.
- A professional engagement under any auditing standard
  (ISA, GAAS, ISAE 3000, AT-C 105, …).
- A "fairness audit" within the NYC DCWP definition unless conducted
  by an independent auditor of the buyer's choosing under §1-22 et seq.
- A SOC 2 or ISO 27001 control test.

The artefact (signed audit envelope) **may be evidence used by**
those regulated processes, but the library does not perform them.

---

## Recommended language for marketing and contracts

When citing `regaudit-fhe` in marketing, customer collateral, or
contracts, prefer language that makes the scope explicit:

- ✓ "Our pipeline produces technical evidence supporting the NYC LL144
   bias-audit workflow using `regaudit-fhe`."
- ✓ "We submit cryptographically signed drift-monitoring envelopes
   monthly under our FDA SaMD predetermined-change-control plan."
- ✓ "All disparity primitives run end-to-end under CKKS encryption with
   128-bit IND-CPA security; per-row labels are never decrypted."
- ✗ "Our system is NYC LL144 / EU AI Act / FDA SaMD compliant."
- ✗ "We are certified under EU AI Act Article 17."
- ✗ "Our audit is a regulator-recognised conformity assessment."

The first set is defensible. The second set isn't, regardless of what
the library outputs — only the regulator or accredited body can grant
those statuses.

---

## When in doubt

Ask qualified counsel. The library cannot be the source of truth for
compliance status. It can only produce repeatable, signed,
parameter-bound technical evidence that compliance professionals then
use as one input to their decision.

For commercial deployments, VaultBytes Innovations Ltd offers paid
consulting to map specific deployments to specific regulatory
requirements; contact **b@vaultbytes.com**.
