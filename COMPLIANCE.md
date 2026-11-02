# Compliance scope and limits

> **Read this before citing `regaudit-fhe` in any compliance, audit,
> conformity, or filing context.** It states what the library produces
> and — equally important — what it does NOT produce.

---

## What the library is

`regaudit-fhe` produces **technical evidence**: numerical scalars,
boolean breach indicators, decryption-error bounds, depth-budget
fields, and Ed25519-signed audit envelopes. The artefacts are
designed to fit into compliance workflows but **do not constitute
compliance, certification, conformity assessment, or regulatory
acceptance** by themselves.

A regulator, auditor, conformity-assessment body, or licensed
attorney decides whether a given audit envelope satisfies a given
regulatory requirement. The library cannot make that decision and
does not attempt to.

A signed envelope carries authenticated claims. The signature shows that a
holder of the named key signed those fields. It does not independently verify
that an encrypted computation ran. `depth_budget.consumed` is 6 unless the
caller passes a value, so by default it is not a measurement.

These releases rely on AI-assisted testing and review. They have had no
independent external security audit, and no production assurance is claimed.

---

## Mapping primitives to regulations

The table below is the binding scope statement. Anything not listed is
out of scope. Items in the **What the library does NOT prove** column
must be addressed by other parts of the deployment (legal review,
governance, validation studies, regulator submissions, etc.).

"Encrypted" in this table names the optional functions in `regaudit_fhe.fhe`.
The default path, the CLI and the HTTP server run on plaintext. Encryption is
partial and the key stays in the same process: `fairness_encrypted`, for example,
encrypts only `y_pred`. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) §3 for
each primitive. The status of the regulations named here is in
[Regulatory status notes](#regulatory-status-notes).

| Regulation                              | Requirement area                              | What `regaudit-fhe` computes                                          | What it does NOT prove                                                 |
| --------------------------------------- | --------------------------------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **NYC Local Law 144**                   | Bias audit for HR-AI tools.                   | Encrypted demographic-parity, equal-opportunity, and predictive-parity disparity scalars between two protected groups. | Legal compliance with LL144. Independent-auditor designation. Public bias-audit posting requirements. Notice-to-candidate obligations. |
| **EU AI Act, Article 10**               | Data and data-governance.                     | Encrypted top-K training-data-provenance histogram; input-commitment hashes binding the audit to a specific dataset. | Conformity assessment. Lawful basis for training-data processing. Demonstrated representativeness or relevance of the training set. |
| **EU AI Act, Article 15**               | Accuracy, robustness and cybersecurity.       | Encrypted drift, calibration, fairness, and disagreement scalars; signed audit envelopes for evidentiary record-keeping. | Any level of accuracy, robustness or cybersecurity the Article requires. Accuracy benchmarks against the regulator's reference dataset. The Article 17 quality-management system. |
| **EU AI Act, Article 72**               | Post-market monitoring.                       | Encrypted drift, calibration, and disagreement scalars that a monitoring process can repeat over time; signed audit envelopes for record-keeping. | The post-market monitoring system or plan itself. |
| **EU AI Act, Article 17**               | Quality management system.                    | Schema- and signature-pinned audit-trail envelopes that a QMS can ingest. | The QMS process itself. Document-control. Change-management. Training records. |
| **Colorado SB26-189**                   | Automated decision-making technology. Requirements start 1 January 2027. | The same encrypted disparity scalars as NYC LL144. These are not mapped to a specific duty under SB26-189. | Compliance with SB26-189. Consumer disclosures or any other duty under the Act. |
| **ECOA and Regulation B**               | Adverse-action duties.                        | Encrypted disparity scalars at decision boundary.  | Reg B / ECOA compliance. Adverse-action notice content. Reasons-for-denial accuracy. |
| **FDA SaMD Predetermined Change-Control Plan (PCCP)** | Post-market AI/ML monitoring. | Encrypted concordance (C-index), calibration, drift, and disagreement primitives at fixed CKKS parameters. | FDA acceptance of a specific PCCP submission. Clinical validation. Substantial-equivalence determinations. SaMD risk classification. |
| **FDA AI-SaMD UQ guidance**             | Distribution-free uncertainty quantification. | Encrypted conformal-prediction-set bitmask. | Validation of the calibration set. Coverage-guarantee proofs in the regulatory submission. |
| **EMA AI guidance**                     | Survival-AI performance attestation.          | Encrypted concordance audit primitive. | Marketing authorisation. Pharmacovigilance reporting. Real-world-evidence study design. |
| **SR 26-2 and OCC Bulletin 2026-13**    | Model risk management. Generative and agentic AI are outside the scope. | Encrypted cross-model disagreement (champion-vs-challenger).         | Independent model validation. Internal audit findings. Any finding that a bank's model risk management meets this guidance. |
| **HIPAA**                               | PHI minimum necessary.                        | The HTTP server and the default path process inputs in plaintext. The encrypted functions take plaintext inputs and decrypt in the same process, so the library alone does not keep PHI from the host running it. | A HIPAA Security Rule risk assessment. Business-associate agreements. Breach-notification programme. |
| **GDPR, Article 22**                    | Algorithmic-decision review.                  | Encrypted attribution-bucket histograms feeding a human review process. | The right-to-explanation as interpreted in your jurisdiction. Lawful basis under Article 6. Data-protection impact assessment. |
| **21 CFR Part 11**                      | FDA training-data audit trail.                | Ed25519-signed audit envelopes with SHA-256 canonical receipts.                                                          | Validated electronic-signature programme under §11.10. Computer-system-validation lifecycle. |
| **ISO/IEC 23053**                       | Trustworthy AI framework.                     | Calibrated UQ + concordance + drift primitives that map to several ISO 23053 controls. | ISO 23053 certification. Management-system audit. |
| **UNECE WP.29**                         | UQ for autonomous-vehicle AI.                 | Encrypted conformal-prediction-set bitmask. | Type-approval of the AV system. Cybersecurity Management System (CSMS) audit under R155. |
| **Basel III model risk**                | Distribution-shift evidence for credit models. | Encrypted drift primitive over input-feature histograms. | The Basel III internal-models approval. Capital-floor calculation. Backtesting framework. |

---

## Regulatory status notes

Status of the items below as checked on 2026-11-01. This is a summary and not
legal advice. The other rows of the table were not rechecked on that date.

- **SR 11-7 and OCC Bulletin 2011-12** were superseded on 17 April 2026 by
  SR 26-2 and OCC Bulletin 2026-13. Generative and agentic AI are outside the
  scope of the new guidance. An earlier version of this file called SR 11-7 an
  "OCC Supervisory Letter", which was a misnomer.
- **Colorado SB24-205** was repealed and reenacted by SB26-189, signed on
  14 May 2026. SB26-189 is about automated decision-making technology, with
  requirements starting on 1 January 2027. The legislative summary does not
  describe impact assessments or bias audits.
- **CFPB Circular 2022-03** was withdrawn on 12 May 2025 (90 FR 20084). The
  adverse action duties in ECOA and Regulation B stay.
- **The EU AI Act** was amended by Regulation (EU) 2026/1744, in force on
  27 July 2026. Annex III high-risk requirements apply from 2 December 2027 and
  Annex I from 2 August 2028. Article 15 is accuracy, robustness and
  cybersecurity. Post-market monitoring is Article 72.

Default reports still sign the older labels in `REGULATION_MAP`, including
`OCC_SR_11_7`, `COLORADO_AI_ACT` and `CFPB_ALG_DISCRIM`, and `EU_AI_ACT_ART15` on
the monitoring primitives. These are identifiers and not a statement that a rule
is in force or applies. A library caller can pass `regulations=` to `envelope()`
or `envelope_v2()` to sign a different list.

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
- ✗ "All disparity primitives run end-to-end under CKKS encryption;
   per-row labels never leave the encrypted domain." (`fairness_encrypted`
   encrypts only `y_pred`, and labels are plaintext in the same call.)
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
