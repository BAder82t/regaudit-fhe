# Security policy

## Supported versions

`regaudit-fhe` is currently at `0.0.1`. Only the latest release receives
security updates.

## Reporting a vulnerability

Email **b@vaultbytes.com** with the subject line `regaudit-fhe security`.
Please include:

- a description of the vulnerability,
- a minimal reproduction (input or attacker model),
- the impact you observed or expect,
- any proposed mitigation.

VaultBytes Innovations Ltd will acknowledge receipt within five business
days and provide a remediation timeline within ten business days.

## Threat model

`regaudit-fhe` operates inside a standard CKKS threat model:

- The audit operator (the entity running the primitives) is honest but
  curious. Encrypted inputs are never decrypted server-side.
- Auditor-public quantities are the regulation citations, the audit
  envelope schema, and a set of public group-cardinality scalars
  documented in each primitive's specification under `docs/specs/`.
- IND-CPA security at 128 bits is inherited from the underlying CKKS
  parameter set (`N = 2^15`, `log Q ~ 240`, hybrid key switching
  `dnum = 3`).

Findings outside that model — for example, side-channel timing on the
audit operator's host — should be reported through the same channel.
