# Security policy

## Supported versions

| Version | Status |
| --- | --- |
| `0.2.0` (published 2026-10-31) | Latest release; receives security updates. |
| `0.1.1`, `0.1.0` | Still on PyPI, not yanked; not supported. Upgrade to the latest release. |

Only the latest release receives security updates. See `CHANGELOG.md` and
`docs/releases/` for what each release contains and its known limitations. These
are AI-assisted engineering releases: not externally audited, and human code review
was waived by the owner.

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
