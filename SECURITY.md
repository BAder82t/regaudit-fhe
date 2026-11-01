# Security policy

## Supported versions

| Version | Status |
| --- | --- |
| `0.2.1` (published 2026-11-01) | Latest release; receives security updates. |
| `0.2.0`, `0.1.1`, `0.1.0` | Still on PyPI, not yanked; not supported. Upgrade to the latest release. |

Only the latest release receives security updates. See `CHANGELOG.md` and
`docs/releases/` for what each release contains and its known limitations. These
releases rely on AI-assisted testing and review. They have had no independent external
security audit, and no production assurance is claimed.

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

The full model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). This section
keeps three things apart: what 0.2.1 does, what is experimental, and what is
only an intended design.

**Actual behaviour in 0.2.1**

- The default path, the CLI and the HTTP server run on plaintext. The host
  running them can read the inputs.
- The encrypted path is six Python functions in `regaudit_fhe.fhe.primitives`,
  available with the `[fhe]` extra (TenSEAL). Each function takes plaintext
  arguments, the context holds the secret key, and one process encrypts,
  evaluates and decrypts. There is no separation between the party that
  evaluates and the party that holds the key.
- Not every input is encrypted. `fairness_encrypted` encrypts only `y_pred`, and
  `y_true`, `group_a` and `group_b` are plaintext in the same call.
- The functions decrypt more than the values in the report. The calibration
  function decrypts a real-valued membership signal for each class, and a party
  who sees that signal and knows `quantiles` and `score_range` can solve for each
  per-class score, within CKKS error. The disagreement function decrypts a
  per-slot output vector for each model.
- The default parameters are `N = 2^15` with a 360-bit chain for `CKKSParams()`,
  and `N = 2^14` with a 400-bit chain for `build_d6_context()`. `CKKSParams` checks
  them against the SEAL log Q bounds for 128-bit IND-CPA in `SEAL_MAX_LOG_Q_128`.
  No separate security estimate is recorded in this repository, and nothing in the
  code sets a key-switching `dnum` value.
- The library makes no IND-CPA-D claim. See
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) §5.1.
- Declared depth is only compared with a counter, and the counter does not count
  every level TenSEAL uses. With TenSEAL 0.3.18 at `N = 2^14`, concordance used
  6 levels against a declared 5 and calibration used 5 against a declared 4.
- A signed report carries authenticated claims. The signature does not
  independently verify that an encrypted computation ran.

**Experimental configurations**

- The OpenFHE backend (`[openfhe]`) is experimental, covers five of the six
  primitives and is not the verified reference. Its context also keeps the secret
  key, so the same single-process limit applies.

**Intended future architecture, not delivered in 0.2.1**

- An honest-but-curious operator would see only ciphertexts and auditor-public
  scalars, and a separate party would hold the CKKS secret key and decrypt the
  output. The roles and key custody in the threat model describe this design.
  Nothing in 0.2.1 provides this separation.
- Group counts and the other values called auditor-public are a design assumption
  for that deployment. The library does not publish them.

Findings outside this model, for example side-channel timing on the audit
operator's host, should be reported through the same channel.
