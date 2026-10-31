# Migrating to 0.2.0 (release notes)

AI-assisted engineering notes. Not a security audit and not a production assurance. 0.2.0 is not yet
released; this file describes the release candidate on `master`.

## What is new

* `regaudit_fhe.verify_trusted(report, trust_store, *, policy=None)` returns a
  `TrustedVerification` whose `.verdict` is `TRUSTED`, `SELF_SIGNED_ONLY` or `INVALID`.
  `.trusted` is `True` only for `TRUSTED`. The result has no truth value on purpose
  (`if verify_trusted(...)` raises `TypeError`), a `trust_store` of `None` raises `TypeError`
  instead of falling back to a self-signed check, and a malformed report is `INVALID`, not an
  exception.
* `regaudit_fhe.parse_envelope_strict(data)`: the parser every acceptance path now uses.
* CLI: `keygen`, `trust add`, `trust list`, and `audit --signing-key ...` (signs a `report.v2`
  with a long-lived key). `verify` exits `0` only for `TRUSTED`, as before.

## Deprecations (return values unchanged)

| API | Now |
| --- | --- |
| `verify_receipt(env)` **without** `trust_store=` / `trusted_keys=` | `DeprecationWarning` once per process, naming the self-signed case, in addition to the existing one-time `UserWarning`. Still returns `True` for an intact self-signed report. |
| `verify_receipt(env, trust_store=...)` / `trusted_keys=...` | No warning (unchanged). `True` there already means the issuer key matched your material. |
| `verify_envelope(...).valid` | `DeprecationWarning` text now says that `True` includes self-signed reports. Value unchanged. |

Replace both with `verify_trusted(report, store).trusted` (or `verify_report(...).accepted`).

## Compatibility classification

Unchanged: every report.v1 and report.v2 file written by regaudit-fhe 0.1.0 (and the receipt
and timestamp shapes written since 0.0.2) verifies exactly as before. This is tested against
files produced by the published 0.1.0 source (`tests/vectors/published_0_1_0/`).

| Change | Class | Who is affected |
| --- | --- | --- |
| `verify_trusted`, `parse_envelope_strict`, `keygen`, `trust ...`, `audit --signing-key` | Additive | Nobody. |
| `DeprecationWarning` on `verify_receipt` (no trust material) and on `.valid` | Warning only | Code run with `-W error` or `filterwarnings = error`. |
| `regaudit-fhe verify` and `POST /v1/verify` now parse strictly. | **Compatibility change (interpretation of previously accepted evidence).** | Only a report.v1 whose JSON text is not exactly the shape the library writes. See below. |
| `parse_envelope`, `verify_report`, `verify_envelope*`, `verify_receipt` | Unchanged | Nobody. They still accept the lenient shapes. Their docstrings now say they are not a strict acceptance path. |
| `verify_trusted`, `regaudit-fhe verify` and `POST /v1/verify` refuse an envelope whose signed `backend` or `parameter_set_hash` contradicts its own `parameter_set` (`PROVENANCE_CONTRADICTION`). | Compatibility change (new refusal) | Only an envelope that contradicts itself; none written by this library. Missing evidence is not refused (`PROVENANCE_UNVERIFIABLE`). |

### What strict parsing refuses (and previously accepted as `TRUSTED`)

For `report.v1`: an unknown top-level member; a missing member the lenient reader defaults
(`backend`, `input_commitments`, `issuer`, ...); `regulations` as a string, `result` as a list
of pairs, or other coerced containers; `null` for `dp` or `timestamp`; extra members in the
`receipt` or `timestamp` blocks (neither is covered by the v1 signature); a non-string
`primitive` and similar wrong types. For both formats: any report whose JSON differs, after
sorting keys, from the re-serialisation of the object parsed from it; non-finite numbers;
non-JSON values in a mapping; and, for text input, duplicate keys, `NaN`/`Infinity`, a BOM
and trailing data (already refused by `parse_envelope` for text).

Why: the v1 signature covers the bytes re-derived from the parsed object, not the file. A
reader that verifies and then reads the raw JSON could see members the signer never signed.
The signed content is not altered by any of this; only which JSON texts count as that content.

HTTP and CLI behaviour: the server answers 422 `malformed envelope` (it used to answer 200
`TRUSTED` for these shapes, or 500 for a non-string `primitive` under a scoped trust entry).
The CLI answers exit 2 with `malformed report` on stderr and nothing on stdout (it used to
print a verdict and exit 0 or 1).

Library callers who hold an already parsed `AuditEnvelope` object are not affected unless they
call `verify_trusted`, which re-serialises the object and applies the same checks.

### Migration

1. If anything you produce is not written by `regaudit_fhe.envelope(...)` /
   `envelope_v2(...)` / `AuditEnvelope.to_json()` (hand edited, re-serialised by another tool
   with added members), re-issue it, or keep using `verify_report(parse_envelope(...))` and
   accept that the verdict then applies to the re-canonicalised body only.
2. Replace `verify_receipt(env)` without trust material and `.valid` with
   `verify_trusted(text, store).trusted`. Pass the report as text or bytes to get duplicate-key
   detection.
3. Issuers: `regaudit-fhe keygen`, send the public key and its fingerprint to verifiers over a
   channel you trust; verifiers run `regaudit-fhe trust add --fingerprint ...`.

## Known limits of 0.2.0

* `report.v1` signatures do not cover `receipt` or `timestamp`; strict parsing pins their shape
  but not their values (the receipt is recomputed and checked; a timestamp is evidence verified
  separately).
* The CLI private key file is an unencrypted PEM (mode 0600, refused if group/other readable).
* The `backend` field is signer-asserted. The strict paths now refuse an envelope whose `backend` or
  `parameter_set_hash` contradicts its own `parameter_set`, but a consistent claim is still only a claim: it does
  not prove an FHE computation ran, and a default library call signs `plaintext` even on the encrypted path.
* `trust add` is not a key-lifecycle or revocation system: no retire, revoke or rotation commands.
* Key custody: whoever can read the CLI private key file can sign as the issuer. Keep it mode 0600 (the CLI
  refuses a group- or other-readable file), off shared and synced folders, in an encrypted volume, and rotate by
  issuing a new key and enrolling it. For production use a KMS/HSM-backed signer through the library.
* `regaudit-fhe verify` prints the report's own identifiers (`issuer`, `key_id`, `primitive`, `issued_at`,
  `regulations`, `parameter_set_hash`, `deployment_id`, `audit_run_id`) even for a refused report. They are not
  key material, but the report's producer chooses them: treat them as untrusted text in logs and tooling, and as
  possibly sensitive in some deployments. The free-form `result` is never printed.
* No change was made to resource limits, Docker, or any signed field; the 0.1.1 protections still apply,
  including on the signed CLI path.
