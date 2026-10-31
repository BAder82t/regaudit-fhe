# regaudit-fhe 0.2.0: release record

AI-assisted engineering record. Not an audit; no production assurance is claimed. Human code review was waived by the
owner (AI-only assurance waiver) [owner]. Written 2026-10-31, after publication. Provenance checks detect
contradictions in signed metadata; they do not prove that an encrypted computation occurred.

Evidence labels: **[CI]** GitHub-recorded; **[session]** run by the assistant and re-observed; **[agent]** reported or
run by a delegated agent and not repeated; **[owner]** stated by the account holder.

## 1. Identity

| Item | Value |
|---|---|
| Version | 0.2.0 (trust and usability release on 0.1.1) |
| Tag | `v0.2.0`, annotated, tag object `12f8d858187db775c3c3bdc76973382b468661e1`, tagger BAder82t, message `regaudit-fhe 0.2.0` |
| Tagged commit | `93c3d66c31c7eb9643aa17a1cb5ae47ba9eef118` (merge of PR #47) |
| Tagged tree | `0f4f4259cf1240efefe3d9c5e37c113668a59d2d` |
| Qualified master before PR #47 | `53fb615d987093df4dc1883532150954f0829d2b`, tree `9f74b8861d56a4921fede2939fd48c33994decb8` [CI] |
| PR #47 | CHANGELOG heading "unreleased" changed to 2026-10-31; the date was confirmed by the owner [owner] |
| `v0.1.1` / `v0.1.0` | unchanged: tag objects `2efae7fc59439a330073ab357c2be5eac363f550` / `fe4921632bda80e3c9533e2a2038eccdc8c59586`; both remain on PyPI |
| Production run | `pypi-release.yml` run `41247733730`: 11 of 11 jobs succeeded [CI] |

## 2. Published artifacts [CI][session]

| File | SHA-256 |
|---|---|
| `regaudit_fhe-0.2.0-py3-none-any.whl` | `8978139dd4de5771ddd0dde5c4c9d8ed64b3e1aa76247227da9ad9880ef3c0de` |
| `regaudit_fhe-0.2.0.tar.gz` | `590019b2dbe0c82b0517482ea627435266024240550a95eafc490adcabdca8ad` |

The digests are identical in the workflow artifacts, on PyPI and in the GitHub Release.

## 3. Pre-release state

- Master `53fb615`: ci run 41238774627, codeql 41238774493, docs 41238774502, all success [CI].
- Rehearsal run `41246147759` (`release-rehearsal.yml`, workflow_dispatch) on `93c3d66`: 7 of 7 jobs succeeded [CI].
  An earlier rehearsal, run 41229690029 on `daa7400` (tree equal to `53fb615`), also passed 7 of 7 [CI].
- Open code-scanning alerts on master: the 19 that pre-date 0.2.0 (8 9 10 11 14 17 18 19 20 21 22 23 45 46 47 48 49 50 51) [CI].

## 4. Post-publication verification [session]

- Sigstore: both PyPI-served files verified against identity
  `https://github.com/BAder82t/regaudit-fhe/.github/workflows/pypi-release.yml@refs/tags/v0.2.0`, issuer
  `https://token.actions.githubusercontent.com`.
- Clean install of `regaudit-fhe[server]==0.2.0` from PyPI and `scripts/smoke_installed_wheel.py` passed; 14 schemas.
- Compatibility: verdicts for reports signed by 0.1.0 and 0.1.1 under the lenient verifiers are byte-identical.

## 5. What changed (observable); full text in CHANGELOG.md

Added: `verify_trusted` (TRUSTED / SELF_SIGNED_ONLY / INVALID), `parse_envelope_strict`, CLI `keygen`, `trust add`,
`trust list`, `audit --signing-key` (emits `report.v2`); the strict paths refuse `PROVENANCE_CONTRADICTION` and report
`PROVENANCE_UNVERIFIABLE` for absent evidence.
Compatibility changes: `regaudit-fhe verify` and `POST /v1/verify` parse strictly (CLI exit 2, HTTP 422
`malformed envelope`); self-contradicting provenance is refused. Signing formats, schemas, canonicalisation and
backends are unchanged. The HTTP `/v1/audit/*` endpoints still emit `report.v1` with an ephemeral key.
Docs fix: DEPLOYMENT.md default limits corrected (code unchanged).

## 6. Rehearsal versus real workflow

Same reusable `release-build.yml` (build, twine check, metadata check, 4-version smoke, sdist tests, pip-audit, SBOM).
The rehearsal has no tag-equals-version check, no `guard` job, no Sigstore signing, no `pypi` environment or approval,
no `id-token`, no PyPI upload and no GitHub Release. It cannot exercise Trusted Publisher OIDC binding, the environment
gate or the Sigstore identity.

## 7. Publisher configuration

The PyPI Publishing settings were verified by the account holder as: only `BAder82t/regaudit-fhe`, workflow
`pypi-release.yml`, environment `pypi`, and no legacy `publish.yml` binding [owner]. **No evidence of the PyPI settings
page was shown to the assistant and the repository cannot read it, so the absence of an obsolete `publish.yml` binding
is owner-stated, not independently confirmed.** The successful production run and the Sigstore identity show
publication through `pypi-release.yml`; they do not show that an obsolete binding is absent.
GitHub side, read through the API on 2026-10-31 for the 0.2.0 preparation [agent]: environment `pypi` requires reviewer
BAder82t (self-review allowed), admin bypass off, `v*` tag policy; rulesets `master-protected`,
`release-tags-create-maintainer-only` and `release-tags-immutable` active; SHA pinning required.

## 8. Remaining limitations (also in CHANGELOG)

- No key lifecycle or authoritative revocation: trust stores are local files; `trust add` has no retire, revoke or
  rotation.
- The CLI private key is an unencrypted PEM (mode 0600).
- `backend` is signer-asserted; a consistent provenance claim is still only a claim, and a default library call signs
  `plaintext` even on the encrypted path. Nothing here proves FHE execution.
- `verify` prints report-chosen identifiers (issuer, key_id, deployment_id, ...): untrusted, possibly sensitive text.
- Availability risks from 0.1.1 are unchanged (section 7 of `RELEASE_0.1.1_RECORD.md`): request bodies are read before
  the admission gate; slow clients can hold the body budget until the request timeout; a submitted verify job keeps
  running after a timeout; a reverse proxy limiting body size, connections, timeouts and rates is still required.
- Not qualified here: Python 3.15, native Windows, the `[fhe]` Docker image and the OpenFHE backend.
- No external security audit and no regulator approval; human code review was waived [owner].

## 9. Preserved, not part of this release

Research branches, trust-lifecycle and availability-hardening work in progress, Phase 3B/OpenFHE and PR #32 (Docker
Python 3.15) are not part of 0.2.0. The published 0.2.0 release and its tag are not modified by this record.
