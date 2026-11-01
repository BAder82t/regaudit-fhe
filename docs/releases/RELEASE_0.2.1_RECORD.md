# regaudit-fhe 0.2.1: release record

AI-assisted engineering record. Not an audit; no production assurance is claimed. Written 2026-11-01, after
publication. Provenance checks detect contradictions in signed metadata; they do not prove that an encrypted
computation occurred.

Evidence labels: **[CI]** GitHub-recorded; **[session]** run by the assistant and re-observed; **[owner]** stated by
the account holder.

## 1. Identity

| Item | Value |
|---|---|
| Version | 0.2.1 (availability patch on 0.2.0) |
| Tag | `v0.2.1`, annotated, tag object `53ea048968733cfeacbc290ff8839638d7970490`, tagger BAder82t, message `regaudit-fhe 0.2.1` |
| Tagged commit | `869133678a4d1cd8216b75319911ff4f2e19f522` (merge of PR #51) |
| Tagged tree | `32778efa35e56984e7b2b755387e26e8f5bf95f2` |
| Availability implementation | PR #49, merge `fc30510ea423e5d68cd8f44eedc42659779227b0` |
| Production run | `pypi-release.yml` run `41338785197`: 11 of 11 jobs succeeded [CI] |
| Published | PyPI upload 2026-11-01 19:03:05 UTC (wheel) and 19:03:06 UTC (sdist); GitHub Release 19:03:21 UTC [CI] |
| `v0.2.0`, `v0.1.1`, `v0.1.0` | Unchanged: tag objects `12f8d858187db775c3c3bdc76973382b468661e1`, `2efae7fc59439a330073ab357c2be5eac363f550`, `fe4921632bda80e3c9533e2a2038eccdc8c59586`; all remain on PyPI, not yanked |

## 2. Published artifacts [CI][session]

| File | SHA-256 |
|---|---|
| `regaudit_fhe-0.2.1-py3-none-any.whl` | `482800d94574d45ac383cbce8a8604e431a80e9d330d8cc3be861920703d78ce` |
| `regaudit_fhe-0.2.1.tar.gz` | `ae412a7dcf7dac280374774c2b867179212288029b91e3d219ab30755ba21bf6` |

The files are byte-identical in the workflow artifacts, on PyPI and in the GitHub Release.

The wheel is also byte-identical to the pre-tag rehearsal and to a local build. The sdist is not: its archive
timestamps record the build time, so its hash differs between builds, while its 195 files were identical to the
rehearsal's and the local build's.

## 3. Review status

| Item | Status |
|---|---|
| Who performed the security review | AI agents, working under the owner's release decisions [owner] |
| Evidence | Automated tests, static analysis and the executable checks in this record |
| Not performed | Independent human code review, independent external security audit, regulator approval |
| Assurance | AI-assisted testing and review. No production assurance is claimed |

## 4. Pre-release state [CI]

| Check | Run | Result |
|---|---|---|
| PR #51 checks at `b584e4b3a388a7fada311604826bb9b56b025125` | ci `41336135838`, codeql `41336135820`, docs `41336135895`, rehearsal `41336135850` | 26 of 26 |
| Post-merge CI on the tagged commit | `41336948067` | 16 of 16 jobs |
| Post-merge CodeQL and docs | `41336947775`, `41336947761` | Success |
| Rehearsal on the tagged commit (`workflow_dispatch`) | `41336957882` | 7 of 7 jobs |

Open code-scanning alerts on master at release: the 19 note-level alerts that pre-date this release (8 9 10 11 14 17
18 19 20 21 22 23 45 46 47 48 49 50 51). None is new. PR #52 addresses them separately.

## 5. Post-publication verification [session]

- **Sigstore:** both PyPI-served files verified with `sigstore` 4.5.1 against the bundles in the GitHub Release, identity
  `https://github.com/BAder82t/regaudit-fhe/.github/workflows/pypi-release.yml@refs/tags/v0.2.1`, issuer
  `https://token.actions.githubusercontent.com`. A wrong identity (`publish.yml`) was refused.
- **PyPI attestations:** both files verified with `pypi-attestations` 0.0.30 for repository `BAder82t/regaudit-fhe`;
  the provenance names workflow `pypi-release.yml` and environment `pypi`. A wrong repository was refused. The first
  by-name lookup of the wheel returned "could not find the artifact", while the same check on the sdist passed; the
  wheel then verified through its direct URL and by name. The cause of the first failure was not established.
- **Clean install from PyPI:** `regaudit-fhe[server,dev]==0.2.1` in new virtualenvs on Python 3.13 and 3.10 (macOS);
  `pip check` clean, and `scripts/smoke_installed_wheel.py` passed.
- **Tests from the PyPI sdist against the PyPI install:** 1450 passed, 48 skipped (3.13); 1448 passed, 50 skipped
  (3.10). The extra skips compared with a checkout are tests that need files an sdist does not ship.
- **Installed CLI:** 13 of 13 checks on 3.13 (key generation, signing, enrolment, verification, refusal of a wrong
  fingerprint and of a tampered report).
- **Installed server:** 10 of 10 checks on each of 3.13 and 3.10, over real sockets with authentication on (including
  the 408 for a stalled body, the 422 for a deep body and the bounded 422 detail).
- **Compatibility:** 16 reports each, signed by the published 0.1.0, 0.1.1 and 0.2.0 wheels and by 0.2.1 from PyPI (64
  in total). All are `TRUSTED` and all 64 tampered copies are refused under both the published 0.2.0 verifier and 0.2.1,
  and the verdict files are byte-identical (SHA-256 `8fd7625c66914beb2b2be93c2b9a6c4e204b1d21925337cea191550f4f6cd0c0`).

Linux coverage comes from the workflow's installed-wheel tests on Python 3.10 to 3.13. The `[fhe]` extra was tested only
there, on Python 3.12.

## 6. What changed (observable); full text in CHANGELOG.md

Server only, apart from the version identifiers: a 408 for a stalled request body (10 s idle by default), `/v1/verify`
limits of depth 16 and 65 536 elements, a 2048-character cap on schema 422 details, quiet handling of a client
disconnect, a `verify_request_abandoned` log line, and an opt-in `REGAUDIT_FHE_AUTH_BEFORE_BODY`. Signing formats,
schemas, canonicalisation, trust decisions and replay semantics are unchanged. New reports carry 0.2.1 as their
`algorithm_version` and `library_version`, so their `parameter_set_hash` also changes.

## 7. Publisher configuration and deployment approval

The PyPI Publishing settings were inspected by the account holder before tagging: `BAder82t/regaudit-fhe`, workflow
`pypi-release.yml`, environment `pypi`, no `publish.yml` entry [owner]. **The repository cannot read that page, so the
absence of an obsolete binding is owner-confirmed, not independently verified.** The attestations show publication
through `pypi-release.yml`; they do not show that no other binding exists.

GitHub side, read through the API on 2026-11-01 [session]: environment `pypi` requires reviewer BAder82t (self-review
allowed), admin bypass off, `v*` tag policy, no environment secrets; rulesets `master-protected`,
`release-tags-create-maintainer-only` and `release-tags-immutable` active; SHA pinning required; default workflow token
read-only.

The deployment was approved on 2026-11-01 at about 19:02 UTC. The assistant submitted the approval through the API under
the BAder82t account, on the owner's explicit written authorization for this run [owner][CI].

## 8. Remaining limitations (also in CHANGELOG)

- The idle timeout is not a minimum-rate policy; a reverse proxy limiting body size, connections, timeouts and rates is
  still required.
- The idle timeout measures wall-clock time on the event loop, so a stall about as long as the timeout can answer 408 to
  a client that was still sending.
- By default `/v1/audit` parses the body before it authenticates the caller, on the event loop.
- A 504 from `/v1/verify` does not tell the client the outcome; in replay `record` mode the report may or may not have
  been recorded.
- No key lifecycle or authoritative revocation; the CLI private key is an unencrypted PEM (mode 0600); `backend` is
  signer-asserted, and nothing here proves FHE execution.
- There is no dependency lockfile, so the pip-audit and SBOM results reflect the versions resolved on 2026-11-01.
- Not qualified here: Python 3.15, native Windows, the `[fhe]` Docker image and the OpenFHE backend.

## 9. Preserved, not part of this release

PR #52 (the note-level CodeQL backlog) is not part of 0.2.1. Revocation work, Phase 3B/OpenFHE and PR #32 (Docker Python
3.15) are not part of it either. The published 0.2.1 release and its tag are not modified by this record.
