# regaudit-fhe 0.1.1 — release record

AI-assisted engineering record. Not an audit; no production assurance is claimed. Human code review was waived by the
owner (AI-only assurance waiver). Written 2026-10-28.

Evidence labels: **[CI]** GitHub-recorded; **[session]** run by the assistant in this session and re-observed;
**[agent]** reported by a delegated agent and not repeated; **[owner]** stated by the account holder.

## 1. Identity

| Item | Value |
|---|---|
| Version | 0.1.1 (defensive patch on 0.1.0) |
| Tag | `v0.1.1`, annotated, tag object `2efae7fc59439a330073ab357c2be5eac363f550`, tagger BAder82t, message `regaudit-fhe 0.1.1` |
| Tagged commit | `e588f17e210d870aabc1bec4ceeec904f3fd74f7` (merge of PR #42) |
| Tagged tree | `54c72ce4bedbed5936ab03a999cedc62656b6bb5` |
| `v0.1.0` | unchanged: tag object `fe4921632bda80e3c9533e2a2038eccdc8c59586`, commit `600066fe7f3f4c0b85be057f2e5f1569083862af` |
| Production run | GitHub Actions `pypi-release.yml` run `40772504037` — 11 of 11 jobs succeeded [CI] |

History on `master` (all by protected PR, merge commits):

| PR | Merge commit | Tree | Content |
|---|---|---|---|
| #41 | `1bc39ea33481eec1465df3e2d00ce09a29d21a27` | `03697271c8844c229751be0685057a093d39468f` (= accepted candidate `c6b5ae0`) | the defensive patch |
| #42 | `e588f17e210d870aabc1bec4ceeec904f3fd74f7` | `54c72ce4bedbed5936ab03a999cedc62656b6bb5` | CHANGELOG only: dated heading, known limitations |
| #43 | `1fdd6f5b84dc57f9a02576c802d5db122ea415a9` | `1cc9d87ca786449282f756745c1b66384308d86c` | README only, after the release (not in the 0.1.1 artifacts) |

## 2. Published artifacts [CI][session]

| File | SHA-256 |
|---|---|
| `regaudit_fhe-0.1.1-py3-none-any.whl` | `0fec0b25797902e3dea12030d76c44b37950a3139c85e5364442a49a2ffd9107` |
| `regaudit_fhe-0.1.1.tar.gz` | `b3358cd236b799c42ab4b0e9c6356e980c0ceb474f847d47760666d45fab2d78` |

Identical in the workflow artifacts, on PyPI (JSON API digests), and in the GitHub Release (`shasum -c SHA256SUMS`
passes). The GitHub Release (not draft, not prerelease) holds the wheel, sdist, both `.sigstore.json` bundles,
`sbom.cdx.json` and `SHA256SUMS`. The wheel contains 14 schemas, version 0.1.1 and the LICENSE; its `_limits.py` is
byte-identical to the file at `e588f17` [session]. 0.1.0 remains on PyPI, unyanked.

## 3. Post-publication verification [session]

- Sigstore: both PyPI-served files verified with `sigstore verify identity`, identity
  `https://github.com/BAder82t/regaudit-fhe/.github/workflows/pypi-release.yml@refs/tags/v0.1.1`, issuer
  `https://token.actions.githubusercontent.com`.
- Clean install of `regaudit-fhe[server]==0.1.1` from PyPI into a fresh Python 3.13 venv; `smoke_installed_wheel.py
  --version 0.1.1` passed from a clean directory (an earlier attempt from a directory containing the venv failed by
  the script's own guard — operator error, not a defect); 14 schemas.
- Signing compatibility: fixtures generated with the PyPI 0.1.1 install, verified by the published 0.1.0 and by 0.1.1:
  byte-identical verdicts (39 TRUSTED, 12 SELF_SIGNED_ONLY, 225 INVALID, 24 identical `EnvelopeFormatError` entries).
  Forward (0.1.0-signed, 0.1.1-verified): 300 verdicts identical on the pre-release candidate [agent].
- Source diff of the candidate against `d0a4105`: `canonical.py`, `trust.py`, `report_v2.py`, `schemas.py`, `_keys.py`,
  `replay.py` and both schema directories have no diff [session]. `verification.py` and `reports.py` differ by a
  primitive-type guard, a finite-number check and the version string only.

## 4. What changed (observable)

Fixed: non-finite audit results no longer signed (422 / CLI exit 2); `/v1/verify` returns 422 `malformed envelope`
for any non-string `primitive` (0.1.0: 500, or 200 for `null`/numbers); `/v1/audit` parses strict JSON (422);
request timeout now cancels queued work.

Added and changed: 413 `INPUT_LIMIT_EXCEEDED` above 131072 elements per array, 524288 in total, depth 4, 8192
concordance samples, 32 disagreement models, 1024 provenance buckets and 2^23 provenance cells (all configurable);
503 `SERVER_BUSY` with `Retry-After` beyond 2 running + 4 queued audits and on the shared in-flight body budget
(max(32 MiB, 2x body limit)); `serve` header deadline and uvicorn limits; strict startup validation of numeric
settings (zero, negative, NaN, infinite, padded or malformed values refused; rate limit 0 formerly meant 1/min and
timeout 0/NaN returned 504 for every request); Docker runtime stage without pip and a wider `.dockerignore`.
Full text: `CHANGELOG.md` 0.1.1.

Why the provenance bound exists: a 100-byte request with `n_buckets=8192` allocated about 520 MB. The earlier
resource-bounds work also found the 512 MiB container OOM-killed by 64 concurrent legal 1 MiB requests (2 of 2 runs)
and by 64 concurrent 5.3 MB bodies before a shared body budget was added.

## 5. Qualification evidence

- Full suite on Python 3.13, run by the assistant on the final candidate `c6b5ae0`: 1242 passed, 7 skipped; ruff,
  ruff format and mypy clean [session]. Reported by the agent for the same commit: 3.10 1240 passed 9 skipped; 3.11
  1242/7; 3.12 (TenSEAL) 1306/4; 3.14 1242/7 [agent].
- GitHub CI on the PR head `c6b5ae0`: 26 of 26 checks passed, including both `server floors` jobs, macOS and Linux
  tests, CodeQL, the distributions build and installed-wheel tests on 3.10–3.13, SBOM, pip-audit and the reproducible
  wheel check [CI]. Post-merge CI, CodeQL and docs on `e588f17` succeeded after the rerun in section 6 [CI].
- Real Python 3.14.10 image built from the unchanged Dockerfile and run with `--memory 512m --cpus 1 --pids-limit 256
  --read-only --cap-drop ALL --security-opt no-new-privileges`: no pip, uid 10001, healthy, signed audit 200, oversize
  413; overload scenarios ended without OOM and `/healthz` kept answering; 63 oversized `n_buckets` requests all refused
  with 413 at a 61 MiB peak [agent]. The earlier combined candidate's image smoke was also re-run by the assistant on
  the pre-release `98b5acd` candidate [session].
- Independent read-only review (an AI reviewer, not a human) of the resource code found one high and several medium
  issues; the high one (`n_buckets`) and the unvalidated timeout setting were fixed in `c6b5ae0` and reproduced by the
  assistant before and after [session]. The rest are in section 7.
- Latency figures in the resource-bounds documents were measured on a heavily loaded host (load average 25–45); treat
  them as directional. Outcomes, memory peaks and OOM behaviour are the stronger evidence.

## 6. Documented CI incident

Post-merge `ci` on `e588f17` (run `40768105222`): job `tests (macos-latest, py3.12)` failed the wall-clock test
`tests/test_fhe_equivalence_matrix.py::test_runtime_within_documented_bound[concordance]` — 30.59 s against a 30.00 s
bound (2% over). The four jobs that depend on it were skipped. Only `CHANGELOG.md` differed from the previously
passing commit, and the same test had passed on four earlier commits. A single-job rerun passed and the skipped jobs
then passed. Classified by the owner as a probable timing flake, not proven infrastructure failure. No code or test
was changed. Maintenance note: separate hard correctness checks from noisy wall-clock thresholds in the FHE timing
tests. An earlier, different failure on the PR (`macos-latest, py3.12`, cancelled because no runner was acquired)
was a runner-capacity failure and was rerun.

## 7. Remaining limitations (not fixed in 0.1.1; also in CHANGELOG)

The limits reduce denial-of-service exposure; they do not remove it. A reverse proxy limiting body size, connections,
timeouts and request rates is still required.

- Request bodies are read, and strictly parsed on the event loop, before the admission gate or structure limits can
  refuse them (about 60–125 ms per 1 MiB).
- Slow clients sending partial bodies can hold the shared in-flight body budget until the request timeout (30 s
  default); no body-inactivity deadline.
- The body budget bounds bytes being read, not total request memory.
- A submitted `/v1/verify` job keeps running after a timeout; in replay-record mode a retry can be flagged as replay.
- Schema-validation 422 messages echo parts of the request; uvicorn's own `limit_concurrency` 503 is plain text without
  `Retry-After`.
- Open question, not verified: whether `np.float32` values are caught by the finite-number check.
- Provenance (0.2.0 investigation, nothing changed): the verifier does not check that the signed top-level `backend`
  matches `parameter_set.backend`, or that `parameter_set_hash` matches `parameter_set`; `backend` is what the signer
  asserted, and a default call signs `plaintext` even on the encrypted path.
- The `[fhe]` Docker image and the OpenFHE backend were not tested. Native Linux amd64, Windows and Python 3.15 were
  not tested. Latency was not measured on an idle machine.

## 8. Publisher configuration — status

The account holder typed "confirmed, start" before the tag was pushed [owner]. No screenshot, setting text or other
evidence of the PyPI Publishing page was provided to the assistant, and the assistant cannot read it. The successful
production run and the Sigstore identity show publication through `pypi-release.yml` and environment `pypi`; they do
not show whether an obsolete `publish.yml` binding is absent. **That remains a separate account-configuration check.**
GitHub-side controls observed [session]: environment `pypi` requires one reviewer (BAder82t), admin bypass off,
deployments limited to `v*` tags; rulesets `master-protected`, `release-tags-immutable`,
`release-tags-create-maintainer-only` active; `sha_pinning_required` true. The `pypi` deployment was approved through
the GitHub API using the account holder's own token after the artifact checks in section 2, on the account holder's
instruction to publish.

## 9. Preserved, not part of this release

`prep/0.2.0-trust-dx` (`dc4b997154f3755bb077e409720a44a8aded43e1`, local only), research branches A–D, Phase 3B,
PR #32 (Docker Python 3.15) — all on hold. Temporary 0.1.1 branches (`prep/0.1.1-combined`, `release/0.1.1`,
`docs/readme-0.1.1-limits`, `prep/0.1.1-defensive-patch`, `prep/resource-bounds`) and worktrees under
`/Users/baderissaei/dev/regaudit-fhe-agents/` await a single cleanup decision.
