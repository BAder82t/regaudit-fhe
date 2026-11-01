# Release process and the controls around it

This document describes how a regaudit-fhe release is meant to be produced, which controls live in the
repository (and are tested), and which controls live in **GitHub / PyPI settings that the repository cannot
enforce**. The workflows were checked statically (`actionlint`), by policy tests, and by running their commands
locally. The full pipeline has run on GitHub Actions twice: for `v0.1.1` (run `40772504037`, 11 of 11 jobs; see
`docs/releases/RELEASE_0.1.1_RECORD.md`) and for `v0.2.0` (run `41247733730`, 11 of 11 jobs; see
`docs/releases/RELEASE_0.2.0_RECORD.md`). Settings in section 3 were last read through the GitHub API on 2026-10-31
(section 3, status note); the PyPI side cannot be read by the repository.

## 1. Pipeline

```
push of tag vX.Y.Z  ──►  guard ──► build (release-build.yml) ──► sigstore ──► publish (environment: pypi) ──► github-release
                                     │ build, twine check, check_release_metadata.py
                                     │ smoke × Python 3.10 3.11 3.12 3.13 (installed wheel, tests from the sdist)
                                     │ pip-audit of the installed wheel's environment
                                     └ SBOM
```

| Control | Where it lives | Enforced by |
|---|---|---|
| The only trigger is a push of a tag matching `v[0-9]+.[0-9]+.[0-9]+`; no `workflow_dispatch` | `pypi-release.yml` | repo + `tests/test_release_workflow.py` |
| The tag is an annotated tag, equals the event commit, and that commit is an ancestor of the default branch | `pypi-release.yml` job `guard` | repo (shell; ran on GitHub for v0.1.1 and v0.2.0) |
| Tag = `pyproject.toml` version = `__version__` = `LIB_VERSION` = wheel METADATA = sdist PKG-INFO; one wheel + one sdist; 14 schemas and `py.typed` in each | `scripts/check_release_metadata.py` (called from `release-build.yml`) | repo + `tests/test_release_scripts.py` |
| The built wheel is installed in a clean venv and used from outside the checkout; the test suite shipped in the **sdist** runs against it (the metadata check refuses an sdist that lacks the test helpers, test data, scripts or CHANGELOG) | `release-build.yml` job `smoke` | repo (shell; ran on GitHub for v0.1.1 and v0.2.0) |
| The files signed and uploaded are the files that were built (SHA-256 recorded as job outputs and re-checked) | `pypi-release.yml` (`sigstore`, `publish`) | repo |
| PyPI upload only in the `publish` job, bound to the `pypi` environment, `id-token: write` only in `sigstore` and `publish`, default token empty | `pypi-release.yml` | repo + policy tests |
| Third-party actions pinned to commit SHAs | all three release workflows | repo + policy tests |
| The publishing workflow has its own file name (`pypi-release.yml`) that the PyPI trusted publisher is bound to, so an **older commit** that still carries the former, unguarded `publish.yml` cannot get a token PyPI accepts (GitHub runs the workflow file from the tagged commit) | file name + **PyPI setting (section 3.4)** | repo + owner action |
| Required human approval of the `pypi` environment | **GitHub setting** | **not enforced by the repository: owner action (section 3)** |
| Only maintainers can create `v*` tags | **GitHub ruleset** | **owner action (section 3)** |
| PyPI trusted publisher bound to this workflow and environment | **PyPI project setting** | **owner action (section 3)** |
| Human code review of the release | process | **not enforced anywhere** |

`release-rehearsal.yml` runs the same `release-build.yml` on pushes to `release/**` branches, on pull requests that
touch packaging or release files, and on demand (a `workflow_dispatch` needs the file on the default branch). Because it is path-filtered it must **not** be configured as a *required* status check (a
PR that does not touch those paths would wait for it forever). It publishes nothing, signs nothing, has no environment and no `id-token`.

## 2. What a release needs before the tag is pushed
1. The review the owner has decided on for this release, recorded with the full 40-character commit. For 0.1.0, 0.1.1 and 0.2.0 the owner waived human code review and substituted AI-agent reviews plus executable verification (see the release records in `docs/releases/`); that is a lower assurance than a professional audit and must be stated as such in the release notes.
2. `CHANGELOG.md` section for the version, known limitations listed; version bumped consistently
   (`python scripts/check_release_metadata.py --dist dist --tag vX.Y.Z` after a local build).
3. A green `release-rehearsal` run on the exact commit (GitHub Actions, not only local).
4. The owner's explicit decision to publish.
5. The release commit **merged into the default branch first** (the `guard` job refuses a commit that is not reachable from it), then an **annotated** tag on that commit:
   `git tag -a vX.Y.Z -m "regaudit-fhe X.Y.Z" <commit>` then
   `git push origin "refs/tags/${TAG}:refs/tags/${TAG}"` (fully qualified, braced; `TAG=vX.Y.Z`), and read the tag back with `git ls-remote`.
6. Approve the `pypi` environment deployment in the GitHub UI after reading the job summary.
7. After publication: install from PyPI into a clean venv outside the repository and run
   `scripts/smoke_installed_wheel.py --version X.Y.Z`; verify the Sigstore bundle and the PyPI attestation
   (the Sigstore recipe in `docs/SUPPLY_CHAIN.md` was run for v0.1.1 and v0.2.0).

## 3. Settings the repository cannot enforce: exact instructions for the owner
These commands are **not executed by anything in this repository**. Review them, adapt the numeric ids, and
run them yourself (or use the web UI). `OWNER=BAder82t REPO=regaudit-fhe`.

> **Status note (read-only GitHub API, 2026-10-31; the PyPI side was not read).** Environment `pypi`: required
> reviewer `BAder82t`, `prevent_self_review` false, admin bypass off, deployment policy limited to `v*` tags. Rulesets
> `master-protected`, `release-tags-create-maintainer-only` and `release-tags-immutable` active; "require actions to be
> pinned to a SHA" on. So the "currently" statements in 3.1 to 3.3b below describe the state before these were set and
> are kept as the recipe. Not verifiable from the repository: the PyPI Publishing settings (3.4).

**3.1 Protect the `pypi` environment with a required reviewer.** Currently the environment has only a
deployment-tag policy (`v*`) and no reviewers, so a pushed tag publishes without a human click.
```
gh api repos/$OWNER/$REPO/environments/pypi --jq '{reviewers: .protection_rules, policy: .deployment_branch_policy}'   # inspect first
USER_ID=$(gh api users/<second-maintainer-login> --jq .id)        # a person other than the one who pushes tags, if one exists
gh api -X PUT repos/$OWNER/$REPO/environments/pypi --input - <<JSON
{ "reviewers": [ { "type": "User", "id": $USER_ID } ],
  "prevent_self_review": true,
  "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true } }
JSON
```
With a single maintainer `prevent_self_review: true` would block every release; then set it to `false`: the
approval is a deliberate second click by the same person, not a separation of duties. Keep the existing tag
policy (`v*`).

**3.2 Restrict who can create, move and delete release tags** (repository ruleset on tags).
```
gh api -X POST repos/$OWNER/$REPO/rulesets --input - <<'JSON'
{ "name": "release-tags", "target": "tag", "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [ { "type": "update" }, { "type": "deletion" }, { "type": "non_fast_forward" } ],
  "bypass_actors": [] }
JSON
```
(Creation is intentionally still allowed to maintainers; the `guard` job and the environment approval are the
other two layers.)

**3.3 Protect the default branch** (currently "Branch not protected"): require pull requests and the CI
checks `lint`, `typecheck`, `bandit`, `tests` and `pip-audit`. Do not require `release-rehearsal` (path-filtered). A required
approving review is possible only if a second collaborator exists.

**3.3b Enforce SHA pinning of actions** (Settings → Actions → General → "Require actions to be pinned to a full-length commit SHA"; currently off). All workflows in the repository already use full SHAs.

**3.4 PyPI trusted publisher** (PyPI project settings → Publishing). **Change the existing publisher from the
workflow file `publish.yml` to `pypi-release.yml`** (owner `BAder82t`, repository `regaudit-fhe`, environment
`pypi`) **before the first release from this pipeline**, and remove any other entry. Until it is changed a release
from the new workflow fails at the upload (fails closed); once it is changed, runs of the old `publish.yml` (still
present in older commits and tags) can no longer obtain a token PyPI accepts. `v0.1.1` and `v0.2.0` were published
through `pypi-release.yml`, which shows that a binding for that workflow works; it does **not** show that an obsolete
`publish.yml` binding is absent. For 0.2.0 the account holder stated that the settings were checked (only
`BAder82t/regaudit-fhe`, `pypi-release.yml`, environment `pypi`, no `publish.yml` binding) [owner]; the repository cannot
read the PyPI page, so this remains an owner action and is not independently confirmed.

**3.5 Rehearse the publication path without touching the real project.** Make a throw-away fork or a new
TestPyPI project with its own trusted publisher, point a copy of `pypi-release.yml` at it
(`repository-url: https://test.pypi.org/legacy/`), and push a `v0.0.0`-style tag **there**. Compare the output
with `docs/SUPPLY_CHAIN.md` and correct that document. Do not do this in the real repository.

## 4. Known gaps
* **The guard cannot stop someone who can push to the repository.** GitHub runs the workflow file from the tagged commit, so a writer can ship a modified `pypi-release.yml` under the same name. Only the owner-side controls (3.1 required reviewer on the `pypi` environment, 3.2 tag ruleset, 3.3 branch protection, 3.4 the PyPI publisher bound to the environment) limit that. Until they are in place the pipeline is not protected against a malicious or compromised writer.
* The `sigstore` job signs outside the `pypi` environment, so a Sigstore bundle proves "this workflow file at this tag produced the files", not "a reviewer approved"; the PyPI attestation created in the `publish` job is the environment-bound one.
* The build tools and their transitive dependencies are version-pinned only for `build`, `twine`, `pip-audit` and `cyclonedx-bom` (not hash-pinned); `wheel` floats within the `setuptools` bound.
* The `guard`, `smoke`, `sigstore`, `publish` and `github-release` steps ran on GitHub for `v0.1.1` and `v0.2.0`.
  Two successful runs are not a test matrix: failure paths (a lightweight tag, a commit off the default branch, a
  rejected environment approval) have only been exercised locally.
* `release-build.yml` installs `pip-audit` and `cyclonedx-bom` at exact versions but does not hash-pin them or
  their dependencies, and the wheel's own dependencies are resolved at release time from their lower bounds
  upward (no lockfile), so the audited environment is a point-in-time resolution.
* The SBOM is generated from a virtualenv that contains the wheel and its runtime extras only; the generator
  runs from a separate virtualenv.
* Old tags and commits keep the workflows they were tagged with. Only the PyPI-side binding to the new file name
  (3.4) and the environment approval (3.1) limit what a tag on an old commit can do.
* A tag push that passes every gate still publishes without a human reading the code unless a reviewer is
  configured in 3.1.
* Yanking a faulty release is a manual PyPI action and is not automated.
