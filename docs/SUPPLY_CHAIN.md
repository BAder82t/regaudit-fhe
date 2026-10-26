# Supply chain and release controls

How `regaudit-fhe` builds, pins, scans, signs, and ships its
artefacts. Read this if you ingest the wheel or sdist into a
regulated pipeline; everything below is the publicly available
attestation surface.

---

## At a glance

| Control                    | Mechanism                                                | File / location                                   |
| -------------------------- | -------------------------------------------------------- | ------------------------------------------------- |
| Dependency updates         | GitHub Dependabot, weekly                                 | `.github/dependabot.yml`                          |
| Vulnerability scanning     | `pip-audit --strict --vulnerability-service osv` in CI    | `.github/workflows/ci.yml`, `pypi-release.yml`         |
| SBOM (CycloneDX 1.6 JSON)  | `cyclonedx-py environment` in CI + on every release       | `.github/workflows/ci.yml`, `pypi-release.yml`         |
| Dev environment pins (legacy, **not authoritative**) | `requirements-dev.txt` (pip-tools, partial; see below) | repository root                          |
| OIDC PyPI publish          | `pypa/gh-action-pypi-publish@release/v1` (Trusted Publisher) | `.github/workflows/pypi-release.yml`               |
| Sigstore build attestation | `attestations: true` in publish action                    | `.github/workflows/pypi-release.yml`                   |
| Release-asset checksums    | `sha256sum dist/*` uploaded as a release asset            | `.github/workflows/pypi-release.yml`                   |

The release pipeline, its controls and the GitHub/PyPI settings it depends on are described in
[RELEASE_PROCESS.md](RELEASE_PROCESS.md); the pipeline has not yet run on GitHub Actions.

Every artefact uploaded to PyPI carries a Sigstore-backed publish
attestation that links the release to the GitHub Actions workflow run
that produced it. The release tag, SBOM, and SHA-256 checksum file are
attached to the matching GitHub Release page.

---

## Verifying a wheel from PyPI

> **Status: this recipe has not been exercised.** No release has been produced by the current
> `pypi-release.yml` since its actions were bumped to new major versions, so neither the attestation
> location nor the identity strings below have been checked against a real release. In particular
> `pip download` fetches only the wheel: the `.sigstore.json` bundles are uploaded to the GitHub Release
> (and as a workflow artefact), not to PyPI, so download the bundle from the Release assets (or the
> attestation from the PyPI provenance URL). The certificate identity names the tag the workflow ran
> on, so a run that was not triggered by that tag will not match it.

> The procedure below assumes Python 3.10+, `sigstore-python`, and
> `cyclonedx-py` are installed on the verifier host:
>
> ```bash
> pip install sigstore cyclonedx-bom
> ```

1. **Download the wheel and signed publish attestation.**

   ```bash
   pip download regaudit-fhe==<VERSION> --no-deps --dest dl/
   ```

2. **Verify the Sigstore publish attestation.** PyPI exposes the
   attestation under
   `https://pypi.org/integrity/regaudit-fhe/<version>/<filename>/provenance`.

   ```bash
   sigstore verify identity \
     --bundle dl/regaudit_fhe-<VERSION>-py3-none-any.whl.sigstore.json \
     --cert-identity "https://github.com/BAder82t/regaudit-fhe/.github/workflows/pypi-release.yml@refs/tags/v<VERSION>" \
     --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
     dl/regaudit_fhe-<VERSION>-py3-none-any.whl
   ```

   The verifier confirms (a) the artefact was produced by the
   ``pypi-release.yml`` workflow at the named tag, (b) the identity was
   issued by GitHub's OIDC provider, and (c) the file was not
   modified after signing.

3. **Cross-check the SHA-256.** The publish workflow uploads
   `SHA256SUMS` to the GitHub Release page; `sha256sum -c SHA256SUMS`
   on the downloaded wheel must produce `OK`.

4. **Inspect the SBOM.** The CycloneDX 1.6 JSON file lives next to
   the wheel under the GitHub Release. Useful queries:

   ```bash
   jq '.components | length' sbom.cdx.json
   jq '.components[] | select(.licenses)' sbom.cdx.json
   ```

   Most ingestion stacks (Dependency-Track, Snyk, Anchore, GitHub
   Advanced Security) consume CycloneDX directly.

---

## Pinned development environment (legacy, not authoritative)

`requirements-dev.txt` is **not** a complete or authoritative lockfile and nothing in CI, the Dockerfile
or the release pipeline installs from it: CI and the release workflow run `pip install -e ".[dev,server,fhe]"`
(unpinned extras), and the Dockerfile runs `pip install ".[server]"`. It was generated once with

    pip-compile --extra=dev --extra=server --output-file=requirements-dev.txt pyproject.toml

and has not been regenerated since: it lacks packages that the `dev` extra now lists (for example
`bandit`, `pdoc` and `setuptools`) and Dependabot updates individual pins in it. Treat it as a
contributor convenience only. Do not cite it as evidence that a release was built from pinned
dependencies. The point-in-time evidence for a release is the qualification record that lists the
resolved versions and the `pip-audit` result (see `docs/rc/`). Regenerating it, or deleting it and
removing this section, is a maintainer decision that was not made as part of the 0.1.0 candidate.

Production users should pin the wheel in their own application's lockfile.

---

## Reproducible builds

Measured for the 0.1.0 candidate (setuptools 82.0.1, `python -m build` with build isolation, two
clean checkouts in different directories, `SOURCE_DATE_EPOCH` set to the commit time):

  - **The wheel is byte-identical** across builds (same SHA-256), and a wheel built from the sdist has
    the same members with identical contents as the directly built wheel.
  - **The sdist is not byte-identical.** Its file contents are identical (`diff -r` of the unpacked
    trees is empty), but the tar member modification times, owner and group names, and the gzip header
    timestamp reflect the build, so the archive hash differs between builds. `SOURCE_DATE_EPOCH` does
    not make the sdist archive deterministic with this toolchain. Do not rely on an sdist hash to
    verify a rebuild; compare unpacked contents, or verify the Sigstore bundle published with the
    release.
  - The wheel is `py3-none-any` (no compiled extensions in `regaudit-fhe` itself; CKKS support comes
    from the optional `tenseal` dependency, which is built separately).

Caveats:

  - Reproducibility requires the same Python minor version, `build`
    version, `setuptools` version, and `wheel` version. CI pins these
    indirectly via `actions/setup-python@v5 cache: pip`.
  - The optional `[fhe]` extra pulls TenSEAL, whose wheels ship
    pre-built per-platform from PyPI; verifying TenSEAL itself is the
    user's responsibility.

To reproduce the wheel locally::

    git checkout v<VERSION>
    python -m pip install --upgrade pip build
    SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) python -m build
    sha256sum dist/*.whl

The wheel hash should match the `SHA256SUMS` file uploaded with the matching release when the toolchain
versions match. (Not demonstrated against a published release: no release has been built from this
pipeline since the reproducibility measurement above.)

---

## Vulnerability disclosure

See [SECURITY.md](../SECURITY.md). Supply-chain findings (compromised
dependency, malicious tag, build-system tamper) should be reported
through the same channel.

---

## Changelog of supply-chain controls

| Date       | Change                                                                                |
| ---------- | ------------------------------------------------------------------------------------- |
| 2026-04-26 | Initial release: Trusted Publisher, Sigstore attestation, dev lockfile, pip-audit CI. |
| 2026-04-27 | SBOM (CycloneDX) generation in CI and release workflow.                               |
| 2026-04-27 | Dependabot weekly updates for pip, GitHub Actions, and Docker base images.            |
