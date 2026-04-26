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
| Vulnerability scanning     | `pip-audit --strict --vulnerability-service osv` in CI    | `.github/workflows/ci.yml`, `publish.yml`         |
| SBOM (CycloneDX 1.6 JSON)  | `cyclonedx-py environment` in CI + on every release       | `.github/workflows/ci.yml`, `publish.yml`         |
| Pinned dev environment     | `requirements-dev.txt` (pip-tools)                        | repository root                                   |
| OIDC PyPI publish          | `pypa/gh-action-pypi-publish@release/v1` (Trusted Publisher) | `.github/workflows/publish.yml`               |
| Sigstore build attestation | `attestations: true` in publish action                    | `.github/workflows/publish.yml`                   |
| Release-asset checksums    | `sha256sum dist/*` uploaded as a release asset            | `.github/workflows/publish.yml`                   |

Every artefact uploaded to PyPI carries a Sigstore-backed publish
attestation that links the release to the GitHub Actions workflow run
that produced it. The release tag, SBOM, and SHA-256 checksum file are
attached to the matching GitHub Release page.

---

## Verifying a wheel from PyPI

> The procedure below assumes Python 3.10+, `sigstore-python`, and
> `cyclonedx-py` are installed on the verifier host:
>
> ```bash
> pip install sigstore cyclonedx-bom
> ```

1. **Download the wheel and signed publish attestation.**

   ```bash
   pip download regaudit-fhe==0.0.1 --no-deps --dest dl/
   ```

2. **Verify the Sigstore publish attestation.** PyPI exposes the
   attestation under
   `https://pypi.org/integrity/regaudit-fhe/<version>/<filename>/provenance`.

   ```bash
   sigstore verify identity \
     --bundle dl/regaudit_fhe-0.0.1-py3-none-any.whl.sigstore \
     --cert-identity "https://github.com/BAder82t/regaudit-fhe/.github/workflows/publish.yml@refs/tags/v0.0.1" \
     --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
     dl/regaudit_fhe-0.0.1-py3-none-any.whl
   ```

   The verifier confirms (a) the artefact was produced by the
   ``publish.yml`` workflow at the named tag, (b) the identity was
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

## Pinned development environment

`requirements-dev.txt` is the lockfile a contributor (or CI runner)
uses to reproduce the development environment that generated the
release artefacts. Refresh the lock with::

    pip install pip-tools
    pip-compile --extra=dev --extra=server --output-file=requirements-dev.txt pyproject.toml

Production users should pin the wheel in their own application's
lockfile; `requirements-dev.txt` is a development convenience, not
a published runtime contract.

---

## Reproducible builds

The release pipeline aims for byte-identical sdist output across
runs at the same tag. Properties that the current build inherits
from `python-build`:

  - `SOURCE_DATE_EPOCH` is automatically set by `python-build` from
    the latest VCS commit timestamp.
  - The wheel is `py3-none-any` (no compiled extensions in
    `regaudit-fhe` itself; CKKS support comes from the optional
    `tenseal` dependency, which is built separately).
  - `setuptools` writes deterministic METADATA / RECORD entries when
    `SOURCE_DATE_EPOCH` is set.

Caveats:

  - Reproducibility requires the same Python minor version, `build`
    version, `setuptools` version, and `wheel` version. CI pins these
    indirectly via `actions/setup-python@v5 cache: pip`.
  - The optional `[fhe]` extra pulls TenSEAL, whose wheels ship
    pre-built per-platform from PyPI; verifying TenSEAL itself is the
    user's responsibility.

To reproduce locally::

    git checkout v0.0.1
    python -m pip install --upgrade pip build
    python -m build
    sha256sum dist/*

The hash should match the `SHA256SUMS` file uploaded with the matching
release.

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
