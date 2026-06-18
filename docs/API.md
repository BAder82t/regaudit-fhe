# API reference

`regaudit-fhe` ships an HTML API reference generated directly from the
package's docstrings with [pdoc](https://pdoc.dev). It documents every
public symbol re-exported from `regaudit_fhe` — the six audit primitives
and their `*Report` dataclasses, the signed-envelope surface
(`envelope`, `verify_envelope_or_raise`, `Signer`, `CallableKeyProvider`,
`TrustStore`), the differential-privacy layer (`regaudit_fhe.dp`), and the
FHE backends (`regaudit_fhe.fhe`, including the backend registry and the
TenSEAL / OpenFHE adapters).

## Build it locally

```bash
pip install -e ".[dev]"        # pins pdoc
scripts/build_api_docs.sh      # writes site/api/index.html
```

The output directory (`site/`) is git-ignored; CI rebuilds it on every
push and uploads it as a workflow artifact (see
`.github/workflows/docs.yml`).

## Module map

| Module | What it covers |
| --- | --- |
| `regaudit_fhe` | Top-level audit primitives, oracles, and envelope helpers. |
| `regaudit_fhe.reports` | Canonical JSON, parameter sets, Ed25519 signing, key-custody seam, envelope verification. |
| `regaudit_fhe.trust` | `TrustStore` and the typed verifier exception hierarchy. |
| `regaudit_fhe.dp` | Differential-privacy output perturbation (Laplace / Gaussian mechanisms, accountant, `privatize_report`). |
| `regaudit_fhe.schemas` | JSON Schema loading and validation. |
| `regaudit_fhe.server` | Hardened FastAPI audit server (optional `[server]` extra). |
| `regaudit_fhe.fhe` | CKKS backends: parameter validation, the backend registry, and the TenSEAL / OpenFHE slot-vector implementations. |

For prose-level guidance see [the README](../README.md),
[COMPLIANCE.md](../COMPLIANCE.md), and the threat model under
[docs/THREAT_MODEL.md](THREAT_MODEL.md).
