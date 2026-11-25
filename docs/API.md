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
| `regaudit_fhe.server` | FastAPI audit server for the plaintext audit functions, with request limits and optional authentication (optional `[server]` extra). It has no encrypted path. |
| `regaudit_fhe.fhe` | CKKS backends: parameter validation, the backend registry, and the TenSEAL / OpenFHE slot-vector implementations. |

For prose-level guidance see [the README](../README.md),
[COMPLIANCE.md](../COMPLIANCE.md), and the threat model under
[docs/THREAT_MODEL.md](THREAT_MODEL.md).

## Opt-in response format

The default output of `regaudit-fhe verify` and `POST /v1/verify` does not say anything about revocation. Ask for `regaudit-fhe verify --response-format v2`
or `POST /v1/verify?response_format=v2` to get every existing field, unchanged, plus:

| Field | Value |
|---|---|
| `response_format` | `regaudit-fhe.verification-response.v2` |
| `revocation_evaluation` | `not_evaluated`: no usable revocation data was consulted. `evaluated`: fresh signed data was consulted, and the report may still be refused because of it. `required_but_unavailable`: required and not established, never trusted |
| `policy_evidence` | Versioned detail, `policy_evidence_version: 1` |
| `claim_assessment` | The label set, text only: `encrypted_execution: "not_established"`, `statement` ("Encrypted execution not established."), `invariant` ("A signed report can authenticate a claim without proving that claim is true."), what the report declares (`plaintext_declared`, `fhe_declared`, `unrecognized` or `not_stated`), and `lines`, the same statements as display text. It takes no part in the decision |

`TRUSTED` keeps its meaning: signed by a key in your trust store, under your policy. `not_evaluated` beside `TRUSTED` means nothing is known here about revocation.
The HTTP server has no revocation gate, so it always reports `not_evaluated`. Any other `response_format` value is a 422.

The default response of `POST /v1/verify` has no field for claim labels and gained none: its keys and values are as before, and no
note was added to `reasons`. Read "Encrypted execution not established." and "A signed report can authenticate a claim without
proving that claim is true." as the rule for every default response too. `claim_assessment` is for clients that ask for the
versioned format. It never reads a signed field as evidence of encrypted execution.

`GET /version` keeps `library_version`, `python` and `tenseal`, and adds `server_execution`: "plaintext-only". The `tenseal`
field is the version of an installed library, if any. It is not a capability of this server and not evidence of encrypted execution:
the audit routes run plaintext functions.

