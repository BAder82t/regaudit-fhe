# Installing and developing

All install options, how to check a fresh clone, and where the code lives.

## Install

```bash
pip install regaudit-fhe
```

That is enough for everything except encrypted execution and the HTTP server: the six
audit primitives run in the plaintext reference model, and signing, verification, the
schemas and the `regaudit-fhe` command all work (Python 3.10 or newer; the only hard
dependencies are `numpy`, `cryptography` and `jsonschema`).

| You want to... | Install | Notes |
| --- | --- | --- |
| Audit, sign, verify, use the CLI | `pip install regaudit-fhe` | Plaintext reference model. |
| Run the primitives on CKKS ciphertexts | `pip install "regaudit-fhe[fhe]"` | Adds TenSEAL. Needs a TenSEAL wheel for your platform and Python; if `pip` cannot find one the install fails, and the base package still works. |
| Run `regaudit-fhe serve` / `build_app()` | `pip install "regaudit-fhe[server]"` | Adds FastAPI and uvicorn. Without it `serve` stops with a message naming this extra. |
| Try the experimental OpenFHE backend | `pip install "regaudit-fhe[openfhe]"` | Optional and experimental. |
| Work on the project | `pip install -e ".[dev,server,fhe]"` | Test, lint and type-check tools. |

Quote the extra: in **zsh** (the default macOS shell) an unquoted `regaudit-fhe[fhe]` fails
with `no matches found`.

Check the install from any directory (it needs nothing from a checkout):

```bash
regaudit-fhe --help
regaudit-fhe schema --list                         # the 14 bundled JSON Schemas
python -c "import regaudit_fhe as rf; print(rf.__version__)"
```

## Verify a fresh clone

The release gate is one shell block. Anything that fails this block
is a release blocker:

```bash
git clone https://github.com/BAder82t/regaudit-fhe.git
cd regaudit-fhe
python -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

python -m py_compile src/regaudit_fhe/*.py src/regaudit_fhe/fhe/*.py tests/*.py
python -c "import regaudit_fhe; print(regaudit_fhe.__version__)"
regaudit-fhe --help
regaudit-fhe schema --list
pytest -q
```

CI runs an equivalent matrix on every push (see
[.github/workflows/ci.yml](../.github/workflows/ci.yml)) and the badge at
the top of the [main README](../README.md) reflects the latest result.

## Layout

```
src/regaudit_fhe/
  _slot.py             plaintext SlotVec model with depth-budget enforcement
  _validation.py       finite/binary/length input guards
  cli.py               regaudit-fhe CLI entrypoint
  reports.py           report.v1 envelope: canonical JSON, parameter-set hash,
                       input commitments, Ed25519 signing, legacy
                       verify_envelope / verify_envelope_or_raise()
  report_v2.py         report.v2 envelope: signed identity, domain-separated
                       signing, strict parsing, sealed digest, parse_envelope()
  canonical.py         strict v2 canonical JSON policy + canonical base64
  verification.py      VerificationPolicy / verify / VerificationResult:
                       the shared trust engine (library, CLI, HTTP)
  replay.py            local in-memory and sqlite replay caches
  trust.py             TrustStore (key lifecycle, scope) + typed verification
                       exceptions (UntrustedIssuer, RevokedIssuer,
                       WrongParameterSet, HashMismatch, InvalidSignature,
                       TimestampInvalid, TimestampUnverified)
  schemas.py           JSON Schema loader + validator (envelope, envelope.v2)
  schemas/             bundled Draft-2020-12 schemas (one per input/output + envelope)
  server.py            hardened FastAPI HTTP audit server
  egf_imss.py          fairness primitive
  etk_fpa_hbc.py       provenance primitive
  esc_cia.py           concordance primitive
  ecp_qssp.py          calibration primitive
  ew1_cdsf.py          drift primitive
  ecmd_jps.py          disagreement primitive
  fhe/                 TenSEAL CKKS encrypted backend (optional [fhe] extra):
    context.py           build_d6_context, CKKSContext
    params.py            validated CKKSParams
    slot_vec.py          EncryptedSlotVec mirroring the plaintext SlotVec API
    primitives.py        encrypted variants of every audit primitive

docs/specs/            per-primitive technical specifications
docs/TRUST_SPEC.md     trust specification: key lifecycle, chronology, replay, outcomes
docs/THREAT_MODEL.md   roles, key custody, per-primitive public-surface tables
COMPLIANCE.md          regulator-facing scope statement and disclaimers
docs/DEPLOYMENT.md     server hardening guide + production checklist
docs/SUPPLY_CHAIN.md   Sigstore verification, SBOM, reproducible build notes
docs/roadmap/          design notes for non-shipping work
schemas/               copy of the JSON Schemas (the package loads src/regaudit_fhe/schemas/; a test keeps them identical)
tests/                 unit, integration, edge-case, property-based, schema, security,
                       canonical report.v2 vectors (tests/vectors/), exit-code tests
scripts/               build helpers and the mutation-sensitivity check
examples/              client + regulator end-to-end flows
benchmarks/            d=6 CKKS wall-clock + memory benchmarks
```
