# 0.3.0 trust protocol: implementation plan

Companion to [the frozen proposal](../../TRUST_REVOCATION_PROTOCOL_PROPOSAL.md) and [the test matrix](TEST_MATRIX.md). A plan only:
nothing below has been done. AI-assisted engineering work; not an audit and no production assurance.

## Starting point

| Item | State |
|---|---|
| Branch | `qual/0.3-trust-lifecycle`, local only. Holds `trust status`, `trust retire`, `trust revoke` and their tests |
| `master` | Moved on. The merge conflicts in `CHANGELOG.md` only: both sides add a top section. Keep both, with 0.3.0 above 0.2.1. Not merged in this milestone, as instructed |
| Prototype | `tests/experimental_revocation/`. `proto.py` is the document verifiers. `trust_gate.py` is the state store, gate, wrapper and migration model. Both may be ported, and neither is product code |
| Blocked by | TRUST_SPEC 4.5: not to be implemented or advertised as `high-assurance` until the O8 designations are made. OD-1 to OD-5 and OD-8 in the proposal cover them |

## What the owner decides first

| Gate | Decisions | Phases it releases |
|---|---|---|
| G-A | OD-6 (schema publication) | Phase 1 |
| G-B | OD-2 (pinned store), OD-3 (state store) | Phases 2, 3 |
| G-C | OD-1 (authority custody), OD-4 (anchor), OD-5 (distribution), OD-8 (TRUST_SPEC mapping and approver) | Phase 6, and any statement that `required` is usable |
| G-D | Whether 0.3.0 ships `required` at all, or only the local commands | Release scope, below |

OD-7 (history) blocks nothing. The recommendation is to leave it undecided and ship no option.

Phases 1 to 5 can be built behind `off` before G-C. Under `off` no verdict changes, so they are safe to merge if the owner wants the code
ahead of the deployment decisions. They must not be advertised.

## Release scope options for 0.3.0

| Option | Ships | Needs |
|---|---|---|
| A. Local commands only | What is on the branch today. The protocol stays a proposal | Nothing further. This is the only option available without owner decisions |
| B. Formats and `advisory` | A plus phases 1 to 5, with `required` present but documented as unusable until a deployment exists | G-A, G-B |
| C. `required` usable | B plus phase 6 and a real deployment | G-A to G-C |

Recommendation: A for 0.3.0 unless G-C is expected soon, with B as the next minor release. Shipping schema names earlier than the custody
decisions makes them hard to change if a decision forces a format change.

## Phases

Each phase ends with its matrix rows passing against product code, and with the prior phases' rows and the published verdict comparison still
passing.

### Phase 1: formats (G-A)

| File | Change |
|---|---|
| new `src/regaudit_fhe/_revocation.py` | Port the document verifiers from `proto.py`: list, transition, recovery, digests, signing inputs. Pure functions |
| new `src/regaudit_fhe/schemas/revocation-*.v1.schema.json` | The three schemas, unchanged except the final `$id` and title |
| `src/regaudit_fhe/schemas.py` | Register them |
| `tests/experimental_revocation/test_not_shipped.py` | Retire deliberately: replace with a test that the API stays private until phase 3 |
| Move to `tests/vectors/` | Golden vectors and corpus, unchanged. Run corpus and vectors against product code |

Rows: L*, M01 to M17, A01 to A10, A13, C01 to C15, C17 to C37, K06, N01 replaced. Changing `$id` changes the schema digests: re-pin deliberately and
leave `schema_version` at 1.

Risk: `canonical_bytes` uses Python's number formatting. These formats hold only integers and strings, so a non-Python verifier is less
exposed here than for reports, but TRUST_SPEC 11's RFC 8785 note still applies.

### Phase 2: state store (G-B)

| File | Change |
|---|---|
| new `src/regaudit_fhe/_revocation_state.py` | `CasStore` protocol, record encode and decode with integrity digest, commit protocol, `FileCasStore`, ingest functions, ceremonies |
| Adapter per OD-3 | The chosen independent store. Not started until decided |

Rows: E06 to E12, E17 to E21, M18, M19, S01 to S15, S17 to S24, D05, D07, plus S16 once a real store exists. Needs real-filesystem crash testing beyond the simulated crash points, and
review of `fcntl` on the supported platforms. The repository is tested on Linux and macOS; Windows behaviour of this store has not been considered.

### Phase 3: gate and wrapper (G-B)

| File | Change |
|---|---|
| new `src/regaudit_fhe/_revocation_gate.py` | `RevocationContext`, `gate`, `overlay`, join, config check |
| `src/regaudit_fhe/trusted.py` or a new public function | The opt-in path. **`verification.py` is not changed.** TRUST_SPEC 9.1 asks for one enforcement function shared by entry points: this wrapper becomes that function for opted-in paths |
| `src/regaudit_fhe/__init__.py`, `docs/API.md` | Additive exports. `tests/test_public_api_v2.py` updated |

Rows: A11, A12, C16, D01, G01 to G21, G24 to G31, H01 to H08, K01 to K05, K07 to K10, V01 to V05.

Decision for review at this phase: whether the disclosure is a separate object beside `VerificationResult` (recommended, as `to_dict` output under
`off` must stay byte-identical) or new optional fields.

### Phase 4: CLI

| File | Change |
|---|---|
| `src/regaudit_fhe/cli.py` | `verify --revocation-mode --revocation-pins --revocation-state --revocation-evidence-age`; `revocation enroll, status, ingest, rebaseline`; `trust migrate`, with dry run; `trust add` refuses a key equal to an enrolled authority or anchor |
| Exit codes | Gate codes per proposal 10.2. `REVOCATION_STORE_UNSUPPORTED` and unsafe combinations are exit 2 |

Rows: E14, E15, G22 for the CLI, T01 to T12.

### Phase 5: server

| File | Change |
|---|---|
| `src/regaudit_fhe/server.py` | Configuration from the environment; startup refusal for unsafe configurations (TRUST_SPEC 9.4, no fallback to a weaker profile); gate per request. `serve` reads the trust store once at start and must not treat this state the same way; ingest runs separately |
| `docs/DEPLOYMENT.md` | Heartbeat dependency, store placement, restore procedure |

Rows: E15, G22 for HTTP, G23. Merge `master` first: `server.py` changed substantially in 0.2.1.

### Phase 6: issuer tooling (G-C)

| File | Change |
|---|---|
| `src/regaudit_fhe/cli.py` | `revocation sign-list, sign-transition, sign-recovery`, using `KeyProvider`. The authority persists its epoch before publishing |
| Runbooks in `docs/` | Enrollment ceremony, rotation, compromise recovery, restore |

Rows: D06, plus a full exercise of rotation and recovery with real tooling.

### Phase 7: documents

`docs/TRUST_SPEC.md` per proposal section 17; `docs/THREAT_MODEL.md`; `docs/API.md`; a new `docs/MIGRATION_0.3.md`; `README.md`; `CHANGELOG.md`;
`docs/TRUST_LIFECYCLE_PROPOSAL.md` status. Wording constraints stay: "verified as of", no statement that a key "is not revoked", and no assurance
beyond what the protocol shows.

### Phase 8: qualification

* All matrix rows against product code, including every `none` row.
* V06 and V07: installed published wheels, including the real 0.2.1 wheel rather than tag source.
* Mutation testing of the verifiers, the gate and the commit protocol.
* Replay of the independent challenge corpus being built on another branch. It has not been read for this proposal, so disagreements with
  it are real findings against this spec.
* Who reviews, and how that is described in the release record, is for the owner to state.

## Source changes this requires (none made)

| Reason | File |
|---|---|
| Document verifiers, state, gate | three new private modules |
| Opt-in entry point, exports | `trusted.py` or new, `__init__.py` |
| Schemas | `schemas/`, `schemas.py` |
| Commands | `cli.py` |
| Serving | `server.py` |

Not to be changed: `verification.py`, `trust.py`, `canonical.py`, `reports.py`, `report_v2.py`, `replay.py`, `_keys.py`, and the report schemas.

## Risks

| Risk | Mitigation |
|---|---|
| A heartbeat outage takes every `required` verifier to refusal at once | OD-5 monitoring; a longer evidence age is available, at the cost of the 9.6 bound |
| Operators start from a restored state file without a ceremony | Runbook; `state_seq` in results; independent store under OD-3 |
| Operator misreads `advisory` as protection | `revocation_evidence: unproven` in output; not available under `high-assurance` |
| Latch triggered by an authority's own mistake | Authority persists its epoch first; a ceremony clears it; the record keeps the digest for diagnosis |
| The reference model passes while the port differs | Run the same tests against both during phases 1 to 3, then delete the model |
| The matrix's `none` rows are forgotten | Phase 8 exit requires them |
| A row's named test does not exercise what it says | The consistency test only checks names. Phase 8 mutation testing is the check on this, and an independent read found such rows here |
