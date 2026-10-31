# Owner-signed revocation lists: proposed protocol, draft v1 (prototype only)

Status: **proposal with a tests-only prototype. Not implemented in the product, not part of the published
protocol, no schema registered.** AI-assisted engineering work; not an audit, not a production or regulatory
assurance.

Owner decision recorded: the revocation authority model is **independent owner-signed revocation records,
verifiable by recipients, signed by a designated revocation key that is distinct in purpose from ordinary
report-signing keys.** This document is the complete proposed format, threat model, compatibility statement and
test plan for that model. It refines `docs/TRUST_SPEC.md` sections 4.5 and 4.6 and does not override them.

What is real today (shipped on this branch): only the local `trust status|retire|revoke` commands, which are a
**LOCAL VERIFIER POLICY CHANGE** and not evidence of issuer-authorised revocation (section 10).
What is prototype: everything else here, in `tests/experimental_revocation/` and
`docs/proposals/revocation-list.v1/` (section 14).

## 1. Roles and the purpose-separated key

* **Issuer report keys** sign reports (existing). They are never trusted to speak about their own revocation.
* **Revocation key** (one per issuer, held by the issuer's owner): Ed25519, used *only* to sign revocation lists.
  Identified by its SPKI SHA-256 fingerprint. It must never be enrolled as a report key; a verifier refuses a
  list when the pinned revocation key's fingerprint also appears in its trust store
  (`REVOCATION_KEY_IS_REPORT_KEY`). Separation is also cryptographic: lists are signed under their own domain
  prefix, so a report signature (or a seal digest) is not a valid list signature and vice versa.
* **Verifier**: pins `(issuer, revocation-key public key)` out of band (never read from a list or from the
  channel that delivered it, never trust-on-first-use) and keeps verifier-side high-water marks.

## 2. The format: `regaudit-fhe.revocation-list`, `schema_version` 1

One cumulative list per `(issuer, revocation key)`; each new list states the complete current set.

```json
{
  "schema": "regaudit-fhe.revocation-list",
  "schema_version": 1,
  "algorithm_version": 1,
  "issuer": "acme",
  "authority": {"key_id": "acme-rev-1", "key_fingerprint": "<64 hex: SPKI SHA-256 of the revocation key>"},
  "epoch": 7,
  "prev_list_digest": "<64 hex digest of epoch 6, or null when epoch == 1>",
  "issued_at": "2026-11-01T09:00:00Z",
  "valid_from": "2026-11-01T09:00:00Z",
  "valid_until": "2026-11-08T09:00:00Z",
  "entries": [
    {"key_id": "acme-2025", "key_fingerprint": "<64 hex>", "status": "compromised",
     "effective_from": "2026-08-15T00:00:00Z"},
    {"key_id": "acme-2026a", "key_fingerprint": "<64 hex>", "status": "replaced",
     "effective_from": "2026-10-01T00:00:00Z",
     "successor": {"key_id": "acme-2026b", "key_fingerprint": "<64 hex>"}}
  ],
  "signature": {"algorithm": "ed25519", "signature_b64": "<canonical base64, 64-byte signature>"}
}
```

Rules enforced by the prototype (and by the draft schema where JSON Schema can express them):
* exactly these members, at every level; unknown or missing members are refused (no forward-compat fallback);
* integers only (`epoch >= 1`), RFC 3339 strict times, fingerprints 64 lowercase hex;
* `issued_at <= valid_from < valid_until` (the validity period); `effective_from` may not be later than
  `issued_at + 5 min` (a list is evidence about the past, not a schedule);
* `entries` strictly sorted by `key_id`, unique; an entry identifies a key by `(key_id, key_fingerprint)`,
  never by `key_id` alone;
* `status` is one of `retired`, `compromised`, `replaced` (section 3); only `compromised` may have
  `effective_from: null` (unknown boundary); `replaced` requires `successor`; a successor may not equal the key
  (by id or fingerprint) and successor chains may not cycle;
* `signature` is outside the signed body.

Draft schema file: `docs/proposals/revocation-list.v1/revocation-list.v1.schema.json` (not shipped, not
registered). The prototype and the schema are tested to agree on structural tamper; ordering/uniqueness,
cycles and chaining are semantic checks that JSON Schema cannot express and stay in the verifier.

## 3. Retirement, compromise revocation and replacement (explicitly distinct)

| Status | Meaning | Boundary | Effect when applied to a trust store | History |
|---|---|---|---|---|
| `retired` | planned end of use; **no** belief of exposure | `effective_from` = R, required | store `retired`, `retired_at = R` | a report is acceptable only if provably signed strictly before R |
| `replaced` | planned rotation with a signed successor | `effective_from` = R, required; `successor` required | store `retired`, `retired_at = R` (the store format has no successor member) | same as retired; the successor is evidence, never trust |
| `compromised` | key believed exposed from C | `effective_from` = C, or `null` = unknown | store `compromised`, `compromised_from = C` or unknown | only authenticated chronology strictly before C; unknown refuses everything; signer-asserted time never counts |

`replaced` is a retirement plus authenticated successor information; it is not a compromise. A key that is both
compromised and replaced is listed `compromised` with a `successor` (the successor member is allowed on any
status; only `replaced` requires it). Choosing `retired`/`replaced` for a key that is actually compromised leaves
its pre-R history acceptable under chronology rules; nothing can detect that owner error, which is why the
revocation key holder, not an ordinary operator, signs these.

## 4. Canonical signing form (existing rules, unchanged)

`signing_input = b"regaudit-fhe/revocation-list/v1/sign\x00" || canonical_bytes(signed_body)`

* `canonical_bytes` is the existing `regaudit_fhe.canonical.canonical_bytes` (sorted keys, `,`/`:` separators,
  UTF-8 without ASCII escaping, finite numbers, depth limit). `canonical.py` is not modified.
* `signed_body` is every member except `signature`.
* Parsing uses the existing `loads_strict` (no duplicate keys, no NaN/Infinity, no BOM, size cap 4 MiB).
* Signature: Ed25519 over `signing_input`, canonical base64 of 64 bytes (the existing `verify_signature`).
* Chain digest: `sha256(b"regaudit-fhe/revocation-list/v1/digest\x00" || canonical_bytes(signed_body))`, hex.
* Domain prefixes differ from the report prefix (`regaudit-fhe/report/v2/sign\x00`) and from each other.
  The prototype pins a golden vector (signing-input sha256, list digest, deterministic signature) so any
  change to canonicalisation is caught.

## 5. Verifier algorithm (order matters; every refusal is fail-closed and writes nothing)

1. parse strictly and validate the shape: `REVOCATION_MALFORMED`;
2. `schema_version`/`algorithm_version` supported: `REVOCATION_VERSION_UNSUPPORTED`;
3. `issuer` equals the pinned issuer: `REVOCATION_WRONG_ISSUER`;
4. `authority.key_fingerprint` equals the pinned key's fingerprint: `REVOCATION_AUTHORITY_MISMATCH`
   (the key itself comes from the pin, never from the list);
5. pinned key is not a report key in the verifier's trust store: `REVOCATION_KEY_IS_REPORT_KEY`;
6. signature valid under the pinned key and the list domain prefix: `REVOCATION_SIGNATURE_INVALID`;
7. validity: `issued_at`/`valid_from` not after now + skew (`REVOCATION_NOT_YET_VALID`); now strictly before
   `valid_until` (`REVOCATION_EXPIRED`);
8. semantic entry checks (effective_from not after issuance, no successor cycle): `REVOCATION_MALFORMED`;
9. for each entry (and each successor) whose key_id is in the local store, the fingerprint must equal the
   store's key: `REVOCATION_KEY_MISMATCH` (a list is never merged over a different key);
10. epoch, rollback, fork and monotone merge against the high-water mark (section 7).

Verification is pure; the mark advances only through a separate `commit` after full acceptance.

## 6. Monotone merge (a list can only tighten)

Against the retained previous list: no entry is removed; a key's fingerprint is never rebound; `retired` and
`replaced` keep their `effective_from`; a retired/replaced key may become `compromised` only with a boundary at
or before its `effective_from` or unknown; a compromised boundary may move earlier or become unknown, never
later and never from unknown to known; `successor` once present is never changed or removed (it may be added).
Violation: `REVOCATION_NOT_MONOTONE`. The list therefore cannot un-revoke, re-date or loosen; a revocation-key
thief can only add restrictions (denial of service), not lift one.

Applying an accepted list to an `entries` store takes the **stricter of local and list** per key (never
loosens a local retirement or compromise; unknown boundary dominates); legacy and bare-mapping stores cannot
carry lifecycle state and are refused (`REVOCATION_STORE_UNSUPPORTED`).

## 7. Epochs, high-water marks, rollback and fork detection, and the honest limit

Persisted by the verifier, per `(issuer, revocation-key fingerprint)`: `epoch`, list digest, `issued_at`,
`valid_until`, and the accepted entries. Decisions for a candidate list (all after steps 1-9):

| Condition | Outcome |
|---|---|
| no mark | accepted with note `REVOCATION_NO_HIGH_WATER_MARK`; `rollback_detection: none` |
| `epoch` < mark | `REVOCATION_ROLLBACK` |
| same epoch, same digest | accepted, `REVOCATION_REPEAT` |
| same epoch, different digest | `REVOCATION_FORK` (equivocation by the key holder or a forged list) |
| `epoch` == mark + 1 | `prev_list_digest` must equal the mark's digest, else `REVOCATION_FORK` |
| `epoch` > mark + 1 | accepted with note `REVOCATION_EPOCH_GAP` if monotone over the retained list; refused with `allow_gap=False` |

**Honest limit (stated in every result's `limit` field and in the CLI/status output of the local tool):**
*a verifier with no independently preserved high-water mark cannot reliably detect a rollback of both the
revocation data and its local state.* A present mark detects replay of an older authentic list; it does not
protect against anyone who can also rewrite, lower or delete the mark (the prototype asserts exactly this: deleting
or lowering the state makes the older list acceptable with `rollback_detection: none`). First use has no mark.
Independent preservation (a second verifier, write-once storage, an external witness of the list head) is a
deployment decision and is not supplied by this library. A hash chain proves linkage of the lists supplied, not
completeness of everything ever issued.

## 8. Evaluating historical signatures; making "authenticated history" producible

Policy (reuses `VerificationPolicy`, `TrustHistory`, chronology; **`verification.py` is not changed**):

* The list never rewrites or invalidates a stored report. It changes the verifier's *current* trust-store entries
  and supplies the freshness statement the engine already asks for.
* Let T be the report's authenticated chronology (verified timestamp `genTime + accuracy`; the engine's
  `AUTHENTICATED`) and B the entry's boundary.
  * active / not listed: unchanged from 0.2.0.
  * `retired`/`replaced` (B = R): accepted only if T exists, T < R strictly, and an authenticated fresh
    `TrustHistory` is present (below); otherwise `KEY_RETIRED_NO_CHRONOLOGY`, `SIGNED_AFTER_RETIREMENT` or
    `TRUST_STORE_FRESHNESS_UNPROVEN`.
  * `compromised` with C: T < C strictly plus fresh history; no T: `KEY_COMPROMISED_NO_CHRONOLOGY`; unknown C:
    always refused; signer-asserted `issued_at` is never accepted for a compromised key.
  * reports without a verified timestamp get nothing from a list; reports after the boundary are refused.
* **Producing authenticated history** (the seam `TrustHistory(authenticated=True)` was reserved for):
  after a list verifies (section 5) and is inside `valid_until`, a caller-side module returns
  `TrustHistory(as_of=list.issued_at, authenticated=True)`; it returns `None` for a missing, unverifiable,
  expired or refused list. The engine's existing 24 h `trust_history_max_age` then applies to `as_of`, so a list
  that stays current must be **re-issued at least daily** (a heartbeat list is a new epoch with unchanged
  entries). `authenticated=True` means "owner-signed, fresh, under the pinned key"; it is the owner's attestation
  at `issued_at`, not proof that no other revocation exists.
* `high-assurance` keeps refusing historical acceptance of retired/compromised keys (the engine's
  `history_ok()` is false there). Relaxing it would be a `verification.py` change and is **not** proposed here; it
  would need its own verdict-preservation proof and owner approval.
* **Missing or unverifiable list never means "nothing revoked".** `evaluate()` returns status `NO_LIST` or
  `UNVERIFIED`, the store unchanged, no history, and `revocation_evidence: "unproven"`. A previously accepted list
  is not reused after its `valid_until`. Consequently a locally-retired key's historical report stays refused
  (`TRUST_STORE_FRESHNESS_UNPROVEN`) until a verified list supplies history. A key that is merely *active* locally
  and absent from every list is not protected by an absent list: the verifier only learns of a revocation by
  holding a verified list, and the result says the evidence is unproven rather than clean.

## 9. Rotation: authenticated successor information

* `successor {key_id, key_fingerprint}` is signed by the revocation key and bound to fingerprints.
  `resolve_successors` follows the chain with fingerprint binding at each hop and stops (no chain) when a
  hop's fingerprint does not match.
* It is **evidence, not trust**: naming B does not enrol B, does not make B's reports acceptable, and does not
  treat A's reports as B's. B must be enrolled with `trust add` and an out-of-band fingerprint. If B is enrolled
  with a different key than the list names, the list is refused (`REVOCATION_KEY_MISMATCH`).
* A key_id is never reused: an entry's fingerprint is never rebound, and the verifier's store never frees an id.
* Compromise semantics: if A is compromised, only the revocation-key-signed successor counts; anything signed by
  A after C is worthless, so A-signed "I am replaced by B" statements are not part of this format.

## 10. The local, unsigned `trust revoke` is a local verifier policy change

`trust retire` and `trust revoke` edit the verifier's own file. They are **not** evidence that the issuer
authorised anything, they are not distributed, and whoever can write the file can undo them. Wording now used:
JSON `scope: "LOCAL VERIFIER POLICY CHANGE"`, `issuer_authorized: false`, a `notice` and `rollback_detection`
field, the same notice on stderr, and `--help` descriptions. `trust status` carries the same scope and the
no-high-water-mark statement. These commands remain useful for an operator who wants to stop trusting a key
immediately; they must not be presented as revocation by the issuer.

## 11. Threat model

| Threat | Handled by | Residual |
|---|---|---|
| Forged list by a party without the revocation key | pinned key, signature, domain separation | none beyond key compromise |
| Report key used to sign a list | purpose check (pinned key not in store), different domain prefix, pin mismatch | none for lists; a store that enrols the revocation key as a report key disables lists (fail-closed) |
| Replay of an older authentic list | high-water mark, `valid_until`, epoch chain | undetected with no/deleted/lowered mark (section 7) |
| Fork / equivocation by the key holder | same-epoch digest check, `prev_list_digest` | only detected by a verifier that sees both lists |
| Silent drop of an entry | monotone merge, cumulative lists | first-use verifier cannot know what it was never shown |
| Stale list presented as current | `valid_until`, 24 h `TrustHistory` freshness | owner must heartbeat |
| Revocation key theft | monotone: thief can only tighten (DoS); pin re-provisioning recovers | needs owner decision (section 15) |
| Report key compromise before listing | `compromised` + boundary + chronology | window between compromise and publication is not closable by any list |
| Wrong status chosen (`retired` for a compromised key) | owner process | undetectable |
| Key relabelling | `(key_id, fingerprint)` identity, store fingerprint uniqueness, mismatch refusal | none |
| Clock manipulation on the verifier | skew-bounded validity checks | a verifier with a wrong clock misjudges expiry |
| Local writer on the verifier host | none | can delete/lower marks, edit store, re-pin: out of scope |
| Missing/unverifiable list treated as clean | `evaluate()`: unproven, no history, store unchanged | caller must surface `revocation_evidence` |

## 12. Compatibility

* No existing format, schema, verification rule or verdict changes. With no list configured the prototype is not
  used, and the published 0.2.0 wheel and this branch produce **byte-identical** verdicts on every fixture:
  signers 0.1.0/0.1.1/0.2.0 x report.v1/v2 x six primitives x 12 stores (bare, legacy active/revoked, entries
  active/retired/compromised, and command-edited retired/revoked): 1368 records, sha256
  `9a1eb45ba6b4831a7f8ce23e645905a7b4d55bcc058086c4e15844172f3809b4` for both.
* A list-derived store is an ordinary `entries` store (existing members only), so old verifiers load it.
* Lists are a new artifact: old verifiers ignore them entirely, and a new verifier given no list behaves as 0.2.0.
* The prototype produces inputs for the unchanged engine; the end-to-end tests run the real `verify()`.

## 13. Test plan and prototype coverage (`tests/experimental_revocation/`)

Pinned: golden canonical bytes/digest/signature; canonical stability (member order, whitespace, Unicode);
tamper of **every** one of the 23 leaf fields of a two-entry list, plus removal/addition of every member;
malformed/oversized/deeply nested input; unsupported versions; wrong issuer; unpinned authority; claiming the
pinned fingerprint without the key; report key as revocation key (three ways) and as anchor; other domains;
non-canonical base64; fingerprint mismatch with the store; validity period including exact boundaries; epochs
(first use, advance, rollback, repeat, fork, bad chain, gap allowed/forbidden, refused list never advances,
out-of-order commit, per-issuer marks); every monotone rule in both directions; successor chains, cycles,
self-succession, fingerprint binding, mismatch with an enrolled successor, successor-is-not-trust; apply as
stricter-of (14 cases); missing/unverifiable list gives no history and no store change; legacy store
refused; end-to-end through `verify()` for retired/compromised/high-assurance; state file round trip, mode
0600, atomic failure; the honest-limit test; draft schema vs prototype agreement; deterministic fixture
generator; not-shipped guards (no `src` mention, no registered schema). Mutation: 42 mutants of the prototype,
42 killed (4 initial survivors were killed by added tests; one redundant check was removed).

## 14. Prototype versus production

| Item | Location | Shipped? |
|---|---|---|
| Local `trust status/retire/revoke` | `src/regaudit_fhe/_trust_lifecycle.py`, `cli.py` | yes (candidate 0.3.0), local policy only |
| Reference sign/verify, state, apply, history derivation | `tests/experimental_revocation/proto.py` | **no**, tests only |
| Fixture generator | `tests/experimental_revocation/gen_fixtures.py` | no |
| Draft JSON schema | `docs/proposals/revocation-list.v1/revocation-list.v1.schema.json` | no, not registered |
| Everything in this document | `docs/` | proposal |

Nothing in `src/regaudit_fhe` (including `schemas.py`, `trust.py`, `verification.py`, `canonical.py`, `_keys.py`,
`replay.py`) was changed for the prototype; a guard test fails if the source tree starts mentioning the format.

## 15. Remaining owner decisions and exact blockers to ship

Owner decisions (software cannot decide these):
1. **Revocation key custody**: who holds it, where (HSM/offline), backup and access rules; one per issuer or per
   deployment.
2. **Pinning**: the ceremony and storage for `(issuer, revocation public key)` on each verifier, and how a new
   verifier first obtains the fingerprint out of band (never from the list channel).
3. **Rotation of the revocation key**: the succession statement (outgoing key names incoming) is only sketched
   (`regaudit-fhe/revocation-authority-succession/v1`), not specified or prototyped; needs approval.
4. **Quorum and recovery**: whether one key suffices or multiple signatures are required (v1 has a single
   `signature`; multi-signature would be v2), and the procedure after loss or theft of the revocation key.
5. **Distribution and heartbeat**: channel(s), cadence (daily if `trust_history_max_age` stays 24 h), who runs it.
6. **Independent preservation of the high-water mark** (second verifier, write-once store, witness), because a
   local mark is bypassable by whoever can write it.
7. **High-assurance policy**: whether the profile may ever accept historical retired/compromised keys with a
   list-derived history (requires a separate `verification.py` change and verdict proof).

Engineering blockers (do not exist yet; not done, as instructed):
* publish the schema: add the file to `src/regaudit_fhe/schemas/`, register it in `schemas.py`, fix `$id`;
* a production module equivalent to the prototype and CLI/server wiring (`--revocation-list`, `--revocation-anchor`,
  `--revocation-state`), including a compare-and-set state store modelled on `SqliteReplayCache`;
* cross-signature / `retired_at` coexistence in the entries format are **not** needed by this design.

Recommendation: ship the local commands (clearly labelled) in the next minor; hold the signed list until owner
decisions 1, 2 and 6 are made and the schema publication is approved. No compatibility fallback may treat a
missing or unverifiable list as "nothing revoked".
