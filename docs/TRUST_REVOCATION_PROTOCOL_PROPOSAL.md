# Owner-signed revocation: FROZEN protocol specification, draft v1 (prototype only)

Status: **FROZEN DRAFT v1 for review. Not implemented in the product, not part of the published protocol,
no schema registered, no public API, no change to verification acceptance semantics, no server wiring.**
AI-assisted engineering work; not an audit, not a production or regulatory assurance.

"Frozen" means the three draft schemas and the golden vectors in `docs/proposals/revocation-list.v1/` are pinned
by SHA-256 in `tests/experimental_revocation/test_frozen.py`, and the adversarial corpus in
`tests/experimental_revocation/corpus/` is pinned byte-for-byte to its generator. Any change needs a version bump
(`schema_version: 2`) and a deliberate re-pin. This document refines `docs/TRUST_SPEC.md` 4.5/4.6 and does not
override them.

## 0. Owner decisions encoded

| # | Decision | Where encoded |
|---|---|---|
| 1 | Revocation authority = issuer-designated owner authority; its key is separate from report keys | 2, 3.1 |
| 2 | Verifier trust = explicit LOCAL ENROLLMENT of the authority public key (never learned from a list) | 2, 6 |
| 3 | Routine rotation = authenticated old-to-new transition; compromise recovery = separate path through an independently enrolled recovery anchor | 3.2, 3.3, 8 |
| 4 | Single authorized signer; multi-signature is FUTURE WORK and nothing here implies a quorum guarantee | 1 |
| 5 | Distribution is independent of trust establishment | 10 |
| 6 | Rollback protection = verifier-persisted monotonic high-water mark OUTSIDE the list file | 7 |
| 7 | High-assurance: no historical acceptance from list history; a cumulative current list is not an authenticated history | 9 |
| 8 | Retirement = no NEW signatures after the effective time; explicit compromise policy for historical signatures with worked examples | 5, 9 |

## 1. Scope and plain non-claims

* One authorized signer per role. The transition and recovery statements carry two signatures (outgoing and
  incoming key, or anchor and incoming key) but that is proof of possession, **not a quorum**. Multi-signature,
  threshold or two-person rules are future work (would be v2); no document, output or test may imply otherwise.
* Nothing here proves completeness of all revocations ever issued. A list is the owner's attestation at
  `issued_at`.
* The existing lenient APIs (`verify_receipt`, `verify_envelope`, `verify_report`) and every existing verdict are
  untouched; the prototype only produces inputs for the unchanged `TrustStore`/`TrustHistory`/`verify()`.

## 2. Principals and keys (purpose separation)

| Principal | Key | Purpose | Enrolled how |
|---|---|---|---|
| Issuer report keys | Ed25519 | sign reports | `trust add` + out-of-band fingerprint (existing) |
| Revocation authority | Ed25519, distinct | signs revocation lists and routine transitions | operator enrolls `(issuer, public key)` locally, out of band |
| Recovery anchor | Ed25519, distinct, offline | signs compromise-recovery statements only | operator enrolls locally, out of band, at the same ceremony |
| Verifier state | files/store | enrollments, high-water mark, archive of accepted lists | created by the verifier |

Enforcement: enrollment refuses an authority or anchor equal to a report key in the store or to each other;
a list, transition or recovery that would install a key that is a report key or the recovery anchor is refused
(`REVOCATION_KEY_IS_REPORT_KEY`); signatures use role-specific domain prefixes (section 4).

## 3. Frozen formats (draft schemas: `docs/proposals/revocation-list.v1/*.schema.json`, golden vectors: `golden-vectors.json`)

All three: exact member sets (unknown or missing members refused), integers only, strict RFC 3339 times,
fingerprints 64 lowercase hex (SPKI SHA-256), `schema_version` 1 / `algorithm_version` 1 (anything else is
`REVOCATION_VERSION_UNSUPPORTED`; there is no fallback), canonical base64 64-byte Ed25519 signatures.

### 3.1 Revocation list `regaudit-fhe.revocation-list`

Members: `schema, schema_version, algorithm_version, issuer` (issuer scope), `authority{key_id, key_fingerprint,
generation}` (authority identity), `epoch` (>= 1), `prev_list_digest` (null iff epoch 1), `issued_at`, `valid_from`,
`valid_until` (validity interval, `issued_at <= valid_from < valid_until`), `entries`, `signature`.
Each entry (key action): `{key_id, key_fingerprint, status, effective_from, successor?}`, strictly sorted by
`key_id`; a key is identified by `(key_id, fingerprint)`, never by `key_id` alone. `status` is `retired`,
`replaced` (requires `successor{key_id, key_fingerprint}`) or `compromised` (only this status may have
`effective_from: null` = unknown boundary). `effective_from` may not exceed `issued_at` + 5 min. A list may only
name keys of its own `issuer` (`REVOCATION_ISSUER_SCOPE` if the local entry belongs to another issuer).
Cumulative: each list states the complete current set.

### 3.2 Authority transition (ROUTINE rotation) `regaudit-fhe.revocation-authority-transition`

`issuer, from_authority{key_id, key_fingerprint, generation}, to_authority{key_id, key_fingerprint, generation,
public_key_pem}, issued_at, valid_until, signatures{from, to}`. `from` is signed by the current enrolled authority,
`to` by the incoming key (proof of possession). `to.generation == from.generation + 1`; the incoming key must be
fresh (never an earlier, superseded or compromised authority) and not a report key or the recovery anchor.

### 3.3 Recovery anchor statement (COMPROMISE RECOVERY) `regaudit-fhe.revocation-authority-recovery`

`issuer, recovery_anchor{key_id, key_fingerprint}, recovery_epoch (>= 1), declares_compromised[{key_fingerprint,
compromised_from|null}] (non-empty, sorted, unique), new_authority{key_id, key_fingerprint, generation,
public_key_pem}, rebase (null | {epoch, list_digest}), issued_at, valid_until, signatures{anchor, new_authority}`.
Signed by the separately enrolled **recovery anchor**, never by the authority being replaced; the new authority
co-signs as proof of possession.

### 3.4 Signing domains (canonical bytes reused UNCHANGED)

`signing_input = DOMAIN || canonical_bytes(body without the signature member(s))`, where `canonical_bytes` is
`regaudit_fhe.canonical.canonical_bytes` (not modified) and parsing uses `loads_strict`.

| Use | Domain prefix |
|---|---|
| list signature | `regaudit-fhe/revocation-list/v1/sign\x00` |
| list digest (chain) | `regaudit-fhe/revocation-list/v1/digest\x00` (sha256) |
| transition, outgoing / incoming | `.../revocation-authority-transition/v1/sign-from\x00` / `sign-to\x00` |
| transition digest | `.../revocation-authority-transition/v1/digest\x00` |
| recovery, anchor / new authority | `.../revocation-authority-recovery/v1/sign-anchor\x00` / `sign-new-authority\x00` |
| recovery digest | `.../revocation-authority-recovery/v1/digest\x00` |

All eight prefixes are distinct and differ from the report prefix; a signature in one role never verifies in another
(tested, including swapped roles). Golden vectors pin signing-input hashes, digests and deterministic signatures.

## 4. Key actions (retirement, revocation, replacement)

* `retired` (R = `effective_from`): the key is **no longer approved for NEW signatures at or after R**. A report is
  acceptable only if provably signed strictly before R (existing engine rule: verified timestamp
  `genTime + accuracy < R`).
* `replaced`: a retirement plus an authenticated successor. The successor is evidence, never trust: it does not
  enroll the successor, and a successor already enrolled with a different key is refused.
* `compromised` (C): only authenticated chronology strictly before C can qualify; unknown C refuses everything;
  signer-asserted `issued_at` never counts.
* Applying an accepted list to an `entries` trust store takes the stricter of local and list per key; it never
  loosens (retired date never later, compromise boundary never later, unknown dominates). Legacy and bare stores
  cannot carry this state (`REVOCATION_STORE_UNSUPPORTED`).
* Monotone merge across lists: no entry removed, no fingerprint rebound, retired/replaced dates fixed,
  retired to compromised only at or before the retirement, boundary only earlier, unknown never becomes known,
  successor never changed or removed (`REVOCATION_NOT_MONOTONE`).

## 5. Verifier algorithms (pure; refusal writes nothing)

List (in order): shape (`MALFORMED`), version, enrolled issuer (`NOT_ENROLLED`), issuer match (`WRONG_ISSUER`),
authority compromised/superseded (`AUTHORITY_COMPROMISED` / `AUTHORITY_SUPERSEDED`), pinned fingerprint and
generation (`AUTHORITY_MISMATCH`), authority not a report key, signature, validity (`NOT_YET_VALID`, `EXPIRED`;
upper bound exclusive), entry semantics, store checks (`KEY_MISMATCH`, `ISSUER_SCOPE`), then epoch rules (section 7).
Transition: shape, version, enrolled, from-authority compromised / superseded / mismatch, generation
(`TRANSITION_GAP`), key reuse (`TRANSITION_CYCLE`), role conflict, both signatures, validity.
Recovery: shape, version, enrolled, anchor present (`RECOVERY_ANCHOR_ABSENT`), anchor fingerprint
(`RECOVERY_ANCHOR_MISMATCH`), both signatures, validity, `recovery_epoch` (`RECOVERY_REPLAY`, `FORK`), fresh new key,
generation increases, rebase baseline known (`RECOVERY_BASELINE_UNKNOWN`).

## 6. Enrollment

Only an operator action creates an enrollment `(issuer, authority public key, optional recovery anchor)`. Nothing is
learned from a list, a transition, a recovery statement or the channel; an unenrolled issuer gets `NOT_ENROLLED`.
Deleting the state forgets enrollments and compromise knowledge and fails closed (nothing is trusted until
re-enrolled).

## 7. Epochs, high-water mark and its precise assumption

The verifier persists, per issuer (the epoch chain spans authority rotations): the last accepted list
(`epoch`, digest, entries), an archive of accepted lists, and the enrollments. Rules: lower epoch
`ROLLBACK`; same epoch same digest repeat; same epoch different digest `FORK`; epoch + 1 must chain
`prev_list_digest` else `FORK`; larger jump accepted with note `EPOCH_GAP` only if monotone (or refused with
`allow_gap=False`). The mark advances only through a separate commit after full acceptance; recovery is the only
operation that may lower it (rebase to an archived list).

**Assumption, stated precisely.** The mark must live OUTSIDE the list file in verifier-persisted state. If an attacker
can roll back both the signed list and the verifier's remembered version (delete, lower or replace the state), detection
fails and the older authentic list is accepted (the prototype asserts exactly this, and every result carries
`limit`: *a verifier with no independently preserved high-water mark cannot reliably detect a rollback of both the
revocation data and its local state*). A local editable file is **not sufficient** for that stronger threat model;
it needs an independent store with compare-and-set semantics or an external witness (section 14). First use has no mark.

## 8. Authority rotation versus authority compromise (distinct paths)

**Routine rotation** (3.2): the current authority and the incoming key both sign. Effects: generation +1, old key
superseded forever, epoch chain continues, old-authority lists refused (`AUTHORITY_SUPERSEDED`).
Chains: applied in order; a missing hop is `TRANSITION_GAP`/`AUTHORITY_MISMATCH`, key reuse or a loop is
`TRANSITION_CYCLE`, a duplicate or replayed record is `AUTHORITY_SUPERSEDED`; the first refusal stops the chain.

**Compromise recovery** (3.3) does NOT rely on the compromised authority signing its own replacement. It requires the
**recovery anchor**: an independent Ed25519 key, held offline by the owner, distinct from the authority and every
report key, enrolled on the verifier out of band at the same ceremony as the authority (fingerprint confirmed
like `trust add`). Without an enrolled anchor, recovery is refused (`RECOVERY_ANCHOR_ABSENT`); the only remedy is
operator re-enrollment with a fresh out-of-band ceremony. The anchor is a total trust root for the authority: whoever
holds it can replace the authority (tested as a documented limit), so it must be offline and rarely used.

**A transition signed by a key later declared compromised.**
1. Before any recovery statement the verifier cannot know: a valid transition is accepted (honest limit; the thief
   may take the authority).
2. After a recovery statement declares key K compromised (from C, or unknown), any transition or list signed by K
   is refused (`AUTHORITY_COMPROMISED`), including a transition K signs after the declaration.
3. Transitions already accepted that K signed at or after C (all, if C is unknown) are recorded as void; the
   recovery statement replaces whatever authority the verifier currently holds, even one installed by those
   transitions, provided `recovery_epoch` is newer and the new key is fresh.
4. Lists accepted from the thief: with `rebase = {epoch, list_digest}` the verifier restores its mark to that archived
   list (otherwise its mark, possibly inflated, stays and the new authority must exceed it); an unknown baseline
   is refused, never guessed. Recovery never loosens the local trust store: tightening done by lists stays until an
   operator edits it (the tool never auto-loosens). A thief can only tighten, so the worst case is denial of service.

## 9. Historical signatures: policy and worked examples

Rules (existing engine, unchanged): a report signed by a retired or compromised key needs authenticated chronology
(verified timestamp) strictly before the boundary AND a fresh authenticated `TrustHistory`. Claimed `issued_at` is
not independently trusted and is used only in `development` signer-asserted mode for a retired (never a compromised) key.

**A cumulative current list is not an authenticated history.** It attests the current set at `issued_at` and says
nothing verifiable about earlier states or completeness. Therefore:
* `high-assurance`: never accepts historical retired/compromised keys on list evidence; `derive_trust_history`
  returns `None` for it even if "approved", and the engine's `history_ok()` stays false there. Without separately
  authenticated historical evidence and chronology the profile keeps refusing.
* `development` / `confidential`: a list-derived `TrustHistory(authenticated=True)` is a **documented option that
  needs explicit owner approval and is NOT implemented**; default is none. (Prototype flag `owner_approved`.)

Scenario table (every row executed against the real `verify()`; `OK` = accepted; blank history = default). Codes:
FRESH=`TRUST_STORE_FRESHNESS_UNPROVEN`.

| Scenario | development | confidential | high-assurance |
|---|---|---|---|
| A. active key, not listed | OK | OK | OK |
| B. retired R, timestamp before R, default (no list history) | FRESH | FRESH | FRESH |
| C. same, OPTIONAL owner-approved list history | OK | OK | FRESH |
| D. retired R, timestamp after R (a new signature) | SIGNED_AFTER_RETIREMENT | same | same |
| E. retired R, claimed issued_at before R, no timestamp | KEY_RETIRED_NO_CHRONOLOGY | same | same |
| F. same as E, development signer-asserted mode | OK (note CHRONOLOGY_UNAUTHENTICATED) | not selectable | not selectable |
| G. retired R, backdated issued_at, timestamp after R, signer-asserted | OK (!) development only: that mode ignores timestamps | not selectable | not selectable |
| H. compromised C, timestamp before C, OPTIONAL history | OK | OK | FRESH |
| I. same, default | FRESH | FRESH | FRESH |
| J. compromised C, attacker backdates issued_at, no timestamp | KEY_COMPROMISED_NO_CHRONOLOGY | same | same |
| K. compromised C, timestamp after C | SIGNED_AFTER_COMPROMISE | same | same |
| L. compromised, unknown boundary | KEY_COMPROMISED_NO_CHRONOLOGY | same | same |
| M. compromised, signer-asserted mode | KEY_COMPROMISED_NO_CHRONOLOGY | not selectable | not selectable |
| N. replaced A by B, report signed by enrolled B | OK | OK | OK |
| O. replaced A by B, B not enrolled | ISSUER_UNKNOWN | same | same |
| P. list missing or unverifiable, key locally active | store unchanged; accepted by the engine, but the outcome says `revocation_evidence: unproven` | same | same |

Row G is an existing development-mode weakness documented here, not introduced by this proposal. Row P: absence of a
list never means "nothing revoked"; callers must surface `revocation_evidence`.

## 10. Distribution is independent of trust

Lists, transitions and recovery statements are public. Any channel may carry them (file drop, HTTPS pull, queue,
mirror); none is trusted for authenticity. Acceptance rests only on enrolled keys, signatures, epochs, generations and
the validity interval. A failed or absent fetch is "no new evidence", never "nothing revoked". Owners should re-issue
(heartbeat, a new epoch with unchanged entries) so that `valid_until` and the 24 h history freshness never lapse.

## 11. Threat model

| Threat | Handled by | Residual |
|---|---|---|
| Forged list / wrong issuer / cross-issuer revocation | enrolled key, signature, issuer match, issuer scope | none beyond key theft |
| Report key used as authority | purpose checks, role domains | none for statements |
| Replay of older authentic list | mark, validity, epoch chain | undetected if mark deleted/lowered (7) |
| Fork / equivocation | same-epoch digest, `prev_list_digest`, recovery fork | seen only by verifiers holding both |
| Omitted (previously revoked) key | monotone merge | first-use verifier cannot know |
| Authority key theft | monotone (tighten only), recovery path | DoS until recovered; thief can hand over before detection (8.1) |
| Authority AND anchor theft | none | total; custody decision |
| Epoch inflation by a thief | rebase to archived list | needs archive; else new authority must exceed |
| Stale list | validity interval, history freshness | owner heartbeat |
| Local writer on verifier host | none | out of scope |
| Wrong status chosen by owner | process | undetectable |
| Clock error on verifier | skew-bounded checks | wrong clock misjudges expiry |

## 12. Compatibility (existing behaviour preserved)

No schema is registered, no source file under `src/regaudit_fhe` mentions the format (guard test), lenient APIs and
every verdict are unchanged. The published 0.2.0 wheel and this branch were compared on 1368 records (signers
0.1.0/0.1.1/0.2.0 x report.v1/v2 x six primitives x 12 stores incl. command-edited ones): byte-identical, see the
delivery report for the digest.

## 13. Test corpus (tests only, `tests/experimental_revocation/`)

`test_revocation_prototype.py` (lists: golden, tamper of every leaf, versions, issuer/authority, purpose
separation, validity, epochs, monotone rules, successors, apply, state, schema agreement),
`test_authority_lifecycle.py` (enrollment, routine rotation, chains with gaps/cycles/replay, recovery distinct from
rotation, old authority signing after declaration, anchor absent, epoch poisoning and rebase, boundary merging, every
leaf of transition/recovery tampered, omitted keys, duplicates, conflicting epochs, malformed signatures),
`test_worked_examples.py` (15 scenarios x 3 profiles through the real engine), `test_corpus.py` + `corpus/`
(41 byte-exact adversarial cases with expected outcome, pinned to the generator), `test_frozen.py` (pins and schema
agreement), `test_not_shipped.py` (guards). Prototype mutation results are in the delivery report.

## 14. Trust-ownership table

| Credential / state | Holder | Lives | Attacker who obtains it can |
|---|---|---|---|
| Report signing key | issuer operations | issuer's key store | sign reports as that key until retired/revoked; cannot revoke anything |
| Revocation authority private key | issuer OWNER | offline/HSM (owner decision) | publish stricter-only lists (DoS), hand the authority to their key before detection; cannot loosen; cannot recover once anchor acts |
| Recovery anchor private key | issuer OWNER, separate custody | offline, rarely used | replace the authority entirely (total control of revocation); cannot sign reports or lists |
| Pinned authority + anchor public keys | each verifier operator | verifier-persisted enrollment | change who is trusted (re-pin), i.e. defeat revocation for that verifier |
| High-water mark and list archive | each verifier | verifier-persisted store, ideally independent with compare-and-set | roll back to an older authentic list undetected; drop knowledge of compromise |
| Local trust store | each verifier | file | un-revoke, enrol own keys (as today) |
| Distribution channel | operator/mirror | any | withhold or delay lists (verifier stays "unproven"), replay old ones (caught only with an intact mark) |

## 15. MISSING for deployment (none of this exists)

1. Revocation-authority key custody and ceremony (who, where, backup, access, signing procedure).
2. A pinned-authority store: protected persistence of enrollments, with a defined enrollment/re-enrollment ceremony.
3. An independent high-water-mark store with compare-and-set semantics (and ideally an external witness); the prototype
   JSON file is bypassable by whoever can write it.
4. The recovery anchor: generation, offline custody, out-of-band enrollment on every verifier, and recovery runbook.
5. A distribution and heartbeat operator (who publishes at least daily, monitoring, alerting).
6. A production module (the prototype lives under `tests/` only), CLI/server wiring, and operator tooling for lists.
7. Schema publication: files in `src/regaudit_fhe/schemas/`, registration in `schemas.py`, final `$id`.
8. Owner approval for any list-derived `TrustHistory` option (lower profiles only) and a verdict-preservation proof for it.
9. Multi-signature/quorum (future work, v2); revocation of the authority-succession tooling beyond this draft.
