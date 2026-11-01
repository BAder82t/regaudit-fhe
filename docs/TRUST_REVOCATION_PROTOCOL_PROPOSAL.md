# 0.3.0 trust protocol: frozen proposal v2

Status: **FROZEN PROPOSAL v2, for owner decision. Not implemented in the product and not part of the published
protocol.** No schema is registered, no public API or verification rule has changed, nothing under `src/` implements
or mentions it, and nothing here is wired to the CLI or the server. AI-assisted engineering work. It is not an audit,
gives no production assurance and has no regulator approval. It says nothing about whether an encrypted computation
ran. Companion documents: [test matrix](proposals/revocation-list.v1/TEST_MATRIX.md),
[implementation plan](proposals/revocation-list.v1/IMPLEMENTATION_PLAN.md).

"Frozen" means:

* The wire formats are the draft v1 formats, unchanged. The three schemas and the golden vectors in
  `docs/proposals/revocation-list.v1/` keep their SHA-256 pins and stay at `schema_version: 1`. "v2" is the version of
  this document, not of the formats.
* This document and the test matrix are pinned by SHA-256 in `tests/experimental_revocation/test_frozen.py`. The
  adversarial corpus is pinned byte for byte to its generator. A change needs a deliberate re-pin, and a change to a
  format needs `schema_version: 2`.
* It builds on `docs/TRUST_SPEC.md` 4.5 and 4.6. TRUST_SPEC stays in force. Section 17 lists where this proposal departs from it
  and what the owner would have to rule before this could ship.

Sections 7 to 13 are normative for an implementation. A local reference model of them lives in
`tests/experimental_revocation/`; it is not product code.

## 1. Owner decisions encoded

These are settled and are not reopened here. Section 16 lists what is still open.

| # | Decision | Section |
|---|---|---|
| 1 | Issuer-designated revocation authority, separate from report signing keys | 3 |
| 2 | Explicit local enrollment of that authority by the verifier | 6 |
| 3 | Authenticated routine rotation, plus a separate compromise-recovery path | 8 |
| 4 | Single signer | 3 |
| 5 | Authenticated distribution | 12 |
| 6 | Verifier-persisted high-water mark, held outside the list file | 9 |
| 7 | No high-assurance history derived from a list | 11 |
| 8 | Report signatures establish origin; separately signed revocation data establishes current authorization policy; verifiers independently retain trusted authority state | 2 |
| 9 | The first high-assurance profile fails closed when required revocation data is absent, stale, contradictory or rolled back | 10 |
| 10 | Historical verification needs explicit timestamp and policy rules; a timestamp claimed in a report does not prove when it was signed | 11 |

## 2. Architecture

A verifier answers three separate questions from three separate sources.

| Question | Source | What it can show |
|---|---|---|
| Origin: did the holder of this key sign these bytes? | Report signature, checked against the key in the verifier's trust store | The key signed the bytes. Not when, and not whether the key is still acceptable |
| Current authorization: does the issuer's policy, as last seen, still allow this key? | Revocation list signed by the enrolled authority, joined with local state | The authority's statement as of the list's `issued_at`. Not that the statement is complete, and not anything earlier |
| Whose statements count? | Authority state the verifier retains itself: enrollment, generation, high-water mark | What this verifier has established. Not what other verifiers hold |

**A valid report signature does not mean the issuer remains trusted.** A report can keep `integrity_valid: true` and be
refused, and that is the expected result for a report signed by a key listed as compromised. Report bytes are never
rewritten: a verdict is a statement about current policy, and a later verification of the same bytes can differ.

### Non-claims

* A list is the authority's attestation at `issued_at`. Nothing here proves that all revocations ever issued are
  present, or that the authority told the truth.
* Between the moment a key is stolen and the moment a list naming it reaches a verifier, reports signed with it are
  accepted. The protocol bounds how stale the verifier's view can be (section 10). It does not close that window.
* Two verifiers that do not share a state store can reach different verdicts on the same report at the same moment
  (section 9.5). Nothing claims global agreement.
* One signer per role. A transition or recovery statement carries two signatures, but the second is proof of
  possession and not a quorum. Multi-signature, threshold and two-person rules are future work (a format version bump);
  no document, output or test may imply otherwise.

## 3. Principals and keys

| Principal | Key | Purpose | Established by |
|---|---|---|---|
| Issuer report keys | Ed25519 | Sign reports | `trust add` with an out-of-band fingerprint (existing) |
| Revocation authority, designated by the issuer | Ed25519, distinct | Signs lists and routine transitions, nothing else | Operator enrollment, out of band |
| Recovery anchor | Ed25519, distinct, kept offline | Signs recovery statements, nothing else | Operator enrollment, out of band, same ceremony |
| Verifier authority state | Local stores | Pin, high-water mark, list archive, joined key actions | Created by the verifier |

Purpose separation is enforced in four places. Enrollment and re-baselining refuse an authority or anchor equal to a report key in
the store or to each other. A list, transition or recovery that would install a key that is a report key or the anchor is
refused (`REVOCATION_KEY_IS_REPORT_KEY`). A report key added later that equals the authority or the anchor stops lists or
recovery being accepted, with the same code. Signatures use role-specific domain prefixes (section 4.4).

## 4. Wire formats (unchanged from draft v1)

Schemas: `docs/proposals/revocation-list.v1/*.schema.json`. Golden vectors: `golden-vectors.json`. All three formats have
exact member sets (unknown or missing members refused), integers only, strict RFC 3339 times, fingerprints of 64
lowercase hex (SPKI SHA-256), `schema_version` 1 and `algorithm_version` 1, and canonical base64 64-byte Ed25519 signatures.
A document of this shape with another version is `REVOCATION_VERSION_UNSUPPORTED`. One with new members is `REVOCATION_MALFORMED`,
because shape is checked first. Neither has a fallback.

### 4.1 Revocation list `regaudit-fhe.revocation-list`

Members: `schema, schema_version, algorithm_version, issuer`, `authority{key_id, key_fingerprint, generation}`, `epoch`
(>= 1), `prev_list_digest` (null iff epoch 1), `issued_at`, `valid_from`, `valid_until`
(`issued_at <= valid_from < valid_until`), `entries`, `signature`.

Each entry is `{key_id, key_fingerprint, status, effective_from, successor?}`, strictly sorted by `key_id`. `status` is
`retired`, `replaced` (requires `successor{key_id, key_fingerprint}`) or `compromised`. Only `compromised` may have
`effective_from: null`, meaning an unknown boundary. `effective_from` may not exceed `issued_at` + 5 minutes. Lists are
cumulative: each states the complete current set.

### 4.2 Authority transition `regaudit-fhe.revocation-authority-transition`

`issuer, from_authority{key_id, key_fingerprint, generation}, to_authority{key_id, key_fingerprint, generation,
public_key_pem}, issued_at, valid_until, signatures{from, to}`. `from` is signed by the current authority and `to` by
the incoming key as proof of possession. `to.generation == from.generation + 1`.

### 4.3 Recovery statement `regaudit-fhe.revocation-authority-recovery`

`issuer, recovery_anchor{key_id, key_fingerprint}, recovery_epoch (>= 1), declares_compromised[{key_fingerprint,
compromised_from|null}]` (non-empty, sorted, unique)`, new_authority{key_id, key_fingerprint, generation, public_key_pem},
rebase (null | {epoch, list_digest}), issued_at, valid_until, signatures{anchor, new_authority}`. Signed by the recovery
anchor, never by the authority being replaced. The new authority co-signs as proof of possession.

### 4.4 Signing domains

`signing_input = DOMAIN || canonical_bytes(body without the signature member(s))`, using
`regaudit_fhe.canonical.canonical_bytes` unmodified. Parsing uses `loads_strict`.

| Use | Domain prefix |
|---|---|
| list signature | `regaudit-fhe/revocation-list/v1/sign\x00` |
| list digest (chain) | `regaudit-fhe/revocation-list/v1/digest\x00` (SHA-256) |
| transition, outgoing and incoming | `regaudit-fhe/revocation-authority-transition/v1/sign-from\x00`, `.../sign-to\x00` |
| transition digest | `regaudit-fhe/revocation-authority-transition/v1/digest\x00` |
| recovery, anchor and new authority | `regaudit-fhe/revocation-authority-recovery/v1/sign-anchor\x00`, `.../sign-new-authority\x00` |
| recovery digest | `regaudit-fhe/revocation-authority-recovery/v1/digest\x00` |

The prefixes are distinct from each other and from the report prefix, so a signature in one role never verifies in
another.

## 5. Key states

### 5.1 Retirement and compromise are distinct

| | Retired | Compromised |
|---|---|---|
| Cause | Planned rotation; no belief of exposure | Confirmed or suspected exposure |
| Declared by | Authority (`retired` or `replaced`), or local `trust retire` | Authority (`compromised`), or local `trust revoke` |
| Time carried | `retired_at` = R. Always known | `compromised_from` = C, the earliest possible exposure, or unknown |
| New signatures | Refused at or after R | Refused |
| Report with authenticated chronology strictly before the boundary | Refused unless authenticated, fresh history also exists (section 11) | Same |
| Report with `issued_at` only | Refused. In `development` with `signer-asserted`: accepted before R, labelled `CHRONOLOGY_UNAUTHENTICATED` | Always refused, because the attacker controls `issued_at` |
| Unknown boundary | Not expressible | Every signature refused, whatever any token says |
| Refusal codes | `KEY_RETIRED_NO_CHRONOLOGY`, `SIGNED_AFTER_RETIREMENT` | `KEY_COMPROMISED_NO_CHRONOLOGY`, `SIGNED_AFTER_COMPROMISE` |
| Legacy `revoked` | Never maps here | Maps to compromised with an unknown boundary |

`replaced` is a retirement plus signed successor evidence. It does not enroll the successor. A successor already
enrolled under a different key is refused (`REVOCATION_KEY_MISMATCH`), and a report by an unenrolled successor is
`ISSUER_UNKNOWN`.

Choosing `retired` for a key that is really compromised leaves its pre-R history reachable under the chronology rules.
No tool can detect that error.

### 5.2 The join

Every combination of local state and list state is a join on one order. It never loosens, and it is the same whether
applied in one step or in sequence:

```
active < retired(later R) < retired(earlier R) < compromised(later C) < compromised(earlier C) < compromised(unknown)
retired(R) joined with compromised(C) = compromised(min(R, C))
legacy revoked = compromised(unknown)
```

### 5.3 Monotone rule across lists

Between an accepted list and a later one: no entry removed; no key_id rebound to another fingerprint; retired and
replaced dates fixed; `retired` may gain a successor; retired or replaced may become compromised only at or before the
retirement, or with an unknown boundary; a compromise boundary may only move earlier; unknown never becomes known; a
successor never changes or disappears; `issued_at` never decreases. Any violation is `REVOCATION_NOT_MONOTONE`.

**Issuer rule.** A retired key found to be compromised later, at C after R, must be published as compromised at `min(R, C)`. The
unclamped form is refused and latches (section 10.3). Issuer tooling must clamp or refuse. The two forms mean the same
thing for a verifier, since nothing the key signed at or after R is acceptable anyway.

### 5.4 Authority key states

| State | Meaning | Lists and transitions it signs |
|---|---|---|
| current | Named by the verifier's authority state at this generation | Accepted, subject to all checks |
| superseded | Replaced by a routine transition or a recovery that did not declare it compromised | Refused, `REVOCATION_AUTHORITY_SUPERSEDED` |
| compromised (boundary or unknown) | Declared by a recovery statement, or installed by a voided transition (section 8.2) | Refused, `REVOCATION_AUTHORITY_COMPROMISED`. A held high-water mark taken from it at or after the boundary stops counting as evidence (section 10) |

## 6. Enrollment

Only an operator ceremony creates a pin. Nothing is learned from a list, a statement or a channel. An unenrolled issuer
gets `REVOCATION_NOT_ENROLLED`.

A **pin** contains: issuer; authority public key and its generation; recovery anchor public key (optional in the format; see
OD-4); the newest known `recovery_epoch` and recovery digest; `enrollment_id`; and a **baseline** `(epoch, digest)`. The baseline
states the newest list the ceremony knows of, or epoch 0 when the ceremony asserts that no list exists yet. Fingerprints are
confirmed out of band, as for `trust add`. All of this comes from the issuer, out of band. The generation and recovery epoch matter
at a re-baseline: if they reset, an old recovery statement could put an old authority back.

* The ceremony writes the first state record, so a later missing record is detectably lost rather than looking like first
  use.
* `required` mode (section 10) refuses to start without a baseline. It has no trust on first use. `advisory` mode may run
  without one; the verifier then has no mark until its first list and says so (`REVOCATION_NO_HIGH_WATER_MARK`).
* A first list below the baseline is `REVOCATION_ROLLBACK`. A first list at the baseline epoch with another digest, or at
  baseline + 1 not chaining to the baseline digest, is `REVOCATION_FORK`.
* A second enrollment over an existing record is refused. A record whose `enrollment_id` does not match the pin is
  `REVOCATION_STATE_UNAVAILABLE`.
* **Re-baselining** is its own ceremony, with a new `enrollment_id` and baseline. It runs the purpose checks. Against a readable
  record it refuses a pin behind the record's generation or recovery epoch, and refuses a key declared compromised: a key once
  declared compromised is never enrolled again. It carries over the joined key actions and the compromised and superseded sets,
  and records the digests of any latched contradiction as adjudicated. If the record is missing or unreadable, that knowledge is
  gone and the operator must say so explicitly (`accept_loss`). Clearing key actions is a further explicit choice, and is a local
  act and not an issuer statement.
* **The recovery anchor changes only by re-enrollment.** No format has a member for it, and a statement that adds one is
  `REVOCATION_MALFORMED`. This is the re-provisioning path TRUST_SPEC 4.5 requires for revoking an anchor.

## 7. List verification (ingest)

Pure against a snapshot of the state. A refusal writes nothing except where sections 8.2 and 10.3 say.

In order: strict parse and exact shape including one fingerprint per list (`MALFORMED`); version; enrolled issuer
(`NOT_ENROLLED`); issuer match (`WRONG_ISSUER`); authority compromised or superseded; pinned fingerprint and generation
(`AUTHORITY_MISMATCH`); authority is not a report key; signature; validity (`NOT_YET_VALID`, and `EXPIRED` with an
exclusive upper bound); entry semantics; epoch rules; store checks. All codes are prefixed `REVOCATION_`. Epoch rules come
before store checks, so a replayed old list is a rollback whatever has since changed in the local store.

**Store checks.** A key is identified by `(key_id, fingerprint)`. A local entry with the same fingerprint belonging to another
issuer is `REVOCATION_ISSUER_SCOPE`. A local entry of this issuer under the same `key_id` with another fingerprint is
`REVOCATION_KEY_MISMATCH`. A local entry of **another** issuer under the same `key_id` with another fingerprint is an unrelated
key, because key_ids are not namespaced. A local entry with the same fingerprint under a different `key_id` is the same key and
gets the listed state.

**Epoch rules.** Against the mark: lower epoch is `ROLLBACK`; same epoch and digest is a repeat with no state change; same
epoch with another digest is `FORK`; epoch + 1 must chain `prev_list_digest` or it is `FORK`; a larger jump is accepted
with the note `EPOCH_GAP` if monotone. Gaps are accepted because intermediate lists may have expired and cannot be
validated, and because the cumulative list plus the monotone rule catches omission. A verifier may refuse gaps as local
policy. The `issued_at` rule is in section 5.3.

**A condemned mark** (gate row 8) was taken from a stolen key. Against it, only the epoch floor applies: a lower epoch is still
`ROLLBACK`, and any other list from the current authority is accepted with the note `REVOCATION_MARK_CONDEMNED`, skipping the
chain, monotone and `issued_at` checks. What a thief told this verifier must not make an honest list look contradictory. Nothing
loosens, because the joined key actions keep every tightening.

**Limit.** A gap can hide a fork between the two epochs. Only key theft can produce one.

Transition: shape, version, enrolled, from-authority compromised, superseded or mismatched, generation (`TRANSITION_GAP`),
key reuse (`TRANSITION_CYCLE`), role conflict, both signatures, validity.

Recovery: shape, version, enrolled, anchor present (`RECOVERY_ANCHOR_ABSENT`), anchor fingerprint
(`RECOVERY_ANCHOR_MISMATCH`), both signatures, validity, `recovery_epoch` (`RECOVERY_REPLAY`, `FORK`), fresh new key,
generation increases, rebase rule (section 8.3).

## 8. Rotation and recovery

### 8.1 Routine rotation

The current authority and the incoming key both sign. Generation + 1, the old key is superseded forever, the epoch chain
continues across the rotation. Chains apply in order and the first refusal stops the chain: a missing hop is
`TRANSITION_GAP` or `AUTHORITY_MISMATCH`, key reuse or a loop is `TRANSITION_CYCLE`, a replay is
`AUTHORITY_SUPERSEDED`. A mark signed by the superseded key stays usable until it goes stale (section 10): rotation is not
a statement that anything is wrong.

**A verifier offline past a transition's `valid_until`** gets `EXPIRED` and cannot walk the chain. It then fails closed
when its mark goes stale, and the remedy is the re-baseline ceremony. Owners should therefore give transitions a long
validity (recommended at least one year) and keep them published.

### 8.2 Compromise recovery

Recovery does not depend on the compromised authority signing anything. It needs the recovery anchor: an independent key,
held offline, enrolled at the same ceremony. Without an enrolled anchor, recovery is `RECOVERY_ANCHOR_ABSENT` and the only
remedy is re-enrollment. The anchor is a total trust root for the authority: whoever holds it can replace the authority.

A transition signed by a key later declared compromised:

1. Before any recovery statement the verifier cannot know. A valid transition is accepted, and a thief can take the
   authority this way.
2. After a statement declares key K compromised (from C, or unknown), any list or transition K signs is refused,
   including one signed after the declaration.
3. A transition K signed is void if its `issued_at` **or this verifier's own acceptance time** is at or after C, because a thief
   writes `issued_at`. Every transition after the first void one is void too.
4. **Keys installed by void transitions are compromised, with an unknown boundary.** The statement cannot name them: nobody but
   the thief knows them.
5. The statement replaces whichever authority the verifier holds. Its new generation must exceed the generation **before the first
   void transition**, not the one the thief reached, because the anchor cannot know how far a thief took each verifier. The new
   generation is then set, even if lower.
6. Recovery never loosens. Tightening accepted from a thief persists in the joined key actions, so a thief's worst case
   there is denial of service, which only a re-baseline ceremony can clear.

**Declarations always land.** Once the anchor signature verifies, what a coherent statement declares is committed, even when the
authority change is refused for any reason: lost rebase baseline, expiry, an old `recovery_epoch`, a generation, a role conflict. A
refused recovery otherwise leaves a verifier trusting a key it has been told is stolen. Lists from that key are then refused and
gate row 8 fails closed until a statement completes or a ceremony runs. This is the one case where a refused document writes
state. A statement is coherent unless a boundary is after its `issued_at`, or it declares the anchor or its own new key. These
declarations can only tighten, and they do not expire.

A repeated statement is a **strict no-op** with the note `REVOCATION_REPEAT`. Statements are public and replayable, so a
repeat must not re-apply anything.

Statements must be cumulative in `declares_compromised`, because a verifier that misses one never learns what only that one said.
They should have long validity (recommended at least one year).

### 8.3 Rebase

`rebase = {epoch, list_digest}` undoes epoch inflation by a thief.

| Verifier's mark | Effect |
|---|---|
| None | Refused, `RECOVERY_BASELINE_UNKNOWN`: it holds no list to reason about. Declarations still land |
| Epoch lower than `rebase.epoch` | No-op, note `REVOCATION_REBASE_NOOP`. The verifier never passed the baseline and needs no lowering. The authority change still applies |
| Epoch equal or higher, list present in the archive at that epoch | The mark moves to the archived list |
| Epoch equal or higher, list absent | Refused, `RECOVERY_BASELINE_UNKNOWN`. Never guessed. Declarations still land. The remedy is the re-baseline ceremony |

This is the only operation that lowers a mark in normal running. Without a rebase, the new authority must exceed an
inflated mark. The new authority's next list should chain to the rebase digest.

### 8.4 Update order

A verifier applies, in order: recovery statements by `recovery_epoch`; transitions by generation, **first discarding any whose
`to` generation is at or below its current one**; then the list. The distribution point serves everything on every poll, so without
the discard a polling verifier would stop at its first replay. A list from a generation the verifier has not reached is
`AUTHORITY_MISMATCH`, which does not latch: it means a statement has not arrived yet.

## 9. Monotonic state

### 9.1 What is held and where

The high-water mark is held outside the list file, and the pin is held apart from the state record.

| Store | Contents | Written by |
|---|---|---|
| Pinned-authority store | The pin (section 6) | Ceremony only. The verifier process needs no write access |
| State store | One record per issuer: `seq`; `enrollment_id`; current authority, generation, superseded and compromised sets, recovery epoch and digest, accepted transitions with their acceptance time, voided transitions; the mark (`epoch, digest, issued_at, valid_until, accepted_at, authority fingerprint`, entries); the list archive; joined key actions; any contradiction; adjudicated digests; a clock floor; a local integrity digest | Ingest and ceremonies only. Report verification never writes it |

**The trust-store file is never written by this protocol.** Listed state is applied as an overlay for each verification. So a
commit never spans two files, a key enrolled after a list still gets its listed state, and hand-editing the local file back
to `active` cannot undo a listed action. A writer who also changes the entry's `issuer` can step around the overlay, which is
applied per issuer so that one issuer can never revoke another's key. That writer is the residual in section 14.

The integrity digest detects torn or accidentally corrupted records. It is not authentication: anyone who can write
the record can recompute it.

**Size.** A record has a read limit, and every write is checked against it before compare-and-set, because a record that outgrows
its limit would brick the verifier. The archive exists for rebase, is pruned oldest first to stay inside the limit, and an
implementation should store it outside the record, by digest. The recommended retention is 400 days. A pruned baseline gives
`RECOVERY_BASELINE_UNKNOWN`, and because declarations always land, that fails closed. The mark and key actions are never pruned. If
they alone do not fit, the document is refused with `REVOCATION_STATE_FULL` and the record stays usable. The limit must fit the
largest legal list (10,000 entries); the model uses 32 MiB.

### 9.2 Store contract

A state store declares `durable`, `compare_and_set`, `independent` and `scope`.

```
read(issuer) -> record bytes or none; raises when unavailable
compare_and_set(issuer, expected bytes or none, new bytes) -> bool; atomic; raises when unavailable
```

`scope` is `LOCAL_FILE` for one file on the verifier host, or `INDEPENDENT_CAS` for a store the verifier host cannot rewrite
with its own credentials. It is disclosed in every result. `required` mode needs `durable` and `compare_and_set`. Whether
it also needs `independent` is OD-3.

### 9.3 Commit protocol

1. Read the record (snapshot). Check the clock floor.
2. Verify the document purely against the snapshot.
3. Build the next record: `seq + 1`, new mark, joined key actions, raised clock floor.
4. `compare_and_set(snapshot, next)`. For a file: lock, re-read and compare, write a temp file, `fsync`, rename, `fsync` the
   directory.
5. Only after step 4 returns true is the document accepted.
6. If step 4 returned false, go back to step 1 and re-verify from scratch. After a bounded number of attempts refuse with
   `REVOCATION_STATE_CONFLICT`. Never overwrite blindly.

### 9.4 Failure and recovery

| Event | Detection | Result | Recovery |
|---|---|---|---|
| Crash before the rename or CAS | None needed | Old record intact; a temp file may remain and is ignored | Re-deliver the document. Converges |
| Crash after the rename, before the directory `fsync` | None needed | The whole old or the whole new record survives | Re-deliver. A repeat or an advance, both safe |
| Torn or corrupted record | Integrity digest or parse failure | `REVOCATION_STATE_UNAVAILABLE`. Never read as empty. No fallback to a backup | Re-baseline ceremony |
| Store unreachable | The read raises | `required`: refuse. `advisory`: note, engine on the local store | Restore access. Nothing to repair |
| State lost, pin survives | Pin present, record absent | `REVOCATION_STATE_LOST` for both ingest and verification | Re-baseline ceremony with a baseline obtained out of band |
| State and pin both lost | Indistinguishable from a new verifier | `REVOCATION_NOT_ENROLLED`. Fails closed | Enrollment ceremony |
| State restored from a backup, process running | This process remembers `(seq, epoch, generation, recovery_epoch)` per enrollment. Any decrease, other than epoch or generation under a higher `recovery_epoch`, is a rollback. `seq` alone is not enough: replaying authentic old lists walks it back up | `REVOCATION_STATE_ROLLBACK` | Re-baseline ceremony |
| Record would exceed its limit | Size check before the write | Archive pruned; failing that `REVOCATION_STATE_FULL`, record unchanged and usable | Move the archive out of the record |
| State restored from a backup, fresh process, `LOCAL_FILE` | **Not detected** | See 9.6 | Operator procedure: treat any restore as a re-baseline. Do not start from a restored file without a fresh baseline |
| State restored in an independent store | Only if the store itself reports it, or by a process's remembered `seq` | As above | The store operator's restore procedure must re-baseline |
| Clock behind the state's floor by more than the skew | Clock floor | `REVOCATION_CLOCK_REGRESSION`, no ingest and no acceptance | Fix the clock |
| Clock moved forward | Lists look expired | Fails closed as stale | Fix the clock. The floor has risen, so a large forward error needs a re-baseline |

### 9.5 Concurrent verifiers

| Arrangement | Guarantee |
|---|---|
| Several processes, one store | Compare-and-set serialises writers. A loser re-verifies, so a slow writer holding an older list gets `ROLLBACK` and cannot lower the mark. A cached read must not outlive the staleness rule |
| Several verifiers sharing one store | One mark. A list accepted by one is seen by all on their next read |
| Independent verifiers, no shared store | Marks may differ legitimately. Each detects only what it holds. A fork is seen only by a verifier that holds both sides. Same limit as `replay_scope` in TRUST_SPEC 6.1 |

### 9.6 Precise assumption and its bound

A verifier with no independently preserved high-water mark cannot reliably detect a rollback of both the revocation data and
its local state. A `LOCAL_FILE` store is therefore **not sufficient** against an attacker who can write that file. This
limit is carried in every result.

What does hold is a bound, under three stated assumptions: the verifier's clock is honest; the attacker holds **no current or former
authority key**; and the record was restored or withheld, not edited. Then, after an undetected restore plus a replay of an older
authentic list, the verifier accepts the older view only until that list goes stale under section 10.2. With the default, the forgotten
window is at most 24 hours past the replayed list's `issued_at`. As soon as a newer list arrives, monotone state recovers. The same
bound applies to an attacker who only withholds new lists. A test asserts this (`test_S05_...`).

**Outside the bound, stated plainly:**

* Someone holding the current authority key can sign fresh heartbeats that omit new revocations, indefinitely, until recovery lands.
* A restore can make a previously replaced stolen key current again. If the recovery statement is also withheld, that key can then sign
  fresh lists (`test_S19_...`). This is the reason recovery statements need long validity and wide publication.
* Someone who can edit a `LOCAL_FILE` record can recompute its digest and write any state. No bound applies. That is what OD-3 is
  for, and the same writer can usually change the trust store as well.

## 10. Verification-time gate

### 10.1 Opt-in modes

| Mode | Effect | Allowed under |
|---|---|---|
| `off`, the default | The unchanged engine. No state is read. No output changes | All profiles |
| `advisory` | Overlay applied, so verdicts can only tighten. Gate failures are non-blocking notes and the result says `revocation_evidence: unproven` | `development`, `confidential` |
| `required` | Overlay applied. Any gate failure blocks. The first high-assurance profile is `high-assurance` with this mode | All profiles |

A verifier that does not opt in sees no change in any verdict, including under `high-assurance`. `high-assurance` without
`required` makes no revocation claim. With a mode set, `policy_id` becomes
`regaudit-fhe/<profile>+revocation-<mode>/v1`, so results from the two cannot be confused.

Refused at startup, exit 2 (TRUST_SPEC 9.3.5): `high-assurance` with `advisory`; any mode other than `off` with a store not in the
`entries` form (`REVOCATION_STORE_UNSUPPORTED`; see section 13.3); any mode with `signer-asserted`, which would let a report's
own clock rescue a listed key; `required` without a baseline, or on a store without `durable` and `compare_and_set`.

### 10.2 The gate

The gate reads state only. The issuer is taken **from the verifier's trust-store entry for the key**, never from the
report, so a report cannot select an issuer whose data happens to be fresh. In order:

| # | Condition | Code | Owner's term | CLI, HTTP |
|---|---|---|---|---|
| 1 | No pin for the issuer | `REVOCATION_NOT_ENROLLED` | absent | 3, 503 |
| 2 | Record missing | `REVOCATION_STATE_LOST` | absent | 3, 503 |
| 3 | Record unreachable, unreadable or from another enrollment | `REVOCATION_STATE_UNAVAILABLE` | absent | 3, 503 |
| 4 | Record `seq` below what this process saw | `REVOCATION_STATE_ROLLBACK` | rolled back | 3, 503 |
| 5 | A contradiction is latched | `REVOCATION_CONTRADICTORY` | contradictory | 1, 200 |
| 6 | Clock behind the floor | `REVOCATION_CLOCK_REGRESSION` | freshness cannot be judged | 3, 503 |
| 7 | No list ever accepted | `REVOCATION_DATA_ABSENT` | absent | 1, 200 |
| 8 | Mark **condemned**: signed by an authority declared compromised, with an unknown boundary, or with `issued_at` or this verifier's `accepted_at` at or after the boundary | `REVOCATION_AUTHORITY_COMPROMISED` | contradictory | 1, 200 |
| 9 | `now >= valid_until`, or `now - issued_at` exceeds the evidence age (default 24 h, same as `trust_history_max_age`) | `REVOCATION_DATA_STALE` | stale | 1, 200 |

Exit codes follow TRUST_SPEC 9.3.5: an unusable required resource is 3, a well-formed report refused by policy is 1. If the engine
also refuses the report, an infrastructure code still gives 3, as `REPLAY_STATE_UNAVAILABLE` does today. `trust_status` is
`INVALID` and `accepted` is false for every blocking code.

The evidence age is a setting of its own, not linked to `trust_history_max_age`. It has no ceiling, since the owner may trade it against
heartbeat frequency, but the bound in section 9.6 scales with it and every result discloses its value.

A key the trust store does not know skips the gate, and the engine refuses it (`ISSUER_UNKNOWN`).

**Rollback, precisely.**

* A list older than the mark, offered in the background, is refused and never applied. It does not latch, because replay
  needs no key and a latch would let anyone deny service. The state is ahead of the attacker, so verification continues on
  the mark, until it goes stale.
* Evidence presented with one verification call is compared against the record and never written, so TRUST_SPEC 4.6 rule 1 holds: it
  can refuse that call and nothing else. An older list gives `REVOCATION_ROLLBACK`, and any other refusal gives its own code. A newer
  valid list is not applied, and the call proceeds on the record.
* A state rollback that is detected is row 4. One that is not detected is the limit in section 9.6.

### 10.3 Contradiction latch

A list refused with `REVOCATION_FORK` or `REVOCATION_NOT_MONOTONE` carries a valid signature by the current authority, and its
conflict is with signed history, so nobody without that key can create one. On one of these, ingest writes the contradiction into the
record. While it is latched, lists and transitions are refused with `REVOCATION_CONTRADICTORY`, and `required` mode refuses every
report of that issuer. Only an accepted recovery statement or a re-baseline ceremony clears it.

Not latching, on purpose, so that public replay cannot deny service:

* `REVOCATION_KEY_MISMATCH` and `REVOCATION_ISSUER_SCOPE`. They depend on the local store, which changes, and an issuer chooses its own
  key_ids. The list is refused, and staleness then fails closed if the conflict persists.
* Recovery forks. A second anchor-signed statement at the same epoch is refused and nothing more.
* A list whose digest a ceremony has already adjudicated. Once both sides of a fork exist, anyone can replay the loser until it expires;
  after the ceremony that is an ordinary refusal.

A signed conflict that has been latched and adjudicated cannot be turned back into a latch by replay. Authorities must persist their own
epoch before publishing, so that a crash cannot produce an accidental fork.

### 10.4 Order with the engine

1. Gate. 2. Build the overlay. 3. Run the unchanged `verify()` on the overlay. 4. Add any gate code.

When the gate refuses, the engine runs with replay in `check` rather than `record`. A gate refusal must not burn the
report's `audit_run_id` (TRUST_SPEC 6.1, no poisoning). Report verification writes no revocation state, with or without presented
evidence.

### 10.5 Disclosure

Every result under a mode, including one for an unknown key, carries the gate outcome, `revocation_evidence`
(`verified-as-of-<issued_at>` or `unproven`), `state_store_scope`, the evidence age and the limit text from section 9.6. When the gate
passed it also carries the epoch, digest, `valid_until` and `state_seq`. "Verified as of" is the strongest wording allowed. No output may state that a key "is not revoked".

## 11. Revocation history and historical verification

**A cumulative current list is not an authenticated history.** It attests the current set at `issued_at` and says nothing
verifiable about earlier states or completeness. The verifier's archive, joined key actions and voided transitions are a
local record of what this verifier saw. They are useful for operators and for rebase. They are not evidence for anybody else,
and they are never a `TrustHistory`.

### 11.1 Time evidence

| Source | Status |
|---|---|
| `issued_at` in a report | A claim written by the signer. Never chronology outside `development` with `signer-asserted`, and never for a compromised key |
| `timestamp` on `report.v1` | Covers the body, not the signature (TRUST_SPEC F2). Never chronology |
| An entry in `timestamps` on `report.v2`, no pinned verifier configured | `UNVERIFIED`. Not chronology. Anyone can attach one, and its `issued_at` member is also a claim |
| An entry in `timestamps` verified by the caller's pinned verifier over the sealed digest | Chronology. `latest_signing_time = genTime + accuracy`, an upper bound on signing time only |
| `effective_from` in a list | The authority's statement. Trusted only as far as the authority is. It can tighten; it proves nothing about signing time |

The boundary comparison is strict: equal is refused. The library bundles no timestamp authority.

### 11.2 Policy rules

1. A report by an active key needs no chronology. An acceptance says the key is currently allowed as of the list, and says
   nothing about when the report was signed.
2. A report by a retired or compromised key is acceptable only with chronology strictly before the boundary **and** an
   authenticated, fresh `TrustHistory`. Unknown compromise boundary: never.
3. `required` under `high-assurance`: never, on any list evidence. The engine's `history_ok()` stays false in that profile,
   whatever a caller supplies. Without separately authenticated evidence the profile keeps refusing.
4. Lower profiles: a list yields no `TrustHistory` by default. Any option is OD-7.
5. `max_age` compares against `issued_at`. It limits replay by someone without the key and is not chronology.

### 11.3 Worked examples

Every row runs the real engine. `FRESH` = `TRUST_STORE_FRESHNESS_UNPROVEN`. Rows with "option" assume OD-7 was approved, which
it has not been.

| Scenario | development | confidential | high-assurance |
|---|---|---|---|
| A. active key, not listed | accepted | accepted | accepted |
| B. retired R, timestamp before R, no history | FRESH | FRESH | FRESH |
| C. same, option | accepted | accepted | FRESH |
| D. retired R, timestamp after R | `SIGNED_AFTER_RETIREMENT` | same | same |
| E. retired R, claimed `issued_at` before R, no timestamp | `KEY_RETIRED_NO_CHRONOLOGY` | same | same |
| F. same as E, `signer-asserted`, `off` only | accepted, `CHRONOLOGY_UNAUTHENTICATED` | not selectable | not selectable |
| G. retired R, backdated `issued_at`, timestamp after R, `signer-asserted`, `off` only | accepted: that mode ignores timestamps, an existing `development` weakness | not selectable | not selectable |
| H. compromised C, timestamp before C, option | accepted | accepted | FRESH |
| I. same, no history | FRESH | FRESH | FRESH |
| J. compromised C, attacker backdates `issued_at`, no timestamp | `KEY_COMPROMISED_NO_CHRONOLOGY` | same | same |
| K. compromised C, timestamp after C | `SIGNED_AFTER_COMPROMISE` | same | same |
| L. compromised, unknown boundary | `KEY_COMPROMISED_NO_CHRONOLOGY` | same | same |
| M. compromised, `signer-asserted` | `KEY_COMPROMISED_NO_CHRONOLOGY` | not selectable | not selectable |
| N. A replaced by B, report by enrolled B | accepted | accepted | accepted |
| O. A replaced by B, B not enrolled | `ISSUER_UNKNOWN` | same | same |
| P. no usable list, key locally active, `off` or `advisory` | accepted, `revocation_evidence: unproven` under `advisory` | same | `off` only |
| Q. no usable list, key locally active, `required` | gate code | gate code | gate code |

## 12. Distribution

**Authenticated distribution means every object a verifier acts on is authenticated by a signature under a key it already
holds.** Lists, transitions and recovery statements are public, and acceptance rests only on enrolled keys, signatures,
epochs, generations and validity. A channel never establishes trust: a bare download cannot enroll anything (TRUST_SPEC 4.5).
Operators should still use an authenticated transport, because it narrows who can interfere, but no verifier rule depends on
it. A signature cannot stop a channel from withholding data, which is why staleness fails closed.

The distribution point holds: the latest list; every transition since the first enrollment; the latest recovery statement.
A failed or absent fetch is "no new evidence", never "nothing revoked". The authority re-issues on a schedule (a new epoch
with unchanged entries) more often than the evidence age. A signed heartbeat missed for longer than the evidence age takes
`required` verifiers to fail closed, so the heartbeat is an availability dependency, and OD-5 has to own it.

## 13. Compatibility and migration

### 13.1 Nothing changes without an opt-in

No format, schema, canonicalisation, signing input or verification rule changes. `off` is the default and calls the unchanged
engine. A test asserts `off` output equals direct engine output.

Run for this proposal: 378 verdict records (signers 0.1.0, 0.1.1, 0.2.0 and 0.2.1; `report.v1`, `report.v2` with and without
audience; seven stores; three profiles; `verify_trusted`; CLI `verify` for two signers) were byte-identical between the 0.2.0
wheel, the source of tag `v0.2.1` and this branch. No signer version changed any verdict.

### 13.2 Reports from published versions

The published versions differ only in the version strings they write (`algorithm_version`, `parameter_set.library_version`)
and therefore in `parameter_set_hash`. No verification rule reads a version string, so the signer version does not change a
verdict (tested), **except through a `parameter_set_pin`**: a pin binds the hash, so a report from another signer version is
`PIN_MISMATCH`. That is existing behaviour, unchanged here, and migration carries pins over as they are (tested).

The table is the same for reports from 0.1.0, 0.1.1, 0.2.0 and 0.2.1. A report signed by a key in the verifier's store, with no
pin, under `off`, on an `entries` store:

| Report | development | confidential | high-assurance |
|---|---|---|---|
| `report.v1` | `TRUSTED`, note `LEGACY_V1_FORMAT` | `INVALID`, `REPLAY_ID_MISSING` | `INVALID`, `LEGACY_V1_FORMAT`, `AUDIENCE_MISMATCH` |
| `report.v2`, no audience | `TRUSTED` | `TRUSTED` | `INVALID`, `AUDIENCE_MISMATCH` |
| `report.v2`, audience names the verifier | `TRUSTED` | `TRUSTED` | `TRUSTED` |
| Ephemeral key (CLI `audit` without `--signing-key`, `/v1/audit`) | `ISSUER_UNKNOWN` with a store | same | same |

How the reports are reached: 0.1.0 and 0.1.1 emit `report.v2` from the library API only. 0.2.0 and 0.2.1 also emit it from CLI
`audit --signing-key`. Since 0.2.0 the trust-bearing paths parse strictly, which is an existing change recorded in
`docs/MIGRATION_0.2.md`.

Under each mode, for the same reports:

| Situation | `off` | `advisory` (not under high-assurance) | `required` |
|---|---|---|---|
| Key not listed, fresh list | table above | table above | table above, `policy_id` changed, evidence disclosed |
| Key listed retired, no verified timestamp | table above | adds `KEY_RETIRED_NO_CHRONOLOGY`, `TRUST_STORE_FRESHNESS_UNPROVEN` | same as `advisory` |
| Key listed compromised, unknown boundary | table above | adds `KEY_COMPROMISED_NO_CHRONOLOGY` | same as `advisory` |
| No list accepted, or stale, contradictory, or state unusable | table above | table above, plus a non-blocking gate note | **every report refused** with the gate code, `integrity_valid` unchanged |
| `report.v1`, key retired or compromised in the local file | refused | refused | refused. Its timestamp never counts |

The replay check runs last and only if nothing else blocked, so `REPLAY_ID_MISSING` does not appear beside another refusal.
Under `required`, opting in can turn `TRUSTED` into `INVALID` for every published report until data is flowing. That is what
fail closed means, and it is why the mode is an explicit opt-in.

### 13.3 Trust-store forms

| Form | Shape | Today | Under a mode other than `off` |
|---|---|---|---|
| Bare mapping | `{key_id: PEM}` | Verifies. No issuer, no lifecycle. `trust retire`/`revoke` refuse it | `REVOCATION_STORE_UNSUPPORTED` at startup |
| Legacy keys | `{keys, revoked, parameter_set_pins}` | Verifies. `revoked` is `KEY_REVOKED`. `trust retire`/`revoke` refuse it | `REVOCATION_STORE_UNSUPPORTED` at startup |
| Entries | `{entries, as_of?}` | Verifies. Full lifecycle | Supported. Local state is one input to the join |

Stores are never converted implicitly. Without a migration, a store keeps its exact behaviour under `off`.

### 13.4 Migration specification

A new operator command (see the plan), `trust migrate --from OLD --to NEW --issuer KEY_ID=ISSUER ...`:

1. Writes a new file and leaves the old one untouched. Refuses if `NEW` exists. Atomic, with the source's permission bits.
2. The issuer of every key is an operator statement. There is no default and nothing is inferred, least of all from reports.
   A key without a statement, or a statement for an unknown key, refuses the whole migration. An `entries` source is refused.
3. Key material and `key_id` are preserved; the tool checks fingerprints before and after. `parameter_set_pins` become
   `parameter_set_pin`.
4. An active key stays `active`.
5. **A legacy `revoked` key becomes `compromised` with an unknown boundary, never `retired`.** The legacy form does not say why
   it was revoked, and only the strictest reading is safe. There is no flag to choose otherwise, because that would be a
   loosening, and TRUST_SPEC 4.2 does not allow an edit that removes a compromise.
6. Prints a row per key: fingerprint, before and after, issuer, reason-code change.
7. A dry-run mode runs a report corpus the operator supplies under both stores and prints every difference.

Effect on verdicts, tested on the published vectors under all three profiles:

| Change | Accept or refuse | Reason |
|---|---|---|
| Active, correct issuer | Unchanged | Unchanged |
| Legacy revoked | Unchanged: refused | `KEY_REVOKED` becomes `KEY_COMPROMISED_NO_CHRONOLOGY`; `key_status` becomes `compromised` |
| Active, **wrong issuer stated** | **Newly refused** | `ISSUER_MISMATCH`. This is why the migration is an explicit act with a dry run |

**Migrating existing `entries` stores to the new state** needs no conversion. Local `retired_at` and `compromised_from` stay in
the file. The state store starts empty of key actions at enrollment, and the join applies at each verification. A local state
stricter than the list stays in force, and a list state stricter than the local file wins, without writing the file. The
lifecycle commands keep working on the file and keep their LOCAL VERIFIER POLICY CHANGE label. `trust add` should additionally
refuse a key equal to an enrolled authority or anchor (recorded in the plan; list acceptance already refuses that case).

**Downgrade.** A verifier that goes back to 0.2.x ignores the state store and keeps its `entries` file unchanged, because
the file was never written. It loses all listed state, so keys it knew only from lists become acceptable again. That is
what `off` means, and operators need to be told.

## 14. Threat model

| Threat | Handled by | Residual |
|---|---|---|
| Forged list, wrong issuer, cross-issuer revocation | Enrolled key, signature, issuer match, issuer scope by key_id and fingerprint | None beyond key theft |
| Report key used as authority | Purpose checks, role domains | None for statements |
| Replay of an older authentic list | Mark, validity, chain | Undetected if the mark is deleted or lowered; bounded by staleness (9.6) |
| Replay of a recovery statement to lower the mark | Repeat is a strict no-op | None |
| Public replay to cause a latch | Epoch rules before store checks; store conflicts do not latch; adjudicated digests | A thief's unadjudicated fork can latch: needs the key |
| Recovery blocked by a lost baseline or expiry | Declarations always land | Fails closed until a ceremony |
| Thief backdates a list or transition | Local acceptance time | The verifier's clock |
| Thief installs a key the owner never saw | Keys from void transitions are condemned | None once recovery lands |
| Record outgrows its limit | Size check, pruning, `STATE_FULL` | A pruned baseline needs a ceremony |
| Fork or equivocation | Same-epoch digest, `prev_list_digest`, recovery fork, latch | Seen only by verifiers holding both sides |
| Omission of a previously revoked key | Monotone rule, joined key actions | A verifier with no state before the omission cannot know. The baseline narrows this |
| Key relabelled locally | Fingerprint matching | None |
| Report chooses a fresh issuer | Issuer comes from the trust store | None |
| Authority key theft | Tighten only, recovery path | Until recovery lands: denial of service, handover to the thief's key (8.2), and **suppression** of new revocations through fresh heartbeats that omit them |
| Authority and anchor theft | None | Total. Custody decision |
| Epoch inflation by a thief | Rebase | Needs the archive; otherwise the new authority must exceed it |
| Stale or withheld data | Staleness rule | Bounded view, without an authority key (9.6). Denial of service for `required` verifiers |
| Lost, restored or racing state | Section 9 | Restore without detection (9.6) |
| Writer on the verifier host | Independent store narrows it | Can change the trust store, its issuers and the pin, and on `LOCAL_FILE` the record. Out of scope |
| Wrong status chosen by the owner | Process | Undetectable |
| Clock error on the verifier | Floor, skew, staleness | A wrong clock misjudges expiry. Backward errors beyond the floor are caught; forward errors fail closed |

## 15. Reason codes

New codes only: TRUST_SPEC 8.3 says existing codes must not change meaning. `TRUST_STORE_STALE`, `TRUST_STORE_ROLLBACK`,
`TRUST_STORE_FORK` and `TRUST_ANCHOR_MISSING` describe the anchor-signed bundle of TRUST_SPEC 4.5, which this is not, so they
stay reserved and unused.

| Layer | Codes |
|---|---|
| Document refused at ingest | `REVOCATION_MALFORMED`, `REVOCATION_VERSION_UNSUPPORTED`, `REVOCATION_NOT_ENROLLED`, `REVOCATION_WRONG_ISSUER`, `REVOCATION_AUTHORITY_COMPROMISED`, `REVOCATION_AUTHORITY_SUPERSEDED`, `REVOCATION_AUTHORITY_MISMATCH`, `REVOCATION_KEY_IS_REPORT_KEY`, `REVOCATION_SIGNATURE_INVALID`, `REVOCATION_NOT_YET_VALID`, `REVOCATION_EXPIRED`, `REVOCATION_ISSUER_SCOPE`, `REVOCATION_KEY_MISMATCH`, `REVOCATION_ROLLBACK`, `REVOCATION_FORK`, `REVOCATION_EPOCH_GAP`, `REVOCATION_NOT_MONOTONE`, `REVOCATION_TRANSITION_GAP`, `REVOCATION_TRANSITION_CYCLE`, `REVOCATION_RECOVERY_ANCHOR_ABSENT`, `REVOCATION_RECOVERY_ANCHOR_MISMATCH`, `REVOCATION_RECOVERY_REPLAY`, `REVOCATION_RECOVERY_BASELINE_UNKNOWN`, `REVOCATION_CONTRADICTORY`, `REVOCATION_CLOCK_REGRESSION`, `REVOCATION_STATE_LOST`, `REVOCATION_STATE_UNAVAILABLE`, `REVOCATION_STATE_CONFLICT`, `REVOCATION_STATE_FULL` |
| Note on an accepted document | `REVOCATION_REPEAT`, `REVOCATION_EPOCH_GAP`, `REVOCATION_NO_HIGH_WATER_MARK`, `REVOCATION_REBASE_NOOP`, `REVOCATION_MARK_CONDEMNED` |
| Gate, on a report | `REVOCATION_NOT_ENROLLED`, `REVOCATION_STATE_LOST`, `REVOCATION_STATE_UNAVAILABLE`, `REVOCATION_STATE_ROLLBACK`, `REVOCATION_CONTRADICTORY`, `REVOCATION_CLOCK_REGRESSION`, `REVOCATION_DATA_ABSENT`, `REVOCATION_AUTHORITY_COMPROMISED`, `REVOCATION_DATA_STALE`, and any document code for presented evidence |
| Configuration, at startup | `REVOCATION_STORE_UNSUPPORTED` |

## 16. Open owner decisions

Not decided here. Each has a recommendation. Until OD-1 to OD-5 and OD-8 are made, TRUST_SPEC 4.5 forbids implementing or advertising
this as `high-assurance`.

| # | Decision | Recommendation | What it blocks |
|---|---|---|---|
| OD-1 | Revocation key custody: who, where, backup, signing procedure | A non-exportable Ed25519 key in an HSM or KMS, usable only by a restricted list-publishing role. Daily heartbeats rule out a fully offline key unless the evidence age is lengthened. Confirm the chosen service supports Ed25519 | Any real list |
| OD-2 | Pinned-authority store | A read-only file provisioned by deployment tooling, owned by another account than the verifier, kept apart from the trust store and the state store. Fingerprints confirmed out of band as for `trust add` | Enrollment tooling |
| OD-3 | Independent high-water-mark store with compare-and-set | Yes, required for `required` under `high-assurance`: a store with conditional writes, administered under credentials the verifier host does not hold. `LOCAL_FILE` for `advisory` and lower-profile `required` only, always disclosed. If declined, `required` under `high-assurance` still runs and must disclose the 9.6 limit | The strongest claim in 9.6 |
| OD-4 | Recovery anchor | Mandatory under `required`. One offline key per issuer, in separate custody from the authority, enrolled at the same ceremony, with a written runbook. Split custody is not a quorum and must not be described as one | Compromise recovery. Without it, every compromise means re-enrolling every verifier |
| OD-5 | Distribution operator | The issuer runs a static endpoint plus at least one mirror, publishes every 12 hours against the 24-hour evidence age, and monitors staleness with alerts | `required` in any real deployment |
| OD-6 | Schema publication | Publish the three schemas at `schema_version: 1` with a final `$id`, registered in `schemas.py`, in the same release that ships `required`, and not before OD-1 to OD-4 are made. Published names are hard to withdraw | Plan phase 1 |
| OD-7 | Any history option | None for 0.3.0. If wanted later, prefer a witness or transparency log as a separate authenticated source over a list-derived `TrustHistory`. The prototype's flag for lower profiles stays test-only | Historical acceptance in any profile |
| OD-8 | The rest of TRUST_SPEC 4.5 and O8: how the proposal maps onto the 4.5 anchor, and the "independent approval authority" row, which OD-1 to OD-5 do not cover | Rule on the mapping in section 17. Designate an approver or record that none is required under the single-signer decision | Any `high-assurance` claim |

## 17. What TRUST_SPEC would need

Not edited in this milestone. These are departures or gaps the owner has to rule on (OD-8), not settled changes.

**The mapping.** TRUST_SPEC 4.5 has one anchor, which signs bundles and rotates through a statement it signs. This proposal has two keys.
The reading proposed here is: the 4.5 **anchor is the pin plus the recovery anchor** (provisioned out of band, kept outside distributed
data, replaced only by re-provisioning, as 4.5 requires), and the revocation authority is a delegate that signs lists, which are not
the 4.5 bundle. Under this reading the 4.5 rule that anchor rotation "MUST NOT be accepted from the bundle channel alone" holds. If the
owner instead reads the authority as the 4.5 anchor, then routine transitions served beside lists, and recovery not signed by the outgoing
key, both conflict with 4.5, and owner decisions 3 and 5 would have to supersede it.

| TRUST_SPEC | Here | Needed |
|---|---|---|
| 4.5 "Rotation quorum" pending | Single signer, owner decision 4 | Record it against O8 |
| 4.5 "Independent approval authority" pending | Not addressed | OD-8 |
| 4.5, 4.6 rule 2 durable monotonic head | Rebase lowers the mark, under an anchor-signed statement | Allow it explicitly |
| 4.2, 4.6 rule 3 no edit removes a compromise | The ceremony can clear joined key actions, explicitly and locally | Allow or forbid |
| 4.6 result fields | `trust_store_as_of` stays the local file's `as_of`; list evidence is in the disclosure | Say so |
| 8.3 | Section 15's codes | Add |
| 9.4 | Modes and the `policy_id` form | Add |
| C.1 | O8 items | Mark accordingly |

## 18. Changes from draft v1

**Kept unchanged:** all three wire formats, all signing domains, the golden vectors, the 41-case corpus and every expected outcome
in it.

**Corrected, because a run against the draft v1 prototype showed the flaw.** Each has a test that failed at `f3e2a55`:

| Flaw in draft v1 | Consequence | Now |
|---|---|---|
| A repeated recovery statement re-applied its rebase | Anyone could replay a public document, lower the mark, and have an older list that omitted a newer compromise accepted | Strict no-op |
| A rebase beyond the verifier's mark was refused | A clean verifier stayed on the compromised authority | No-op on the mark; authority change applies |
| Listed keys matched by `key_id` only | A compromised key stayed active under a local alias, and fingerprint matching was absent from issuer scope | Matched by fingerprint, scope checked both ways |
| `issued_at` could decrease across epochs | A later list could present itself as older | Part of the monotone rule |
| One fingerprint could appear twice in a list | Two statuses for one key | `MALFORMED` |
| A local compromise later than a listed retirement kept the later time | Loosened against the list | Join takes the earlier time |
| Whole-file save with no compare-and-set | Two writers could lower the mark (observed: from 3 to 2) | Compare-and-set with re-verification |
| A refused recovery changed nothing | Lost baseline, gap or expiry left the verifier trusting a declared-stolen key | Declarations always land |
| Generation compared with the thief's | One thief hop made the honest recovery refuse itself | Compared with the last honest generation |
| Keys from void transitions merely superseded | A mark signed by the thief's own key kept counting | Those keys are compromised |
| Boundaries compared with `issued_at` | A thief backdates | Acceptance time compared too |
| Store checks before epoch rules, and latching | A public replay after a local store change latched the issuer | Epoch first; store conflicts do not latch |
| A condemned mark was still chained against | An honest list after recovery latched | Epoch floor only |

**Added, because the milestone or owner decisions require it:**

* Fail closed at verification time. Draft v1 checked lists only at ingest, and its row P accepted with no data in every profile.
  Sections 10.1 to 10.5 are new, including the opt-in modes.
* The overlay. Draft v1 applied lists to the store, which spanned two files and missed later-enrolled keys.
* The enrollment baseline. Draft v1 had first use, and a missing state file silently read as empty.
* Marks from a compromised authority stop counting.
* Evidence age. Draft v1 accepted any validity period, including 70 years (observed).
* The contradiction latch, and the distinction between signed contradictions and replays that need no key.
* State-store contract, commit protocol, and failure tables for crash, lost, restored and concurrent state.
* Trust-store migration and the published-version verdict tables. The issuer is taken from the trust store.
* Time-evidence rules as a normative table. "Authenticated distribution" stated as the distribution rule.
* Custody wording: draft v1 said the authority key is "offline/HSM"; a daily heartbeat rules out offline.

The rows from "A refused recovery" down, and several rules in sections 6 to 10, came from an independent adversarial read of an
earlier state of this document, and each was reproduced with a failing test before it was fixed. That read was AI-assisted as well. It
found problems; it is not evidence that none remain.

## 19. Ownership

| Credential or state | Holder | Attacker who obtains it can |
|---|---|---|
| Report signing key | Issuer operations | Sign reports as that key until listed; cannot revoke anything |
| Revocation authority private key | Issuer owner | Publish stricter-only lists (denial of service), hand the authority to their own key before detection, suppress new revocations through fresh heartbeats; cannot loosen for a verifier holding state; cannot act on a verifier once recovery lands there, unless that verifier is later restored to before it (9.6) |
| Recovery anchor private key | Issuer owner, separate custody | Replace the authority entirely; cannot sign reports or lists |
| Pin | Each verifier operator | Change who is trusted, which defeats revocation for that verifier |
| State record | Each verifier | Roll back, drop compromise knowledge, or on `LOCAL_FILE` write any state (9.6) |
| Local trust store | Each verifier | Enrol their own keys (as today); cannot undo listed state by editing status, but can by relabelling the issuer (9.1) |
| Distribution channel | Operator or mirror | Withhold or delay, which `required` verifiers turn into refusal; replay, which an intact mark catches |
