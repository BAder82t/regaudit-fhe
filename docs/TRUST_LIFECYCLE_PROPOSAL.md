# Trust lifecycle: local `trust status | retire | revoke` (0.3.0 candidate)

Status: implemented as a compatible local-file subset; the signed/authenticated part is a proposal in
`docs/TRUST_REVOCATION_PROTOCOL_PROPOSAL.md`. AI-assisted engineering work. Not an audit, not a production or
regulatory assurance, and **not authoritative revocation**: these commands edit an unauthenticated local file.
This document adds no verification rule that `docs/TRUST_SPEC.md` section 4 does not already contain; none of
`trust.py`, `verification.py`, `trusted.py`, `canonical.py`, `schemas.py`, `_keys.py`, `replay.py` or any report
schema was changed.

**Wording rule.** `trust retire` and `trust revoke` are a **LOCAL VERIFIER POLICY CHANGE**: they edit this
verifier's own file and are not evidence that the issuer authorised a revocation. Their JSON output carries
`scope`, `issuer_authorized: false`, `notice` and `rollback_detection` (no independently preserved high-water
mark: rollback of the file and `.prev` is undetectable); the notice is repeated on stderr and in `--help`.
The owner-signed alternative is `docs/TRUST_REVOCATION_PROTOCOL_PROPOSAL.md`.

## 1. States and what they mean

| State (entry `status`) | Meaning | What a verifier accepts |
|---|---|---|
| `active` | enrolled, usable | any report that passes identity/integrity checks |
| `retired` (`retired_at` = R) | planned rotation; no belief of exposure | a report only if provably signed strictly before R (section 2) |
| `compromised` (`compromised_from` = C, or absent = unknown) | key believed exposed from C | only authenticated chronology strictly before C; unknown C refuses everything |
| legacy `revoked` (flat `revoked` list) | legacy form of "compromised, unknown boundary" | nothing (`KEY_REVOKED`); cannot be produced by the new commands |
| unknown key_id | not in the store | refused, `ISSUER_UNKNOWN`; a different key under a known key_id is `KEY_EMBEDDED_MISMATCH` |

`issued_at` is a signer-written field. It is chronology only in `development` with
`historical_acceptance="signer-asserted"` and only for a retired key (reported `SIGNER_ASSERTED`). A compromised
key controls its own clock, so signer-asserted time never rescues it.

## 2. State-transition matrix (command x state)  [agent-run: `tests/test_trust_lifecycle_qualification.py`]

All transitions are one-way, never re-date, never delete, and never touch `issuer`/`public_key_pem`/other keys.

| State | `retire --at T` | `revoke --compromised-from C` | `revoke` (no C) |
|---|---|---|---|
| active | -> retired, `retired_at=T` (default now). T not in future (>5 min), not before `not_before` | -> compromised, `compromised_from=C` | -> compromised, unknown boundary |
| retired (R) | REFUSED (no re-retire, no re-date, earlier or later) | -> compromised if `C <= R` (`retired_at` dropped; old value only in `.prev`); `C > R` REFUSED (would loosen) | -> compromised, unknown boundary (stricter, allowed) |
| compromised, C unknown | REFUSED | REFUSED (boundary never edited) | REFUSED |
| compromised, C known | REFUSED | REFUSED (no earlier or later edit) | REFUSED (no widening) |
| key_id absent | REFUSED | REFUSED | REFUSED |
| legacy-keys or bare-mapping store | REFUSED (exit 3; never converted) | REFUSED (exit 3) | REFUSED (exit 3) |

Every refusal leaves the store and `.prev` byte-identical. Also refused: boundary beyond now + 5 min,
unparseable/offset-less RFC 3339, naive clock, store `as_of` more than 5 min ahead of this machine's clock
(possible rollback or foreign store), non-regular store path (directory, FIFO), dangling/looping symlink,
store larger than 4 MiB (checked on `stat`, before reading), any store that does not validate with
`TrustStore.from_dict`, and any edit whose result would not validate (defence in depth).

`trust status` is read-only for all three store forms (`entries`, `legacy-keys`, `bare-mapping`); it prints
`store_form`, `store_mode`, `warnings` (group/world-writable), `as_of`, per-key status/boundaries/SPKI fingerprint
and `authenticated: false`. Exit 0 / 2 unknown key_id / 3 unusable store.

## 3. Verification outcome matrix  [agent-run: 150 parametrised cases, stores produced by the commands]

Rules derived from TRUST_SPEC 4.3/4.4 independently of `verification.py`. "TS" = verified RFC 3161-style
timestamp (injected test verifier; the library bundles none) whose `genTime + accuracy` is before/after the
boundary; "FH" = a `TrustHistory(authenticated=True)` fresher than 24 h (no code in this release produces one;
the test injects it as the existing seam). Report issue time = min(TS time, a fixed earlier date).

| Key state | Evidence | development / confidential | high-assurance |
|---|---|---|---|
| active | any | accepted | accepted |
| unknown key_id | any | refused `ISSUER_UNKNOWN` | same |
| retired, before R | none | refused `KEY_RETIRED_NO_CHRONOLOGY` | same |
| retired, before R | TS, no/stale/unauthenticated FH | refused `TRUST_STORE_FRESHNESS_UNPROVEN` | same |
| retired, before R | TS + fresh FH | accepted | refused `TRUST_STORE_FRESHNESS_UNPROVEN` (never ok) |
| retired, after R | TS (any FH) | refused `SIGNED_AFTER_RETIREMENT` | same |
| compromised C known, TS before C | TS + fresh FH | accepted | refused `TRUST_STORE_FRESHNESS_UNPROVEN` |
| compromised C known, no TS | any | refused `KEY_COMPROMISED_NO_CHRONOLOGY` | same |
| compromised C known, TS after C | any | refused `SIGNED_AFTER_COMPROMISE` | same |
| compromised C unknown | any | refused `KEY_COMPROMISED_NO_CHRONOLOGY` | same |
| retired, `development` + `signer-asserted`, issued_at < R | none | accepted, note `CHRONOLOGY_UNAUTHENTICATED` | not selectable (`PolicyError`) |
| retired, same, issued_at >= R | none | refused `SIGNED_AFTER_RETIREMENT` | not selectable |
| compromised, `signer-asserted` | none | refused (always) | not selectable |

Consequences stated plainly:
* In this release line a retired or compromised key's historical report is accepted only if the *caller* supplies
  both timestamp evidence and a `TrustHistory` marked authenticated. The library cannot produce the latter, so the
  default outcome for any historical report of a retired/compromised key is **refusal**. Retiring a key therefore
  effectively stops accepting its reports unless the caller wires those two seams (or runs the `development`
  signer-asserted mode). That is the 0.2.0 behaviour; the new commands only make editing the store safe.
* Retire/revoke never invalidates or validates a report retroactively; it changes the verifier's current policy.
  A report is "authentic history" (integrity + key possession) and "currently acceptable" (store state) separately.
  Test: with timestamp evidence, a report signed before both a retirement and a later revoke whose boundary is
  after the timestamp stays acceptable; moving the boundary before the timestamp refuses it; unknown boundary
  refuses it. The report bytes are never rewritten.
* Retirement is not compromise. Choosing `retire` for a key that is actually compromised leaves its pre-R history
  acceptable under the chronology rules; the tool cannot detect that operator error.

## 4. Durable update, permissions, symlinks

Implemented in `src/regaudit_fhe/_trust_lifecycle.py`:
* Validate, then stage new bytes and the previous bytes in temp files in the store's (resolved) directory,
  `fsync` each, require the store to be byte-identical to what was read (narrows a concurrent-writer race; not a
  lock), `os.replace` the backup to `STORE.prev` then the new file onto the store, `fsync` the directory. Failure
  before the replace leaves the old store byte-identical and removes temp files. A crash between the two replaces
  can leave a `.prev` equal to the live store (harmless). `kill -9` mid-edit can leave a `.trust-*.tmp` file.
  Only one backup generation is kept (`.prev` is overwritten by the next edit).
* **Permissions.** The store and its `.prev` get exactly the permission bits the store had, set with an explicit
  `chmod` so the result is independent of the umask. This corrects the first draft (research branch), which forced
  the store to 0644 (could widen a 0600 store) and the backup to 0600. `trust add` writes 0644, so a store created
  by `trust add` stays 0644 through retire/revoke; a 0600 store stays 0600. Ownership/ACLs/xattrs are **not**
  preserved (a new inode is created). A group- or world-writable store is edited but reported in `warnings`
  (never silently "fixed", never refused). `.prev` has the store's sensitivity: both hold only public keys and
  lifecycle data, no secrets, yet whoever can write either can change trust.
* **Symlinks.** A symlinked store is edited *through* the link (the real file and `.prev` live next to the target;
  the link keeps pointing at the updated file). Dangling or looping links, directories and FIFOs are refused before
  anything is created. Following a link means the operator's path decides which file changes; do not point the
  command at a path in a directory writable by another user. `trust add` (unchanged) replaces a symlink with a
  regular file; that existing behaviour was not altered.
* `as_of` is set to the local clock and never moved backwards (it is informational; no verifier compares it).

## 5. Rotation and replacement design

Rotation = enrol the new key under a NEW key_id (`trust add`, fingerprint-confirmed out of band), switch signers,
then `trust retire --key-id OLD`. Enforced today: a key_id is never reused (`trust add` refuses an existing id; no
command deletes an entry, so a retired or compromised id cannot be freed and re-bound); one public key under one
key_id (SPKI fingerprint uniqueness, so a retired/compromised key cannot be relabelled); report identity is
`(key_id, SPKI fingerprint)` inside the signed body and must equal the store's entry. Tested: a different key
presented under the retired key_id is `KEY_EMBEDDED_MISMATCH`; a new key under a never-enrolled key_id is
`ISSUER_UNKNOWN`; old and new keys coexist with distinct ids. There is **no successor link** in the format, so
nothing says "B replaces A"; a verifier never treats one key as another. A `replaces` link or cross-signature
needs a new schema; see the protocol proposal. If the old key is *compromised*, use `revoke`, not `retire`.

## 6. Compatibility  [agent-run]

Fixtures signed by published wheels 0.1.0, 0.1.1 and 0.2.0 (report.v1 and report.v2, six primitives) verified
under the published 0.2.0 wheel and under this branch against 12 store files per signer: bare mapping, legacy
keys (active, revoked), entries (active, retired before/after the issue date, compromised unknown/bounded) and the
same four lifecycle states produced by the new commands. 1368 records (strict `verify_trusted` verdict+reasons,
engine results in both historical-acceptance modes, and CLI `verify` stdout/stderr/exit) are byte-identical
(sha256 `9a1eb45ba6b4831a7f8ce23e645905a7b4d55bcc058086c4e15844172f3809b4` for both runs). Edited stores
differ from a hand-written equivalent only by the existing `as_of` member. The harness lives outside the repo
(`compat/` scratch scripts); it is not part of the test suite.

## 7. Threat and limitations

* **A local file is not a revocation authority.** Anyone who can write it can set a key back to `active`, remove a
  `compromised` entry, edit a boundary or restore an old copy. The one-way rules are CLI policy, not something the
  verifier checks.
* **Rollback of an old store is undetectable locally** (`as_of` is not compared by any verifier).
* **No distribution.** Nothing pushes a revocation to verifiers; `serve` reads its store once at start-up, so a
  revocation also needs a restart there.
* **Signer-asserted time** stops only careless old-key signers.
* **Edit attacker** can also enrol their own key. Everything depends on file permissions and the delivery channel.
* **Concurrency.** A byte-compare before replace narrows but does not close a race between two editors; no lock.

## 8. Owner decisions (not implemented)

See `docs/TRUST_REVOCATION_PROTOCOL_PROPOSAL.md` (signed revocation lists, epochs, high-water marks, successor
evidence, authenticated trust history) and its section 16 for the open owner decisions.
