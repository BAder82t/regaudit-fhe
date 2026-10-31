# Trust lifecycle proposal (post-0.2.0, not part of 0.2.0)

Status: proposal plus a compatible local-file subset on branch `research/0.3-trust-lifecycle`.
Not a release feature, not an audit, not a production or regulatory assurance. It builds on
`docs/TRUST_SPEC.md` section 4 and adds no rule that spec does not already contain.

## 1. What the existing format already supports

An `entries` trust store (`TrustStore`) already validates, per key_id: `issuer`, `public_key_pem`,
`status` in `active | retired | compromised`, `not_before`, `retired_at` (required iff retired),
`compromised_from` (only if compromised; absent means unknown boundary), `deployments`,
`primitives`, `parameter_set_pin`, plus a top-level `as_of`. A public key may sit under one key_id
only. The legacy `keys/revoked/parameter_set_pins` form maps revoked keys to `revoked`
(compromised with unknown boundary). Verification already reports `key_status`, `chronology`
(`NONE | SIGNER_ASSERTED | AUTHENTICATED`) and `trust_store_as_of`. `as_of` is informational
only; nothing compares it with anything.

## 2. Semantics (all already enforced by the engine; restated precisely)

**Retirement** (`retired_at = R`): planned rotation, no belief of exposure. A report is accepted
only if it is provably signed strictly before `R`. Outside `development`, "provably" means a verified
RFC 3161 timestamp over the sealed v2 artifact with `genTime + accuracy < R`, and a fresh
authenticated trust history (which Phase 3A cannot produce, so the default is refusal:
`KEY_RETIRED_NO_CHRONOLOGY` / `TRUST_STORE_FRESHNESS_UNPROVEN`). Only in the `development`
profile with `historical_acceptance="signer-asserted"` is `issued_at < R` used.
Retirement does not invalidate or validate anything retroactively; it stops the key being
accepted for anything not otherwise proven earlier.

**Revocation / compromise** (`compromised_from = C` or unknown): signature acceptance requires
authenticated chronology `< C`; unknown `C` refuses everything the key ever signed. There is no
signer-asserted path, because a compromised key controls its own clock.

**What `issued_at` proves.** It is a field the signer wrote inside the signed body. It proves the
holder of the key at signing time claimed that time. It does not prove when signing happened, and
an attacker holding the key can pick any value. It is therefore usable only for development
convenience (retired keys, never compromised ones) and is labelled `SIGNER_ASSERTED`. Independent
timestamp evidence proves "this exact sealed artifact existed no later than genTime + accuracy",
nothing about what happened afterwards, and nothing about who held the key.

**Signed historical evidence vs current trust.** A valid signature proves integrity and key
possession at some time. Whether the key is trusted now is a property of the verifier's trust
store at verification time. A report can be authentic history and still not be currently
acceptable. The two are reported separately (`key_status`, `chronology`, verdict); no rule here
retroactively invalidates a signature, and none should be invented. A later compromise of a key
whose interval was accepted is only caught if the verifier's store learns of it, see section 5.

**Rotation / replacement.** Rotation = enrol the new key under a NEW key_id, then retire the old
one. Rules, mostly already enforced:
1. A key_id is never reused for a different key. `trust add` refuses an existing key_id and the
   lifecycle commands never touch `public_key_pem`. Entries are never deleted by any command, so a
   retired or compromised id cannot be freed and re-bound.
2. One public key under one key_id (`_require_unique_keys`, SPKI fingerprint), so a revoked key
   cannot be relabelled to regain trust.
3. Identity is `(key_id, SPKI fingerprint)`; the report's embedded key must match the store's key
   for that key_id. Overlap (old key retired, new key active) is unambiguous because the two have
   different key_ids and each report names its own.
4. Retiring the old key at the instant the new one is first used is the operator's job; there is
   no cross-signature or successor link in the format (would be a schema change).

## 3. Durable update and rollback of a local store

Implemented for the new commands (`src/regaudit_fhe/_trust_lifecycle.py`):
- Validate the edited payload with `TrustStore.from_dict` before any write.
- Stage new bytes and the previous bytes in temp files in the same directory, `fsync` each, check
  the store is byte-identical to what was read (narrows a concurrent-writer race; not a lock),
  `os.replace` the backup to `STORE.prev` then the new file onto the store, `fsync` the directory.
  Failure before the replace leaves the store byte-identical and removes temps.
  A crash between the two replaces can leave an updated `.prev` with the old store: harmless.
- One-way transitions only: active to retired, active or retired to compromised. No re-dating, no
  un-revoking, no deletion. Retired to compromised drops `retired_at` (the format cannot hold both);
  the old value remains in `.prev` only.
- Never loosens: a compromise boundary later than an existing `retired_at` is refused.
- Future-dated boundaries (beyond 5 minutes of the local clock) are refused.
- `as_of` is set to the local clock and never moved backwards; a store whose `as_of` is more than
  5 minutes ahead of the local clock is refused for editing.

Not solved: a verifier reading an older copy of the file. `as_of` is not compared by the verifier,
so replacing the store with an earlier version (which may predate a revocation) is undetectable
locally.

## 4. CLI

| Command | Effect | Exit |
|---|---|---|
| `trust status --store S [--key-id K]` | read-only JSON: form, `as_of`, per-key status, boundaries, fingerprint, `authenticated: false` | 0; 2 unknown key_id; 3 unusable store |
| `trust retire --store S --key-id K [--at T]` | active to retired; T default now, not future | 0; 2 refused; 3 store unusable |
| `trust revoke --store S --key-id K [--compromised-from T]` | to compromised; no T = unknown boundary | same |

Refusals: unknown key_id, wrong source state, legacy-form store (never converted), bad or future
time, loosening boundary, `as_of` ahead of clock. `trust add` is unchanged.

## 5. Threat and limitations report

- **A local file is not a revocation authority.** Anyone who can write the file can set a key back
  to `active`, delete a `compromised` entry, edit `compromised_from` later, or restore an old copy.
  The commands guard honest operators, not an attacker. Their one-way rules are CLI policy, not a
  property the verifier checks.
- **Edit attacker.** Can also enrol their own key. Everything depends on file permissions and the
  channel by which the file reached the verifier.
- **Rollback / replay of an old store.** Undetected (see section 3). An old store makes a revoked
  key look active.
- **Signer-asserted time.** See section 2. Retirement boundaries checked against `issued_at` stop
  a careless old-key signer only; they stop nobody who holds the key.
- **No distribution.** Nothing pushes a revocation to verifiers. A running server reads its store
  once at start-up (0.2.0 limitation), so revocation also needs a restart there.
- **Retirement is not compromise.** Marking a compromised key `retired` makes its pre-retirement
  history acceptable under the same chronology rules; choosing the wrong command is an operator
  error the tool cannot detect.
- **Timestamp coverage.** The engine accepts historical retired-key reports only with timestamp
  evidence plus an authenticated trust history. This release line cannot produce the latter.

## 6. Needs an owner decision (not implemented)

| Need | Options | Recommendation |
|---|---|---|
| Independently protected revocation | (a) signed, owner-authorised trust-store/revocation list with monotonic `version`, verified against a pinned anchor; (b) keep local file and document it as operator-controlled; (c) transparency log | (a), as a new schema; (b) is today's state |
| Rollback detection | verifier-side durable high-water mark of `version`/`as_of` (needs a signed `version`); local-only `as_of` high-water file is bypassable by the same attacker | tie to (a) |
| Preserve `retired_at` after compromise | add `retired_at` coexistence or an append-only `history` list | with the new schema |
| Successor link / cross-signing for rotation | `replaces: key_id` + fingerprint in the entry | with the new schema |
| Authenticated TrustHistory producer | anchor-signed snapshots | with (a) |

## 7. Compatibility of existing stores

Public-key-only stores (bare mapping), legacy `keys/revoked/pins` stores and `entries` stores load
and verify exactly as before: no change was made to `trust.py`, `verification.py`, `trusted.py`,
`canonical.py`, `schemas.py`, `_keys.py`, `replay.py` or any report schema. The lifecycle commands
refuse legacy-form and bare-mapping stores rather than converting them; migrate by re-enrolling keys
with `trust add` into an `entries` store (key_ids and fingerprints must be re-confirmed out of band).
Edited stores gain only the existing `as_of` member, which `TrustStore` already accepts and
surfaces as `trust_store_as_of`.

## 8. Shippable in a minor release without a new schema

`trust status`, `trust retire`, `trust revoke` as implemented (additive CLI, same format,
unchanged verdicts for unedited stores). Everything in section 6 needs owner authority and a new
schema.
