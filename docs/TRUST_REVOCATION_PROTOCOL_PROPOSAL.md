# Authenticated revocation protocol: proposal, version 0.1 (NOT IMPLEMENTED)

Status: design proposal for a future minor release. AI-assisted engineering work; not an audit, not a production
or regulatory assurance. **Nothing in this document is implemented.** The only implemented subset is the local
`trust status|retire|revoke` file editing described in `docs/TRUST_LIFECYCLE_PROPOSAL.md`, which is an
unauthenticated local file and is not revocation authority. This proposal refines `docs/TRUST_SPEC.md` 4.5 and 4.6
(which already require a pinned anchor, a monotonic head, `TRUST_STORE_ROLLBACK`/`FORK`/`STALE`) into a concrete
artifact; where it differs, the spec's owner decisions (O8 HOLD) prevail.

Protocol version string: `regaudit-fhe.revocation-list` / `schema_version: 1`. A verifier refuses any other
version, any unknown member, and any list whose algorithm it does not implement. There is no silent fallback to
the local-file behaviour; absence of a list is reported as `TRUST_HISTORY` unproven (the 0.2.0 outcome), never as
"nothing revoked".

## 1. Roles

* **Issuer keys**: sign reports (existing). They never sign revocations about themselves in a way a verifier
  relies on: a compromised key must not be able to un-revoke or forge its own revocation.
* **Revocation authority (RA)**: one Ed25519 key per deployment (or per trust domain) whose only job is signing
  revocation lists. Distinct from every issuer key. Identified by its SPKI SHA-256 fingerprint (`authority_id`).
* **Verifier**: pins the RA fingerprint out of band (same ceremony as `trust add --fingerprint`), holds durable
  high-water state, fetches or is handed lists.

## 2. Artifact: revocation list (signed, cumulative, not a delta)

```json
{
  "schema": "regaudit-fhe.revocation-list",
  "schema_version": 1,
  "algorithm_version": 1,
  "authority_id": "<64-hex SPKI SHA-256 of the RA public key>",
  "domain": "<trust domain / deployment label>",
  "epoch": 7,
  "issued_at": "2026-11-20T09:00:00Z",
  "next_update": "2026-11-21T09:00:00Z",
  "prev_list_digest": "<64-hex digest of epoch 6, or null when epoch == 1>",
  "entries": [
    {"key_id": "acme-2026a", "key_fingerprint": "<64-hex>", "status": "retired",
     "retired_at": "2026-10-01T00:00:00Z",
     "successor": {"key_id": "acme-2026b", "key_fingerprint": "<64-hex>"}},
    {"key_id": "acme-2025", "key_fingerprint": "<64-hex>", "status": "compromised",
     "compromised_from": "2026-08-15T00:00:00Z"}
  ],
  "authority_signature": {"algorithm": "ed25519", "signature_b64": "<canonical base64>"}
}
```

* `entries` is sorted by `key_id`, unique by `key_id`; a key is identified by `(key_id, key_fingerprint)` (never
  by `key_id` alone, so a re-labelled key cannot inherit or dodge an entry). `compromised_from` absent means
  unknown boundary (refuse everything, as in spec 4.4). `epoch` is a positive integer (no floats anywhere).
* The signed body is every member except `authority_signature`.
* **Canonical signing form (reuses existing rules, `canonical.py` is not changed):**
  `signing_input = b"regaudit-fhe/revocation-list/v1/sign\x00" || canonical_bytes(signed_body)` where
  `canonical_bytes` is exactly the existing function (sorted keys, `,`/`:` separators, UTF-8 without ASCII
  escaping, finite numbers, depth limit, no duplicate keys on parse via `loads_strict`). The signature is Ed25519
  over `signing_input`, encoded with the existing canonical base64. The list digest used for chaining is
  `sha256(b"regaudit-fhe/revocation-list/v1/digest\x00" || canonical_bytes(signed_body))`. Distinct domain
  prefixes make a list signature unusable as a report signature, a seal digest or a timestamp input (and the
  reverse). Parsing uses `loads_strict` with the existing size cap.
* Number formatting caveat inherited from spec C.3: Python `repr` for floats. The list contains only integers
  and strings, so the RFC 8785 issue does not arise for this artifact.

## 3. Verification and monotonic merge

A verifier accepts a list only if all hold, in order: the pinned `authority_id` equals the RA key fingerprint;
signature verifies under the pinned key (the key is **not** read from the list); `schema_version == 1`; no
unknown members; times parse as strict RFC 3339; `issued_at` not later than verifier clock + skew; `epoch`
checks (section 4); and the list is a **monotone extension** of the verifier's last accepted list:

1. every previously listed `(key_id, key_fingerprint)` is still listed;
2. status only moves `retired -> compromised`; never back; `active` is not representable;
3. `retired_at` of a retired entry is never changed; `compromised_from` may only move **earlier**; a known
   boundary may become unknown (stricter), but unknown may never become known (that would loosen);
4. an entry that was `retired` and becomes `compromised` must have `compromised_from` at or before the old
   `retired_at`, or be unknown (same rule as the local command: never re-open a closed interval);
5. `successor` once present is never changed or removed.

Violation of 1-5 is `REVOCATION_LIST_NOT_MONOTONE`; the list is refused and the HWM is not advanced.

Applying an accepted list to a local store: new module (not `trust.py`) builds a `TrustStore` whose entry for each
listed `(key_id, fingerprint)` is the stricter of the local entry and the list entry. A listed fingerprint that
does not match the local entry's key is a conflict and is refused (`REVOCATION_KEY_MISMATCH`), never merged.

## 4. Epoch, high-water mark, rollback and fork detection

State persisted by the verifier (a small SQLite file or an atomically replaced JSON file, mode 0600, in the same
state directory as the replay cache; path from verifier configuration, never from the artifact being verified):

`(authority_id, domain, epoch, list_digest, accepted_at, next_update, accepted_list_canonical_bytes)`

Decision on a candidate list L against high-water mark H (same `authority_id` and `domain`):

| Condition | Outcome |
|---|---|
| no H (first use) | accept after section 3 checks, record H; **rollback cannot be detected** (honest limit 1) |
| `L.epoch < H.epoch` | refuse `REVOCATION_ROLLBACK` |
| `L.epoch == H.epoch`, digest equal | idempotent, no change |
| `L.epoch == H.epoch`, digest differs | refuse `REVOCATION_FORK`, keep H, alert operator |
| `L.epoch == H.epoch + 1` | require `prev_list_digest == H.list_digest` else `REVOCATION_FORK` |
| `L.epoch > H.epoch + 1` | allowed (lists are cumulative) only if monotone over H's retained list; chain gap is recorded |

Advance of H is a single compare-and-set transaction after the new list has been fully validated. Staleness:
if verifier clock is later than `next_update` + skew, the history is `STALE` (maps to the existing
`trust_history == "STALE"`), fail-closed for compromise-sensitive historical acceptance.

**Honest limits** (must be stated wherever this is documented):
1. A verifier with no state, or whose state was deleted, cannot know it is being shown an old but authentic list.
2. **Anyone who can write the state file can lower or delete the high-water mark**, or can replace the pinned
   fingerprint in the verifier's configuration. A local mark detects accidental rollback and a network-only
   attacker, not a local writer. Defence against a local writer needs something outside the verifier host (a
   second witness of the head, write-once media, or an operator-held countersigned head). That is a deployment
   decision, not something this library can provide.
3. A hash chain proves linkage of supplied lists, not completeness of everything ever issued.
4. The RA key is a single point of trust: whoever holds it can revoke, and if it is stolen can also publish a
   list that omits nothing but is *stricter* only (monotonicity stops it un-revoking; it can still maliciously
   revoke, a denial-of-service). RA compromise is recovered only by re-provisioning the pin (section 8).

## 5. Historical verification versus current acceptance

Two questions, reported separately (as the spec already requires):

* **Historical verification**: "is this report authentic history?" = integrity + identity
  `(key_id, fingerprint)` + chronology against the key's boundary. Uses the list as evidence of the boundary;
  needs a `TrustHistory`-class freshness statement for retired/compromised keys.
* **Current acceptance**: "would this verifier act on this report now?" = historical verification **and** key
  not retired/compromised-for-the-purpose **and** list fresh (`issued_at` within `trust_history_max_age`).

Mapping onto existing code without changing it: after a list passes section 3/4, a new caller-side module may
construct `TrustHistory(as_of=list.issued_at, authenticated=True)` and pass it in `VerificationPolicy`. This is
the only place `authenticated=True` may ever be set, and only by code that has just verified the signature
against the pinned anchor. `verification.py` already treats `TrustHistory` as the seam (spec O8). No retroactive
invalidation is introduced: a revocation changes the verifier's current policy; it never alters a stored report.
`high-assurance` keeps refusing historical acceptance of retired/compromised keys regardless (`history_ok()` is
false there today); relaxing that is an owner decision (spec 4.6 rule 4).

## 6. Rotation successor evidence and compromise semantics

* `successor` in an entry is **evidence for operators and auditors, not a verification rule**. A verifier never
  accepts a report signed by key B because key A names B, and never treats A's reports as B's. B must be enrolled
  on its own (`trust add` with out-of-band fingerprint) or listed by the RA in a future "authorised-keys" list
  (out of scope here).
* Optional cross-signature (new schema member): B signs
  `b"regaudit-fhe/key-succession/v1\x00" || canonical_bytes({"old": fp_A, "new": fp_B, "domain": ...})` to show
  B's holder consents to be named. It proves nothing about A's holder if A was compromised: after `compromised_from`
  A's signatures are worthless, so only the **RA-signed** `successor` counts, never an A-signed one.
* Retirement vs compromise: `retired` entries may carry `successor`; `compromised` entries may too, but the
  semantics of what A signed before C are decided only by chronology evidence.
* key_ids are never reused; a list never frees an id.

## 7. Authentication and distribution of trust-history records

`TrustHistory` is derived from the list (section 5). Distribution is **transport-only**: files handed over
out-of-band, an HTTPS pull, a message queue; none is trusted for authenticity, because every list is verified
against the pinned anchor. Lists are public (no secrets). A pull must not follow redirects to another trust
domain, must cap size (existing 4 MiB trust-store cap), and must treat any failure as "no new list", never as
"no revocations". Offline verifiers receive lists with the reports' bundle and are subject to limit 1 and 2.

## 8. Anchor pinning and RA rotation (owner decisions)

* Pin = RA fingerprint in verifier configuration, enrolled with a typed-in fingerprint confirmation, never from
  the list channel or trust-on-first-use (spec 4.5).
* RA rotation: new anchor announced by a statement signed by the outgoing RA naming the incoming fingerprint
  (`b"regaudit-fhe/revocation-authority-succession/v1\x00"`), accepted only if the verifier already pins the
  outgoing key, or by full re-provisioning. Loss or compromise of the RA is full re-provisioning.

## 9. What needs what (exact blockers)

| Part | Needs | Status |
|---|---|---|
| Revocation list artifact and its JSON Schema | **A NEW schema file**, e.g. `src/regaudit_fhe/schemas/revocation-list.v1.schema.json`, plus registration in `schemas.py` (list_schemas/get_schema) and a published `$id` | BLOCKER: this task forbids editing `schemas.py`; no schema exists. Not implemented. |
| Signature, canonical form, domain prefix | existing `canonical.py`, `_keys.py` only (no change); new prefix constants in a new module | feasible, but meaningless without the schema and the anchor |
| Verifier HWM state (SQLite/JSON) | new module modelled on `SqliteReplayCache`; no change to replay.py | feasible, **not implemented** (no list to feed it) |
| Merging a list into a store | new module; the entries format already holds status, `retired_at`, `compromised_from` | feasible; `retired_at` coexisting with `compromised` and `successor` need entry-schema changes in `trust.py` (`_ENTRY_KEYS`), out of scope |
| `TrustHistory(authenticated=True)` producer | new caller-side module; `verification.py` unchanged | **needs owner decision O8** (custody); until then nothing sets `authenticated=True` |
| RA key custody, pin ceremony, RA rotation quorum, recovery, initial distribution | **owner decision** (spec section 4.5 table: all "Pending owner designation") | BLOCKER, cannot be settled by code |
| CLI/server wiring (`--revocation-anchor`, `--revocation-state`) | `cli.py` and `server.py` changes after the above | after the schema |

Options and recommendation:
* (A) Do nothing signed; ship only the local commands, document the limits. Today's state; honest, no new trust claim.
* (B) Signed list as above with a single RA key held by the deployment owner, pin by fingerprint, local HWM.
  Detects accidental rollback and network-level replay; does not stop a local writer (limit 2).
* (C) (B) plus an external witness of the list head (second verifier, transparency log, write-once store).
  Closes limit 2 against a single-host attacker; largest operational burden.

Recommendation: ship (A) in the next minor (this branch); take (B) as the next design step **only after** the owner
designates the RA custodian and approves the schema file; treat (C) as a high-assurance prerequisite, consistent
with spec 4.6 rule 4. Do not add a compatibility fallback that treats a missing or unverifiable list as
"nothing revoked".

## 10. Conformance tests required before any implementation

Signature over the exact canonical bytes (golden vector); wrong domain prefix refused; unknown member/version
refused; pinned-key mismatch; `epoch` rollback, fork, gap, idempotence; each monotonicity rule 1-5; stale list;
cumulative superset; fingerprint/key_id mismatch; HWM compare-and-set under concurrency; deleted-state
first-use behaviour documented as undetected; verdict byte-identity of all 0.2.0 vectors when no list is configured.
