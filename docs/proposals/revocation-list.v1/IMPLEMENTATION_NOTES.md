# 0.3.0 trust protocol: implementation notes

Records how the implementation on `impl/0.3-protocol-v2` differs from [the frozen proposal](../../TRUST_REVOCATION_PROTOCOL_PROPOSAL.md),
which stays pinned as written, and how the owner's rulings were applied. EXPERIMENTAL, off by default, on a local branch.
AI-assisted engineering work; not an audit and no production assurance. The API for a challenger is in
[CHALLENGER_API.md](CHALLENGER_API.md).

## Rulings

| Ruling | Implementation |
|---|---|
| `high-assurance` with revocation `off` | Decisions and `policy_id` unchanged. Revocation is NOT EVALUATED and is not described as satisfying the revocation-aware profile |
| `high-assurance` with `required` | **Unavailable.** `verify_with_revocation` raises `PolicyError` (`REVOCATION_HIGH_ASSURANCE_UNAVAILABLE`), and the CLI exits 2, for any store and for `advisory` too. There is no `independent` attribute anywhere, because a flag on an object would be self-attestation. It never falls back to a local file |
| OD-8, authority model | The pin and recovery anchor are the root and the signer a delegate. No approver, no quorum. Every policy-evidence section discloses this |
| Evidence age | `max_evidence_age` is capped at 24 hours. Zero, negative, non-finite, unbounded and wrong types are refused. Applied in `advisory` as well as `required`. Read as being about held epochs, not the report's `max_age`, which is not capped |
| Withheld lists, later authority compromise | A held mark serves until its freshness deadline. A mark taken before a known later compromise boundary stays usable until that deadline: **a bounded availability policy, not proof the authority was uncompromised**. An unknown boundary condemns the mark, since nothing shows it came first |

## Response format

**Default output is unchanged.** `to_dict`, CLI stdout and stderr, the HTTP response body and `/openapi.json` keep their exact bytes. Adding a field to `to_dict` was tried in a scratch copy and fails the pinned inventory in `tests/test_cli_verify_output_no_secrets.py`, and `POST /v1/verify` returns the same dict.

**Opt-in, versioned, on both surfaces:** `verify --response-format v2` and `POST /v1/verify?response_format=v2`. It adds `response_format: regaudit-fhe.verification-response.v2`, an explicit `revocation_evaluation`, and a `policy_evidence` section, and every existing field is kept as it was. The query parameter is read from the request rather than declared, which is what keeps `/openapi.json` unchanged; it is documented in `docs/API.md`.

| `revocation_evaluation` | Meaning |
|---|---|
| `not_evaluated` | No usable revocation data was consulted: mode `off`, `advisory` with no usable data, an unknown key, and every HTTP response, since the server has no gate |
| `evaluated` | Fresh signed data was consulted. "Verified as of" is the most it says. The report may still be refused because of what it said |
| `required_but_unavailable` | Mode `required` and the data was absent, stale, contradictory, rolled back or unusable. `trust_status` is `INVALID`, and the builder raises rather than represent it as trusted |

`TRUSTED` keeps its meaning. The CLI prints the status on exit 3 as well, when opted in. HTTP keeps its 503 with no verdict body for an unusable replay store. A default consumer learns nothing from the default output, and the ruling is that it must opt in to learn.

## F-07: replay policy floor and published files

* A sqlite file now has a schema version: a `replay_meta` row holding the origin, the two floors, and any cutovers. Floors only go down, and a larger setting is not honoured (`REPLAY_POLICY_FLOOR_APPLIED`).
* **A published file never recorded its policy, and its expired rows may be purged, so nothing can reconstruct either.** It is refused until an operator runs `regaudit-fhe replay migrate`, stating one of two things:
  * `--previous-max-age-seconds N`: the largest `max_age` it ever served. An **operator statement**, recorded as `operator-attested`. It becomes the floor. A statement its rows contradict is refused. A false one the rows cannot show is undetected.
  * `--previous-policy-unknown`: recorded as `history-unknown`. Every report issued up to the migration plus the clock skew is refused (`REPLAY_HISTORY_UNKNOWN`), because it may have been recorded and purged. Nothing is invented.
* **A legacy file is untrusted input.** This replaced an in-place migration that carried a planted trigger over, so the same report was TRUSTED twice.
  * `sqlite_master` is compared whole against the exact published shape: one table with its exact SQL, its automatic index, nothing else. Any trigger, view, index, table or other object is a refusal before a row is read. It is an allow-list, not a list of what looks dangerous.
  * Also refused before sqlite opens it for use: a `-journal`, `-wal` or `-shm` sibling, WAL mode, not a regular file, not owned by the runner. And after: a non-zero `user_version`, a failed integrity check, a malformed row.
  * The rows are read as values under `trusted_schema = OFF` and an exclusive lock, and written to a **new file** with fixed DDL. Nothing executable can carry over. That file is read back before the swap and again after it: objects, policy record and a digest over every row.
  * **The original is kept at `<file>.pre-migration`**, a hard link with its bytes unchanged. Nothing uses it, and it is the operator's to delete. An existing different file at that name is refused, not overwritten.
  * **A kill at any step** leaves `<file>` as the whole original or the whole new file. Before the swap, another run finishes it. After, another run says it is already current. A leftover temp is swept by the next run. Each step is tested with a real SIGKILL.
  * The mode and group of the original are kept. A group- or world-writable mode is kept and reported, not changed. The file must be owned by whoever runs the migration. A symlinked path migrates the real file and the link stays. The directory needs hard links.
* **The same schema check runs on every open and every operation on a current file,** since a trigger can be planted after migration: an unexpected object is `REPLAY_STATE_UNAVAILABLE` at the engine and exit 3 at the CLI, not a quiet loss of protection.
* **Edits to `replay_meta`:** fields are checked against each other: origin against its cutovers and migration time, floor types and signs, the trust-history floor against the ceiling, the schema version. A row must exist. Incoherent records are refused.
* **Undetectable for someone who can write the file:** a coherent edit. They can raise a floor, delete rows, turn the record into `origin = new`, or replace the file. The record carries a local integrity check of its own shape, not authentication, since no key is available. A running object catches a floor that went up. A new process cannot. Replay state is a local file, and that writer is out of scope, as before.

**What changes for a deployment that upgrades with an existing replay file:**

| Situation | Before | Now |
|---|---|---|
| Any use before migrating, `record` or `check`, any report | Worked | `SqliteReplayCache` raises `LegacyReplayFile`. CLI `verify` exits 3. `serve` refuses to start, exit 2. A file swapped in under a running process gives `REPLAY_STATE_UNAVAILABLE` (HTTP 503) |
| A file with anything beyond the published shape | Worked | Refused at open and at migration. Not migratable: decide what to do with it by hand |
| Migrated with the true `max_age`, setting unchanged | | Verdicts as before, and recorded decisions honoured |
| Migrated with the true `max_age`, setting raised | Same report accepted twice | The stated value is enforced: `REPORT_TOO_OLD`, with the note |
| Migrated as unknown | | Reports issued before the migration plus skew: refused, `REPLAY_HISTORY_UNKNOWN`. Later ones: as before |
| Read-only file in `check` mode, not migrated | Worked | Refused, since migration needs to write |
| New file, or replay off | | Unchanged |

**Migration procedure changes since the last freeze:** stop every verifier first, because a journal sibling is refused; if one remains from a crash, let a published version open the file once. The file is replaced, not edited in place, so a process holding the old file open keeps writing to the kept original. No separate backup is needed for the file itself. Without `--previous-trust-history-max-age-seconds`, older trust histories stop counting (see F-12).

**What does not change:** with `max_age` unchanged or lowered on a current file, verdicts and reasons are as before. `check` mode records no identifier; it writes the floor, and keeps working on a read-only current file. A broken floor surfaces at the replay step with the existing `REPLAY_STATE_UNAVAILABLE`, so an already refused report keeps its exit path. In `development` that is a non-blocking note, as for any replay failure there, so a raised `max_age` is honoured in that one failure case.

**Remains open for F-07:**
* An operator's false statement cannot be detected, except where rows contradict it.
* A published version can still open a migrated file and ignores the floors. After a downgrade and return, identifiers it recorded under another policy cannot be told apart.
* A restored backup of a current file with a higher floor is refused by a running object that remembers, not by a new process.
* A floor set by a mistaken low value stays, and so does one set by a second policy sharing the store, and any verification under the policy sets it, including of a report then refused. The remedy is a new replay file, which forgets identifiers.
* A new replay file remembers nothing, and pointing a verifier at one is the operator's decision.
* `max_age` with replay off keeps no state, so it has no floor (`development` only; other profiles require a replay cache). Raising `clock_skew` is not floored: it does not extend the old side of the window.
* A third-party cache without the methods has no floor.

## The expiry edge

Freshness is inclusive at exactly `issued_at + max_age`, and retention is exactly `max_age + 2 * clock_skew`, but the purge and `seen` treated the expiry instant as gone, so with `clock_skew=0` an identifier was forgotten at the last instant its report was fresh. Reproduced on the published 0.2.1 wheel with a first presentation at exactly T. The stores now keep an entry through its expiry instant. **Only verdict change:** that second presentation goes from TRUSTED to `REPLAY_DETECTED`. The CLI and server have no `clock_skew` option, so it is reachable through the library only.

The same principle in the gate: the state record keeps a monotonic `policy_floor` of mode and evidence age. A raised evidence age is not honoured (`REVOCATION_POLICY_FLOOR_APPLIED`), and a record that served `required` refuses `advisory` (`REVOCATION_POLICY_DOWNGRADE`, blocking in every mode). A ceremony keeps it unless reset explicitly. **`off` cannot be refused**, because it reads nothing, and the ruling on `off` requires that.

## F-12: `trust_history_max_age`

It is the same route: raising the setting turned a stale `TrustHistory` fresh, so a historical report by a retired or compromised key could become acceptable because a setting changed. It is reachable only where a caller supplies an authenticated history, since the library produces none, and never under `high-assurance`, whose `history_ok()` stays false.

| Route | Now |
|---|---|
| Any setting above 24 hours (C7-07, a new file, a self-declared durable cache, a subclass) | **Closed.** A fixed ceiling applies to every path. A cache's declaration about itself is not read. Only the exact shipped `SqliteReplayCache` is believed to hold a floor at all |
| Broken floor (C7-08, a raising binder, a real file swapped for a published one) | **Closed.** A failure no longer widens anything: no history counts (`UNPROVEN`), in every profile |
| Raise below 24 hours on a surviving shipped store, across restart | **Closed** by the floor |
| First-contact legacy file with no statement | **Closed conservatively.** A history as of the migration or earlier is not fresh, since nothing says it was not already stale. Nothing is invented |
| False operator statement of the earlier setting | **Bounded, not closed.** Refused above 24 hours. Below that it is believed |
| Raise below 24 hours with no shipped store, a new file, or a restored backup in a new process | **Bounded, not closed.** It needs state that survives somewhere the verifier's host cannot rewrite, which does not exist here. The conservative behaviour is the ceiling: the window cannot exceed 24 hours, and tests named `limit` state it |

**Verdict change:** a caller with a setting above 24 hours and a history older than 24 hours is now refused (`TRUST_STORE_FRESHNESS_UNPROVEN`, with `TRUST_HISTORY_FLOOR_APPLIED`), on every store. This was already a non-default setting used with a caller-supplied history. Default policies are unaffected.

## F-09: issuer attribution

The property is in TRUST_SPEC 3.1. The owner's ruling: `confidential` and `high-assurance` refuse a store without issuers (provisional, in the next
security release), and the property is not inferred from the number of keys. `TrustStore.binds_issuers` is the test, and
`VerificationPolicy.__post_init__` is the one place that refuses, so every route to a policy passes it: the CLI, `build_app`, `verify_trusted`, and
`dataclasses.replace`. There is no opt-out.

Rejected, with reasons: binding legacy keys where the issuer can be established, since a legacy store holds nothing independent and the report's name is what is
being checked, and first-seen pinning lets the first attacker win; an `expected_issuer` per call, since it does not stop tenant B signing as A; a per-key
statement beside a legacy store, which is the `entries` form in another syntax.

Whether `development` and the lenient paths should refuse too is a later decision by the owner. Until then they are labelled, not changed. A departure from the proposal, section
"Legacy keys": it said such a store verifies in every profile.

## Retired key later marked compromised

`next_list` now **refuses** a compromise time after the retirement. The clamp is gone: there is no flag for it, because rewriting a stated time is a decision about what is true. The refusal says which forms verifiers accept, and the operator states the retirement time or earlier, or no time for an unknown boundary. A list signed some other way is still refused by a verifier and latches: the key stays refused, the whole issuer fails closed, replays and later lists clear nothing, and only an accepted recovery statement or a re-baseline ceremony clears it. A real test runs the whole sequence on the file store.

## Departures from the proposal's text

- A store without issuers no longer verifies under `confidential` or `high-assurance` (F-09, above).

| Section | Proposal | Implementation | Why |
|---|---|---|---|
| 9.1, 10.2, 10.4 | Report verification never writes the state | One exception: the first verification under a tighter policy writes the floor. A normal verification writes nothing (tested) | F-07 principle on the gate |
| 9.2 | Stores declare `durable`, `compare_and_set`, `independent` | No declarations. The public gate accepts exactly the shipped `FileStateStore` | Ruling on self-attestation |
| 10.1 | `required` all profiles; `advisory` lower profiles | Lower profiles only; `high-assurance` unavailable | Ruling |
| 10.2 | Evidence age has no ceiling | Capped at 24 hours | Ruling |
| 8.2 | "Every transition after the first void one is void too" | Only transitions since the last recovery are in question, and a statement at or below the current recovery epoch voids nothing | Otherwise replaying a public statement condemned the current authority |
| 8.3, 8.4 | Feed poll stops at the first refusal | A refused statement does not stop the poll; the list decides | Honest feeds carry old statements, and anyone reaching the channel could add junk |
| 10.3 | Latch on signed conflicts | As written. `REVOCATION_KEY_MISMATCH`, `REVOCATION_ISSUER_SCOPE` never latch | As in the proposal |
| 13.4 | `trust migrate` proposed | Implemented, except the dry run's report-corpus comparison: `--dry-run` checks and prints the keys only | Scope |
| 16 | OD-8 open | Settled by ruling. OD-1 to OD-7 remain open, and release scope is undecided | Ruling |
| Plan | `verification.py` not changed | Changed for F-07, narrowly | Authorized |
| Plan | Server wiring in phase 5 | Not built. `POST /v1/verify` has the opt-in response format only and no revocation mode, so it always says `not_evaluated` | Not in the build list |

## Things an operator can still do to themselves

* A wrong fingerprint in a list signed with `--allow-unknown-keys`, or with no inventory through the API, is permanent: lists are cumulative and an entry can never be withdrawn. Verifiers holding that key_id then refuse every later list. The way out is a recovery to a new authority and a ceremony on each verifier.
* `flock` has no timeout, so a stuck process holding it blocks ingest and ceremonies. Verification does not take the lock, except to tighten the floor.
* A `0755` state directory owned by the verifier's user is accepted. Other local users can read the state, though not write it.

## Reason codes added since the frozen proposal

`REVOCATION_HIGH_ASSURANCE_UNAVAILABLE` (configuration), `REVOCATION_POLICY_DOWNGRADE` (blocking in every mode), `REVOCATION_POLICY_FLOOR_APPLIED`
(informational), and on the engine `REPLAY_POLICY_FLOOR_APPLIED`, `TRUST_HISTORY_FLOOR_APPLIED` and `ISSUER_UNBOUND` (informational) and `REPLAY_HISTORY_UNKNOWN` (blocking), all added to TRUST_SPEC 8.3.

## Evidence kinds

* **Real:** the file store, under real processes killed with SIGKILL, real concurrent processes, new processes after a restart, files
  damaged and restored on disk. Replay migration: a real process killed at every step, new processes, the CLI and `serve` as processes, backups restored on disk. A file
  really written by the published 0.2.1 wheel is a committed fixture in the suite, and a harness outside it runs the real 0.2.1 CLI.
* **Simulated:** the independent store is a test double (`tests/experimental_revocation/trust_gate.py`), reached only through the private
  `_run_gate`. Every row under `high-assurance` with `required` is algorithm evidence only, and shows nothing about a real store. A torn
  write is made by truncating a file. Power loss has not been tested at all.
