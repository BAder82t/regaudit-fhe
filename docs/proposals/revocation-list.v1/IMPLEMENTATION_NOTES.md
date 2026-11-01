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

* A sqlite file now has a schema version: a `replay_meta` row holding the origin, the two floors, and any cutover. Floors only go down, and a larger setting is not honoured (`REPLAY_POLICY_FLOOR_APPLIED`).
* **A published file never recorded its policy, and its expired rows may be purged, so nothing can reconstruct either.** It is refused until an operator runs `regaudit-fhe replay migrate`, stating one of two things:
  * `--previous-max-age-seconds N`: the largest `max_age` it ever served. An **operator statement**, recorded as `operator-attested`. It becomes the floor. A statement its rows contradict is refused. A false one the rows cannot show is undetected.
  * `--previous-policy-unknown`: recorded as `history-unknown`. Every report issued up to the migration plus the clock skew is refused (`REPLAY_HISTORY_UNKNOWN`), because it may have been recorded and purged. Nothing is invented.
* Migration is one exclusive sqlite transaction and touches no row. A malformed or ambiguous file (wrong columns, extra tables or views, wrong row types, failed integrity check) is refused and left as it was.

**What changes for a deployment that upgrades with an existing replay file:**

| Situation | Before | Now |
|---|---|---|
| Any use before migrating, `record` or `check`, any report | Worked | `SqliteReplayCache` raises `LegacyReplayFile`. CLI `verify` exits 3. `serve` refuses to start, exit 2. A file swapped in under a running process gives `REPLAY_STATE_UNAVAILABLE` (HTTP 503) |
| Migrated with the true `max_age`, setting unchanged | | Verdicts as before, and recorded decisions honoured |
| Migrated with the true `max_age`, setting raised | Same report accepted twice | The stated value is enforced: `REPORT_TOO_OLD`, with the note |
| Migrated as unknown | | Reports issued before the migration plus skew: refused, `REPLAY_HISTORY_UNKNOWN`. Later ones: as before |
| Read-only file in `check` mode, not migrated | Worked | Refused, since migration needs to write |
| New file, or replay off | | Unchanged |

**What does not change:** with `max_age` unchanged or lowered on a current file, verdicts and reasons are as before. `check` mode records no identifier; it writes the floor, and keeps working on a read-only current file. A broken floor surfaces at the replay step with the existing `REPLAY_STATE_UNAVAILABLE`, so an already refused report keeps its exit path. In `development` that is a non-blocking note, as for any replay failure there.

**Limits:**
* An operator's false statement cannot be detected, except where rows contradict it.
* A published version can still open a migrated file and ignores the floors. After a downgrade and return, identifiers it recorded under another policy cannot be told apart.
* A restored backup of a current file with a higher floor is refused by a running object that remembers, not by a new process. Replay state is a local file.
* A floor set by a mistaken low value stays, and so does one set by a second policy sharing the store, and any verification under the policy sets it, including of a report then refused. The remedy is a new replay file, which forgets identifiers.
* `max_age` with replay off keeps no state, so it has no floor (`development` only; other profiles require a replay cache). Raising `clock_skew` is not floored: it does not extend the old side of the window.
* A third-party cache without the methods has no floor.
* Pre-existing, not changed: at `clock_skew=0` the same report is accepted twice at exactly `T+max_age`.

The same principle in the gate: the state record keeps a monotonic `policy_floor` of mode and evidence age. A raised evidence age is not honoured (`REVOCATION_POLICY_FLOOR_APPLIED`), and a record that served `required` refuses `advisory` (`REVOCATION_POLICY_DOWNGRADE`, blocking in every mode). A ceremony keeps it unless reset explicitly. **`off` cannot be refused**, because it reads nothing, and the ruling on `off` requires that.

## F-12: `trust_history_max_age`

It is the same route: raising the setting turned a stale `TrustHistory` into a fresh one, so a historical report by a retired or compromised key could become acceptable because a setting changed. It is reachable only where a caller supplies an authenticated history, since the library produces none, and never under `high-assurance`, whose `history_ok()` stays false.

* **With a durable shipped store** (always, under `confidential`): closed the same way, by a second floor in `replay_meta`. A raised setting is not honoured (`TRUST_HISTORY_FLOOR_APPLIED`, stale stays stale). A migration sets it to the stated value, default 24 hours, the library default: if the earlier setting was lower, state it.
* **Without one** (`development` with replay off, an in-memory or third-party cache): it **cannot** be closed the same way, because nothing persists to remember the earlier setting. The conservative alternative is a fixed ceiling at the default, 24 hours: a larger setting is not honoured at all. A raise below the ceiling, say from 1 hour to 3, cannot be seen. That residual is at most 24 hours, in `development` or with a store that keeps nothing, and a test states it. **Verdict change:** only for a caller with no durable store, a setting above 24 hours, and a history older than 24 hours.

## Retired key later marked compromised

`next_list` now **refuses** a compromise time after the retirement. The clamp is gone: there is no flag for it, because rewriting a stated time is a decision about what is true. The refusal says which forms verifiers accept, and the operator states the retirement time or earlier, or no time for an unknown boundary. A list signed some other way is still refused by a verifier and latches: the key stays refused, the whole issuer fails closed, replays and later lists clear nothing, and only an accepted recovery statement or a re-baseline ceremony clears it. A real test runs the whole sequence on the file store.

## Departures from the proposal's text

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
(informational), and on the engine `REPLAY_POLICY_FLOOR_APPLIED` and `TRUST_HISTORY_FLOOR_APPLIED` (informational) and `REPLAY_HISTORY_UNKNOWN` (blocking), all added to TRUST_SPEC 8.3.

## Evidence kinds

* **Real:** the file store, under real processes killed with SIGKILL, real concurrent processes, new processes after a restart, files
  damaged and restored on disk. Replay migration: a real process killed inside the transaction, new processes, the CLI and `serve` as processes,
  backups restored on disk. Files from a real 0.2.1 wheel go through the same sequence in a harness outside the suite; in the suite a published
  file is made with the same SQL the published versions run.
* **Simulated:** the independent store is a test double (`tests/experimental_revocation/trust_gate.py`), reached only through the private
  `_run_gate`. Every row under `high-assurance` with `required` is algorithm evidence only, and shows nothing about a real store. A torn
  write is made by truncating a file. Power loss has not been tested at all.
