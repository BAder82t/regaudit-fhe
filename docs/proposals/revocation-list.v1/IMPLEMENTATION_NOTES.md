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

## Default output: what changed, and how a consumer learns revocation was not evaluated

**Tested first.** Adding one field to `VerificationResult.to_dict` was tried in a scratch copy. It fails the pinned inventory in
`tests/test_cli_verify_output_no_secrets.py`, and that function feeds `POST /v1/verify` too, so any strict consumer of either
would break.

**Chosen: nothing changes in the default output.** `to_dict`, CLI stdout and stderr, and the HTTP response keep their exact fields.
A separate optional section, `policy_evidence` with `policy_evidence_version: 1`, appears only with `verify --policy-evidence` or
a revocation mode, or from `_revocation_gate.policy_evidence()`.

**How a consumer on the default output learns it:** `policy_id`, a field already present. `regaudit-fhe/high-assurance/v1` means
revocation was not evaluated. Any result that consulted revocation data has `+revocation-<mode>` in its `policy_id`. This is a
documented reading of an existing field, not a new signal: a consumer that does not know this rule learns nothing from the default
output. That is the cost of not changing it. HTTP has no way to request the section, since the server is not wired to this.

## F-07

A persistent floor, not a change to retention arithmetic.

* The sqlite cache adds one table, `replay_policy_floor`, holding the smallest effective `max_age` served, in `record` or `check`. It only
  goes down. `InMemoryReplayCache` holds the same for its lifetime. A third-party cache without `bind_max_age` has no floor.
* **What changes:** only when the setting is larger than the floor. The floor is enforced instead, for freshness and for retention, and
  the result gains the informational `REPLAY_POLICY_FLOOR_APPLIED`. A report outside the floor is `REPORT_TOO_OLD`.
* **What does not change:** with `max_age` unchanged or lowered, verdicts and reasons are as before. `check` mode still records no identifier; it
  does write the floor, because a report refused as stale there must stay refused, and it keeps working on a read-only file. A broken floor
  surfaces at the replay step with the existing `REPLAY_STATE_UNAVAILABLE`, so an already refused report keeps its exit path.
  In `development`, a broken floor is a non-blocking note, as with any replay failure there, so a raised `max_age` is honoured in that case.
* **Published files:** have no floor, keep working, and adopt the policy in force at their first `record` under this code. Their expired
  rows carry no policy, so a raise made before that moment cannot be seen. Stated limit, with a test. A published version reading a file
  with the extra table ignores it, and then ignores the floor.
* **Hazard:** a floor set by a mistaken low value stays, and so does one set by a second policy sharing the store: it holds both to the smaller
  `max_age`, even with no raise. Any verification under the policy sets it, including of a report that is then refused. The remedy is a new
  replay file, which forgets old identifiers.
* **Not covered:** `max_age` with replay off keeps no state anywhere, so it has no floor. That is `development` only; the other profiles
  require a replay cache. Raising `clock_skew` is not floored: it does not extend the old side of the window, and entries recorded under a
  smaller skew still outlive their report.

The same principle in the gate: the state record keeps a monotonic `policy_floor` of mode and evidence age. A raised evidence age is not
honoured (`REVOCATION_POLICY_FLOOR_APPLIED`), and a record that served `required` refuses `advisory` (`REVOCATION_POLICY_DOWNGRADE`,
blocking in every mode). A ceremony keeps it unless reset explicitly. **`off` cannot be refused**, because it reads nothing, and the ruling
on `off` requires that.

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
| Plan | Server wiring in phase 5 | Not built. `POST /v1/verify` is untouched and has no revocation mode | Not in this milestone's build list |

## Things an operator can still do to themselves

* A wrong fingerprint in a list signed with `--allow-unknown-keys`, or with no inventory through the API, is permanent: lists are cumulative and an entry can never be withdrawn. Verifiers holding that key_id then refuse every later list. The way out is a recovery to a new authority and a ceremony on each verifier.
* `flock` has no timeout, so a stuck process holding it blocks ingest and ceremonies. Verification does not take the lock, except to tighten the floor.
* A `0755` state directory owned by the verifier's user is accepted. Other local users can read the state, though not write it.

## Reason codes added since the frozen proposal

`REVOCATION_HIGH_ASSURANCE_UNAVAILABLE` (configuration), `REVOCATION_POLICY_DOWNGRADE` (blocking in every mode), `REVOCATION_POLICY_FLOOR_APPLIED`
(informational), and on the engine `REPLAY_POLICY_FLOOR_APPLIED` (informational, added to TRUST_SPEC 8.3).

## Evidence kinds

* **Real:** the file store, under real processes killed with SIGKILL, real concurrent processes, new processes after a restart, files
  damaged and restored on disk.
* **Simulated:** the independent store is a test double (`tests/experimental_revocation/trust_gate.py`), reached only through the private
  `_run_gate`. Every row under `high-assurance` with `required` is algorithm evidence only, and shows nothing about a real store. A torn
  write is made by truncating a file. Power loss has not been tested at all.
