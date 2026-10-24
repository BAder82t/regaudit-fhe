# regaudit-fhe — Phase 3A consistency review and contract corrections

Scope: the six contract decisions and the nine acceptance gates set after the
Phase 3A report. No new features. Supersedes the identities, test counts and
"open questions" in `PHASE3A-REPORT.md` (that report remains as the record of the
first delivery). Nothing was pushed, merged or released; Encompute is untouched.

## 1. Exact retirement-boundary decision

Let `latest_signing_time = genTime + accuracy` of the authenticating token.

| Boundary | Rule | Equality |
|---|---|---|
| Retired key (`retired_at`) | `latest_signing_time < retired_at` | **refused** |
| Compromised key, known boundary (`compromised_from`) | `latest_signing_time < compromised_from` | **refused** |
| Signer-asserted retirement (development profile only) | `issued_at < retired_at` | **refused** |

This changes the delivered candidate, which accepted equality for retirement. A
timestamp equal to a boundary does not show the signature preceded it, because clock
values alone do not establish an order. Equality could be allowed only where
independently authenticated evidence (for example sequence numbers) gives a reliable
event order; Phase 3A has no such mechanism. A valid timestamp also does not establish
that trust history is complete or that no later compromise was declared: the O8
freshness limitation is unchanged (`TRUST_STORE_FRESHNESS_UNPROVEN` still blocks
historical acceptance without an authenticated, fresh `TrustHistory`).

The rule lives in `verification._apply_key_lifecycle`, is specified in
`docs/TRUST_SPEC.md` §4.3 ("Boundary semantics"), and is pinned by
`test_retirement_boundary_is_strict` / `test_compromise_boundary_is_strict` (six
offset/accuracy cases each, including equality and `genTime + accuracy == boundary`)
plus mutants B01 and B02.

## 2. The six decisions as implemented

| # | Decision | Code | Evidence |
|---|---|---|---|
| 1 | `RECORDED_LOCAL` approved; never global protection, exactly-once or proof of completion; durability disclosed | `verification.py` (`replay_durable`), `replay.py` (`durable`) | `test_replay_state_labels_and_durability_are_disclosed`, `test_reserved_and_consumed_are_never_produced_in_phase_3a`, mutants D01–D03; spec §6.2 |
| 2 | `report.v1` refused in `confidential` | `REPLAY_ID_MISSING` | `test_cli_refuses_v1_in_confidential_profile_with_replay_required`, engine tests; spec §7, §9.4 |
| 3 | Omitted `--trusted-keys` → 2; supplied but unusable (even empty) → 3; policy refusal → 1; accepted → 0 | `cli._cmd_verify` | `test_cli_exit_codes_for_the_four_outcomes`, `test_cli_a_supplied_but_empty_trusted_keys_path_is_infrastructure_failure`, mutant X01 |
| 4 | Required timestamp needs authenticated evidence; absent never satisfies; `ABSENT` stays distinct from `FAILED` in diagnostics | `VerificationPolicy`, `_evaluate_timestamps` | `test_required_timestamp_refuses_every_kind_of_non_evidence` |
| 5 | Unix sockets / unauthenticated transports refused **for the development option only** | `server.check_dev_exposure` | `test_unix_sockets_are_refused_for_the_development_option`, `test_normal_trusted_verification_still_works_over_a_unix_socket`, mutants U01–U02 |
| 6 | Strict chronology boundaries; O8 freshness still required | §1 above | §1 above |

## 3. Acceptance gates

| Gate | Result | How it is established |
|---|---|---|
| Key aliases | PASS | Loaders **and direct `TrustStore(...)` construction** refuse a key under two ids (SPKI-fingerprint based, so PEM formatting variants are caught). The direct-construction hole was found by the review and fixed (mutant Z01). `test_gate_key_alias_is_refused_by_every_loader`, `test_gate_direct_trust_store_construction_refuses_key_aliases` |
| Key scope | PASS | Issuer, deployment, primitive and `not_before` are honoured by the shared engine, the legacy `verify_envelope` / `verify_envelope_or_raise` / `verify_receipt`, the CLI (real process) and HTTP, for v1 and v2: `test_gate_key_scope_is_honoured_by_library_cli_and_http`, `test_legacy_api_honours_entry_scope`, `test_legacy_api_agrees_with_the_engine_on_scoped_entries` |
| Canonical base64 | PASS | One strict decoder (`canonical.decode_canonical_b64`) is used for v2 parsing, engine timestamp tokens, **and the v1 signature and v1 timestamp-token paths**. The v1 gap was found by the review and fixed (mutants Z02–Z03, E04–E05). `test_gate_alternate_base64_is_refused_on_the_v1_path_too`, `test_gate_alternate_base64_cannot_change_artifact_identity` |
| v1 compatibility | PASS | v1 verifies over its original canonical bytes and is subject to current policy (profiles, compromised/retired, replay, legacy flag, timestamps never `VERIFIED`) |
| CLI exit codes | PASS | Real-process tests for every branch (incompatible options → 2, unusable specified resources → 3, see §8); stdout empty for 2 and 3; a replay store failing *during* verification outside development is now 3 / HTTP 503 rather than a policy `1`. Precedence documented: input errors (2) before infrastructure errors (3) |
| Development exception | PASS | `test_gate_no_path_from_self_signed_to_trusted_on_any_entry_point` (library, HTTP, CLI × v1/v2/tampered) and `test_gate_flag_plus_store_never_turns_an_unregistered_issuer_into_trusted` |
| Retirement boundary | PASS | §1; the stale `≤` in spec §4.1 was found by the review and corrected, and a docs test now forbids `≤ retired_at` |
| Replay status | PASS | Labels, durability and the spec §8 enum (which had omitted `RECORDED_LOCAL`) are consistent; `RESERVED`/`CONSUMED` are never produced |
| Spec and changelog | PASS | `docs/TRUST_SPEC.md` (§4.3, §6.2, §7, §8.1, §9.3.3, §9.3.5, §9.4, Appendix C.2/C.4), `CHANGELOG.md`, `README.md`, `docs/DEPLOYMENT.md`, `docs/THREAT_MODEL.md`. `test_every_reason_code_the_engine_can_emit_is_documented_in_the_spec` and the other docs tests guard against drift |

## 4. Findings from the focused review, and what changed

An independent subagent reviewed the nine gates against the working tree and found
contradictions, all fixed with a failing test first:

* **Gate 1 FAIL → fixed:** direct `TrustStore(...)` construction accepted aliases.
* **Gate 3 FAIL → fixed:** the `report.v1` signature and timestamp-token paths decoded
  base64 leniently.
* **Gate 7 FAIL → fixed:** spec §4.1 still said `≤ retired_at`.
* **Gate 8 partial → fixed:** spec §8 consumption enum omitted `RECORDED_LOCAL`;
  README and DEPLOYMENT now document `RECORDED_LOCAL` and `replay_durable`.
* **Gate 9 partial → fixed:** spec §7 and the §9.4 profile table still said v1 was
  allowed in `confidential`; the README and `THREAT_MODEL.md` did not state the
  decisions; a server comment still said "loopback/Unix socket".
* **Replay store failure during verification** outside development returned a policy
  refusal; under the owner's rule it is infrastructure failure (CLI 3, HTTP 503).
* Noted and documented, not changed: input errors (2) are reported before
  infrastructure errors (3) when both apply; in the development profile a replay store
  that fails while verifying fails open with a disclosed `REPLAY_STATE_UNAVAILABLE`.

A fresh, independent re-check of all nine gates was run afterwards (§6).

## 5. Verification results

| Check | Result |
|---|---|
| Full suite, Python 3.11.7 (with TenSEAL), `CI=1` | **837 passed, 3 skipped**, 1 pre-existing warning |
| Coverage (`--cov-fail-under=80`) | passed, **89.03%** |
| Python 3.12 and 3.13 (dev+server extras, no TenSEAL; FHE matrix deselected) | 763 passed, 7 skipped on each |
| `ruff check`, `ruff format --check`, `mypy` (28 files), `bandit` medium+ | clean / 0 issues |
| Mutation check (`scripts/mutation_check_phase3a.py`, 96 mutants) | **93 killed, 3 argued equivalent, 0 survived** |
| Python 3.10, GitHub CI | **not run** |

Targeted regressions added in this round: `tests/test_phase3a_contract.py` (35 tests,
including docs-consistency gates) plus updates to `test_server_trust.py`
(Unix-socket and peer rules). One earlier test was changed because it encoded the
superseded Unix-socket behaviour; no cryptographic assertion was weakened.

## 6. Independent re-check

After the fixes, a second, fresh reviewer (no access to the first review) re-checked all
nine gates and tried to break each with real CLI processes and direct library calls.
**Result: all nine gates PASS in code.** It found only documentation imprecision and one
hardening nit, all fixed with a failing test first:

* spec §4.3 item 3 ("at or before `signed_not_after`") and §4.4
  (`signed_not_after + accuracy`) used inconsistent boundary vocabulary → both now use
  `latest_signing_time = genTime + accuracy` (the reported `signed_not_after` is `genTime`);
* spec §4.4 and decision D3 said an unknown compromise boundary is refused "unless
  independent chronology predates `not_before`", but the code refuses it unconditionally →
  spec now says unconditional;
* spec §6.2 said `/v1/verify` must always report `NOT_CHECKED` → qualified by whether
  replay checking is configured; `CHECKED_NOT_CONSUMED` is now defined as "this call
  recorded nothing" (it is also what `REPLAY_DETECTED` reports);
* spec §8.3 omitted six emitted reason codes → complete list, with held codes marked;
* DEPLOYMENT's endpoint row and THREAT_MODEL's "Replay protection is not provided" were
  unqualified → qualified (development flag / replay outage; `report.v1` only);
* a trust-store entry's `key_id` was not checked against its map key → now refused.

One ambiguity the re-check raised for the owner (see §8).

## 7. Still open (unchanged)

O8 trust-anchor custody, O9 timestamp authority, high-assurance historical
verification, shared replay infrastructure, the reserve/perform/commit protocol,
`report.v2` emission from the CLI/HTTP audit paths, RFC 8785 number formatting, the
header-less local proxy limitation, and the larger confidential-computation limits
(RA-01). Phase 3A remains a candidate trust core, not production readiness. A public
push, merge or release remains on HOLD.

## 8. Final CLI correction (owner decision applied)

A policy-invalid flag combination is a command-configuration error, so it exits **2**,
not 3: `--allow-self-signed` with `--profile confidential` / `high-assurance`, and a
production profile without its required options (`--max-age-seconds`, replay options,
`--verifier-id`). Exit **3** is reserved for a required resource that *was specified* but
is unusable: an unreadable, malformed or empty `--trusted-keys`, an unusable
`--replay-db`, or a replay store failing while verifying outside development. The line:
an invalid configuration discovered at startup is 2; an otherwise valid configuration
whose resource cannot be loaded is 3.

Tests: `test_exit_2_dev_flag_is_a_usage_error_outside_development`,
`test_exit_2_production_profile_with_missing_required_options` (confidential without
`--max-age-seconds` or replay options, `high-assurance` without `--verifier-id`),
`test_unusable_trust_and_replay_resources_still_exit_3_in_a_valid_configuration`, and a
docs gate. No other behaviour changed.
