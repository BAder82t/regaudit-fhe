# 0.3.0 trust protocol: test matrix

Companion to [the frozen proposal](../../TRUST_REVOCATION_PROTOCOL_PROPOSAL.md). AI-assisted engineering work; not an audit and no
production assurance. An implementation is finished when every row passes against product code, including the `none` rows. Rows `S16`, `G23`, `T12`,
`V06` and `V07` stay `none` in the suite: `S16` needs real power loss and a real independent store, `G23` needs server wiring
that this milestone does not build, and the last three are run by a release harness outside the suite.

**Reading the last column.** `existing` means a test that was already in the draft v1 prototype at `f3e2a55`. `new` means a test
added in this milestone, run against the reference model and the corrected prototype (`trust_gate.py`, `proto.py`). `none`
means nothing runs it yet, usually because it needs product code. Every row passing here shows that the proposal is consistent
with itself and with the unchanged engine. It does not show that a product implementation exists.
`test_matrix_consistency.py` checks that each named test exists in the labelled file set.

**Verdict notation.** For a document: `accepted`, or `refused CODE`, at ingest, with state unchanged unless stated. For a report:
`TRUSTED`, or `INVALID CODE`. Codes without a prefix are existing engine codes. Since the implementation milestone, every test here runs against product code under `src/`, except where a row or
the file says it uses the test double. "Permissive" describes what an implementation
missing the rule would visibly do; rows marked (observed) were seen by running either the draft v1 prototype at `f3e2a55` or an
earlier state of the reference model.

**Components.** enrollment (ceremony, pin); list verifier; transition verifier; recovery verifier; state store (commit protocol);
gate; overlay (join applied for one verification); wrapper (opt-in path around the engine); config check (startup); engine
(unchanged `verify()`); migration tool; issuer tooling; CLI; server.

## E. Enrollment

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| E01 | List signed by the enrolled authority | accepted | list verifier | n/a: positive control | existing: test_enrolled_list_verification_uses_the_enrolled_key_only; corpus:list-valid-epoch1 |
| E02 | List, transition or recovery for an issuer never enrolled | refused REVOCATION_NOT_ENROLLED | list verifier, enrollment | Learn the authority from the document (trust on first use), so anyone can become an authority | existing: test_nothing_is_enrolled_from_a_list_or_statement; corpus:list-not-enrolled |
| E03 | Enrolling a report key as authority or anchor | ceremony refused | enrollment | Let a stolen report key revoke other keys | existing: test_enrollment_is_explicit_local_and_refuses_unsafe_keys |
| E04 | Enrolling the same key as authority and anchor | ceremony refused | enrollment | Make recovery depend on the key it recovers from | existing: test_enrollment_is_explicit_local_and_refuses_unsafe_keys |
| E05 | Authority key later added as a report key | refused REVOCATION_KEY_IS_REPORT_KEY | list verifier | Keep accepting lists from a key that can also sign reports | existing: test_enrolling_the_revocation_key_as_a_report_key_disables_it |
| E06 | Second enrollment over a live record | ceremony refused, state unchanged | enrollment | Silently replace the authority | existing: test_enrollment_is_explicit_local_and_refuses_unsafe_keys; new: test_E06_a_second_enrollment_needs_the_ceremony |
| E07 | `required` with a pin that has no baseline | startup refused | config check | Trust the first list seen, which may be old | new: test_G20_unsafe_configurations_are_refused_at_startup |
| E08 | First list below the baseline epoch | refused REVOCATION_ROLLBACK | list verifier, enrollment | Start from an old authentic list that omits later revocations | new: test_E08_first_list_below_the_enrollment_baseline_is_a_rollback |
| E09 | First list at the baseline epoch with another digest | refused REVOCATION_FORK | list verifier, enrollment | Accept a different list at the epoch the ceremony pinned | new: test_E08_first_list_below_the_enrollment_baseline_is_a_rollback |
| E10 | First list at the baseline | accepted | list verifier | n/a: positive control | new: test_E10_first_list_at_the_baseline_is_accepted |
| E11 | State and pin both deleted | refused REVOCATION_NOT_ENROLLED | enrollment | Treat the blank verifier as first use and re-learn | existing: test_deleting_the_state_forgets_enrollment_and_compromise_documented_limit; new: test_E11_no_pin_and_no_record_is_not_first_use |
| E12 | Record from another enrollment | REVOCATION_STATE_UNAVAILABLE | state store | Read another ceremony's mark as if it were this one's | new: test_S08_a_record_from_another_enrollment_is_refused |
| E13 | Statement that adds a new recovery anchor | refused REVOCATION_MALFORMED | transition verifier, recovery verifier | Let a statement replace the root of recovery | new: test_no_statement_can_name_a_new_recovery_anchor |
| E14 | Enrolled authority or anchor offered to `trust add` | refused, exit 2 | CLI | Enrol a revocation key as a report key; lists stop being accepted later | new: test_cli_trust_add_refuses_an_enrolled_authority_or_anchor |
| E16 | `advisory` with no baseline, first list | accepted, note REVOCATION_NO_HIGH_WATER_MARK | list verifier | Claim rollback detection it does not have | existing: test_valid_list_is_accepted_pure_and_reports_the_honest_limit; new: test_E16_advisory_with_no_baseline_says_it_has_no_mark |
| E17 | Old recovery statement replayed after a ceremony that lost the record | refused REVOCATION_TRANSITION_GAP or REVOCATION_FORK, or REVOCATION_REPEAT if the pin holds its digest; authority unchanged | enrollment, recovery verifier | Reset the generation at the ceremony, so an old statement reinstates an old authority | new: test_E17_a_ceremony_states_the_position_so_old_statements_cannot_move_the_authority_back |
| E18 | Ceremony pin behind the record's generation or recovery epoch | ceremony refused; authority history carried over otherwise | enrollment | Move the authority backwards and forget who was compromised | new: test_E18_a_ceremony_cannot_move_the_authority_backwards_or_drop_its_history |
| E19 | Ceremony names a key declared compromised | ceremony refused | enrollment | Re-enrol the stolen key | new: test_E19_a_ceremony_refuses_a_key_declared_compromised |
| E20 | Ceremony names a report key | ceremony refused | enrollment | Skip the purpose checks on the path used in an incident | new: test_E20_a_ceremony_runs_the_purpose_checks |
| E21 | First list at baseline + 1 | must chain to the baseline digest, else refused REVOCATION_FORK | list verifier, enrollment | Skip the chain on the first list | new: test_E21_a_first_list_right_after_the_baseline_must_chain_to_it |
| E15 | Pinned-authority store unreadable at startup under `required` | exit 3, HTTP refuses to start | CLI, server | Start with no authority and accept reports | new: test_cli_infrastructure_failures_exit_3 |

## L. List format and semantics

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| L01 | Golden list bytes, digest, signature | accepted, digest equal | list verifier | Drift in canonical bytes unnoticed | existing: test_golden_vectors_pin_canonical_bytes_digest_and_signature; test_golden_vectors_verify_with_the_prototype |
| L02 | Any leaf changed | refused REVOCATION_SIGNATURE_INVALID | list verifier | Accept altered entries | existing: test_every_leaf_field_is_tamper_evident; corpus:list-tampered-entry |
| L03 | Signature by another key, or truncated | refused REVOCATION_SIGNATURE_INVALID | list verifier | Accept a forged list | existing: test_claiming_the_pinned_fingerprint_without_the_key_fails_signature; corpus:list-bad-signature; corpus:list-truncated-signature |
| L04 | Signature from another role or domain | refused REVOCATION_SIGNATURE_INVALID | list verifier | Accept a transition signature as a list signature | existing: test_signature_over_other_domains_is_refused |
| L05 | Non-canonical base64 signature | refused REVOCATION_SIGNATURE_INVALID | list verifier | Allow signature malleability | existing: test_signature_encoding_must_be_canonical_base64 |
| L06 | Unknown or missing member | refused REVOCATION_MALFORMED | list verifier | Ignore a member, which could fail open | existing: test_removing_or_adding_any_member_is_refused; corpus:list-unknown-member |
| L07 | Duplicate JSON key | refused REVOCATION_MALFORMED | list verifier | Read a different value than the one signed | existing: corpus:list-duplicate-json-key |
| L08 | Non-JSON, oversized or deeply nested input | refused REVOCATION_MALFORMED | list verifier | Raise, or exhaust memory | existing: test_malformed_input_is_refused_not_raised; test_oversized_input_refused; test_deeply_nested_input_refused |
| L09 | `schema_version` or `algorithm_version` other than 1 | refused REVOCATION_VERSION_UNSUPPORTED | list verifier | Fall back and parse a newer format loosely | existing: test_unsupported_versions_are_refused_without_fallback; corpus:list-version-2 |
| L10 | `issuer` differs from the enrollment | refused REVOCATION_WRONG_ISSUER | list verifier | Let one issuer's authority revoke for another | existing: test_wrong_issuer_refused_even_when_correctly_signed; corpus:list-forged-issuer |
| L11 | Signed by a key other than the current authority | refused REVOCATION_AUTHORITY_MISMATCH | list verifier | Trust the key the list names | existing: test_list_signed_by_an_unpinned_key_is_refused; corpus:list-wrong-authority; corpus:list-wrong-generation |
| L12 | Report key used to sign a list | refused REVOCATION_KEY_IS_REPORT_KEY | list verifier | Let a report key revoke | existing: test_a_report_signing_key_is_not_accepted_as_a_revocation_key |
| L13 | `now >= valid_until` at ingest | refused REVOCATION_EXPIRED | list verifier | Accept a dead list, enabling old-list replay | existing: test_expired_and_not_yet_valid_lists_are_refused; corpus:list-expired |
| L14 | `valid_from` or `issued_at` past now + skew | refused REVOCATION_NOT_YET_VALID | list verifier | Accept a list from the future | existing: test_expired_and_not_yet_valid_lists_are_refused |
| L15 | `issued_at <= valid_from < valid_until` violated | refused REVOCATION_MALFORMED | list verifier | Accept an empty validity interval | existing: test_validity_ordering_is_enforced |
| L16 | `effective_from` after `issued_at` + skew | refused REVOCATION_MALFORMED | list verifier | Accept a forward-dated action that leaves a window open | existing: test_effective_from_after_issuance_is_refused |
| L17 | Entries unsorted or key_id duplicated | refused REVOCATION_MALFORMED | list verifier | Two readings of one document | existing: test_correctly_signed_but_unsorted_or_duplicate_entries_are_malformed; corpus:list-unsorted-entries; corpus:list-duplicate-entries |
| L18 | Same fingerprint under two key_ids in one list | refused REVOCATION_MALFORMED | list verifier | Accept two statuses for one key (observed) | new: test_one_fingerprint_may_appear_once_in_a_list |
| L19 | `null` boundary on a non-compromised entry, or `replaced` without successor | refused REVOCATION_MALFORMED | list verifier | Read an unknown retirement as no retirement | existing: test_replaced_requires_a_successor_and_only_compromised_may_have_unknown_boundary |
| L20 | Successor cycle or self-succession | refused REVOCATION_MALFORMED | list verifier | Loop while resolving, or treat a key as its own replacement | existing: test_successor_cycles_and_self_succession_are_refused |
| L21 | Same key_id as a local entry of this issuer, other fingerprint | refused REVOCATION_KEY_MISMATCH, no latch | list verifier | Merge state onto the wrong key, or latch on a local change | existing: test_fingerprint_mismatch_with_local_store_is_refused_never_merged; new: test_L29_a_same_issuer_key_mismatch_refuses_but_does_not_latch |
| L22 | Entry for another issuer's key, same fingerprint | refused REVOCATION_ISSUER_SCOPE, no latch | list verifier | Let issuer A revoke issuer B's key | existing: test_forged_issuer_wrong_authority_and_cross_issuer_revocation; corpus:list-cross-issuer-revocation |
| L23 | Entry for another issuer's key, by fingerprint under an alias | refused REVOCATION_ISSUER_SCOPE | list verifier | Same as L22, through a local alias (observed) | new: test_fingerprint_matching_does_not_open_a_cross_issuer_revocation |
| L24 | Successor enrolled locally with another key | refused REVOCATION_KEY_MISMATCH | list verifier | Accept a successor that contradicts the store | existing: test_successor_fingerprint_must_match_the_enrolled_successor |
| L25 | Entry for a key this store does not hold | accepted, retained | list verifier | Drop it, so a later `trust add` gets an active key | existing: test_entry_for_a_key_the_store_does_not_hold_is_kept_as_evidence |
| L26 | Draft schemas and prototype agree on structural tamper | agreement | list verifier | Schema and verifier diverge | existing: test_draft_schema_and_prototype_agree_on_structural_tamper; test_transition_schema_and_prototype_agree; test_recovery_schema_and_prototype_agree |
| L28 | Same key_id as another issuer's key, other fingerprint | unrelated: list accepted, other key untouched | list verifier, overlay | Let one issuer's choice of key_id refuse or latch another's lists (observed) | new: test_L28_a_key_id_collision_with_another_issuer_is_unrelated |
| L27 | Schemas, vectors and corpus unchanged | digest equal | issuer tooling | Silent format change | existing: test_frozen_files_match_their_pinned_digest; test_corpus_is_frozen_files_equal_regeneration; test_golden_vectors_are_exactly_what_the_generator_produces |

## M. Epochs and the monotone rule

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| M01 | Lower epoch than the mark | refused REVOCATION_ROLLBACK, no latch | list verifier | Accept an authentic old list | existing: test_epoch_chain_advances_and_rejects_replay_of_older_list; corpus:list-rollback-to-epoch1 |
| M02 | Same epoch, same bytes | accepted, note REVOCATION_REPEAT, no write | list verifier | Advance or re-write state on a replay | existing: test_same_epoch_same_content_is_a_repeat_not_a_fork; corpus:list-replay-epoch2; new: test_M19_a_repeat_and_a_refused_document_leave_the_record_bytes_unchanged |
| M03 | Same epoch, other digest | refused REVOCATION_FORK, latched | list verifier, state store | Keep whichever arrived last | existing: test_two_lists_with_the_same_epoch_and_different_content_are_a_fork; corpus:list-fork-epoch2 |
| M04 | Epoch + 1 with the wrong `prev_list_digest` | refused REVOCATION_FORK | list verifier, state store | Skip the chain check | existing: test_next_epoch_must_chain_to_the_accepted_digest; corpus:list-bad-chain-epoch3 |
| M05 | Epoch jump, monotone | accepted, note REVOCATION_EPOCH_GAP | list verifier | Refuse and strand a verifier that missed lists | existing: test_gap_is_allowed_with_a_note_only_if_monotone_and_can_be_forbidden; corpus:list-gap-epoch5 |
| M06 | Epoch jump with local policy forbidding gaps | refused REVOCATION_EPOCH_GAP | list verifier | Ignore the local policy | existing: test_gap_is_allowed_with_a_note_only_if_monotone_and_can_be_forbidden |
| M07 | Previously listed key omitted | refused REVOCATION_NOT_MONOTONE | list verifier, state store | Treat omission as un-revocation | existing: test_omitted_previously_revoked_key_is_refused_even_when_correctly_signed; corpus:list-omits-revoked-key |
| M08 | Compromised moved back to retired, boundary later, unknown made known, date edited | refused REVOCATION_NOT_MONOTONE | list verifier | Let a list loosen | existing: test_loosening_transitions_are_refused; corpus:list-loosens-compromise |
| M09 | Retired to compromised, boundary earlier, successor added | accepted | list verifier | Refuse legitimate tightening | existing: test_tightening_transitions_are_accepted |
| M10 | key_id rebound to another fingerprint | refused REVOCATION_NOT_MONOTONE | list verifier | Move a key's state to another key | existing: test_a_later_list_may_not_rebind_a_key_id_to_another_fingerprint |
| M11 | Higher epoch, earlier `issued_at` | refused REVOCATION_NOT_MONOTONE | list verifier | Accept a list that presents itself as older (observed) | new: test_a_higher_epoch_with_an_earlier_issued_at_is_not_monotone |
| M12 | Higher epoch, equal `issued_at` | accepted | list verifier | Refuse same-second heartbeats | new: test_equal_issued_at_is_allowed_across_epochs |
| M13 | Refused list | mark and record bytes unchanged | state store | Advance on refusal | existing: test_refused_list_never_advances_the_mark; new: test_M19_a_repeat_and_a_refused_document_leave_the_record_bytes_unchanged |
| M14 | Commit out of order | mark not lowered | state store | Last call wins | existing: test_commit_is_monotone_even_if_called_out_of_order |
| M15 | Epoch 1 with a predecessor, or later epoch without one | refused REVOCATION_MALFORMED | list verifier | Accept a broken chain start | existing: test_epoch_one_has_no_predecessor_and_later_epochs_must_name_one |
| M16 | Marks are per issuer and survive rotation | separate, kept | state store | One issuer's epoch blocks another's | existing: test_marks_are_per_issuer_and_authority; test_per_issuer_mark_survives_authority_rotation_and_get_takes_only_the_issuer |
| M17 | Retired R, later compromise at C after R | unclamped refused REVOCATION_NOT_MONOTONE; `min(R, C)` accepted | list verifier, issuer tooling | Accept a boundary later than the retirement | new: test_M17_an_issuer_must_publish_a_later_compromise_of_a_retired_key_clamped |
| M18 | Each signed contradiction, through the store: chain fork, omission, `issued_at` backwards, same-epoch fork | latched; reports INVALID REVOCATION_CONTRADICTORY | state store, gate | Refuse the list and keep accepting on the old mark | new: test_M18_every_signed_contradiction_latches_through_the_store |

## A. Routine rotation

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| A01 | Valid transition, then a list by the new key | accepted, generation + 1, epoch chain continues | transition verifier | n/a: positive control | existing: test_routine_rotation_hands_over_and_the_epoch_chain_continues; corpus:transition-valid; corpus:list-by-new-authority |
| A02 | List by the old key after rotation | refused REVOCATION_AUTHORITY_SUPERSEDED | list verifier | Keep trusting retired authorities | existing: corpus:list-by-superseded-authority |
| A03 | Missing or swapped signature, no proof of possession | refused REVOCATION_SIGNATURE_INVALID | transition verifier | Hand over to a key nobody holds | existing: test_transition_requires_both_signatures_and_binds_roles; corpus:transition-no-possession-proof; corpus:transition-impostor-from |
| A04 | Generation not current + 1 | refused REVOCATION_TRANSITION_GAP | transition verifier | Skip generations | existing: test_transition_generation_gaps_and_replay; corpus:transition-generation-gap |
| A05 | Replay of an applied transition | refused REVOCATION_AUTHORITY_SUPERSEDED | transition verifier | Re-apply | existing: test_transition_generation_gaps_and_replay; corpus:transition-replay |
| A06 | Transition back to an earlier key | refused REVOCATION_TRANSITION_CYCLE | transition verifier | Revive a retired authority | existing: test_transition_chains_gaps_cycles_and_order; corpus:transition-cycle-back-to-old |
| A07 | Transition to the anchor or a report key | refused REVOCATION_KEY_IS_REPORT_KEY | transition verifier | Collapse role separation | existing: test_transition_validity_period_and_role_conflicts; corpus:transition-to-recovery-anchor |
| A08 | Transition for another issuer | refused | transition verifier | Cross-issuer takeover | existing: test_transition_for_another_issuer_is_not_accepted |
| A09 | Any leaf changed | refused | transition verifier | Accept an altered handover | existing: test_every_leaf_of_a_transition_is_tamper_evident; test_transition_member_removal_addition_and_malformed_input |
| A10 | Transition past `valid_until` for a long-offline verifier | refused REVOCATION_EXPIRED; list by new key refused REVOCATION_AUTHORITY_MISMATCH; re-baseline needed | transition verifier | Accept any old handover, including from a key stolen long ago | existing: test_transition_validity_period_and_role_conflicts; new: test_A10_a_long_offline_verifier_fails_closed_until_a_ceremony |
| A11 | Mark signed by a superseded key, still fresh | TRUSTED until stale | gate | Refuse every report at the moment of a routine rotation | new: test_A11_routine_rotation_keeps_the_mark_usable_until_it_lapses |
| A12 | Transition while a contradiction is latched | refused REVOCATION_CONTRADICTORY | transition verifier, state store | Let a possible thief move the authority | new: test_G05_contradiction_latches_until_recovery_and_only_a_signature_can_cause_it |
| A13 | Routine and recovery statements swapped | refused | transition verifier, recovery verifier | Accept one as the other | existing: test_routine_and_recovery_statements_are_not_interchangeable |

## C. Compromise recovery

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| C01 | Valid statement | accepted, authority replaced, generation raised | recovery verifier | n/a: positive control | existing: test_recovery_replaces_a_compromised_authority_via_the_independent_anchor; corpus:recovery-valid |
| C02 | No anchor enrolled | refused REVOCATION_RECOVERY_ANCHOR_ABSENT | recovery verifier | Accept the statement's own anchor | existing: test_recovery_needs_an_enrolled_recovery_anchor; corpus:recovery-anchor-absent |
| C03 | Signed by the authority, not the anchor | refused REVOCATION_RECOVERY_ANCHOR_MISMATCH | recovery verifier | Let a thief recover to their own key | existing: test_recovery_signed_by_the_authority_itself_is_refused; corpus:recovery-signed-by-authority |
| C04 | Forged anchor signature, or no possession proof by the new key | refused REVOCATION_SIGNATURE_INVALID | recovery verifier | Install a key nobody holds | existing: test_recovery_requires_possession_by_the_new_authority; corpus:recovery-forged-anchor-signature |
| C05 | Lower `recovery_epoch` | refused REVOCATION_RECOVERY_REPLAY | recovery verifier | Revert to an earlier recovery | existing: test_recovery_replay_fork_and_repeat |
| C06 | Same `recovery_epoch`, other content | refused REVOCATION_FORK | recovery verifier | Accept two recoveries | existing: test_recovery_replay_fork_and_repeat; corpus:recovery-fork-same-epoch |
| C07 | **Replay of the same statement after later lists** | accepted, note REVOCATION_REPEAT, mark and record unchanged | recovery verifier, state store | Re-apply the rebase, so anyone can lower the mark and have an older list accepted (observed) | new: test_replaying_a_recovery_statement_never_lowers_the_mark_again; test_R02_replaying_recovery_through_the_store_writes_nothing |
| C08 | New key reused, or generation not raised | refused REVOCATION_TRANSITION_CYCLE or REVOCATION_TRANSITION_GAP | recovery verifier | Reinstate the stolen key | existing: test_recovery_new_authority_must_be_fresh_and_generation_must_increase; corpus:recovery-reuses-compromised-key |
| C09 | Declares nothing, or declares its own new key or anchor | refused REVOCATION_MALFORMED or REVOCATION_TRANSITION_CYCLE | recovery verifier | Replace an authority with no declaration | existing: test_recovery_statement_shape_rules; test_recovery_cannot_declare_its_own_new_authority_compromised; corpus:recovery-declares-nothing |
| C10 | Compromised authority signs after the declaration | refused REVOCATION_AUTHORITY_COMPROMISED | list verifier, transition verifier | Keep accepting a thief | existing: test_old_authority_signs_a_transition_after_it_was_declared_compromised; corpus:list-by-compromised-authority; corpus:transition-by-compromised-authority |
| C11 | Transition accepted earlier from a key later declared compromised | superseded; voided only at or after the boundary | recovery verifier | Leave the thief's authority in place | existing: test_transition_accepted_before_recovery_is_superseded_by_the_recovery_statement; test_only_transitions_at_or_after_the_boundary_are_voided |
| C23 | Recovery refused for a lost baseline, on a clean gap verifier | refused REVOCATION_RECOVERY_BASELINE_UNKNOWN; declaration committed; thief's lists refused REVOCATION_AUTHORITY_COMPROMISED; report INVALID | recovery verifier, state store, gate | Change nothing on refusal, so the stolen key stays live and a report it vouches for is TRUSTED (observed) | new: test_C23_a_refused_recovery_still_commits_what_it_declares |
| C24 | Statement past `valid_until`, long-offline verifier | refused REVOCATION_EXPIRED; declaration committed | recovery verifier, state store | Same as C23 (observed) | new: test_C24_a_statement_past_its_validity_still_tells_a_long_offline_verifier |
| C25 | Forged anchor signature | declares nothing; record unchanged | recovery verifier | Let anyone condemn an authority | new: test_C25_a_forged_anchor_signature_declares_nothing |
| C26 | Thief took the verifier to generation 2; honest recovery at generation 2 | accepted, generation 2 | recovery verifier | Compare with the thief's generation, so one hop defeats recovery (observed) | new: test_C26_one_thief_hop_does_not_make_the_honest_recovery_refuse_itself |
| C27 | Recovery generation not above the last honest one | refused REVOCATION_TRANSITION_GAP | recovery verifier | Accept any generation | new: test_C27_a_generation_that_does_not_clear_the_last_honest_one_is_still_refused |
| C28 | Statement names only K1; thief installed a key and signed a list with it | installed key compromised, unknown boundary; report INVALID REVOCATION_AUTHORITY_COMPROMISED | recovery verifier, gate | Mark it superseded, so the thief's mark keeps counting (observed) | new: test_C28_a_key_the_owner_never_saw_is_condemned_with_the_transition_that_installed_it |
| C29 | Several thief hops | all voided, all installed keys compromised | recovery verifier | Stop at the first hop | new: test_C29_every_hop_after_the_first_voided_transition_is_condemned |
| C30 | New authority equal to a condemned key | refused REVOCATION_TRANSITION_CYCLE | recovery verifier | Reinstate the thief's key | new: test_C30_a_new_authority_equal_to_a_condemned_key_is_refused |
| C31 | Thief backdates a transition before the boundary | voided on acceptance time | recovery verifier | Trust `issued_at` (observed) | new: test_C31_a_backdated_transition_from_a_stolen_key_is_voided |
| C32 | Honest list after recovery, no chain to the thief's mark | accepted, note REVOCATION_MARK_CONDEMNED; no latch; tightening kept | list verifier, state store | Latch on what the thief told this verifier (observed) | new: test_C32_an_honest_list_after_recovery_does_not_latch_on_what_the_thief_said |
| C33 | Lower epoch than a condemned mark | refused REVOCATION_ROLLBACK, no latch | list verifier | Drop the floor with the mark | new: test_C33_a_condemned_mark_still_stops_an_older_epoch |
| C34 | Same epoch as a condemned mark | accepted | list verifier | Latch as a fork | new: test_C34_a_same_epoch_list_replaces_a_condemned_mark |
| C35 | Second statement at one `recovery_epoch` | refused REVOCATION_FORK, no latch | recovery verifier | Latch on a public document | new: test_C35_recovery_forks_do_not_latch |
| C36 | Anchor later added as a report key | refused REVOCATION_KEY_IS_REPORT_KEY | recovery verifier | Let a report key act as the recovery root | new: test_C36_an_anchor_later_added_as_a_report_key_stops_validating_recovery |
| C37 | Expired statement, thief had installed a key | declaration and installed key both committed | recovery verifier, state store | Leave the installed key current | new: test_C37_an_expired_statement_also_condemns_the_key_a_thief_installed |
| C12 | Epoch inflation, no rebase | new authority's low epoch refused REVOCATION_ROLLBACK | list verifier | n/a: stated behaviour | existing: test_epoch_poisoning_blocks_the_new_authority_without_a_rebase |
| C13 | Rebase to an archived list | mark lowered to it | recovery verifier, state store | Leave the inflated mark | existing: test_recovery_with_rebase_restores_the_last_good_list_from_the_archive |
| C14 | Rebase to an unknown list, mark at or above it, or no mark | refused REVOCATION_RECOVERY_BASELINE_UNKNOWN | recovery verifier | Guess a position | existing: test_rebase_to_an_unknown_baseline_is_refused_not_guessed; corpus:recovery-unknown-baseline; new: test_rebase_at_the_same_epoch_with_another_digest_stays_unknown |
| C15 | **Rebase beyond a clean verifier's mark** | accepted, note REVOCATION_REBASE_NOOP, mark unchanged, authority replaced | recovery verifier | Refuse, leaving the verifier on the stolen authority (observed) | new: test_rebase_is_a_noop_for_a_verifier_that_never_passed_the_baseline |
| C16 | Rebase keeps every tightening | mark lowered, joined actions kept | state store | Forget a compromise on rebase | new: test_R01_rebase_lowers_the_mark_but_keeps_every_tightening |
| C17 | Compromise boundary only moves earlier across recoveries | tightened | recovery verifier | Later statement widens | existing: test_a_later_recovery_can_only_tighten_a_compromise_boundary |
| C18 | Recovery supersedes a current authority not declared compromised | superseded | recovery verifier | Leave two live authorities | existing: test_recovery_supersedes_a_current_authority_that_was_not_declared_compromised |
| C19 | Anchor holder replaces the authority | accepted: stated limit | recovery verifier | n/a: limit asserted so nobody reads the anchor as more than it is | existing: test_the_recovery_anchor_is_a_total_trust_root_documented_limit |
| C20 | Recovery does not loosen | no loosening API; joined actions kept through a rebase | overlay, state store | Clear a key on recovery | existing: test_recovery_never_loosens_the_local_trust_store; new: test_R01_rebase_lowers_the_mark_but_keeps_every_tightening |
| C21 | Any leaf of a statement changed | refused | recovery verifier | Accept an altered recovery | existing: test_every_leaf_of_a_recovery_statement_is_tamper_evident |
| C22 | Malformed signature on any statement kind | refused, not raised | list verifier, transition verifier, recovery verifier | Raise out of the verifier | existing: test_malformed_signature_encodings_on_every_statement_kind |

## K. Key states and the join

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| K01 | Every local state joined with every listed state | the stricter, per section 5.2 | overlay | Loosen on one of the combinations | existing: test_apply_is_the_stricter_of_local_and_list |
| K02 | Local compromise later than a listed retirement | compromised at the earlier time | overlay | Keep the later time, which re-opens an interval (observed) | new: test_local_compromise_later_than_a_listed_retirement_takes_the_earlier_time |
| K03 | Sequential joins equal one join, all pairs | equal | overlay | Depend on list order | new: test_R03_join_is_the_same_as_applying_lists_one_after_the_other |
| K04 | Listed key under a local alias | listed state applied | overlay | Leave the compromised key active (observed) | new: test_a_listed_key_is_matched_by_fingerprint_under_a_local_alias |
| K05 | Unmentioned entries and other fields | untouched | overlay | Damage pins and scopes | existing: test_apply_keeps_unmentioned_entries_and_unrelated_fields_untouched |
| K06 | Successor named | evidence only: no enrollment, no trust | overlay | Trust the successor | existing: test_naming_a_successor_does_not_make_it_trusted_nor_replace_the_old_key; test_replaced_by_successor_chain_is_signed_and_fingerprint_bound |
| K07 | Retired R, timestamp after R | INVALID SIGNED_AFTER_RETIREMENT | engine | Accept a new signature from a retired key | existing: test_worked_example |
| K08 | Compromised C, timestamp after C | INVALID SIGNED_AFTER_COMPROMISE | engine | Accept a thief's signature | existing: test_worked_example |
| K09 | Compromised, unknown boundary, any evidence | INVALID KEY_COMPROMISED_NO_CHRONOLOGY | engine | Accept with an early token | existing: test_worked_example; test_compromise_in_a_verified_list_is_never_rescued_by_chronology_missing |
| K10 | Report by the enrolled successor, and by one not enrolled | TRUSTED, and INVALID ISSUER_UNKNOWN | engine | Accept the unenrolled successor from the list's say-so | existing: test_worked_example |

## S. State store

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| S01 | Crash before the rename, and after it | whole old or whole new record; re-delivery converges | state store | Leave a half-written record, or lose the update silently | new: test_S01_crash_mid_update_leaves_either_the_old_or_the_new_record_whole |
| S02 | Torn record | REVOCATION_STATE_UNAVAILABLE at ingest and gate; only a ceremony recovers | state store | Read it as empty, so rollback detection silently ends | new: test_S02_torn_record_is_refused_and_recovered_only_by_a_ceremony; test_S02_an_edited_record_that_is_still_valid_json_is_refused |
| S03 | Record lost, pin survives | REVOCATION_STATE_LOST at ingest and gate; INVALID | state store, gate | Treat as first use (observed: a missing file loads as empty) | new: test_S03_lost_state_with_a_surviving_pin_fails_closed_as_lost |
| S04 | Restored from backup, running process, also after authentic old lists walk `seq` back up | REVOCATION_STATE_ROLLBACK | gate | Compare `seq` only and carry on from the older mark (observed) | new: test_S04_a_process_that_remembers_the_counter_detects_a_restore; test_S17_a_public_replay_after_a_restore_does_not_hide_the_lost_position; test_S04_a_restore_that_only_removes_a_latch_is_detected |
| S05 | Restored from backup, fresh process, local file, older list replayed, no authority key held | accepted, undetected, until stale; a newer list recovers. Stated limit | gate | Claim to detect this, or lack the staleness bound | new: test_S05_HONEST_LIMIT_restore_is_not_detected_by_a_fresh_process_and_is_bounded_by_validity; existing: test_HONEST_LIMIT_deleting_or_lowering_the_state_defeats_rollback_detection |
| S06 | Restore with a re-baseline ceremony | older lists refused REVOCATION_ROLLBACK | enrollment, state store | Accept from the restored position | new: test_S06_restore_ceremony_with_a_fresh_baseline_refuses_older_lists |
| S07 | Ceremony keeps key actions unless cleared | kept; `seq` keeps rising | enrollment | Forget compromise knowledge as a side effect | new: test_S07_the_ceremony_keeps_key_actions_unless_the_operator_clears_them |
| S08 | Record from another enrollment | REVOCATION_STATE_UNAVAILABLE | state store | Trust a mark from an old ceremony | new: test_S08_a_record_from_another_enrollment_is_refused |
| S09 | Slow writer with an older list loses the race | re-verifies, refused REVOCATION_ROLLBACK, mark not lowered | state store | Last writer wins, and the mark falls (observed: 3 to 2) | new: test_S09_lost_race_re_verifies_and_never_lowers_the_mark |
| S10 | Endless contention | refused REVOCATION_STATE_CONFLICT, nothing written | state store | Write blindly after a retry limit | new: test_S10_endless_contention_is_a_refusal_not_a_blind_write |
| S11 | Real threads, reversed order, on the file store | ends at the highest epoch | state store | Lose the top list | new: test_S11_real_threads_on_the_file_store_end_at_the_highest_epoch |
| S12 | Independent verifiers without a shared store | may differ; nothing claims otherwise | gate | Claim global state | new: test_S12_two_verifiers_without_a_shared_store_can_disagree_and_nothing_claims_otherwise |
| S13 | Verifiers sharing one store | one mark | state store | Cache a mark past the next read | new: test_S13_two_verifiers_sharing_one_store_see_one_mark |
| S14 | Report verification, with or without presented evidence | writes no revocation state | gate, wrapper | Turn verification into a write, and let the report's channel feed trust history (observed) | new: test_S14_report_verification_never_writes_the_state; test_G30_presented_evidence_is_compared_and_never_written |
| S15 | Refusal leaves the record unchanged, and verification is pure | no change | list verifier, transition verifier, recovery verifier | Partially apply a refused document | existing: test_valid_list_is_accepted_pure_and_reports_the_honest_limit; test_enrollment_state_round_trips_and_verification_is_pure; test_failed_save_leaves_the_previous_state_and_no_temp_file |
| S16 | Power loss after rename on a real filesystem, real independent store under failover | same as S01, S04 | state store | Only a real store shows this | none |
| S17 | Position compared, not only the counter | see S04 | gate | See S04 | new: test_S17_a_public_replay_after_a_restore_does_not_hide_the_lost_position |
| S18 | Recovery lowers the position for a process that remembers it | not a rollback | gate | Fail closed on a legitimate rebase | new: test_S18_recovery_may_lower_the_position_for_a_process_that_remembers_it |
| S19 | Restored record, recovery withheld, stolen key signs fresh lists | accepted. Stated limit, outside the 9.6 bound | gate | Claim the bound holds here | new: test_S19_HONEST_LIMIT_the_staleness_bound_does_not_hold_against_a_stolen_authority_key |
| S20 | Ceremony on a missing or unreadable record | refused unless the loss is stated | enrollment | Silently lose compromise knowledge | new: test_S20_a_ceremony_cannot_lose_key_actions_by_accident |
| S21 | Process memory after a ceremony | per enrollment: no false rollback | gate | Fail closed until restart (observed) | new: test_S21_the_process_memory_is_per_enrollment |
| S22 | Largest legal list | accepted; gate and recovery still work | state store | Write a record it cannot read back (observed) | new: test_S22_the_largest_legal_list_does_not_brick_the_verifier |
| S23 | Archive at the limit | pruned oldest first; mark kept | state store | Grow until the verifier is bricked (observed: about 360 days at 30 entries) | new: test_S23_the_archive_is_pruned_oldest_first_to_stay_inside_the_limit |
| S24 | Record cannot fit | refused REVOCATION_STATE_FULL; record unchanged and usable | state store | Same as S22 | new: test_S24_a_record_that_cannot_fit_refuses_the_document_and_stays_usable |

## G. Verification-time gate

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| G01 | Fresh list, active key, `required`, `high-assurance` | TRUSTED; evidence and limit disclosed; `policy_id` marked | gate, wrapper | Omit the as-of qualification | new: test_G01_fresh_list_active_key_accepted_with_disclosure |
| G02 | No list ever accepted | INVALID REVOCATION_DATA_ABSENT | gate | Read absence as "nothing revoked" and accept (observed: draft row P) | new: test_G02_no_list_ever_accepted_fails_closed |
| G03 | Past `valid_until` at verification | INVALID REVOCATION_DATA_STALE | gate | Check validity only at ingest and accept forever | new: test_G03_list_past_valid_until_fails_closed; test_G03_a_short_validity_ends_before_the_evidence_age_does |
| G04 | Older than the evidence age, still inside `valid_until` | INVALID REVOCATION_DATA_STALE | gate | Honour a 70-year validity (observed) | new: test_G04_list_older_than_the_evidence_age_fails_closed_even_inside_its_validity |
| G05 | Signed contradiction | latched: INVALID REVOCATION_CONTRADICTORY; lists and transitions refused; only recovery or a ceremony clears | gate, state store | Refuse the list and keep accepting reports on the old mark | new: test_G05_contradiction_latches_until_recovery_and_only_a_signature_can_cause_it |
| G06 | Older list replayed in the background | list refused REVOCATION_ROLLBACK; no latch; reports continue on the mark | list verifier, gate | Latch, so anyone can deny service with a public document | new: test_G06_a_replayed_older_list_refused_does_not_latch_and_needs_no_key |
| G07 | Older list presented as the evidence for one call | INVALID REVOCATION_ROLLBACK | wrapper | Accept on the mark and hide the attempt | new: test_G07_a_presented_rolled_back_list_refuses_that_verification |
| G08 | Store down, record corrupt or torn | INVALID REVOCATION_STATE_UNAVAILABLE | gate | Fall back to no revocation data | new: test_G08_unusable_state_fails_closed_never_as_empty |
| G09 | Issuer not enrolled | INVALID REVOCATION_NOT_ENROLLED | gate | Skip the gate for unknown issuers | new: test_G09_issuer_not_enrolled_fails_closed |
| G10 | Gate refusal, then retry after data arrives | first refusal records nothing; retry TRUSTED and recorded | wrapper, engine | Burn the `audit_run_id` on a refusal | new: test_G10_a_gate_refusal_does_not_burn_the_replay_identifier |
| G11 | Report claims a fresh issuer under another issuer's key | gate of the store's issuer: INVALID REVOCATION_DATA_ABSENT | wrapper | Take the issuer from the report and pick a fresh one | new: test_G11_the_issuer_comes_from_the_trust_store_not_the_report |
| G12 | Mark signed by an authority declared compromised | INVALID REVOCATION_AUTHORITY_COMPROMISED until a new list | gate | Keep relying on a thief's last list (observed: the mark stays) | new: test_G12_marks_from_a_compromised_authority_stop_counting_after_recovery |
| G13 | Mark taken before a known compromise boundary | usable | gate | Refuse honest evidence | new: test_G13_a_mark_taken_before_a_known_compromise_boundary_stays_usable |
| G14 | Clock behind the state floor | INVALID REVOCATION_CLOCK_REGRESSION | gate | Accept expired data by winding the clock back | new: test_G14_clock_behind_the_state_floor_fails_closed |
| G15 | Listed key: engine refuses on the overlay | INVALID key-state code; file untouched | overlay, engine | Rewrite the operator's file, or ignore the list | new: test_G15_a_listed_key_is_refused_by_the_engine_on_the_overlay_and_the_file_is_untouched |
| G16 | Key enrolled after the list | listed state applies | overlay | Enrol a revoked key as active | new: test_G16_a_key_enrolled_after_the_list_still_gets_the_listed_state |
| G17 | File hand-edited back to active | listed state still applies | overlay | Let a file edit undo the authority's statement | new: test_G17_hand_loosening_the_local_file_does_not_undo_listed_state |
| G18 | `advisory`, no data; then listed key | TRUSTED with a note and `unproven`; then INVALID key-state code | wrapper | Fail closed in the wrong mode, or claim evidence it lacks | new: test_G18_advisory_mode_tightens_but_does_not_fail_closed |
| G19 | `off` | output equal to the engine, `policy_id` unchanged, even with listed state present | wrapper | Change a verdict without an opt-in | new: test_G19_off_is_exactly_the_engine |
| G20 | `high-assurance` + `advisory`; bare store; non-durable store; no baseline | startup refused | config check | Run a fail-open configuration | new: test_G20_unsafe_configurations_are_refused_at_startup |
| G21 | Signature valid, issuer once trusted, key now listed | INVALID with `integrity_valid: true` | wrapper, engine | Treat a valid signature as current trust | new: test_G21_an_old_signature_by_a_listed_compromised_key_is_refused_when_newly_presented |
| G22 | Exit codes and HTTP status for each gate row | per section 10.2 | CLI, server | Exit 1 for an infrastructure failure, or 0 for anything | new: test_cli_end_to_end_required_with_exit_codes; test_cli_infrastructure_failures_exit_3 |
| G23 | `serve` picks up a list with no restart | gate re-reads state per request | server | Hold state from startup, as it does the trust store | none |
| G24 | Gate codes on the existing result contract, `to_dict`, `valid` alias | additive; no field removed; `off` byte-identical | wrapper | Break callers | new: test_default_cli_output_has_exactly_the_published_fields; test_http_verify_output_has_exactly_the_published_fields |
| G26 | Stolen key signs a list claiming a time before the boundary | INVALID REVOCATION_AUTHORITY_COMPROMISED | gate | Compare the thief's own `issued_at` (observed) | new: test_G26_a_backdated_list_from_a_stolen_key_does_not_survive_as_evidence |
| G27 | `signer-asserted` with any mode | startup refused | config check | Let a report's own clock rescue a listed key under `required` (observed) | new: test_G27_signer_asserted_time_cannot_be_combined_with_a_revocation_mode |
| G28 | Local store changes, then anyone replays an old list | refused REVOCATION_ROLLBACK; no latch | list verifier | Run store checks first and latch, so anyone can deny service (observed) | new: test_G28_replaying_an_old_list_after_a_local_store_change_stays_a_rollback |
| G29 | Fork adjudicated by a ceremony, then replayed | refused REVOCATION_FORK; no latch | state store | Latch again forever by replay (observed) | new: test_G29_a_ceremony_adjudicates_a_fork_so_replaying_either_side_cannot_relatch |
| G30 | Presented fork, garbage, and a newer list | first two refuse that call; the newer list is not applied; record bytes unchanged | wrapper | Write from the report's channel, or latch from it (observed) | new: test_G30_presented_evidence_is_compared_and_never_written |
| G31 | Unknown key under a mode | engine refuses; disclosure present | wrapper | Omit the limit text | new: test_G31_an_unknown_key_still_gets_the_disclosure |
| G25 | State store unreachable, `advisory` | engine on the local store, note | wrapper | Crash | new: test_G25_unreachable_state_under_advisory_runs_the_engine_on_the_local_store |

## D. Distribution

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| D01 | Fetch failed or list missing, `off` or `advisory` | store unchanged, evidence `unproven` | wrapper | Say "nothing revoked" | existing: test_missing_list_means_unproven_not_nothing_revoked; test_unverifiable_lists_change_nothing_and_give_no_history; new: test_D01_a_failed_fetch_through_the_wrapper_is_unproven_not_nothing_revoked |
| D02 | Fetch failed for longer than the evidence age, `required` | INVALID REVOCATION_DATA_STALE | gate | Keep accepting | new: test_G04_list_older_than_the_evidence_age_fails_closed_even_inside_its_validity |
| D03 | Verifier inputs are the document bytes and local state only | same bytes, same outcome; no input names a channel | list verifier | Require or trust the channel | existing: test_corpus_case |
| D04 | Bare download of an authority key | enrolls nothing | enrollment | Install a key from a channel | existing: test_nothing_is_enrolled_from_a_list_or_statement |
| D05 | Feed serves everything on every poll, out of order | applied in the order of section 8.4; passed transitions discarded; repeated polls succeed | state store | Stop at its first replay and never advance (observed) | new: test_D05_a_feed_can_be_polled_repeatedly_and_in_any_order |
| D07 | List from a generation not reached yet | refused REVOCATION_AUTHORITY_MISMATCH; no latch | list verifier | Latch on ordinary delivery order | new: test_D07_a_list_from_a_generation_not_reached_yet_does_not_latch |
| D06 | Issuer tooling persists its epoch before publishing, then crashes | no accidental fork | issuer tooling | Re-issue the same epoch with new content | new: test_a_crash_after_persist_leads_to_a_gap_and_never_a_fork |

## H. Historical verification

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| H01 | Retired or compromised, `required`, seven timestamp cases | never TRUSTED; code per case | engine, wrapper | Derive history from the list | new: test_H01_required_mode_never_accepts_history_from_a_list |
| H02 | Claimed `issued_at` long before the boundary, nothing authenticated | INVALID KEY_RETIRED_NO_CHRONOLOGY | engine | Believe the report's clock | new: test_H02_claimed_issued_at_alone_never_rescues_a_retired_key; existing: test_worked_example |
| H03 | Timestamp attached, no pinned verifier | `UNVERIFIED`, not chronology | engine | Read an unverified token as time | new: test_H03_a_timestamp_without_a_pinned_verifier_is_not_chronology |
| H04 | `high-assurance`, caller supplies a `TrustHistory` | INVALID TRUST_STORE_FRESHNESS_UNPROVEN | engine | Honour it | new: test_H04_no_trust_history_is_derived_for_high_assurance_even_when_a_caller_supplies_one; existing: test_high_assurance_still_refuses_historical_acceptance_with_a_verified_list |
| H05 | List-derived history off by default, never for high-assurance | `None` | list verifier | Turn on by default | existing: test_list_derived_history_is_off_by_default_and_never_for_high_assurance; test_expired_list_gives_no_authenticated_history; test_a_stale_mark_does_not_become_history_when_the_list_is_gone |
| H06 | Option for lower profiles, if the owner ever approves OD-7 | accepted only with chronology before the boundary | list verifier, engine | Accept without chronology | existing: test_verified_list_makes_authenticated_history_producible_for_the_existing_seam; test_worked_example |
| H07 | `signer-asserted` outside `development` | not selectable | engine | Let a higher profile use signer time | existing: test_worked_example |
| H08 | `report.v1` timestamp block | never chronology | engine | Treat a body-only token as covering the signature | new: test_H08_a_report_v1_timestamp_block_is_never_chronology |

## T. Trust-store migration

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| T01 | Bare and legacy active | `active`, issuer as stated | migration tool | Invent an issuer | new: test_T01_legacy_forms_migrate_to_the_expected_state |
| T02 | Legacy revoked | compromised, unknown boundary; never retired; reason change reported | migration tool | Map to retired, which re-opens history | new: test_T02_legacy_revoked_is_never_retired |
| T03 | Pins | carried over | migration tool | Drop a pin, which widens acceptance | new: test_T03_pins_survive_migration |
| T04 | Entries source; missing issuer; issuer for an unknown key | refused, nothing produced | migration tool | Infer, or partially migrate | new: test_T04_migration_refusals |
| T05 | Every published report, every legacy form, every profile | development: accept or refuse unchanged for the right issuer; strict: the migrated store is refused (owner's ruling); only `KEY_REVOKED` changes name | migration tool, engine | Change a verdict silently | new: test_T05_migration_preserves_the_accept_or_refuse_outcome_for_the_right_issuer |
| T06 | Wrong issuer stated | newly INVALID ISSUER_MISMATCH; reported in advance | migration tool | Not warn | new: test_T06_a_wrong_issuer_statement_changes_the_verdict_and_the_report_says_so |
| T07 | Lifecycle commands after migration | work | migration tool | Produce a store the tools refuse | new: test_T07_migrated_store_works_with_the_lifecycle_commands |
| T08 | Lifecycle commands on legacy forms | still refused, file byte-identical | CLI | Convert in place | new: test_T08_lifecycle_commands_still_refuse_the_legacy_forms; existing: test_legacy_store_cannot_carry_lifecycle_state |
| T09 | Local-only state after migration, opted in | stays in force beside the list | overlay | Let an empty list clear it | new: test_T09_after_migration_opting_in_works_and_a_local_only_state_stays |
| T10 | Target exists, source unchanged, permission bits kept, dry run over a corpus | as section 13.4 | migration tool | Overwrite | new: test_migrate_writes_a_new_file_and_leaves_the_source |
| T11 | Legacy store with a mode other than `off` | startup refused REVOCATION_STORE_UNSUPPORTED | config check | Run with no lifecycle state | new: test_V04_opting_in_with_a_legacy_store_is_a_configuration_error_not_a_verdict |
| T12 | Downgrade to 0.2.x after opting in | file unchanged; listed state no longer applies | CLI | Corrupt the file | none |

## V. Published reports

Signers 0.1.0, 0.1.1, 0.2.0 and 0.2.1. The vectors in `tests/experimental_revocation/published_vectors/` were signed by the published
wheels, downloaded from PyPI with their SHA-256 checked.

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| V01 | `off`: 4 signers, 3 report kinds, 6 store forms, 3 profiles | the section 13.2 table, written independently of the engine; a store without issuers under a strict policy is refused (F-09) | engine, wrapper | Change a verdict with no opt-in | new: test_V01_without_opt_in_every_published_report_keeps_its_verdict |
| V02 | `required`, fresh data: not listed, retired, compromised | the section 13.2 table; `policy_id` marked | wrapper, engine | Accept a listed key | new: test_V02_required_mode_with_fresh_data |
| V03 | `required`, no data, every published report | INVALID REVOCATION_DATA_ABSENT; `integrity_valid` unchanged | gate | Accept old reports as grandfathered | new: test_V03_required_mode_with_no_data_refuses_every_published_report |
| V04 | Vectors signed by the versions they name | version strings match | test harness | Test the wrong code | new: test_vectors_were_signed_by_the_version_they_are_named_after |
| V05 | Pin set to one version's hash, reports from each | PIN_MISMATCH for other versions, in `off` and `required` alike | engine | Change the existing pin behaviour | new: test_V05_a_parameter_set_pin_binds_the_signer_version_today_and_stays_that_way |
| V06 | Installed wheel of every published version against product code, cross-engine comparison | byte-identical under `off` | release harness | Regress silently | none |
| V07 | Full verdict comparison at release: 1368-record harness extended to 0.2.1 | byte-identical | release harness | Regress silently | none |

## N. Guards

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| N01 | Shipped code while this is experimental | no registration, nothing exported, default off, default path loads no revocation code | test harness | Ship by accident | new: test_nothing_is_registered_or_shipped_in_the_schema_list; test_nothing_new_is_exported_from_the_top_level; test_importing_the_package_loads_no_revocation_code; test_the_engine_knows_nothing_of_revocation; test_the_cli_default_is_off |
| N02 | Matrix, registry and code name the same things. This does not check that a named test exercises its row | agreement | test harness | Drift | new: test_every_named_test_exists_where_its_label_says; test_codes_in_the_code_and_the_matrix_are_all_in_the_registry; test_every_registered_code_has_a_matrix_row; test_the_gate_table_matches_the_infrastructure_codes |
| N03 | Documents avoid assurance claims | no forbidden wording | test harness | Overclaim | new: test_no_document_uses_forbidden_assurance_language |

## P. Owner rulings on the implementation

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| P01 | `high-assurance` with `required` or `advisory`, any store, public path | PolicyError REVOCATION_HIGH_ASSURANCE_UNAVAILABLE; CLI exit 2 | wrapper | Fall back to a local file, or trust a store that says it is independent | new: test_high_assurance_with_any_mode_is_unavailable_whatever_store_is_passed; test_cli_high_assurance_is_refused_as_a_configuration_error |
| P02 | Object claiming independence | no such attribute; refused on the public path | wrapper | Enable the mode on self-attestation | new: test_no_store_can_declare_itself_independent; test_a_store_other_than_the_shipped_one_is_refused_on_the_public_path |
| P03 | `high-assurance` with `off` | decisions and `policy_id` unchanged; NOT_EVALUATED in the optional section; no new default field | wrapper | Add a field that breaks strict consumers, or read as satisfying the revocation-aware profile | new: test_high_assurance_off_keeps_decisions_and_policy_id_and_is_not_evaluated; test_cli_high_assurance_off_says_nothing_new_by_default |
| P04 | Evidence age zero, negative, non-finite, above 24 h, wrong type | PolicyError; CLI exit 2 | config check | Accept an unbounded window | new: test_evidence_age_outside_the_cap_is_refused; test_cli_evidence_age_outside_the_cap_is_a_configuration_error |
| P05 | Evidence age raised after stale data was refused | still REVOCATION_DATA_STALE, note REVOCATION_POLICY_FLOOR_APPLIED | gate, state store | Accept stale evidence because a setting changed | new: test_raising_the_evidence_age_does_not_make_stale_data_acceptable |
| P06 | Record that served `required`, used under `advisory` | INVALID REVOCATION_POLICY_DOWNGRADE | gate | Downgrade silently | new: test_a_record_that_served_required_refuses_advisory |
| P07 | Ceremony and the floor | kept unless reset explicitly | enrollment | Forget the floor as a side effect | new: test_the_floor_survives_a_new_context_and_a_ceremony_unless_reset_explicitly |
| P08 | `off` after `required` | reads nothing, so cannot refuse. Stated limit, forced by the ruling on `off` | wrapper | Claim to detect it | new: test_limit_off_reads_nothing_so_it_cannot_be_refused |

## F. F-07: replay retention and `max_age`

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| F01 | Record under 1 h, verify at +2 h under 1 d, new cache instance | INVALID REPORT_TOO_OLD, note REPLAY_POLICY_FLOOR_APPLIED | engine, replay store | TRUSTED twice (observed on published 0.2.1 per the finding) | new: test_the_finding_raising_max_age_no_longer_accepts_a_report_twice |
| F02 | `max_age` unchanged | INVALID REPLAY_DETECTED, no new code | engine | Change the normal path | new: test_control_unchanged_max_age_is_the_normal_replay_path; test_control_unchanged_max_age_output_has_no_new_code |
| F03 | Refused as stale, setting raised | still REPORT_TOO_OLD | engine, replay store | Accept because a setting changed | new: test_a_report_refused_as_stale_stays_refused_when_the_setting_is_raised |
| F04 | Lowered, then raised back | floor stays at the lower value | replay store | Restore the wider window | new: test_lowering_is_honoured_and_raising_back_is_not |
| F05 | Floor after a real new process | survives | replay store | Hold it in memory | new: test_the_floor_survives_a_real_new_process |
| F06 | File written by a published version, not migrated | refused at open and in use, `REPLAY_STATE_UNAVAILABLE`, CLI exit 3, `serve` refuses to start | replay store | Adopt it silently, with whatever policy happens to be set | new: test_a_published_file_is_refused_until_migrated; test_cli_verify_on_a_published_file_exits_3_and_says_how_to_migrate; test_serve_refuses_to_start_on_a_published_file |
| F07 | First-contact `max_age` increase on a published file | after an attested migration REPORT_TOO_OLD; after an unknown one REPLAY_HISTORY_UNKNOWN; never accepted twice | replay store, engine | Accept the report twice (observed in the challenger's finding) | new: test_first_contact_increase_after_an_attested_migration_is_not_accepted_twice; test_first_contact_increase_after_an_unknown_migration_is_refused |
| F08 | Corrupt floor | REPLAY_STATE_UNAVAILABLE at the replay step; an earlier refusal keeps its path | engine | Fail open, or change exit codes on refused reports | new: test_a_corrupt_floor_fails_closed_with_the_existing_code; test_an_earlier_refusal_keeps_its_exit_path_when_the_floor_is_broken |
| F09 | sqlite `:memory:`, in-memory cache, third-party cache | as before; in-memory holds a floor for its lifetime; third-party has none | engine | Break existing callers | new: test_the_memory_path_behaves_as_it_did; test_in_memory_cache_holds_the_floor_for_its_lifetime; test_a_third_party_cache_without_the_method_still_works_and_has_no_floor |

## R. Real file store

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| R10 | Real process, SIGKILL at each commit point | whole old or whole new record; re-delivery converges; temp swept | state store | Leave a partial record | new: test_real_process_killed_at_each_commit_point; test_a_temp_file_from_a_killed_writer_is_never_read |
| R11 | Real concurrent processes | highest epoch wins; no lost write | state store | Lower the mark | new: test_real_concurrent_processes_end_at_the_highest_epoch |
| R12 | Damaged record on disk, six ways | REVOCATION_STATE_UNAVAILABLE. Truncation simulates a torn write | state store | Read it as empty | new: test_a_damaged_record_fails_closed_never_as_empty; test_an_unusable_directory_fails_closed |
| R13 | Restored backup | caught by a process that remembers; not by a new one, until the deadline. Stated limit | gate | Claim otherwise | new: test_a_restored_backup_is_caught_by_a_process_that_remembers; test_limit_a_restored_backup_is_not_caught_by_a_new_process_and_the_bound_is_the_deadline |

## X. Hostile sequences against the implementation

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| X01 | Old public recovery statement replayed, expired or superseded | record unchanged; current authority not condemned | recovery verifier, state store | Condemn the current authority with a public document (observed) | new: test_replaying_an_expired_public_recovery_does_not_condemn_the_current_authority; test_replaying_an_older_recovery_does_not_condemn_a_key_rotated_to_since |
| X02 | Later recovery, key rotated to since the last one, not declared; late older statement | superseded, not compromised; its mark usable until the deadline; a late statement lands its declaration and voids nothing | recovery verifier, gate | Refuse a mark nobody condemned (observed) | new: test_a_legitimate_recovery_does_not_condemn_a_key_nobody_declared; test_a_mark_from_a_rotated_key_survives_a_later_recovery_that_did_not_declare_it; test_an_older_statement_lands_its_declaration_and_voids_nothing |
| X03 | Feed poll with old statements and junk | reaches the list | state store | Stop, and go stale for ever (observed) | new: test_an_honest_feed_poll_carrying_old_recoveries_still_reaches_the_list; test_a_junk_transition_in_a_feed_does_not_stop_the_poll |
| X04 | Fingerprint with a trailing newline | refused REVOCATION_MALFORMED | list verifier, issuer tooling | Accept a revocation it never enforces (observed) | new: test_a_fingerprint_with_a_trailing_newline_is_malformed |
| X05 | Null successor, year 9999, non-text documents | refused REVOCATION_MALFORMED | list verifier, recovery verifier | Raise out of the verifier (observed) | new: test_an_explicit_null_successor_is_malformed; test_a_time_at_the_end_of_the_range_is_malformed_not_an_overflow; test_non_text_documents_are_refused_not_raised |
| X06 | Entry without an issuer; mutated context; str subclass profile; private path without its flag | PolicyError | config check, wrapper | Skip the gate, widen the cap, or reach the unavailable profile (observed) | new: test_an_entry_without_an_issuer_is_refused_not_waved_through; test_mutating_the_context_cannot_widen_the_evidence_age_or_invent_a_mode; test_a_str_subclass_cannot_slip_past_the_high_assurance_refusal; test_the_private_algorithm_path_also_refuses_high_assurance_without_its_explicit_test_flag |
| X07 | Ceremony below the mark, or naming a superseded key | refused unless the loss is stated | enrollment | Drop the epoch floor silently (observed) | new: test_a_ceremony_below_the_mark_needs_the_loss_stated; test_a_ceremony_refuses_a_superseded_key |
| X08 | Damaged record with a recomputed digest, group-writable record, FIFO, bad pin | REVOCATION_STATE_UNAVAILABLE or PinStoreError; no traceback, no hang | state store | Crash, which exits 1 as if refused, or hang (observed) | new: test_a_well_digested_record_with_wrong_types_is_unavailable_not_a_traceback; test_a_group_writable_record_is_refused; test_a_fifo_is_refused_without_hanging; test_a_bad_pin_is_never_written_and_never_loads |
| X09 | Successor cycle, mistyped fingerprint, unknown key, other issuer, oversized list, wrong generation after recovery | ActionRefused before signing | issuer tooling | Sign something that wedges the publisher for good (observed) | new: test_a_successor_cycle_is_refused_before_signing; test_a_mistyped_fingerprint_is_refused_with_an_inventory; test_a_key_outside_the_inventory_needs_saying_so; test_another_issuers_key_is_refused; test_an_oversized_list_is_refused_before_signing; test_the_generation_after_a_recovery_is_taken_from_the_statement |
| X10 | CLI: missing publisher state, no inventory, digest at epoch 0, bad output path, hostile documents | refused, no traceback, right exit code | CLI | Start again at epoch 1 and fork (observed) | new: test_cli_a_missing_publisher_state_needs_initial; test_cli_actions_need_an_inventory_unless_waived; test_cli_baseline_digest_at_epoch_zero_is_refused; test_cli_enroll_with_a_bad_recovery_digest_leaves_the_pin_file_usable; test_cli_bad_output_path_and_nested_previous_are_refused_not_tracebacks; test_cli_hostile_documents_are_refusals_not_infrastructure_failures; test_cli_high_assurance_refusal_comes_before_touching_the_pins |
| X11 | Gate refusal under `record`; stale refusal under `check`; read-only store; empty floor table | floor bound; stays refused when raised; read-only keeps working; missing policy record corrupt | engine, wrapper | Honour a raise after a refusal (observed) | new: test_a_gate_refusal_under_record_still_sets_the_floor; test_a_stale_refusal_in_check_mode_stays_refused_when_raised; test_a_read_only_store_in_check_mode_keeps_working; test_a_deleted_policy_record_is_corrupt_not_absent |

## Y. Replay migration, response mode, trust history, retired-then-compromised

| ID | Scenario | Expected | Enforced by | Permissive implementation would | Coverage |
|---|---|---|---|---|---|
| Y01 | Replay after migration | recorded decisions preserved: REPLAY_DETECTED | replay store | Lose the row | new: test_replay_after_migration_preserves_recorded_decisions |
| Y02 | Attested, unchanged `max_age` | verdicts as before | replay store | Change the normal path | new: test_attested_migration_with_the_same_max_age_keeps_verdicts |
| Y03 | Unknown policy | every report up to the cutover plus skew refused; later ones accepted | engine | Invent a policy | new: test_unknown_migration_refuses_older_reports_and_accepts_later_ones |
| Y04 | Malformed or ambiguous file | refused, file unchanged | replay store | Migrate it anyway | new: test_ambiguous_or_malformed_files_are_refused_unchanged |
| Y05 | Attested value contradicted by a row | refused | replay store | Accept the statement | new: test_a_statement_the_rows_contradict_is_refused |
| Y06 | Real process killed at every step of migration | whole original, or whole new file with the original kept; another run finishes or refuses; temp swept | replay store | Half-migrated file | new: test_real_process_killed_at_every_step_of_migration; test_a_killed_migration_leaves_no_temp_behind_after_the_next_run |
| Y12 | Trigger, extra table, view, index, ANALYZE table planted in a real 0.2.1 file | refused before any row is read, file unchanged; no replay protection silently lost | replay store | Migrate it and carry the trigger over, so a report is TRUSTED twice (reproduced on a74cd03) | new: test_planted_objects_in_a_real_published_file_are_refused_unchanged; test_an_analyze_table_is_refused_too; test_the_planted_trigger_case_end_to_end_through_the_cli |
| Y13 | Clean real 0.2.1 file | migrates; replay detected across new processes | replay store | Lose the decisions | new: test_clean_control_a_file_really_written_by_0_2_1_migrates; test_replay_stays_enforced_after_migration_across_real_new_processes; test_clean_control_end_to_end_through_the_cli_replay_is_detected_in_new_processes |
| Y14 | Object planted after migration | refused in every operation and by the CLI | replay store | Keep running with protection disabled | new: test_an_object_planted_after_migration_is_refused_in_every_operation; test_a_trigger_planted_after_migration_stops_the_cli |
| Y15 | Edits to `replay_meta` | incoherent refused; a plausible edit undetected. Stated limit | replay store | Claim to detect it | new: test_incoherent_edits_to_the_policy_record_are_refused; test_limit_a_plausible_edit_by_someone_who_can_write_the_file_is_not_detected |
| Y16 | Same report at exactly T and T+max_age, `clock_skew=0` | REPLAY_DETECTED | replay store | TRUSTED twice (reproduced on 0.2.1) | new: test_a_report_is_not_accepted_twice_at_exactly_issued_at_plus_max_age; test_policy_retention_covers_every_acceptable_presentation; test_the_default_skew_through_the_real_cli |
| Y17 | History setting above 24 h on any cache: self-declared durable, raising binder, subclass, in-memory, new file | never honoured | engine | Grant 30 days (reproduced by the challenger, C7-07, C7-08) | new: test_no_cache_can_get_a_window_above_the_ceiling |
| Y18 | Broken history floor | no history counts | engine | Widen the window | new: test_a_broken_floor_does_not_widen_the_window_it_closes_it_real_sqlite; test_a_running_object_catches_a_restored_history_floor |
| Y19 | Legacy file with no history statement | a history as of the migration or earlier is not fresh | engine, replay store | Invent an earlier setting | new: test_a_legacy_file_with_no_history_statement_does_not_count_older_history; test_a_stated_history_policy_is_the_floor_and_a_false_one_is_bounded |
| Y20 | Raise below 24 h with no surviving floor | undetected, bounded by 24 h. Stated limit | engine | Claim otherwise | new: test_limit_a_raise_below_the_ceiling_without_the_shipped_store_cannot_be_seen; test_limit_a_new_file_or_a_restored_backup_forgets_a_floor_below_the_ceiling |
| Y21 | Tenant's real key signs under another tenant's name: 3 store forms without issuers, `entries`, 3 policies | a strict policy refuses a store without issuers, `entries` gives ISSUER_MISMATCH in all three | engine | TRUSTED with `issuer_trusted` true (reproduced on 0.2.1) | new: test_substituted_issuer_in_a_v2_report; test_the_entries_guard_itself_refuses_the_substitution; test_a_v1_substitution_never_passes_an_entries_store; test_a_lookalike_of_the_enrolled_name_is_a_different_name |
| Y22 | The same on the CLI, HTTP, `verify_trusted`, lenient engine path, `verify_envelope` | as Y21; development and the lenient paths keep their verdict | CLI, server, library | Silent verdict change | new: test_the_real_cli; test_the_http_server; test_the_http_server_will_not_start_on_a_store_without_issuers; test_verify_trusted_with_its_default_policy; test_the_lenient_engine_path; test_the_legacy_verifier_with_a_store; test_the_legacy_verifier_with_a_plain_mapping |
| Y23 | A strict policy moved onto such a store, or given one; an entry built without an issuer | refused | engine | A route round the check | new: test_verify_trusted_refuses_the_policy_not_the_report; test_a_strict_policy_cannot_be_moved_onto_a_store_without_issuers; test_an_entry_built_without_an_issuer_does_not_count_as_bound |
| Y24 | Development on a store without issuers | same verdict, `ISSUER_UNBOUND` in `reasons`, CLI warning, `issuer_binding`, `issuer_bound` | engine, CLI, library | Say nothing; add a field to the default response | new: test_development_keeps_the_verdict_and_says_the_name_was_not_checked; test_the_default_response_has_no_new_field; test_the_versioned_response_states_the_binding; test_the_legacy_verifier_says_whether_the_name_was_compared; test_the_real_cli_on_development_says_so |
| Y25 | Migrate a store, on reports signed by the 0.1.0, 0.1.1, 0.2.0, 0.2.1 wheels | development: same verdict for the right issuer; strict: refused; the upgrade path left is `trust add`, with the same table; a wrong statement gives ISSUER_MISMATCH | migration tool, engine | Infer an issuer; change the source | new: test_an_honest_published_report_gets_the_same_verdict_after_migrating; test_a_strict_policy_refuses_the_old_store_and_the_migrated_one; test_the_upgrade_path_left_is_trust_add_in_a_new_store; test_stating_another_issuer_refuses_that_tenants_reports; test_the_published_0_1_0_store_and_reports; test_an_issuer_is_never_inferred; test_the_source_is_left_as_it_was_and_an_existing_target_is_refused |
| Y26 | One key signed under two names, then migrated | only the stated name. Stated limit | migration tool, engine | Claim a rename can be told from a substitution | new: test_a_known_limit_one_key_that_signed_under_two_names_keeps_only_the_stated_one |
| Y27 | Two services with different `max_age` on one file; a later run omits `max_age` | no double acceptance, floor applied, the smaller value holds across processes | engine, replay store | TRUSTED twice (reproduced on 0.2.1) | new: test_two_services_on_one_file_do_not_accept_a_report_twice; test_a_later_run_that_omits_max_age_does_not_get_thirty_days; test_the_real_cli_with_the_flag_dropped; test_processes_racing_with_different_settings_leave_the_smallest |
| Y28 | The longer service on a shared file | held to the shorter window. Stated cost | engine, replay store | Claim no cost | new: test_limit_the_longer_service_is_held_to_the_shorter_one |
| Y29 | `secure-v1` with any `trust_history_max_age` but 24 h, by construction or replace | refused | engine | Honour or ignore it | new: test_a_caller_cannot_set_the_window_larger_or_smaller; test_replace_cannot_set_it_either; test_a_longer_policy_cannot_be_moved_into_the_profile |
| Y30 | `secure-v1` with the setting omitted: new store, existing store, third-party cache, restart, check mode | fresh at exactly 24 h, stale 1 us later | engine, replay store | A window that depends on the store | new: test_the_edges_of_the_window_with_the_setting_omitted; test_an_existing_file_at_the_window_gets_the_same_window; test_no_state_is_read_with_a_third_party_cache; test_it_survives_a_restart; test_check_mode_gets_the_same_window |
| Y31 | A history refused under a shorter setting, then the move to `secure-v1`, and back and forth | stays refused; later histories get the same 24 h | engine, replay store | Revive it | new: test_an_increase_from_a_shorter_value_does_not_revive_anything; test_after_the_increase_the_window_is_the_same_24_hours; test_going_back_and_forth_does_not_revive_anything; test_the_longer_setting_gets_nothing_back_from_the_takeover; test_a_floor_that_cannot_be_moved_counts_no_history |
| Y32 | An ambiguous issuer name at parsing, construction, `trust add`, pins, `trust migrate` | refused, nothing written, nothing normalised | trust store, CLI | Normalise it into another issuer | new: test_parsing_refuses; test_direct_construction_refuses; test_trust_add_refuses_and_writes_nothing; test_a_revocation_pin_file_refuses; test_the_revocation_enrollment_ceremony_refuses; test_migration_refuses; test_the_cli_migration_refuses_and_writes_nothing |
| Y33 | Legitimate names, including accents and other scripts | kept byte for byte | trust store, CLI | Refuse them | new: test_legitimate_names_pass_the_rule_and_are_kept_byte_for_byte; test_trust_add_takes_a_legitimate_name; test_migration_takes_a_legitimate_name_unchanged |
| Y34 | Look-alikes, normal forms, a signer using a refused name | different names; only a store with no issuers can accept. Stated limit | engine | Claim the rule covers them | new: test_a_lookalike_or_another_normal_form_is_a_different_name_not_an_ambiguous_one; test_signing_is_not_covered_and_such_a_report_cannot_reach_a_store_that_binds_issuers |
| Y35 | A `TrustStore` subclass, a `KeyEntry` subclass or a substituted field under a strict policy | refused, or not bound | trust store, engine | TRUSTED on a substituted issuer (reproduced) | new: test_a_subclass_is_refused_under_a_strict_policy; test_replace_cannot_put_a_subclass_in; test_a_key_entry_subclass_in_an_exact_store_does_not_count_as_bound; test_a_record_with_a_substituted_field_does_not_count_as_bound; test_an_issuer_that_compares_equal_to_anything_is_not_a_name |
| Y36 | A migrated store | output says operator-declared; the record is in the store; every strict profile refuses it, on the library, CLI and server, after a copy, a move or `from_dict`; development accepts and labels | migration tool, engine, CLI | Report it as bound or authenticated | new: test_the_output_says_this_is_a_statement_and_not_a_binding; test_the_store_records_it_on_each_entry_and_there_is_one_record; test_every_strict_profile_refuses_it_and_says_why; test_every_strict_profile_refuses_it_on_the_cli; test_a_strict_policy_cannot_be_moved_onto_it; test_a_copy_or_a_move_keeps_the_refusal; test_from_dict_keeps_the_refusal; test_development_accepts_it_and_says_what_it_is; test_control_trust_add_keeps_working_and_nothing_calls_it_authenticated |
| Y37 | Deliberately deleting the record from the file; another value; a file from a pre-release candidate beside the store | deletion is accepted, which is a stated limit; another value and such a file are refused | migration tool | Claim the record authenticates; let an old file weaken anything | new: test_limit_deliberately_deleting_the_member_is_an_edit_of_local_state; test_another_value_is_refused_not_ignored; test_an_old_record_file_beside_a_store_cannot_weaken_anything; test_any_such_file_is_refused_whatever_it_holds; test_limit_the_source_store_stays_the_way_back |
| Y38 | An envelope object with a substituted type in any field, a subclass, or an added attribute, under a strict profile | MALFORMED_ENVELOPE before any field is read | engine | TRUSTED for the wrong issuer (reproduced) | new: test_the_finding_a_substituted_issuer_through_a_str_subclass_is_refused; test_no_field_may_be_a_substituted_type; test_an_envelope_subclass_is_refused; test_an_instance_attribute_cannot_replace_a_method; test_a_v1_object_is_held_to_the_same_rule; test_control_an_honest_object_from_the_builder_is_accepted; test_limit_development_is_not_covered |
| Y39 | A name that renders as nothing | refused; a mark after a base character works | trust store | Accept a blank issuer (reproduced) | new: test_every_default_ignorable_code_point_is_refused; test_no_lone_code_point_outside_letters_numbers_punctuation_and_symbols_is_a_name; test_a_mark_after_a_base_character_is_part_of_a_name |
| Y40 | Every message to a strict user about a store | names `trust add` and the migration document | engine, CLI, library | Send them to a migration their profile refuses | new: test_the_policy_refusal_points_to_trust_add; test_the_refusal_of_a_migrated_store_points_to_trust_add; test_the_cli_refusal_points_to_trust_add; test_the_cli_warning_in_development_points_to_trust_add; test_the_lenient_verifier_warning_points_to_trust_add |
| Y07 | Pre-migration backup restored, under a running process and in a new one | refused as legacy | replay store | Run on without a floor | new: test_a_restored_premigration_backup_is_refused_again |
| Y08 | Later backup restored with a higher floor | refused by an object that remembers; a new process cannot see it. Stated limit | replay store | Claim otherwise | new: test_limit_a_restored_later_backup |
| Y09 | Response v2 on CLI and HTTP | explicit value; default byte-identical; `required_but_unavailable` never trusted | CLI, server | Change the default, or show unavailable as trusted | new: test_cli_default_is_byte_identical_to_the_engine_dict_and_v2_only_adds; test_http_default_is_byte_identical_and_v2_only_adds; test_required_but_unavailable_is_never_trusted; test_cli_required_but_unavailable_is_shown_on_exit_3 |
| Y10 | `trust_history_max_age` raised on the shipped store | still stale, across a new process | engine, replay store | Accept stale history because a setting changed | new: test_raising_trust_history_max_age_does_not_revive_stale_history; test_the_history_floor_survives_a_real_new_process |
| Y11 | Retired key stated compromised later | tool refuses; signed anyway, verifier latches, key stays refused, cleared only by recovery or ceremony | issuer tooling, gate | Clamp and sign, or clear the latch | new: test_a_retired_key_compromised_later_is_refused_before_signing; test_verifier_fails_safe_on_a_list_that_bypassed_the_tool_and_recovery_clears_it |
