# CodeQL alert triage

Inventory of the open code-scanning alerts on `master` after the Phase 3A merge
(19 open, plus alert #24 which was dismissed earlier), with the evidence for each
classification. Alert numbers and lines are from the analysis of `master` at
`0df24ed`. **18 of the 19 were opened between 2026-04-29 and 2026-06-18, before the
Phase 1-3A work; #35 was opened by the merge.**

"False positive" below means the alert's own data flow shows a name-based match on
harmless data. Nothing here is suppressed on faith: where an alert is a real finding it
is fixed, and where it is a false positive the evidence is recorded and the code is
changed to the recommended API if that is a genuine improvement.

## Addressed in the security-maintenance change

| # | Rule | Location | Classification | Evidence | Disposition |
|---|---|---|---|---|---|
| 1 | `py/stack-trace-exposure` | `server.py` `/readyz` | **True positive (low)** | The flow ends at the handler's return: `error = str(exc)` from a failed `load_schema` was sent to an unauthenticated probe, and exception text can carry file-system paths. | **Fixed.** The response now says `schema bundle unavailable`; the detail is logged server-side. |
| 35 | `py/unused-global-variable` | `reports.py` (one-time warning) | Code quality; the race was benign | A bare module-level flag was checked then set without a lock: at worst a second thread emitted a duplicate warning. No memory-safety or trust impact. | **Replaced** by a lock-guarded once-flag (exactly-once, resettable in tests). |
| 15 | `py/weak-sensitive-data-hashing` | `server.py` `_hash_token` | **Name-based, with a genuine improvement available** | CodeQL's "password" sources are the names `api_keys` and `token`. The data are high-entropy bearer tokens; the digest is used only for a constant-time comparison, is held in process memory, and is never stored. The key is `os.urandom(32)` per process: `regaudit-fhe serve` and the environment configuration never set it, and embedders can supply their own only through the `salt=` parameter of `build_app` / `make_auth_dependency`, which (since the post-merge maintenance change) refuses anything shorter than 16 bytes. Length is a floor, not randomness: a predictable 16-byte key is accepted and is no stronger than its predictability. The key is not persisted or transmitted. `key_id` is a 12-hex-character (48-bit) truncation of the keyed digest, for local operational use (logs, rate-limit buckets) only; it is not collision-free, is not a credential identity, and differs per process and restart (and per worker), so it cannot correlate across them. A slow password hash is not appropriate for per-request token checks. | **Changed** to HMAC-SHA256 keyed by the per-process secret, the correct primitive for this purpose. **No migration is needed** (nothing is persisted). Only the opaque 12-character `key_id` in logs changes value, and it already changed on every restart. CodeQL kept reporting the changed code (#36, `server.py:640`; sources are the identifiers `api_keys` and `config.api_keys`). **Dismissed as a false positive** with the owner's approval: the per-process key is `os.urandom(32)`, the digest is only passed to `hmac.compare_digest` over every entry with no early exit, and nothing is persisted or sent. The identifiers were deliberately not renamed and no password KDF was adopted. |
| 2, 3, 4 | `py/clear-text-logging-sensitive-data` | `examples/regulator_verify_signature.py:79`, `:95`; `examples/signed_envelope.py:70` | **False positive** | The "secret" source expressions are, by column, `out.issuer_trusted`, `bad.issuer_trusted` and `outcome.issuer_trusted`: a boolean named like a credential. The printed value is a public yes/no. The same example lines also read the now-deprecated `.valid`. | **Examples updated** to print `trust_status` and to assert on it, which removes both the match and the deprecated usage. No alert was suppressed. |

## Verified false positives, left unchanged for the owner to decide

| # | Rule | Location | Evidence | Proposed disposition |
|---|---|---|---|---|
| 16 | `py/log-injection` | `server.py` (`/v1/audit/{primitive}` 404) | The user-controlled path parameter reaches only an `HTTPException` detail formatted with `!r`, which escapes newlines and control characters; the application's log formatter is `json.dumps`, which also escapes them. A newline cannot start a forged log line. | Dismiss as a false positive with this evidence, or leave open. |
| 24 | `py/clear-text-logging-sensitive-data` | `cli.py` verify verdict | Sources are the boolean attribute `issuer_trusted` (`cli.py:306`, `verification.py:248`). Same name-based match. | **Dismissed** on 2026-10-24 with the same evidence. |

## Historical alerts, inventoried and deferred (unrelated to this change)

| # | Rule | Location | What it is |
|---|---|---|---|
| 8, 9 | `py/unused-import` | `benchmarks/bench_fhe.py` (`sys`, `dataclasses.field`) | Unused imports |
| 10 | `py/unused-import` | `examples/server_client.py` | Unused import |
| 11 | `py/unused-import` | `examples/signed_envelope.py` (`json`) | Unused import |
| 14 | `py/unused-import` | `examples/03_regulator_verify.py` (`sys`) | Unused import |
| 23 | `py/unused-import` | `fhe/openfhe.py` | An availability probe: `import openfhe as _openfhe  # noqa: F401`. Intentional. |
| 17 | `py/import-and-import-from` | `tests/test_fhe_equivalence_matrix.py` | Import style in a test |
| 22 | `py/import-and-import-from` | `tests/test_dp.py` | Import style in a test |
| 18, 19 | `py/ineffectual-statement` | `reports.py` `KeyProvider` | `...` bodies of a `Protocol`, which is idiomatic |
| 20, 21 | `py/cyclic-import` | `fhe/backends.py` and `fhe/openfhe.py` | A deliberate lazy backend registry: `backends` imports `openfhe` inside a function and `openfhe` registers itself with `backends` |

These are quality notes with no security impact. They were deferred so that this change
stayed confined to the security findings; they are closed in the section below.

## Note-level backlog closed (19 alerts)

All 19 open alerts were `note` severity with no security impact. Each is changed in code; none is dismissed or
suppressed, and the CodeQL configuration is unchanged. No runtime behaviour changes.

| # | Rule | Location | Change |
|---|---|---|---|
| 8, 9, 10, 11, 14 | `py/unused-import` | `benchmarks/bench_fhe.py`, `examples/` | Removed the imports |
| 23 | `py/unused-import` | `fhe/openfhe.py` | The availability probe uses `importlib.import_module("openfhe")`, so it still catches every import failure but binds no name |
| 17, 22 | `py/import-and-import-from` | `tests/test_fhe_equivalence_matrix.py`, `tests/test_dp.py` | One import form per module |
| 18, 19 | `py/ineffectual-statement` | `reports.py` `KeyProvider` | The `...` bodies of the `Protocol` members are replaced by docstrings |
| 20, 21 | `py/cyclic-import` | `fhe/backends.py`, `fhe/openfhe.py` | `backends` no longer imports `openfhe`; the package `__init__` calls `openfhe.register()` instead, so the cycle is gone. `regaudit_fhe.fhe.openfhe.register()` is unchanged |
| 45 | `py/empty-except` | `scripts/resource_bounds_container.py` | Added the explanatory comment |
| 46, 47 | `py/ineffectual-statement` | `server.py` request-timeout middleware | `_ = await task`. CodeQL's "no effect" is wrong for an `await`, which is what waits for the task; this is the same await with the same cancellation behaviour, and it silences the note rather than fixing a defect |
| 48, 49, 50, 51 | `py/ineffectual-statement` | `tests/test_server_resource_bounds.py` | `_ = await ...`, for the same reason |

## 0.2.0 merge (PR #45): alerts #52–#57

Alerts raised on the PR merge ref or on `master` after the 0.2.0 trust-completion merge (`304144b`). The 19
older open alerts above and in the historical table remain in the backlog.

| # | Rule | Location | Disposition | Evidence |
|---|---|---|---|---|
| 52 | `py/overly-permissive-file` | `cli.py` `_write_new_file` | Dismissed, won't fix | Called only by `keygen`. The private key is created 0600 (tested); the 0644 file is the public-key PEM. `O_EXCL`, never overwrites. |
| 53 | `py/overly-permissive-file` | `cli.py` `trust add` | Dismissed, won't fix | The trust store holds `issuer`, `public_key_pem` and `status` only; verifiers must read it. Written to a temp file, then atomically replaced. |
| 54 | `py/comparison-of-identical-expressions` | `report_v2.py` `_assert_plain_json` | Fixed | `value != value` became `math.isnan(value) or math.isinf(value)`. Only exact `float` instances reach it. Tests added. |
| 55 | `py/catch-base-exception` | `cli.py` cleanup handlers | Dismissed, won't fix | Unlinks only the file just created, suppresses `OSError`, then re-raises with a bare `raise`; the original exception is never masked and no partial trust store is published. |
| 56 | `py/import-and-import-from` | `tests/test_legacy_bool_apis_deprecation.py` | Fixed | Test import style. |
| 57 | `py/clear-text-logging-sensitive-data` | `cli.py` verify verdict | Dismissed, false positive | The sources are the boolean `VerificationResult.issuer_trusted` (`cli.py:644`, `verification.py:253`). The printed fields are verdict metadata and report-supplied identifiers; no key material reaches `verify()`. `tests/test_cli_verify_output_no_secrets.py` pins the field inventory and checks for key leaks, including a private key passed as the report or the trust store. |

The identifiers `verify` prints (`issuer`, `key_id`, `deployment_id`, ...) are chosen by the report's producer and may be
sensitive in some deployments; see the 0.2.0 known limitations in `CHANGELOG.md`.

## Draft PR #65: 32 alerts

CodeQL reported 32 alerts on this draft at `13437c9`: 12 high and 20 notes. Each was read at its source line. On 2026-11-04, 30 were dismissed one at a time, each with its own reason, and 2 were not, because they were real findings. No rule was suppressed. PR results only cover changed lines, so this is not a count for the whole repository.

| # | Rule | Location | Classification | Evidence | Disposition |
|---|---|---|---|---|---|
| 95 | `py/overly-permissive-file` | `cli.py:464`, `trust add` | **Benign on Linux and macOS, with one limit** | See below. | Dismissed, won't fix |
| 72, 73 | `py/ineffectual-statement` | `_revocation_state.py:77`, `:79` | False positive | The `...` bodies of methods on `class StateStore(Protocol)`. They never run. | Dismissed, false positive |
| 63, 64 | `py/overly-permissive-file` | `tests/test_replay_migration.py:550`, `:557` | Intentional test behaviour | The `db` fixture is under `tmp_path`. These tests set `0640` and `0660` to show the mode is kept or reported. The modes are not themselves safe. | Dismissed, used in tests |
| 96 to 104 | `py/overly-permissive-file` | `tests/test_replay_storage_policy.py:72`, `:137`, `:194`, `:203`, `:232`, `:377`, `:406`, `:485`, `:544` | Intentional test behaviour | Each target is under `tmp_path` or the `world` fixture, which is `0700`. The loose modes are what these tests refuse. `:137` shows a sticky directory above a private parent is accepted. The modes are not themselves safe. | Dismissed, used in tests |
| 74 to 80, 105 | `py/import-and-import-from` | 8 test modules | Style | `import regaudit_fhe as rf` next to imports of private submodules. No effect on behaviour. | Dismissed, used in tests |
| 88, 90, 91 | `py/unused-import` | `tests/experimental_revocation/proto.py`, `trust_gate.py` | Re-export | Other tests read `proto.canonical_bytes`, `MigrationRefused` and `migrate_store` through these modules. | Dismissed, used in tests |
| 92 to 94 | `py/polluting-import` | `tests/experimental_revocation/proto.py`, `trust_gate.py` | Deliberate star import | Other tests reach 32 names through `proto` and 19 through `trust_gate` that only these imports provide. | Dismissed, used in tests |
| 68, 69 | `py/unnecessary-lambda` | `tests/experimental_revocation/corpus.py:153`, `:188` | Style | Rows of a test table. | Dismissed, used in tests |
| 86 | `py/unused-import` | `tests/experimental_revocation/proto.py:21` | **Real for `_z`** | It names three imports. `_z` was used nowhere and is removed. `_sig_doc` and `_without` are read through `proto` by other tests and stay. | Not dismissed |
| 87 | `py/unused-import` | `tests/experimental_revocation/proto.py:34` | **Real** | `_product_enroll` was used nowhere and is removed. | Not dismissed |

An earlier version of this record called #86 and #87 deliberate re-exports. That was wrong for `_z` and `_product_enroll`. Parsing the test files showed nothing used them.

**#95.** The line is `os.chmod(tmp, stat.S_IMODE(store_path.stat().st_mode) if store_path.exists() else 0o644)`. This is not the line alert #53 was dismissed on, which always set `0o644`, so that dismissal does not carry over.

We checked what can reach it by running `trust add`. A new store is `0644` under umask `000`, `002`, `022` and `077`. An existing `0600`, `0640`, `0644` or `0444` store keeps its mode. `0664`, `0646`, `0666` and `0660` are refused with exit 3 before this line, and the file is unchanged. The file holds `issuer`, `public_key_pem` and `status`, and no private key.

The limit is a platform that cannot establish the owner and permissions. There the check does not refuse, so a `0666` store stays `0666` and the command warns. The command does not loosen the mode, but before this change it would have reset it to `0644`. So this dismissal does not say the command is safe on every platform.

We also checked that this limit cannot reach strict verification, with the platform simulated as `freebsd14` and `win32` on macOS. No real Windows or BSD host was run. `confidential`, `high-assurance` and `secure-v1` refuse with exit 3, even for a safe store and for a key enrolled through `trust add`. `VerificationPolicy` and the server configuration refuse as well. `development` gives `TRUSTED` with a warning and `TRUST_STORE_STORAGE_UNSAFE`.

## Master after the PR #65 merge: 45 alerts

After merging PR #65 as `19ee32b` on 2026-11-05, CodeQL was used to analyze the entire `master` branch. It showed 45 open alerts. The PR check did not show these because it only shows the results for changed lines. All 45 are in test code and none is in `src/`. Each alert was read at the source line. The target of each `chmod` was followed by parsing the test until it reached pytest's `tmp_path`.

44 out of 45 were dismissed one at a time, each with its own reason and comment. These were reviewed and classified, however as they were not fixed in the source a dismissed alert here is not the same as a resolved alert. The 45th is #89. This is a real unused import in a test. This change removes it. Thus, it is resolved through a code change and not through a dismissal. No rule was suppressed and the CodeQL configuration is unchanged.

The reviews were done by the maintainers with AI assistance. These reviews are not an independent review of the code or the CodeQL results. After removing #89 none of the 45 is left open. However, having zero open alerts does not mean that there are no vulnerabilities. CodeQL only reports on what its queries look for, and 44 of these alerts are still in the code with a recorded explanation.

Alert numbers and lines are from the analysis of `master` at `19ee32b`. Each dismissal carries its own comment in GitHub code scanning.

| Group | Rule | Alerts | Disposition |
|---|---|---|---|
| Test permissions | `py/overly-permissive-file` | 33 | Dismissed, used in tests |
| Import style | `py/import-and-import-from` | 8 | Dismissed, used in tests |
| Lambdas | `py/unnecessary-lambda` | 2 | Dismissed, used in tests |
| Chained comparison | `py/test-equals-none` | 1 (#139) | Dismissed, false positive |
| Unused import | `py/unused-import` | 1 (#89) | Resolved by a code change |
| **Total** | | **45** | **44 dismissed, 1 resolved** |

### Test permissions: 33 alerts, dismissed

Each call is in a test. Every target resolves to pytest's per-test `tmp_path`, or to a directory made inside it, which was shown by parsing the test and following fixtures and assignments. The tests set these modes to check how the code treats them. None of this code is in the wheel.

| # | Location | Test or helper | Mode set | Target as written | Reading |
|---|---|---|---|---|---|
| 65 | `test_revocation_hostile_sequences.py:363` | `test_a_group_writable_record_is_refused` | `0o666` | `fs.path(W.issuer)` | Loose mode, the condition under test |
| 66 | `test_revocation_file_store.py:282` | `test_an_unusable_directory_fails_closed` | `0o777` | `box` | Loose mode, the condition under test |
| 67 | `test_revocation_file_store.py:336` | `test_pin_file_refuses_a_group_writable_file_and_malformed_content` | `0o660` | `path` | Loose mode, the condition under test |
| 107 | `test_storage_policy_paths.py:58` | `_evil_layout` | `0o777` | `evil` | Loose mode, the condition under test |
| 108 | `test_storage_policy_paths.py:108` | `_chain` | `0o777` | `mid` | Loose mode, the condition under test |
| 109 | `test_storage_policy_paths.py:190` | `test_trust_add_will_not_launder_a_store_another_process_changed` | `0o666` | `world / 't.json'` | Loose mode, the condition under test |
| 110 | `test_storage_policy_paths.py:215` | `test_trust_add_does_not_keep_a_key_planted_while_it_runs` | `0o777` | `box` | Loose mode, the condition under test |
| 111 | `test_storage_policy_paths.py:256` | `test_trust_list_warns_about_an_unsafe_store` | `0o666` | `world / 't.json'` | Loose mode, the condition under test |
| 112 | `test_storage_policy_paths.py:265` | `test_trust_status_warns_about_a_directory_others_can_write` | `0o777` | `box` | Loose mode, the condition under test |
| 113 | `test_storage_policy_paths.py:272` | `test_serve_under_development_warns` | `0o666` | `world / 't.json'` | Loose mode, the condition under test |
| 114 | `test_storage_policy_paths.py:288` | `test_a_development_result_carries_the_reason` | `0o666` | `world / 't.json'` | Loose mode, the condition under test |
| 115 | `test_storage_policy_paths.py:305` | `test_a_copy_of_an_unsafe_store_is_still_refused` | `0o666` | `world / 't.json'` | Loose mode, the condition under test |
| 116 | `test_storage_policy_paths.py:468` | `test_a_replay_cache_built_without_the_flag_is_refused_by_a_strict_policy_for_its_directory` | `0o777` | `box` | Loose mode, the condition under test |
| 117 | `test_storage_policy_paths.py:525` | `test_a_lifecycle_edit_of_a_world_writable_store_keeps_the_mode_so_strict_still_refuses` | `0o666` | `world / 't.json'` | Loose mode, the condition under test |
| 118 | `test_storage_policy_paths.py:540` | `test_a_descriptor_path_is_recorded_and_refused_by_a_strict_policy` | `0o777` | `box` | Loose mode, the condition under test |
| 119 | `test_storage_policy_paths.py:638` | `test_a_lifecycle_edit_refuses_a_directory_others_can_write` | `0o777` | `box` | Loose mode, the condition under test |
| 120 | `test_storage_policy_paths.py:714` | `test_replay_migrate_refuses_a_link_through_a_directory_others_can_write` | `0o777` | `shared` | Loose mode, the condition under test |
| 121 | `test_storage_policy_paths.py:774` | `_link_chain` | `0o777` | `shared` | Loose mode, the condition under test |
| 122 | `test_storage_policy_paths.py:846` | `test_replay_migrate_refuses_a_file_in_a_directory_others_can_write_reached_from_a_safe_link` | `0o777` | `unsafe` | Loose mode, the condition under test |
| 123 | `test_storage_policy_paths.py:868` | `test_replay_migrate_keeps_a_mode_others_can_write_so_a_strict_profile_keeps_refusing` | `0o666` | `db` | Loose mode, the condition under test |
| 124 | `test_trust_store_storage_policy.py:149` | `test_a_store_replaced_through_a_directory_others_can_write_gives_no_verdict` | `0o644` | `box / 't.json'` | Ordinary readable mode that others cannot write |
| 125 | `test_trust_store_storage_policy.py:162` | `test_a_directory_higher_up_that_others_can_write_is_refused` | `0o777` | `high` | Loose mode, the condition under test |
| 126 | `test_trust_store_storage_policy.py:173` | `test_a_sticky_directory_above_a_private_parent_is_accepted` | `0o1777` | `high` | Sticky directory, as `/tmp` is. The test checks it is accepted above a private parent |
| 127 | `test_trust_store_storage_policy.py:203` | `test_a_symlinked_directory_in_a_directory_others_can_write_is_refused` | `0o777` | `shared` | Loose mode, the condition under test |
| 128 | `test_trust_store_storage_policy.py:224` | `test_a_store_replaced_between_the_read_and_the_check_after_it_is_refused` | `0o644` | `swap` | Ordinary readable mode that others cannot write |
| 129 | `test_trust_store_storage_policy.py:290` | `test_a_store_loaded_without_the_flag_is_still_refused_by_a_strict_policy` | `0o666` | `world / 't.json'` | Loose mode, the condition under test |
| 130 | `test_trust_store_storage_policy.py:298` | `test_development_still_loads_it_warns_and_is_not_protected` | `0o666` | `world / 't.json'` | Loose mode, the condition under test |
| 131 | `test_trust_store_storage_policy.py:359` | `test_the_server_configuration_refuses_a_store_others_can_write` | `0o666` | `world / 't.json'` | Loose mode, the condition under test |
| 132 | `test_trust_store_storage_policy.py:371` | `test_the_server_command_exits_2_on_a_store_others_can_write` | `0o666` | `world / 't.json'` | Loose mode, the condition under test |
| 133 | `test_trust_store_storage_policy.py:392` | `test_revocation_ceremonies_refuse_a_store_others_can_write_and_change_nothing` | `0o666` | `world / 't.json'` | Loose mode, the condition under test |
| 134 | `test_trust_lifecycle_qualification.py:514` | `test_world_writable_store_warns_but_is_still_edited_with_same_mode` | `0o666` | `path` | Loose mode, the condition under test |
| 135 | `test_trust_lifecycle_qualification.py:523` | `test_trust_add_then_lifecycle_keeps_trust_add_mode` | `0o644` | `path` | Ordinary readable mode that others cannot write |
| 136 | `test_trust_lifecycle_qualification.py:886` | `test_cli_mode_after_trust_add_is_preserved_and_symlink_survives` | `0o640` | `tmp_path / 's.json'` | Ordinary readable mode that others cannot write |

In #135 and #136 the test checks that the ordinary mode is kept. In #124 and #128 it is only the starting state: #124 varies the directory mode and #128 swaps the file between the read and the check. The comments on GitHub for #124, #126 and #128 are shorter and less exact than the Reading column, which is the fuller record.

### Import style: 8 alerts, dismissed

Each file imports `regaudit_fhe as rf` and also imports `regaudit_fhe` submodules with from-imports, which parsing each file confirmed. This is style only and has no effect on behaviour.

| # | Location |
|---|---|
| 81 | `test_revocation_hostile_sequences.py:19` |
| 82 | `test_revocation_file_store.py:25` |
| 83 | `test_revocation_public_gate.py:18` |
| 84 | `test_revocation_tooling_and_cli.py:78` |
| 85 | `test_secure_profile_v1.py:22` |
| 140 | `test_storage_policy_paths.py:24` |
| 141 | `test_trust_lifecycle_qualification.py:26` |
| 142 | `test_trust_store_storage_policy.py:19` |

### Lambdas: 2 alerts, dismissed

Each is a row of a parametrized table of replay cache factories. The lambda wraps a class so that the rows are uniform. Style only, no effect on behaviour.

| # | Location |
|---|---|
| 137 | `test_trust_history_floor.py:120` |
| 138 | `test_trust_history_floor.py:121` |

### Chained comparison: #139, dismissed as a false positive

`test_storage_policy_paths.py:308` is `assert copied.storage_problem == store.storage_problem is not None`. This is a chained comparison and means `a == b and b is not None`. Neither `==` has `None` as an operand, and the `None` test already uses `is not`. It is correct as written.

### Unused import: #89, resolved by a code change

`tests/test_revocation_hostile_sequences.py:32` imported `op` and `sign_list` from `test_revocation_tooling_and_cli`. `sign_list` is a helper of that other module and nothing else in this file uses it, so the alert was a true finding. `op` is a pytest fixture that the tests in this file receive by name, so it stays, with its `noqa`. This change removes `sign_list` from the import and changes nothing else. The 59 tests in this file and the 11 in `tests/experimental_revocation/test_matrix_consistency.py`, which reads the file's function names, pass before and after with the same result for each test.
