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
