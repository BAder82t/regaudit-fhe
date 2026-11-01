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
suppressed, and the CodeQL configuration is unchanged. No behaviour changes, apart from removing the internal hook
named below.

| # | Rule | Location | Change |
|---|---|---|---|
| 8, 9, 10, 11, 14 | `py/unused-import` | `benchmarks/bench_fhe.py`, `examples/` | Removed the imports |
| 23 | `py/unused-import` | `fhe/openfhe.py` | The availability probe uses `importlib.import_module("openfhe")`, so it still catches every import failure but binds no name |
| 17, 22 | `py/import-and-import-from` | `tests/test_fhe_equivalence_matrix.py`, `tests/test_dp.py` | One import form per module |
| 18, 19 | `py/ineffectual-statement` | `reports.py` `KeyProvider` | The `...` bodies of the `Protocol` members are replaced by docstrings |
| 20, 21 | `py/cyclic-import` | `fhe/backends.py`, `fhe/openfhe.py` | `backends` now registers the OpenFHE backend itself and `openfhe` no longer imports `backends`, so the cycle is gone. This removes `regaudit_fhe.fhe.openfhe.register()`, which nothing but `backends` called |
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
