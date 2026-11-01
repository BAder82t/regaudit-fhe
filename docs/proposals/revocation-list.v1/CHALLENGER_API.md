# 0.3.0 trust protocol: API for a challenger

For anyone running an independent corpus against the implementation on `impl/0.3-protocol-v2`. All of this is private and experimental:
nothing is exported from `regaudit_fhe`, no schema is registered, and the default verification path uses none of it. AI-assisted
engineering work; not an audit and no production assurance. Formats and rules: [the frozen proposal](../../TRUST_REVOCATION_PROTOCOL_PROPOSAL.md).
Differences from it: [IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md).

## Modules

| Module | Holds |
|---|---|
| `regaudit_fhe._revocation` | Formats, signing domains, document verifiers. Pure |
| `regaudit_fhe._revocation_state` | `Pin`, pin files, `FileStateStore`, record, ceremonies, ingest |
| `regaudit_fhe._revocation_gate` | `RevocationContext`, `gate`, `overlay`, `verify_with_revocation`, `policy_evidence` |
| `regaudit_fhe._revocation_tooling` | Issuer side: refuses hazards before signing |
| `regaudit_fhe._trust_lifecycle` | `migrate_store`, `migrate` |
| `regaudit_fhe.replay` | `bind_max_age`, `max_age_floor` (F-07) |

## Enrollment

```python
from regaudit_fhe import _revocation_state as st
pin = st.Pin(issuer, authority_pem, enrollment_id, recovery_pem=None, baseline_epoch=None,
             baseline_digest=None, authority_generation=1, recovery_epoch=0, recovery_digest=None)
store = st.FileStateStore(directory)                # directory must exist, not group- or world-writable, not a symlink
st.enroll(store, pin, trust_store_or_None, now=now) # raises ValueError if refused or already enrolled
st.save_pin(path, pin); st.load_pins(path)          # PinStoreError if unusable
st.rebaseline(store, pin, now=now, trust_store=None, clear_effective=False, accept_loss=False, reset_policy_floor=False)
```
`baseline_epoch=0` means the ceremony asserts no list exists yet, and takes no digest. `None` means first use, which `required` refuses.
`rebaseline` refuses a pin behind the record's generation, recovery epoch or mark, unless `accept_loss`, which is also what a missing or unreadable record needs.
Out-of-band fingerprint confirmation is done by the CLI (`revocation enroll`); no report-key signature is involved.

## Ingest: list, rotation, recovery

All take raw document text or bytes and an `entries` `TrustStore`, and return `Ingested(accepted, code, notes, seq)`. They never raise on
a bad document.

```python
st.ingest_list(store, pin, raw, trust_store, now)
st.ingest_transition(store, pin, raw, trust_store, now)   # rotation
st.ingest_recovery(store, pin, raw, trust_store, now)     # recovery
st.ingest_feed(store, pin, recoveries=[...], transitions=[...], raw_list=raw_or_None, trust_store=ts, now=now)
st.load(store, pin) -> (Record, raw)                      # Record: seq, state, effective, contradiction, clock_floor, adjudicated, policy_floor
```
Pure document checks, with no store: `_revocation.verify_list_enrolled`, `verify_transition`, `verify_recovery`, `apply_authority`, `commit`.
To build documents: `build_body`/`sign_list`, `build_transition_body`/`sign_transition`, `build_recovery_body`/`sign_recovery`. Signers need
`sign(bytes)`, `key_id` and `public_key_pem()`; `regaudit_fhe.Signer` does.

## Report verification

```python
from regaudit_fhe import _revocation_gate as gate
ctx = gate.RevocationContext(mode, store, {issuer: pin}, max_evidence_age=timedelta(hours=24))
decision = gate.verify_with_revocation(env, policy, ctx, presented=None)  # .result (VerificationResult), .revocation (dict or None)
gate.policy_evidence(decision)
```
`mode` is `"off"`, `"advisory"` or `"required"`. `env` comes from `regaudit_fhe.report_v2.parse_envelope_strict`, `policy` is a
`VerificationPolicy`. Keep one `ctx` across calls to model a long-running process: it remembers the position. Exit-code mapping: `gate.INFRASTRUCTURE_CODES`.

**Public-path restrictions:** `high-assurance` with any mode other than `off` raises `PolicyError`, and any store other than exactly `FileStateStore` raises `PolicyError`.

**The algorithm without those restrictions:** `gate._run_gate(env, policy, ctx, presented=None, _unqualified_test_path=True)`, with any object having `scope`, `read(issuer)` and `cas(issuer, expected, new)`. `tests/experimental_revocation/trust_gate.py` has a test double, `MemoryCasStore`. Results from this path are simulated evidence, not product behaviour.

## Fault injection

* **Crash at a commit point:** subclass `FileStateStore` and override `_fault(self, point)`. Points: `mid-write`, `partial-temp`, `before-rename`, `after-rename`, `after-directory-sync`. `tests/test_revocation_file_store.py` kills a real process there with SIGKILL.
* **Contention:** real processes, or wrap `cas`.
* **Damage or restore:** act on `store.path(issuer)`, or on the double's `.data[issuer]`; the double has `.down = True` for an outage.
* **Clock:** `now` is an argument everywhere, and `policy.now` for reports.
* **Record size:** `_revocation_state.MAX_RECORD_BYTES`.
* **Replay floor:** `SqliteReplayCache.max_age_floor()`, table `replay_policy_floor`.

## Issuer tooling

`_revocation_tooling.next_list(issuer=, authority=, generation=, previous=, actions=[KeyAction(...)], now=, valid_for=, trust_store=None, recovery_anchor_pem=None, allow_unknown_keys=False, after_recovery=None) -> NextList(document, digest, clamped)`,
`sign_transition_statement`, `sign_recovery_statement`, `load_publisher_state`, `publisher_lock`, `persist_before_release`. `ActionRefused` means nothing was signed. The CLI's `sign-list` needs `--initial` for a first list and `--trusted-keys` (or `--allow-unknown-keys`) for any action.

## CLI

```
regaudit-fhe revocation enroll | rebaseline | status | ingest {list,transition,recovery} | sign-list | sign-transition | sign-recovery
regaudit-fhe trust migrate --source S --target T --issuer KEY_ID=ISSUER ... [--dry-run]
regaudit-fhe trust add ... [--revocation-pins PINS]
regaudit-fhe verify ... [--revocation-mode off|advisory|required --revocation-pins PINS --revocation-state DIR
                         --revocation-evidence-age-seconds N] [--policy-evidence]
```
`verify` exits 0 accepted, 1 refused by policy, 2 configuration (including `high-assurance` with a mode), 3 a required resource unusable.

## Not there

Server wiring (`POST /v1/verify` has no revocation mode), an independent store, list-derived history, schema registration.
