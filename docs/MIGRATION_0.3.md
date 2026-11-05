# Upgrading to the next security release

AI-assisted engineering notes. **Published v0.2.1 does not have these changes, including the storage refusals, so do not assume it is protected.** No patch for 0.2.x is planned, and the mitigations are in [the advisories](advisories/). This describes the experimental code from pull request #65, which is not independently security-qualified. v0.3.0 is unreleased and subject to security acceptance.

**Two things stop working until you act, and both fail loudly, before any report is read.**

| What you have | What happens after upgrading | What to do |
| --- | --- | --- |
| A bare `{key_id: PEM}` or `{"keys": ...}` trust store, under `confidential`, `high-assurance` or `secure-v1` | The policy is refused: `regaudit-fhe verify` exits 2, `serve` does not start, the library raises `PolicyError` | [Build a new store with `trust add`](#1-a-trust-store-without-issuers). `trust migrate` does not satisfy these profiles |
| A replay file written by a published version | It is refused: `verify` exits 3, `serve` does not start, the library raises `LegacyReplayFile` | [Migrate the replay file](#2-a-replay-file-from-a-published-version) |

Under `development`, a trust store without issuers keeps working and each result says `ISSUER_UNBOUND`.

Why: with a store that states no issuer, any enrolled key could sign under any issuer name and get `TRUSTED` with `issuer_trusted`
true, however few keys it held ([advisory](advisories/issuer-attribution-0.2.1.md)). A replay file does not record the policy that wrote
it, so raising `max_age`, sharing a file between settings, or leaving `max_age` out could accept one report twice
([advisory](advisories/replay-limitations-0.2.1.md)).

Before either migration: stop the verifiers using the file, and keep a copy of it somewhere only you can write.

## 1. A trust store without issuers

**On a strict profile, build a new store with `trust add`.** For each key, get the fingerprint from the issuer over a channel you trust, not from the old store:

```bash
# one public key file per key, in PEM, then:
regaudit-fhe trust add --store new.json --key-id KEY_ID --issuer ISSUER \
    --public-key KEY_ID.pub --fingerprint FINGERPRINT_THE_ISSUER_GAVE_YOU
regaudit-fhe trust status --store new.json
regaudit-fhe verify -i a_report_you_trust.json --trusted-keys new.json --profile confidential ...
```

Copy each name exactly from the `issuer` field of reports you already trust, since the comparison is byte for byte. Check a sample of reports before you switch, and keep the old store. One key
has one issuer: reports a key signed under an earlier name get `ISSUER_MISMATCH`, since a rename cannot be told from a substitution. A key flagged `revoked` in the old store must not be
carried over as active: mark it with `trust revoke` after adding it.

**`trust add` is normal enrollment, not an authenticated one.** No authenticated enrollment exists yet. It checks the key against the fingerprint you supply, and the result's `issuer_binding` is
`store_entry`, meaning the name was compared with what your store states. Your store is a local file. Whether this should be enough for a strict profile is an open question for the project owner.

**`trust migrate` is for `development` and the lenient paths.** Every strict profile refuses what it writes (`ISSUER_ENROLLMENT_UNAUTHENTICATED`), because `--issuer` is your statement as a local
operator and not proof that a key belongs to that issuer.

```bash
regaudit-fhe trust migrate --source old.json --target new.json --issuer KEY_ID=ISSUER --dry-run
regaudit-fhe trust migrate --source old.json --target new.json --issuer KEY_ID=ISSUER
```

Repeat `--issuer` for every key: nothing is inferred. A flat `revoked` key becomes `compromised` with an unknown boundary, and it stays refused. The output says `issuer_binding: operator-declared`, `authenticated_binding: false`,
and `development` results carry `ISSUER_OPERATOR_DECLARED`.

**The store records this, on each entry, as `issuer_source: operator-declared`.** The record goes with the store through a copy or a move. Deliberately deleting it from the file is an edit of local state that nothing can detect, and
it does not make the names any better established.

**Published versions refuse a migrated store.** 0.1.0, 0.1.1, 0.2.0 and 0.2.1 do not know that member, so `TrustStore.from_json` raises and `regaudit-fhe verify` exits 3. That fails closed. **Keep the source store: `trust migrate` leaves it unchanged, and it is
the way back** to an older verifier.

### Permissions on the trust store

Under `confidential`, `high-assurance`, and `secure-v1` a trust store file that another account owns or can write is refused, directly or through a directory above it. A symlink or a file with a second name is also refused. `verify` will exit with 3 and `serve` will not start. A file that is owned by root is fine as well as `0600`, `0640`, and `0644`. `0660` is refused. Nothing changes the mode for you. `trust add`, `trust retire`, and `trust revoke` keep the mode of a store file. A file that another account could have changed is refused. See [DEPLOYMENT.md](DEPLOYMENT.md#where-the-trust-store-can-live).

### Names that are refused

Everywhere a name is enrolled, loaded or migrated, and in every profile, an issuer may not be empty, have leading or trailing whitespace, contain
whitespace other than an ordinary space, contain a control, zero-width, bidi or other invisible character, or consist only of combining marks or blank characters. **An existing `entries` store holding such
a name no longer loads**: `verify` exits 3 and `serve` does not start. Nothing is normalised for you, because that could turn one issuer into
another. Correct the name in the store only if it is what the key's reports actually carry; a report signed under the old name needs a new key. Names such
as `Acme Bank Ltd` and `Banque Générale` are fine.

## 2. A replay file from a published version

```bash
regaudit-fhe replay status --db replay.db
regaudit-fhe replay migrate --db replay.db --previous-max-age-seconds 86400   # the largest max_age this file ever served
regaudit-fhe replay migrate --db replay.db --previous-policy-unknown          # you do not know
```

State the largest `max_age` the file ever served, or say you do not know. If you do not know, every report issued up to the migration is refused from
then on (`REPLAY_HISTORY_UNKNOWN`), since it may have been recorded and purged. The stated value becomes a floor, and a larger setting is not honoured
on that file. The original stays at `replay.db.pre-migration`. Do not point a verifier at a new empty file to avoid this: a new file remembers nothing.

Full details are in [DEPLOYMENT.md](DEPLOYMENT.md#upgrading-with-an-existing-replay-file). After migrating, give each `max_age` its own replay file and always pass
`max_age`: two settings on one file are held to the smaller one.

### Permissions on the replay file

Under `confidential`, `high-assurance`, and `secure-v1`, a replay file that another account can change will be refused. Also, one that belongs to another account will be refused. A symlink will be refused. A file with a second name will be refused. A file in a directory where group or others can write will be refused. `verify` will exit 3 and `serve` will not start. Nothing will be changed for you. Fix the mode or move the file yourself. This includes a file that keeps a group-writable mode through `replay migrate`, which only warns about it. New files are now `0600` in all profiles where they were `0644`. A second account can no longer read a new file. A read-only verifier running under a different account than the one that writes the file is refused in strict profiles. `development` will accept all these but `replay_durable` would be `false` for an unsafe file. More details and limits are in [DEPLOYMENT.md](DEPLOYMENT.md#where-the-replay-file-can-live).

## 3. Optional: the `secure-v1` profile

A new, versioned profile: `confidential` with **a fixed 24 hour trust-history window**, the same on a new store, an existing store and with no store state. `trust_history_max_age` cannot be set, larger or
smaller: anything but 24 hours is refused when the policy is built. A history older than 24 hours is never fresh. What a shorter setting already refused on a store stays refused after a move to this
profile. It changes nothing about the existing profiles.

A subclass of `TrustStore` is refused under `confidential`, `high-assurance` and `secure-v1`.

## 4. Signing a parameter set for the encrypted path (B-12)

Only for producers that sign an encrypted-path `parameter_set` with the `[fhe]` extra. The CLI, the server and the default
`envelope(...)` path sign `plaintext` and are not affected. A verifier is not affected either: no verdict reads `security_bits`.

0.3.0 signs only what the backend can show, so these now fail, loudly, before anything is signed:

| What you did | What happens in 0.3.0 | What to do |
| --- | --- | --- |
| `CKKSParams(security_level="HEStd_192_classic")` or `"HEStd_256_classic"` | `ParameterValidationError`. TenSEAL builds every context at SEAL's default 128-bit level, so the claim could not be enforced | Use `HEStd_128_classic` |
| `CKKSParams(ring_dim=65536)` or larger | `ParameterValidationError`. SEAL has no table entry there and refuses to build the context | Use 16384 or 32768 |
| A chain with a prime of more than 60 bits, or too many primes of a size the ring cannot supply | `ParameterValidationError`. SEAL refuses these | Use sizes SEAL accepts |
| `CKKSParams(...).to_envelope_parameter_set()` where TenSEAL is not installed, or the backend cannot be shown to enforce the level | `regaudit_fhe.fhe.BackendUnverified`, nothing is signed | Sign on a host with `regaudit-fhe[fhe]` installed |
| `parameter_set_from_ckks_context(ctx, security_bits=192)` or `256` | `ValueError`. The backend enforces 128 | Leave `security_bits` out, or pass 128 |
| `parameter_set_from_ckks_context(obj)` where `obj` is not a TenSEAL CKKS context, or `multiplicative_depth` is more than the chain carries | `BackendUnverified` or `ValueError` | Pass the context itself, or the `CKKSContext` from `build_d6_context` |
| `parameter_set_from_openfhe_context(ctx)` where `ctx.cc` has no `GetRingDimension()` | `BackendUnverified` | See below |

**What stays the same.** `ParameterSet()`, `CKKSParams().to_envelope_parameter_set()` and the default `build_d6_context()` signed through
`parameter_set_from_ckks_context` produce the same fields and the same `parameter_set_hash` as before.

**What changes in a signed value.** A context built with a chain other than the default used to be signed with the default chain. It now
signs its real chain, so its `parameter_set_hash` changes. `CKKSParams()` built through `build_d6_context_from_params` is one of these: it
signed a 9-prime chain for an 8-prime context. If a verifier pins that hash (`parameter_set_pin`), reports from the same configuration are
`PIN_MISMATCH` until you read the new `parameter_set` and pin the new hash. A pin on the old hash was pinning a value that was not true.

**OpenFHE.** `parameter_set_from_openfhe_context` now reads the ring dimension from the context where it used to sign twice the batch size, and
refuses any level but the 128 the builder requests. This has **not** been run against a real OpenFHE: the call name and OpenFHE's enforcement of
the level are only exercised against stand-ins here. The chain is still signed empty.

**Reports already signed.** They verify as before. A `192`, a `256`, a fixed-default chain or a doubled batch size in an old report cannot be told
from a correct value by looking at it. Treat `security_bits` as a declaration ([REPORT_FORMAT.md](REPORT_FORMAT.md#what-parameter_set-and-security_bits-mean)).

## `verify_receipt`

It returns a bare bool, and that bool is not an issuer-attribution or revocation result. When tenant identity matters, use `verify_trusted` with an `entries` store
under a policy that refuses a store without issuers.
