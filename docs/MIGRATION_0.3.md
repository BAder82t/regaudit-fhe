# Upgrading to the next security release

Unreleased, on a local candidate branch. AI-assisted engineering notes.

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

Under `confidential`, `high-assurance` and `secure-v1`, a replay file that other accounts can change is refused, and so is one owned by another account, a symlink, a file with a second name, or a file in a directory that group or others can write. `verify` exits 3 and `serve` does not start. Nothing is changed for you, so fix the mode or move the file yourself. This includes a file that keeps a group-writable mode through `replay migrate`, which only warns about it. New files are now `0600` in every profile, where they were `0644`, so a second account can no longer read a new file. A read-only verifier running under a different account from the one that writes the file is refused under the strict profiles. `development` accepts all of these, but `replay_durable` is `false` for an unsafe file. Details and limits are in [DEPLOYMENT.md](DEPLOYMENT.md#where-the-replay-file-can-live).

## 3. Optional: the `secure-v1` profile

A new, versioned profile: `confidential` with **a fixed 24 hour trust-history window**, the same on a new store, an existing store and with no store state. `trust_history_max_age` cannot be set, larger or
smaller: anything but 24 hours is refused when the policy is built. A history older than 24 hours is never fresh. What a shorter setting already refused on a store stays refused after a move to this
profile. It changes nothing about the existing profiles.

A subclass of `TrustStore` is refused under `confidential`, `high-assurance` and `secure-v1`.

## `verify_receipt`

It returns a bare bool, and that bool is not an issuer-attribution or revocation result. When tenant identity matters, use `verify_trusted` with an `entries` store
under a policy that refuses a store without issuers.
