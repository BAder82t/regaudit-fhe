# Upgrading to the next security release

Unreleased, on a local candidate branch. AI-assisted engineering notes.

**Two things stop working until you act, and both fail loudly, before any report is read.**

| What you have | What happens after upgrading | What to do |
| --- | --- | --- |
| A bare `{key_id: PEM}` or `{"keys": ...}` trust store, under `confidential` or `high-assurance` | The policy is refused: `regaudit-fhe verify` exits 2, `serve` does not start, the library raises `PolicyError` | [Migrate the trust store](#1-a-trust-store-without-issuers) |
| A replay file written by a published version | It is refused: `verify` exits 3, `serve` does not start, the library raises `LegacyReplayFile` | [Migrate the replay file](#2-a-replay-file-from-a-published-version) |

Under `development`, a trust store without issuers keeps working and each result says `ISSUER_UNBOUND`.

Why: with a store that states no issuer, any enrolled key could sign under any issuer name and get `TRUSTED` with `issuer_trusted`
true, however few keys it held ([advisory](advisories/issuer-attribution-0.2.1.md)). A replay file does not record the policy that wrote
it, so raising `max_age`, sharing a file between settings, or leaving `max_age` out could accept one report twice
([advisory](advisories/replay-limitations-0.2.1.md)).

Before either migration: stop the verifiers using the file, and keep a copy of it somewhere only you can write.

## 1. A trust store without issuers

```bash
regaudit-fhe trust migrate --source old.json --target new.json --issuer KEY_ID=ISSUER --dry-run
regaudit-fhe trust migrate --source old.json --target new.json --issuer KEY_ID=ISSUER
regaudit-fhe trust status --store new.json
regaudit-fhe verify -i a_report_you_trust.json --trusted-keys new.json
```

Repeat `--issuer` for every key: a key with no statement refuses the whole migration, and nothing is inferred. Copy each name exactly from
the `issuer` field of reports you already trust, since the comparison is byte for byte. Check a sample of reports against `new.json` before you
switch. The source is left unchanged, so you can go back.

**`--issuer` is your statement as a local operator, not proof that a key belongs to that issuer.** No authenticated enrollment exists. The
command writes `new.json.issuer-provenance.json` beside the store to record this, and the output says `issuer_binding: operator-declared`,
`authenticated_binding: false`. Results on that store carry `ISSUER_OPERATOR_DECLARED`. Keep the two files together. That file is a label:
deleting it does not make the statement any stronger. Published versions read `new.json` as it is, and ignore the file beside it.

* A flat `revoked` key becomes `compromised` with an unknown boundary. It stays refused, and its code changes to
  `KEY_COMPROMISED_NO_CHRONOLOGY`.
* One key has one issuer. Reports a key signed under an earlier name get `ISSUER_MISMATCH`, since a rename cannot be told from a substitution.

### Names that are refused

Everywhere a name is enrolled, loaded or migrated, and in every profile, an issuer may not be empty, have leading or trailing whitespace, contain
whitespace other than an ordinary space, or contain a control, zero-width, bidi or other invisible character. **An existing `entries` store holding such
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

## 3. Optional: the `secure-v1` profile

A new, versioned profile. It is `confidential` with two more rules, and it changes nothing about the existing profiles.

* **A fixed 24 hour trust-history window**, the same on a new store, an existing store and with no store state. `trust_history_max_age` cannot be set, larger or
  smaller: anything but 24 hours is refused when the policy is built. A history older than 24 hours is never fresh. What a shorter setting already refused on a store
  stays refused after a move to this profile.
* **A store recorded as operator-declared is refused.** Enroll each key with `regaudit-fhe trust add` in a new store, checking the fingerprint the issuer gave you.

This is not an authenticated enrollment either, and `secure-v1` does not claim one. A subclass of `TrustStore` is refused under this profile and under
`confidential` and `high-assurance`.

## `verify_receipt`

It returns a bare bool, and that bool is not an issuer-attribution or revocation result. When tenant identity matters, use `verify_trusted` with an `entries` store
under a policy that refuses a store without issuers.
