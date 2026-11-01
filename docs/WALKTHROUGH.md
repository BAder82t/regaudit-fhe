# Walkthrough: sign a report, enrol the key, verify it

AI-assisted engineering documentation. Not an audit, not a production assurance. Every command below was run
against the published `regaudit-fhe==0.2.0` wheel from PyPI, in a clean directory outside the repository, on
2026-10-31, and the output shown is what it printed (timestamps, ids and the fingerprint differ on every run). A test
in this repository (`tests/test_docs_walkthrough.py`) re-runs these commands against the source tree.

You will play two roles on one machine: the **issuer** (signs reports) and the **verifier** (decides whom to trust).
In real use they are different people, and the verifier's trust store lives on the verifier's machine only.

## 1. Install

```bash
python -m venv .venv
.venv/bin/pip install "regaudit-fhe==0.2.0"
.venv/bin/regaudit-fhe --help
```

The rest of this page assumes `regaudit-fhe` is on your `PATH` (`. .venv/bin/activate`). Python 3.10 to 3.13 are
tested for 0.2.0. The plaintext backend used here needs no extra; encrypted CKKS needs the `[fhe]` extra (see the
README).

## 2. Issuer: create a long-lived signing key

```bash
regaudit-fhe keygen --key-id acme-2026 --issuer "Acme Bank" \
  --private-key issuer.key.pem --public-key issuer.pub.pem > keygen.json
```

stderr carries a reminder that the private key is an **unencrypted** PEM (mode 0600); keep it out of version control
and shared folders. stdout (saved in `keygen.json`) is:

```json
{
  "key_id": "acme-2026",
  "issuer": "Acme Bank",
  "algorithm": "ed25519",
  "fingerprint_sha256": "61840ac26ec19879681e83114d604cda8330b832e7c4d2bc7a9cb82c42c2eb15",
  "private_key": "issuer.key.pem",
  "public_key": "issuer.pub.pem"
}
```

`keygen` never overwrites existing files. Send the public key **and the fingerprint** to the verifier over a channel
you trust (not the same channel as the report, ideally).

## 3. Issuer: run an audit and sign it with that key

Save this input as `fairness_input.json`:

```bash
cat > fairness_input.json <<'JSON'
{
  "y_true":  [1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0],
  "y_pred":  [1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0],
  "group_a": [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
  "group_b": [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
  "threshold": 0.1
}
JSON
```

```bash
regaudit-fhe audit fairness -i fairness_input.json -o report.json \
  --signing-key issuer.key.pem --key-id acme-2026 --issuer "Acme Bank" --deployment-id prod-eu-1
echo "exit=$?"
```

```text
signed report.v2 as key_id 'acme-2026' (issuer 'Acme Bank'). It verifies as TRUSTED only for a verifier whose own trust store enrols this key: regaudit-fhe verify --input REPORT --trusted-keys STORE
exit=0
```

Without `--signing-key` the CLI signs a `report.v1` with a throw-away key, which can never be more than
`SELF_SIGNED_ONLY` (section 6). The HTTP server's `/v1/audit/*` endpoints always do that.

## 4. Verifier: enrol the key (with the fingerprint check) and verify

`trust add` refuses to enrol a key whose fingerprint differs from the one you were given:

```bash
FP=$(python -I -c 'import json,sys; print(json.load(sys.stdin)["fingerprint_sha256"])' < keygen.json)
regaudit-fhe trust add --store trust.json --key-id acme-2026 --issuer "Acme Bank" \
  --public-key issuer.pub.pem --fingerprint 0000000000000000000000000000000000000000000000000000000000000000
echo "exit=$?"
```

```text
fingerprint mismatch: nothing enrolled. The public key file has SHA-256 fingerprint 61840ac2...2eb15, not 0000...0000. Compare it against the value the issuer gave you over a trusted channel.
exit=2
```

(The real message prints the full values.) In real use paste the fingerprint the issuer sent you; here `$FP` stands
in for it:

```bash
regaudit-fhe trust add --store trust.json --key-id acme-2026 --issuer "Acme Bank" \
  --public-key issuer.pub.pem --fingerprint "$FP"
echo "exit=$?"
regaudit-fhe trust list --store trust.json
echo "exit=$?"
```

```text
{
  "enrolled": "acme-2026",
  "issuer": "Acme Bank",
  "fingerprint_sha256": "61840ac26ec19879681e83114d604cda8330b832e7c4d2bc7a9cb82c42c2eb15",
  "store": "trust.json",
  "entries": 1
}
exit=0
[
  {
    "key_id": "acme-2026",
    "issuer": "Acme Bank",
    "status": "active",
    "fingerprint_sha256": "61840ac26ec19879681e83114d604cda8330b832e7c4d2bc7a9cb82c42c2eb15"
  }
]
exit=0
```

Now verify against your trust store:

```bash
regaudit-fhe verify -i report.json --trusted-keys trust.json > verdict_trusted.json
echo "exit=$?"
head -n 4 verdict_trusted.json
```

```text
exit=0
{
  "trust_status": "TRUSTED",
  "accepted": true,
  "valid": true,
```

`TRUSTED` and exit 0 mean: the signature and hash are intact **and** the signing key is enrolled in *your* trust store
and active. Exit 0 is the only accepting exit code. Other codes: 1 refused by policy (including `SELF_SIGNED_ONLY`),
2 invalid input or usage, 3 a trust or verification resource is unusable.

## 5. The four things a verdict does and does not tell you

| Question | What answers it | Where |
|---|---|---|
| Is the report intact? (cryptographic validity) | Ed25519 signature plus content hash over the canonical report | `integrity_valid` |
| Is the signer someone I trust? (signer trust) | The key is enrolled in **your own** trust store, with a fingerprint you checked | `issuer_trusted`, `trust_status` |
| Does the signed provenance agree with itself? (provenance consistency) | Signed `backend`, `parameter_set` and `parameter_set_hash` do not contradict each other. A bug detector, not a defence against an adversarial signer. | `PROVENANCE_CONTRADICTION` / `PROVENANCE_UNVERIFIABLE` reasons |
| Did the computation actually run under FHE? | **Not provided.** | none |

The last row matters. `backend` is whatever the signer asserted. A consistent claim of `"backend": "ckks-tenseal"`
is still only a claim, and a default library call signs `"plaintext"` even on the encrypted path. The report above
says `"backend": "plaintext"`. `TRUSTED` means "intact and signed by someone you enrolled", not "audited", not
"computed under encryption", and not "approved by a regulator". There is also no revocation service: a trust store
is a local file, `trust add` has no retire or revoke command, so removing trust means editing or replacing that
file.

## 6. SELF_SIGNED_ONLY: what it proves and why it never exits 0

If you have no trust store, the development-only flag checks integrity against the public key *embedded in the
report*:

```bash
regaudit-fhe verify -i report.json --allow-self-signed > verdict_self.json
echo "exit=$?"
head -n 2 verdict_self.json
```

```text
not accepted: SELF_SIGNED_ONLY. The report is intact and its signature matches the key embedded in it, but nothing shows who holds that key. Verify with --trusted-keys <your trust store> to authenticate the issuer.
exit=1
{
  "trust_status": "SELF_SIGNED_ONLY",
```

What it proves: the file was not changed after whoever held that key signed it. What it does not prove: who that is.
Anyone can generate a key, write any issuer name, and produce a perfectly intact self-signed report, so accepting
it would accept anyone. That is why it never yields exit 0, in any profile. Without `--trusted-keys` or
`--allow-self-signed`, `verify` refuses with exit 2 (`no trust material`).

## 7. INVALID: tamper with one field

Change one signed field (`deployment_id`) and verify again:

```bash
python -I - <<'PY'
import json
d = json.load(open("report.json"))
d["deployment_id"] = "prod-us-9"
json.dump(d, open("tampered.json", "w"), indent=2, sort_keys=True)
PY
regaudit-fhe verify -i tampered.json --trusted-keys trust.json > verdict_tampered.json
echo "exit=$?"
head -n 2 verdict_tampered.json
grep -A3 blocking_reasons verdict_tampered.json
```

```text
not accepted: INVALID (HASH_MISMATCH). See blocking_reasons in the JSON above and docs/TRUST_SPEC.md.
exit=1
{
  "trust_status": "INVALID",
  "accepted": false,
  "valid": false,
  "integrity_valid": false,
  ...
  "blocking_reasons": [
    "HASH_MISMATCH",
    "SIGNATURE_INVALID"
  ],
```

(The first line goes to stderr, the JSON to stdout, which is why it is redirected above.)

## 8. What `verify` prints is report-supplied text

The verdict JSON echoes identifiers taken from the report: `issuer`, `key_id`, `primitive`, `issued_at`,
`regulations`, `parameter_set_hash`, `deployment_id`, `audit_run_id`. They are not key material, but **the report's
producer chooses them**, even for a report that is `INVALID`: the tampered report above printed
`"deployment_id": "prod-us-9"`, the attacker's value. Treat them as untrusted text in logs, terminals, dashboards and
prompts (escape, truncate, do not interpolate into commands), and as possibly sensitive in some deployments, so do not
forward verdict output to places the report's contents should not go. The free-form `result` is never printed.

## 9. Limits to keep in mind

* The private key file is an unencrypted PEM; whoever can read it can sign as the issuer. For production use a
  KMS/HSM-backed signer through the library.
* A trust store is a local file. There is no authoritative revocation or rotation service.
* Resource limits help but do not replace a reverse proxy in front of `regaudit-fhe serve`.
* The releases rely on AI-assisted testing and review. There is no independent external security audit and no
  regulator approval, and no production assurance is claimed. See `docs/releases/RELEASE_0.2.1_RECORD.md`.

Next: `examples/strict_verification_quickstart.py` (library API), `docs/TRUST_SPEC.md` (verdict semantics),
`docs/THREAT_MODEL.md`, `docs/DEPLOYMENT.md`.
