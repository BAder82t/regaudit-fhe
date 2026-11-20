# Command line

The `regaudit-fhe` command from key creation to verification, its options and exit codes, and notes on the HTTP server. The rules behind the verdicts are in [SIGN_AND_VERIFY.md](SIGN_AND_VERIFY.md).

## From key to verdict

```bash
# Issuer, once: a long-lived key (the private file is created 0600 and never overwritten)
regaudit-fhe keygen --key-id acme-2026 --issuer acme \
  --private-key acme.pem --public-key acme.pub      # prints the key's SHA-256 fingerprint

# Issuer, per audit: report.v2 signed by that key
echo '{"y_true":[1,0,1,1],"y_pred":[1,0,0,0],"group_a":[1,1,0,0],"group_b":[0,0,1,1]}' \
  > input.json
regaudit-fhe audit fairness -i input.json -o report.json \
  --signing-key acme.pem --key-id acme-2026 --issuer acme --deployment-id prod-1

# Verifier, once: enrol the issuer's key. Send acme.pub and the fingerprint over a channel
# you trust; the fingerprint you pass is checked against the file, and nothing is ever
# enrolled from a report.
regaudit-fhe trust add --store trust_store.json --key-id acme-2026 --issuer acme \
  --public-key acme.pub --fingerprint <fingerprint from the issuer>

# Verifier, per report: exit 0 only for TRUSTED
regaudit-fhe verify -i report.json --trusted-keys trust_store.json
```

`trust add` and `trust retire`/`trust revoke` exit **0** only when the store holds the change and it has been synced to disk,
**2** when the change was refused or the write failed before the store was replaced (the old store is intact), and **3** when the
store or its lock is unusable. Exit **3** with the message `NOT confirmed durable` is the one case where the change *is* in the
store but a later sync failed: it is not a success. Run the same `trust add` again (an identical repeat is idempotent, replaces nothing and
syncs again; the same `key_id` with a different key or issuer is still refused with exit 2) or `trust status` to see what the store holds. See
[STORAGE_PLATFORM_NOTES.md](STORAGE_PLATFORM_NOTES.md#write-outcomes-and-recovery).

### What `verify` says on stderr about the claims

After every verdict that exists (exit 0 or 1), `regaudit-fhe verify` writes a `claims:` block to stderr. Stdout, the JSON
keys and the exit codes are exactly what they were. The block starts with these two lines, whatever the report says:

```
claims:
  - Encrypted execution not established.
  - A signed report can authenticate a claim without proving that claim is true.
```

The lines that follow separate seven kinds of statement: execution mode observed by a trusted component (none: no signed
field and no independent check records one); execution mode declared in the report (a declaration by the signer); execution
mode established from the available evidence (cannot be established); cryptographic configuration (parameters the signer
declared, not measured); authenticated report content (what the signature and your trust store show: who signed these
bytes, not that what they say is true); independently established computational properties (none); and unsupported or
unverified claims (that the computation ran encrypted, that the results are correct, that privacy holds, that any regulation
is met). Declared TenSEAL parameters, `security_bits` and a depth are never read as encrypted execution, and a report that
declares `backend: "plaintext"` is described as declaring a plaintext backend, because that is also the default a producer signs.
Absent evidence is "not established", not "plaintext". The text is fixed: nothing a report contains is copied into it.
Scripts that treated empty stderr on success as a signal need to read the exit code instead.

`--response-format v2` adds the same statements to stdout as `claim_assessment`. See [API.md](API.md).

Without the `--signing-key` options, `regaudit-fhe audit` still emits `report.v1` signed by
an ephemeral key, which can only ever verify as `SELF_SIGNED_ONLY`. The CLI key file is an
unencrypted PEM for evaluation; for production use a KMS/HSM-backed signer through the
library. Whoever can read that file can sign as the issuer: keep it mode 0600 (the CLI refuses a group- or other-readable
file), off shared or synced folders, and treat `trust add` as enrolment only; it is not a key-lifecycle or revocation system
(no retire, revoke or rotation commands in the published releases). `regaudit-fhe verify` reads the report strictly: duplicate keys, `NaN`, unknown or
missing members in a `report.v1`, and anything else that would let the JSON you hold differ
from the bytes that were signed, are refused with exit 2. The JSON verdict echoes the report's own identifiers
(`issuer`, `key_id`, `deployment_id`, ...), even for a refused report: they are never key material, but whoever produced the
report chose them, so treat them as untrusted text in logs and as possibly sensitive. Useful `verify` options:

| Option | Purpose |
| --- | --- |
| `--trusted-keys FILE` | Trust store JSON (required unless `--allow-self-signed`). |
| `--profile {development,confidential,high-assurance,secure-v1}` | Select the verification profile (default `development`, which is not a high-assurance profile). Stricter profiles require the options below. The profile in effect is stated on stderr when you pass `--profile` and when stderr is a terminal; stdout and exit codes do not change. |
| `--verifier-id ID` | This verifier's audience identifier. |
| `--max-age-seconds N` | Refuse reports older than `N` seconds (positive, finite). Do not raise it on a replay store in use: see the [replay advisory](advisories/replay-limitations-0.2.1.md). |
| `--replay-db FILE`, `--replay-mode {off,check,record}` | Local persistent replay detection. `--replay-mode` defaults to `off`. `check` and `record` need `--replay-db`, and `--replay-db` needs `check` or `record`: a replay file with mode `off` (given explicitly or by the default) is a configuration error (exit 2), because replay protection would be disabled and the file never consulted. |
| `--refuse-legacy-v1` | Refuse `report.v1` envelopes. |
| `--allow-self-signed` | Development-only integrity check; never accepts a report. |
| `--strict` | **Refused with a usage error (exit 2).** It selects no profile, is not an alias for one and never changes a verdict. Use `--profile <name>`; the error lists the valid names. See [MIGRATION_0.3.md](MIGRATION_0.3.md#verify---strict-is-now-a-usage-error). |

`regaudit-fhe verify` exits **0 only when the report is accepted** under the
configured policy:

| Exit | Meaning |
| ---- | ------- |
| `0` | accepted (`trust_status: TRUSTED`) |
| `1` | well-formed report refused by policy, including `SELF_SIGNED_ONLY`, a revoked/compromised issuer, a stale or replayed report (the JSON names the `reason`) |
| `2` | invalid input, command usage or an incompatible combination of options: a malformed report, running with neither `--trusted-keys` nor `--allow-self-signed`, `--allow-self-signed` with a non-development profile, `--strict`, `--replay-db` with replay mode `off`, a `confidential`/`high-assurance` profile without its required options (`--max-age-seconds` and the replay options for both profiles, and `--verifier-id` for `high-assurance` only) |
| `3` | a required trust or verification resource that **was specified** is unavailable or unusable: an unreadable, malformed or empty `--trusted-keys`, an unusable `--replay-db`, or a replay store that fails while verifying outside development |

`--allow-self-signed` is a development-only integrity check: it can report
`SELF_SIGNED_ONLY` but never accepts a report, and is refused outside the
development profile. See [docs/TRUST_SPEC.md](TRUST_SPEC.md).

> **Breaking change:** a consistent self-signed report used to exit `0` and now
> exits `1`; an unreadable or malformed `--trusted-keys` file used to exit `2` and
> now exits `3`. See the [changelog](../CHANGELOG.md) for the full list.

`regaudit-fhe audit <primitive> --schema` prints the JSON shape that
each primitive expects.

> **The HTTP server is NOT a privacy boundary by itself.** The default
> execution path is plaintext; the server runs in-process. Encrypted
> execution requires the `[fhe]` extra AND CKKS secret-key custody
> held off-host. Bearer-token authentication uses constant-time
> hashed comparison (no token timing leak) and `REGAUDIT_FHE_DEV_MODE=1`
> refuses to start on a non-loopback bind, but issuer authenticity
> still relies on the verifier's trust store. Read
> [docs/DEPLOYMENT.md](DEPLOYMENT.md) and
> [docs/THREAT_MODEL.md](THREAT_MODEL.md) before exposing
> publicly.

**Resource limits (0.1.1).** `/v1/audit` refuses oversized inputs with `413`
(`INPUT_LIMIT_EXCEEDED`): 131072 elements per array, 524288 in total, nesting
depth 4, 8192 concordance samples, 32 disagreement models and 1024 provenance
buckets. Beyond 2 running and 4 queued audits it answers `503` (`SERVER_BUSY`,
with `Retry-After`), and the request timeout cancels queued work. Malformed or
non-strict JSON, non-finite numbers and a non-string `primitive` get `422`.
Invalid numeric settings stop the server from starting. Every limit is an
environment setting, listed with its default in
[docs/DEPLOYMENT.md](DEPLOYMENT.md#resource-bounds). These limits reduce
denial-of-service exposure; they do not remove it. An exposed deployment still
needs a reverse proxy that limits request-body size, connections, timeouts and
request rates, and the known open items are listed under "Known limitations"
in the [changelog](../CHANGELOG.md).
