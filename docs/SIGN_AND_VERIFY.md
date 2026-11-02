# Signing and verifying reports

How a report is signed and what a verifier can and cannot conclude from it. The [main README](../README.md) has the short version, [CLI.md](CLI.md) has the same flow on the command line, and [WALKTHROUGH.md](WALKTHROUGH.md) is a hands-on run with real output.

## Client side — produce an audit envelope

```python
import numpy as np
import regaudit_fhe as rf

y_true = np.array([1, 0, 1, 1, 0, 1, 0, 0], dtype=float)
y_pred = np.array([1, 0, 1, 0, 0, 1, 1, 0], dtype=float)
group_a = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
group_b = 1.0 - group_a

report = rf.audit_fairness(y_true, y_pred, group_a, group_b, threshold=0.1)
print(report.demographic_parity_diff, report.threshold_breached)

# Long-lived issuer key in production; ephemeral for demos.
signer = rf.Signer.generate(issuer="acme-bank", key_id="acme-2026-04")
envelope = rf.envelope("fairness", report, signer=signer)
print(envelope.to_json())  # ship this to the regulator
```

## How a report becomes trusted (in plain English)

1. **The client signs.** The audited company runs an audit and signs the result with
   its private key. The result is a JSON file called an *envelope*.
2. **The regulator keeps its own list of approved keys**, called the *trust store*.
   The list belongs to the regulator; a report cannot add itself to it.
3. **The verifier checks the report against that list** and answers with exactly one
   of three words:

| Answer | In plain words | What to do |
| --- | --- | --- |
| `TRUSTED` | An approved key signed it, it has not been altered, and every rule you set was met. | Accept it. |
| `SELF_SIGNED_ONLY` | It has not been altered, but you gave no list of approved keys, so you cannot tell who signed it. | Do not rely on it. Useful only for development checks. |
| `INVALID` | It was altered, or the key is unknown, revoked or out of scope, or it is too old, replayed, or breaks a rule. | Reject it. `blocking_reasons` says why. |

Everything else in this section is detail layered on that one idea.

## A valid signature is not a trusted signer

A report carries the public key that checks its own signature. So anyone can produce a
report whose hash and signature are perfectly consistent: generate a key, sign, embed the key.
Consistency proves the bytes were not changed after signing. It proves nothing about **who**
signed. Only a key the verifier registered beforehand can answer that.

| What you ran | What a good result means | Does it authenticate the issuer? |
| --- | --- | --- |
| `rf.verify_report(env, VerificationPolicy(trust_store=...))` / `regaudit-fhe verify --trusted-keys` | `trust_status == "TRUSTED"`, `accepted` is `True` (CLI exit 0) | **Yes**, within the key's registered scope. |
| `VerificationPolicy(allow_self_signed=True)` / `--allow-self-signed` | `integrity_valid` is `True`, `trust_status == "SELF_SIGNED_ONLY"`, `accepted` is `False` (CLI exit 1) | No. Development only. |
| `VerificationPolicy()` with no trust store | raises `VerificationUnavailable` (CLI exit 2) | n/a: refuses rather than trusting the embedded key. |
| `rf.verify_trusted(report, trust_store)` (new in 0.2.0) | `.verdict` is `TRUSTED`, `SELF_SIGNED_ONLY` or `INVALID`; `.trusted` is `True` only for `TRUSTED`. The report is parsed strictly first. | **Yes**, same rules as `verify_report`; refuses a trust store of `None`. |
| `rf.verify_receipt(env)` | returns `True` for an intact report **signed by anyone** (`DeprecationWarning` and a one-time `UserWarning`) | **No.** Do not use it as an accept/reject decision. |
| `rf.verify_envelope(env)` with no `trusted_keys`/`trust_store` | `.trust_status == "SELF_SIGNED_ONLY"`, but the deprecated `.valid` is `True` | **No.** Branch on `trust_status`, never on `valid`. |

With a legacy `{"keys": ...}` or bare `{key_id: PEM}` store, "Yes" above covers the key and not the
issuer name: see the [issuer attribution advisory](advisories/issuer-attribution-0.2.1.md).

Rules of thumb: decide on `result.accepted` (or the CLI exit code `0`), never on
`integrity_valid`, `valid` or a truthy return value. Build the trust store from keys you
obtained out of band (a key ceremony, the issuer's published fingerprint), not from
a report you received. Even `TRUSTED` says only "signed by a key in my trust store, within
its scope, with every policy rule met"; it does not say the audit is correct or that anything
is compliant. [`examples/strict_verification_quickstart.py`](../examples/strict_verification_quickstart.py)
runs each of these cases.

## Four different questions (and what answers each)

A `TRUSTED` verdict answers the first two only.

1. **Is the report intact? (cryptographic validity)** The Ed25519 signature and content hash match.
2. **Is the signer someone I trust? (signer trust)** The key is enrolled in **your own** trust store. Trust stores are
   local files: there is no authoritative revocation service.
3. **Does the signed provenance agree with itself? (provenance consistency)** The signed `backend`,
   `parameter_set` and `parameter_set_hash` do not contradict each other. This is a bug detector, not a defence
   against an adversarial signer.
4. **Did the computation really run under FHE?** **Not provided.** `backend` is what the signer asserted, and a
   default library call signs `plaintext` even on the encrypted path. Signed provenance gives authenticated claims:
   the signature shows who made the claim, and it does not independently verify that an encrypted computation ran.

A hands-on run of the whole flow, with real output, is in [docs/WALKTHROUGH.md](WALKTHROUGH.md).

## Regulator side — verify a report (recommended)

**Step 1. Write down which keys you approve.** Each key records who it belongs to,
whether it is still active, and optionally where it may be used:

```json
{
  "entries": {
    "acme-2026-04": {
      "issuer": "acme-bank",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "status": "active",
      "not_before": "2026-04-01T00:00:00Z",
      "deployments": ["prod-eu-1"],
      "primitives": ["fairness", "calibration"]
    }
  }
}
```

A key can be listed under one name only, and it must be an Ed25519 key. (The older
flat format with `keys` / `revoked` / `parameter_set_pins` still works, but it does not bind a
key to an issuer: see [the advisory](advisories/issuer-attribution-0.2.1.md).)

**Step 2. Verify.**

```python
import regaudit_fhe as rf

trust_store = rf.TrustStore.from_json("trust_store.json")  # refuses to load if unusable
policy = rf.VerificationPolicy(trust_store=trust_store, verifier_id="regulator-a")

env = rf.parse_envelope(received_text)  # reads v1 or v2; rejects malformed JSON
result = rf.verify_report(env, policy)

if result.accepted:  # the single yes/no decision
    print("trusted:", result.issuer, result.key_id)
else:
    print(result.trust_status, result.blocking_reasons)  # e.g. INVALID ['ISSUER_UNKNOWN']
```

Use `result.accepted` (or `result.trust_status`). Do not use `valid`; it is deprecated
and, without a trust store, only means "the file is intact".

<details>
<summary><strong>What else the result tells you</strong></summary>

| Field | Meaning |
| --- | --- |
| `accepted` | The final decision. True only when `trust_status` is `TRUSTED`. |
| `integrity_valid` | The hash and signature are consistent (checked against *your* registered key). |
| `issuer_trusted` | The key is registered, in scope and not revoked. The signed issuer name is checked only with the `entries` trust-store form. A legacy `{"keys": ...}` or bare `{key_id: PEM}` store has no issuer binding, so this field does not establish the issuer there; see [the advisory](advisories/issuer-attribution-0.2.1.md). |
| `key_status` | `active`, `retired`, `compromised`, `revoked`, `unknown` or `none`. |
| `chronology` / `timestamp_status` | How well the signing time is established (see the rules below). |
| `blocking_reasons` | The codes that caused a refusal (for example `ISSUER_UNKNOWN`, `REPORT_TOO_OLD`). |
| `reasons` | Everything noted, including informational labels such as `LEGACY_V1_FORMAT`. |
| `consumption`, `replay_scope`, `replay_durable` | What the local replay check did (see the rules below). |

</details>

## Client side — `report.v2` (candidate)

`report.v2` signs more of the report's identity than `report.v1`: the issuer, key id
and fingerprint, deployment, a unique run id, and the intended audience.

```python
signer = rf.Signer.generate(issuer="acme-bank", key_id="acme-2026-04")  # a KMS/HSM in production
env = rf.envelope_v2(
    "fairness",
    report,
    signer=signer,
    deployment_id="prod-eu-1",
    audience=["regulator-a"],
)
print(env.to_json())
```

There is no default signer: you must name the key. Unknown fields, duplicate JSON keys,
`NaN`, non-canonical base64 and loose timestamps are refused.

<details>
<summary><strong>The rules in short (profiles, replay, key lifecycle, timestamps, v1)</strong></summary>

`VerificationPolicy` is applied the same way by the library, the CLI, the HTTP server
and `build_app()`. A *profile* (`development`, `confidential`, `high-assurance`) makes
it stricter: production profiles require a trust store, a maximum report age and a
persistent replay cache, and refuse development-only options.

* **Replay detection is local.** `consumption` is `NOT_CHECKED`,
  `CHECKED_NOT_CONSUMED` or `RECORDED_LOCAL`. `RECORDED_LOCAL` means "recorded in this
  verifier's own store at verification time"; it does not prove the authorised operation
  completed. `replay_durable` says whether that record survives a restart. It is never
  global single-use protection or an exactly-once guarantee. Changing freshness settings on an
  existing store has its own limits: see the [replay advisory](advisories/replay-limitations-0.2.1.md).
* **Retired or compromised keys.** They are accepted for historical reports only with
  authenticated chronology *and* an authenticated trust history. **This release cannot
  authenticate a trust history, so such reports are refused by default.** Both
  boundaries are strict: the latest possible signing time must be **strictly earlier**
  than the retirement or compromise time, so equality is refused. If the compromise
  time is unknown, everything that key signed is refused.
* **Required timestamps** need authenticated evidence from a verifier *you* pin
  (`timestamp_verifier=`). A missing timestamp never satisfies the requirement, and no
  timestamp authority is bundled or trusted by default. A verified timestamp is
  **not** proof the key was never revoked.
* **`report.v1`** is still verified over its original bytes, but it is refused in the
  `confidential` and `high-assurance` profiles because it has no signed run id.

</details>

<details>
<summary><strong>Older API for <code>report.v1</code> (still supported)</strong></summary>

These functions enforce the same key scope for `report.v1` but return the older
`VerificationOutcome`:

```python
trust_store = rf.TrustStore.from_json("trust_store.json")
env = rf.AuditEnvelope.from_dict(received_payload)
try:
    outcome = rf.verify_envelope_or_raise(env, trust_store=trust_store)
except rf.UntrustedIssuer:  # unknown key_id, or the report is outside the key's registered scope
    ...
except rf.RevokedIssuer:  # revoked, retired or compromised key
    ...
except rf.WrongParameterSet:  # parameter_set_hash != pinned value
    ...
except rf.HashMismatch:  # body changed since signing
    ...
except rf.InvalidSignature:  # Ed25519 verify failed
    ...
except rf.TimestampInvalid:  # an attached timestamp failed validation
    ...
# All subclass rf.EnvelopeVerificationError.
```

* `verify_receipt(env)` with no trust material only checks that the hash and embedded
  signature agree. That proves the bytes did not change; it does **not** prove an
  approved auditor produced them, and it emits a `DeprecationWarning` (plus a one-time
  `UserWarning`). Pass
  `trust_store=` (recommended: it enforces revocation, pins and scope) or
  `trusted_keys=` (registration only). An empty `trusted_keys={}` trusts nobody.
* `valid` is deprecated and kept through the first `report.v2` release; reading it
  emits a `DeprecationWarning`.
* A `report.v1` timestamp is **not** proof of non-revocation: it covers the body only,
  not the signature or key, so it can never satisfy a required-timestamp policy.
  See [docs/TRUST_SPEC.md](TRUST_SPEC.md) §5.4.

</details>

<details>
<summary><strong>Verifying over HTTP</strong></summary>

`POST /v1/verify` takes exactly `{"envelope": ...}` and **fails closed**: it needs
`REGAUDIT_FHE_TRUST_STORE` (or `serve --trust-store`) and returns 503 otherwise, and
also 503 if the replay store is unavailable outside development. It parses the body
strictly, bounds chunked uploads, and returns the fields above (with `valid` as an alias
of `accepted`). `serve --allow-self-signed` is a development-only option that can report
`SELF_SIGNED_ONLY` but never `TRUSTED`; it is refused outside the development profile,
over non-loopback or Unix-socket transports, and behind forwarding headers. See
[docs/DEPLOYMENT.md](DEPLOYMENT.md).

</details>
