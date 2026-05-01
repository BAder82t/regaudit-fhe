# Commercial License

`regaudit-fhe` is dual-licensed:

1. **AGPL-3.0-or-later** — the default. See [LICENSE](LICENSE) and
   [LICENSING.md](LICENSING.md). Suitable for internal research, AGPL
   forks, and deployments where every linked component (including any
   network service that interacts with users under AGPL §13) is itself
   AGPL-compatible.
2. **VaultBytes Commercial License** — a paid alternative that grants
   you the same source code under non-AGPL terms. This page describes
   what the commercial license is for, who needs one, what it grants,
   and how to obtain one.

The two licenses cover the same code. There is no closed-source build,
no feature paywall, and no telemetry only present in the commercial
build. Commercial licensees receive the same Git tags as AGPL users,
plus the rights, indemnity, and support enumerated below.

---

## Who needs a commercial license

You need a commercial license if **any** of the following apply:

- You ship `regaudit-fhe` (modified or unmodified) inside a product or
  service whose source you do not want to release under AGPL-3.0.
- You operate a hosted service (SaaS, internal portal, regulator
  console, model-risk platform) that exposes audit primitives or
  envelope verification to users over a network and you do not want
  AGPL §13's source-disclosure obligation to extend to that service.
- You link `regaudit-fhe` into a proprietary library or proprietary
  pipeline whose other components are not AGPL-compatible.
- Your legal, procurement, or compliance function has a categorical
  prohibition on AGPL-licensed dependencies (common in regulated
  banking, insurance, medical-device, and government supply chains).
- You require contractual indemnity for IP infringement claims or
  service-level commitments for security patches, neither of which the
  AGPL provides.

You do **not** need a commercial license to:

- Read, study, fork, or modify the source under AGPL-3.0.
- Run the CLI, server, or library inside an organisation whose other
  internal-only software you are willing to release under AGPL-3.0.
- Run the verifier (`regaudit-fhe verify ...`) at a regulator.
- Distribute an AGPL-3.0 fork of `regaudit-fhe` provided you respect
  the AGPL terms and the trademark notice in [LICENSING.md](LICENSING.md).

If you are unsure whether your deployment requires a commercial
license, contact us before you deploy. A short written confirmation is
free and faster than a retrospective compliance review.

---

## What the commercial license grants

A commercial license is a written agreement between VaultBytes
Innovations Ltd and the licensee. Standard terms include:

- A non-exclusive, worldwide, non-transferable right to use, modify,
  and distribute `regaudit-fhe` outside the AGPL-3.0 obligations,
  scoped to the licensed deployment.
- Permission to embed `regaudit-fhe` in proprietary products and to
  operate proprietary network services that depend on it without
  triggering AGPL §13.
- Capped indemnity for third-party intellectual-property infringement
  claims arising from unmodified `regaudit-fhe` releases.
- A defined support level: response times for security advisories,
  named-channel access for verification or interoperability questions,
  and pre-disclosure of CVEs affecting the licensed releases.
- Optional add-ons: hosted TrustStore, managed regulator console,
  custom audit primitive development, conformity-assessment binder
  generation, and on-site integration support.

The exact wording of every clause lives in the signed master licence
agreement. This page is informational; nothing on it constitutes a
binding offer.

---

## What a commercial license does not change

- The cryptographic guarantees, depth-budget enforcement, JSON-Schema
  shapes, envelope format, and signature algorithm are identical
  across both licences. A commercial licensee's audit envelope is
  byte-for-byte verifiable by an AGPL regulator deployment, and vice
  versa.
- The compliance scope statement in [COMPLIANCE.md](COMPLIANCE.md)
  applies in full. A commercial license does not turn a technical
  evidence library into a finished compliance product, conformity
  assessment, or regulatory acceptance.
- The trademark policy in [LICENSING.md](LICENSING.md) applies to
  commercial licensees and AGPL forks alike.

---

## How to obtain a commercial license

Email **b@vaultbytes.com** with:

- Legal entity name, registered address, and country of incorporation.
- A one-paragraph description of the deployment: which primitives,
  approximate envelope volume per year, whether the deployment is
  internal-only or customer-facing, and whether the verifier is
  operated by you or by a regulator.
- Whether you require a perpetual licence, a fixed-term licence, or an
  evaluation licence.
- Procurement contact and preferred contracting vehicle (direct,
  reseller, or marketplace).

Standard turnaround for a quote is two business days. An evaluation
licence — free, time-limited, no production traffic — is available on
request and is the fastest way to start integration without waiting
for procurement.

---

## Frequently asked questions

**We are evaluating `regaudit-fhe` and have not deployed it. Do we
need a licence?**
No. Reading source, running tests in a sandbox, and producing
throwaway envelopes for evaluation are covered by AGPL-3.0. You only
need a commercial licence when you deploy in a way that triggers AGPL
§13 or links into proprietary code.

**Can we contribute back patches?**
External contributions are not accepted; see
[CONTRIBUTING.md](CONTRIBUTING.md). This keeps the copyright clean and
makes dual-licensing possible. Customers with custom-primitive
requirements should raise them via the commercial channel.

**Does the commercial licence cover patents?**
The 6 audit primitives in `docs/specs/` are subject to a separate
patent programme. The standard commercial licence includes a
covenant-not-to-sue scoped to the licensed deployment for any
VaultBytes patents reading on `regaudit-fhe`. Standalone patent
licences for non-`regaudit-fhe` use are negotiated separately.

**What about trademarks?**
"regaudit-fhe" and "VaultBytes" are trademarks of VaultBytes
Innovations Ltd. The commercial licence does not grant trademark
rights beyond reasonable nominative use ("powered by regaudit-fhe").
Co-branding is negotiated separately.

**Can I get pricing without contacting sales?**
Not at this time. Pricing depends on deployment scope and required
support level and is confirmed in writing per quote.

---

Commercial licensing contact: **b@vaultbytes.com**
Security contact: see [SECURITY.md](SECURITY.md)
