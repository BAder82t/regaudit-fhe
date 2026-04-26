# Licensing

`regaudit-fhe` is dual-licensed by **VaultBytes Innovations Ltd**:

1. **Open-source license:** AGPL-3.0-or-later — see [LICENSE](LICENSE).
2. **Commercial license:** proprietary terms negotiated with VaultBytes.

Both licenses cover the same code. Choose whichever fits your deployment.

---

## When AGPL-3.0 is enough

You may use the AGPL-3.0 version freely if **all** of the following apply:

- You can publish the source of any modifications you distribute.
- You can publish the source of any modifications running as a network
  service that interacts with users (AGPL §13 network clause).
- Every system that links against `regaudit-fhe` is itself compatible
  with AGPL-3.0-or-later.

This is the right fit for:

- Academic research and reproducibility.
- Regulator-side verification (regulators can run the code on submitted
  envelopes without releasing their internal stack — they are not
  redistributing modifications).
- Open-source projects under AGPL or GPL family licenses.
- Internal experimentation that never ships outside your org.

---

## When you need a commercial license

You should buy a commercial license if **any** of the following apply:

- You integrate `regaudit-fhe` into a closed-source product, internal
  MLOps pipeline, or proprietary SaaS.
- You distribute software linking against `regaudit-fhe` under a
  non-AGPL-compatible license.
- You run `regaudit-fhe` as part of a network service and your legal
  team cannot or will not publish the surrounding stack under AGPL §13.
- You require warranty, indemnification, or contractual SLAs that
  AGPL-3.0 explicitly disclaims.

The commercial license also unlocks the closed-source companion product
**VaultBytes Audit Platform**, which provides:

- Production OpenFHE backend with vertical-specific calibrated minimax
  polynomial packs (banking, oncology, HR, autonomous-vehicle UQ).
- Multi-tenant audit-trail database with SOC 2 / ISO 27001 controls.
- KMS-backed envelope signing tied to a VaultBytes verifying-key chain
  recognised by partner regulator portals.
- Regulator-portal connectors (NYC DCWP, EU AI Office, FDA SaMD,
  OCC SR 11-7 reviewer).
- 24/7 support, on-call escalation, and contractual response SLAs.

---

## How to buy

Email **b@vaultbytes.com** with:

- your company name and primary jurisdiction,
- the regulation(s) you must satisfy (NYC LL144, EU AI Act §10/§15,
  FDA SaMD PCCP, OCC SR 11-7, ...),
- expected audit volume per month,
- your deployment model (on-prem, private cloud, managed SaaS).

VaultBytes will respond with terms tailored to the deployment.

---

## Trademarks

**regaudit-fhe**, **VaultBytes**, and the VaultBytes Audit Platform
name are trademarks of VaultBytes Innovations Ltd. AGPL forks may
inherit the source but may not use the trademarks in their fork's
name, marketing, or distribution.

---

## Contributions

Outside contributions are not accepted — see [CONTRIBUTING.md](CONTRIBUTING.md).
