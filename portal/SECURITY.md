# Security of the Evidence Verification Portal

## Signature verification does not verify encrypted computation

Signature verification does not verify that any FHE (encrypted) computation was executed.

A valid signature shows that a report was not changed after it was signed and, under your administrator's trust rules, which enrolled key signed it. A report's `backend` and `security_bits` are statements by the signer. The portal shows them as statements and never as findings. This notice is shown on every result, whatever the verdict, and is saved in every exported result.

## Security limitation — published v0.2.1

Published regaudit-fhe v0.2.1 does not enforce the strict filesystem ownership and writable-permission protections for local trust-store and replay-state files introduced in the experimental code.

Users with sufficient filesystem access may be able to modify those files. A valid report signature does not prove that the signing key was enrolled by an authenticated administrator.

These protections are not included in the published v0.2.1 package. Do not rely on that version for security guarantees requiring them.

The portal's pages show a shorter warning with a link to this text: "Published v0.2.1 does not enforce strict ownership and permission protections for the local trust-store and replay-state files. A valid signature does not prove the key was enrolled by an authenticated administrator. Read the full limitation." The link opens a page served by the portal itself and works offline.

## Which engine the portal accepts

Only the published `regaudit-fhe` 0.2.1. The portal gives a verdict only when the installed engine reports version 0.2.1 and its installed source files hash to the digest pinned in `regaudit_portal/engine.py`. It checks this at start-up and before every verification. In every other case it refuses: the portal is not ready, no verification works and no result is saved. A page headed "Verification unavailable" is shown instead, and the reason is printed in the administrator's terminal only. There is no setting, flag or environment variable that changes this. Another engine needs a new, separately reviewed identity added to the portal's own code.

The check hashes the installed source files before the engine is imported, refuses a symbolic link or a stray entry anywhere in the engine's folder, and makes Python ignore any compiled `.pyc` file next to the engine's source by pointing its bytecode cache at a new private folder in the temporary directory. The portal removes that folder when it exits, on Ctrl-C and on SIGTERM. A process that is killed hard (SIGKILL), or that crashes, can leave its temporary folder behind, and it is safe to delete when that portal is not running. It does not show which code is actually running: it does not cover `.pth` files, the libraries the engine uses, or anything else around the files. It is not a defence against a tampered environment.

## What the portal does for safety

- It listens on `127.0.0.1` only, refuses other host names and other web pages, and has no sign-in. Do not put it on a network.
- The administrator's configuration, including the trust rules and profile, is read once at start-up. No page or request can change it.
- Uploads are limited to 1 MB (1,048,576 bytes), parsed as data and never executed, and not kept.
- It gives no verdict when its configuration, its engine or the check itself fails.
- Verdicts and reason codes are exactly what the verifier returned.
- The bundled samples are made-up reports checked against a demonstration trust list, by their id from a list, with a policy that is used for nothing else. A report that is uploaded is checked against the administrator's policy, or refused if there is none, so a demonstration key can never be taken for a trusted issuer. Every sample result is labelled a synthetic demonstration. The package holds the demonstration issuer's public key and no private key.
- The administrator setup page only reads. It creates and changes nothing, enrols no key and never accepts or shows a signing key. Without a configuration the portal starts in welcome mode, where only the samples work, and it never creates the per-user configuration folder by itself.

It does not make the published engine enforce anything. It makes a basic start-up check of the file ownership and permission bits of its own configuration, trust store and replay file, and that check is not the protection described in the limitation above.

## Reporting a problem

Follow the repository's top-level [SECURITY.md](../SECURITY.md).
