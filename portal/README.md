# Evidence Verification Portal

A local browser page for checking a signed regaudit-fhe report. Someone who has never used the command line can choose a report file, verify it and save the result.

It calls the published `regaudit-fhe` 0.2.1 verifier and shows what it returns. It has no cryptography of its own. It checks a signature and the trust rules your administrator set. It is not a regulatory certification and not proof of encrypted computation.

**Signature verification does not verify that any FHE (encrypted) computation was executed.** This is shown on every result, whatever the verdict, and saved in every exported result.

It refuses any other engine: only the published 0.2.1, recognised by its version and by a digest of its installed source files, may produce a verdict. See [The verification engine](#the-verification-engine) and the [security limitation](#security-limitation--published-v021) of that version.

This is a first local version. It runs on one computer with no cloud account. It has no sign-in, so it only listens on `127.0.0.1`, and it should not be put on a network as it is.

## Before you start

This portal is a separate small local app. The main README at the top of the repository is about the regaudit-fhe library and does not describe it. This file is the guide.

You need:

- **A Mac or a Linux computer.** Windows is not supported. At start-up the portal reads Unix file owners and permission bits to check that the trust list and the replay file cannot be changed by other accounts. Windows does not provide those, so there the portal reports itself not ready and gives no verdicts.
- **Python 3.10 or newer.** In a terminal, type `python3 --version`. It should print `Python 3.10` or a higher number. If it prints a lower number, or says the command is not found, install a current Python from https://www.python.org/downloads/ first.
- **A terminal.** On a Mac, open Terminal (in Applications, then Utilities). On Linux, open your terminal program.
- **The `portal` folder.** It is inside the regaudit-fhe project. Get the project from the repository page https://github.com/BAder82t/regaudit-fhe (click Code, then Download ZIP), or from your administrator, and unzip it. In the terminal, type `cd ` (with a space after it), drag the `portal` folder from the unzipped repository into the terminal window, and press Enter. Run every command below from there.

**The page works only while the portal is running.** The `serve` command (step 5 below) is the portal. While it runs in its terminal the page works. If you close that terminal or press Ctrl-C, the page stops. For routine use, the administrator starts it on one computer and keeps it running (see [Keeping it running](#keeping-it-running) below, after the install steps).

It only answers on the computer it runs on (`127.0.0.1`). Other people's computers cannot reach it.

The synthetic sample reports will be in `~/portal-demo/sample-reports` (a folder called `portal-demo` in your home folder). Step 7 below says how to find it in the file chooser.

## Try it in five minutes with synthetic data

You need an internet connection for the install. These steps use only made-up keys and reports.

1. Open a terminal in the `portal` folder (see above).
2. Create a private Python environment: `python3 -m venv .venv`. If this fails with a message about `ensurepip` or `python3-venv`, the system's `python3-venv` package has to be installed first. On Debian and Ubuntu the command is `sudo apt install python3-venv`. Other systems need the equivalent package from their package manager. Then run this step again.
3. Install the portal. This also installs the published `regaudit-fhe` 0.2.1: `.venv/bin/pip install .`
4. Create the demonstration files: `.venv/bin/regaudit-portal demo-setup ~/portal-demo`
5. Start the portal: `.venv/bin/regaudit-portal serve --config ~/portal-demo/portal-config.json`. Leave this terminal open. It prints a line starting "open http://" when the portal is ready.
6. Open http://127.0.0.1:8765 in a browser.
7. Choose a file from `~/portal-demo/sample-reports`, press **Verify report**, read the result, then press **Download result**.

In the file chooser, press Cmd+Shift+G on a Mac (Ctrl+L on Linux), paste `~/portal-demo/sample-reports` and press Enter. The full path is `/Users/YOURNAME/portal-demo/sample-reports` on a Mac and `/home/YOURNAME/portal-demo/sample-reports` on Linux. Or open that folder in Finder or your file manager and drag a file onto the page.

Press Ctrl-C in the terminal to stop the portal. It stops cleanly and prints one line. The sample reports are synthetic and show each outcome:

| File | What you should see |
|---|---|
| `1-trusted.json` | `TRUSTED`. The report says it was computed on plaintext, so the page says there was no encryption |
| `2-untrusted-signer.json` | `INVALID`, because the signing key is not enrolled |
| `3-valid-signature-wrong-issuer.json` | `INVALID`. The signature is valid, but the report names the wrong issuer |
| `4-changed-after-signing.json` | `INVALID`, because the contents no longer match the signature |
| `5-not-a-report.json` | No verdict, because this is not a report |
| `6-too-large.json` | No verdict, because it is over the 1 MB limit (1,048,576 bytes) |
| `7-declares-encrypted-backend.json` | `TRUSTED`. The report says it used an encrypted backend. Nothing was encrypted: the file only says so, and the page says it cannot verify that |

## Keeping it running

For routine use the administrator starts the portal on one computer and leaves it running. After the install steps above, this keeps it running after the terminal is closed. Use your own path to the configuration file:

```
nohup .venv/bin/regaudit-portal serve --config /full/path/to/portal-config.json > portal.log 2>&1 &
echo $! > portal.pid
```

Stop it later with `kill $(cat portal.pid)`, which stops it as cleanly as Ctrl-C does. `portal.log` holds the portal's start-up lines and any error messages. A failing engine check is logged once when it starts failing and once when it recovers, not on every request.

## The welcome screen

The first screen offers three choices. All of them sit behind the same engine check as everything else: if the engine is not the recognised release, none of them is offered and the "Verification unavailable" page is shown instead.

- **Try a sample report.** A short list of made-up demonstration reports, chosen from the list and never uploaded: one the demonstration issuer signed, one signed by a key nobody enrolled, one changed after it was signed, one that says it was computed on plaintext and one that names an encrypted backend although nothing was encrypted. No trust setup is needed. They are checked against a demonstration trust list with a separate demonstration policy that is used for these samples only, selected by their id. Every sample result, on the page and in the saved file, says it is a synthetic demonstration made with made-up data and a demonstration trust list. The saved file carries `synthetic_demonstration: true`, and the issuer is named "DEMO-ONLY synthetic issuer". The verdicts and reason codes are the engine's own. The package holds the demonstration issuer's public key and trust list, and no private key: the key that signed the samples was thrown away when they were made (`tools/make_demo_samples.py` makes them), so nothing in the package can sign anything.
- **Verify your own report.** This uses the administrator's trust policy, as before. If none is set up, the page says "Verification of your own reports is not set up yet. An administrator has to set up trust first.", links to the administrator setup page and offers no upload, and the upload endpoint refuses without a verdict. A sample report uploaded here is checked against the administrator's policy, never against the demonstration's, so a demonstration key can never be taken for a trusted issuer.
- **Administrator setup.** A separate page, `/setup`, with plain instructions and a read-only readiness status: the engine, the configuration, the trust list, the replay setting, the file ownership and permission check, and the port. It creates nothing and changes nothing, and it never accepts or shows a signing key. It shows places only as `~/...`, and never on the verification pages. It says what an administrator has to prepare (the trust list and the issuers' fingerprints received by another route than the report), where the files go and the existing commands that make a trust list.

Making the trust list still needs those existing commands (`regaudit-fhe trust add`, below; run them in Terminal for now, and inside the macOS application by their full path, which the setup page shows). Creating it in the browser would be a separate change that has to be designed and reviewed on its own. The setup page does not do it.

### Where the configuration is looked for

`serve` and `check-config` without `--config` look for the configuration in the standard per-user location:

- macOS: `~/Library/Application Support/Evidence Verification Portal/portal-config.json`
- Linux: `~/.config/evidence-verification-portal/portal-config.json`

If there is no file there, `serve` starts in welcome mode: the samples work and your own reports are not set up. If there is one, it behaves exactly as with `--config`, including refusing when the configuration cannot be used and the check of who owns the folder and its files. With a configuration that cannot be used, your own reports are refused with the usual explanation and the samples still work. `--config` always overrides the standard location. The portal never creates that folder, or anything in it, by itself.

### For a launcher

An application that starts the portal for someone who never opens a terminal can run `regaudit-portal serve --port 0`. That takes any free port on this computer (`127.0.0.1` only, as always). Before the existing human line ("open http://... in a browser"), the portal prints one line a launcher can read once the portal is listening:

```
portal-listening url=http://127.0.0.1:PORT/ mode=MODE
```

`MODE` is `ready` (your own reports can be checked), `welcome` (no configuration: the samples work), `needs-attention` (a configuration that cannot be used: the samples work) or `unavailable` (the engine check failed: only the page saying so is served). The launcher stops the portal with SIGTERM, which stops it as cleanly as Ctrl-C does.

## Reading the result

The big word is the verifier's `trust_status`, copied as it was returned: `TRUSTED`, `SELF_SIGNED_ONLY` or `INVALID`. Only `TRUSTED` means the report was accepted. Under it the page keeps four questions apart.

| On the page | What it tells you |
|---|---|
| **Signature and contents** | Whether the contents still match the signature. A valid signature alone only shows the report was not changed after it was signed. |
| **Issuer** | Whether the signing key is enrolled for this issuer by your administrator. A valid signature does not make an issuer trusted. A key marked retired or compromised, or not yet valid, is shown as not approved, whatever the signature says. |
| **Limits of this result** | What an accepted result still does not establish: for example that the report was not recorded as used, that the signing time is only what the signer stated, that the trust list may be out of date, or that repeats are only detected against this portal's own record file. |
| **Encryption claims in this report** | What the signer says about encryption, labelled as a statement and never as a finding (see below). |
| **Verification engine** | Which copy of regaudit-fhe produced the verdict (see below). |

The reason codes are the verifier's own. Each has a plain-language line beside it that explains the code and does not change it.

Two notices are always on the page, and on every result whatever the verdict. One says: Signature verification does not verify that any FHE (encrypted) computation was executed. The other is a short warning about the security limitation of published v0.2.1, with a link, "Read the full limitation", to the full text. That link opens a page served by the portal itself and works offline.

### Encryption claims

A report's `backend` and `parameter_set.security_bits` are declarations by the signer. A valid signature does not substantiate them, and verification does not show that any encrypted (FHE) computation happened.

- `backend: "plaintext"` (what the command line and the server sign by default): the page says **No encryption: this report states it was computed on plaintext**. The `security_bits` number is a field default and is shown only as "legacy field, not a security level".
- A named encrypted backend, for example `tenseal-ckks`: the page says **The signer declares an encrypted backend. This portal cannot verify that encryption was used.** The `security_bits` number is shown only as "declared by the signer, not verified".
- Any other backend name, or none: the page says it does not recognize it and cannot verify what it is or that encryption was used.

If the report was not accepted, these statements are marked as only what the file says, with nothing to establish them. A `security_bits` value that is too large to display, or is not a whole number, is said to be so. It is never shown as if the field were missing.

### The verification engine

Only one engine is recognised: the published `regaudit-fhe` 0.2.1. It must report version 0.2.1 and its installed source files must be identical to the published 0.2.1 release, which means they hash to the digest pinned in the portal's own code (below). Anything else is refused: a modified file set with the right version string, an unrecognised engine, another version, a missing engine, an unreadable file, an integrity computation that fails, and any development build. Then the portal is not ready, no verification works, and no result is saved. There is no fallback to an unchecked engine, a weaker profile or a made-up result. No setting, flag or environment variable changes this. Using another engine needs a new, separately reviewed identity added to the portal's own code (`regaudit_portal/engine.py`).

The engine is checked when the portal starts and again before every verification and every status request. That costs about 5 ms, so it is done each time. A failure at start-up gives the "Verification unavailable" page described below. A failure later refuses the next request before any upload is read, and the page says verification is unavailable. For a verification the engine is checked once before the upload is read, again immediately before the engine's verify is called, and again immediately after it returns. If any of these checks fails, the result is discarded and the request is refused with no verdict and nothing to save, so a file changed while a slow upload is arriving, or while a verification runs, cannot produce a verdict. Every result, the footer and the saved file name the engine that was checked.

The check hashes the engine's installed source files before the engine is imported. It refuses, rather than skips, a symbolic link anywhere in the engine's folder, anything in it that is not a regular file, and anything in its `__pycache__` folder that is not a regular `.pyc` file. The portal also points Python's bytecode cache at a new private folder (mode 0700), so no compiled `.pyc` file next to the engine's source is ever loaded: the code that runs is compiled from the files that were checked. That folder is in the system's temporary directory. It is removed when the portal exits normally, on Ctrl-C and on SIGTERM (what `kill` sends). A process that is killed hard (SIGKILL), or that crashes, can leave its temporary folder behind. It is safe to delete when that portal is not running.

The check does not cover everything. It does not show which code is actually running: it does not cover `.pth` files or other start-up hooks in the Python environment, the libraries the engine uses (numpy, cryptography, jsonschema and others), the portal's own files, the Python interpreter, or anything else around the engine's files. It is not a defence against a tampered environment: whoever can change installed files, or the Python environment, can change this portal too. It is there so that the label is accurate, not to protect anything.

How the comparison value is made, so that you can reproduce it:

1. List the files in the installed `regaudit_fhe` folder, leaving out anything inside a `__pycache__` folder. Version 0.2.1 has 46. The portal refuses, instead of skipping, a symbolic link anywhere in the folder, anything that is not a regular file, and a `__pycache__` entry that is not a regular `.pyc` file.
2. Name each file by its path inside the folder, written with `/`, for example `fhe/backends.py`.
3. Sort the files by comparing those names part by part, splitting at `/`. So `schemas/drift.input.schema.json` comes before `schemas.py`, which plain text order would not give.
4. Feed SHA-256, for each file in that order: the name as UTF-8, a zero byte, the file's own SHA-256 as 64 lowercase hex characters, and a newline.

For 0.2.1 the result is `84f9d593a2e3b325b091f5324dbec285ed64f10d174efce8c528ee8c1595d58e`. The same value comes from the 0.2.1 wheel on PyPI and from `git archive v0.2.1:src/regaudit_fhe` in the regaudit-fhe repository. The code is `files_digest` in `regaudit_portal/engine.py`.

Published v0.2.1 has a security limitation that concerns its local trust-store and replay-state files. It is stated in full under [Deployment](#deployment) and in [SECURITY.md](SECURITY.md).

The portal uses `regaudit_fhe.verify_report` for the verdict. It also uses two of the engine's helpers for reading uploads strictly (`regaudit_fhe.canonical.loads_strict` and `regaudit_fhe._limits`), which is why it is pinned to exactly 0.2.1.

## When verification is unavailable

If the engine is missing, cannot be loaded, or fails its check, `serve` starts a small separate page instead of the portal. It uses only Python's standard library, so it starts whatever state the installation is in. It is headed "Verification unavailable" and says that no verification was performed and that no uploaded report has been accepted or verified. It accepts no uploads: verification and export requests get an error and nothing is read. It shows nothing about versions, files or paths. What failed, and where, is printed only in the terminal where you started `serve`, with the command to reinstall:

```
pip install --force-reinstall "regaudit-fhe[server]==0.2.1"
```

Restart the portal after you have fixed it. `check-config` and `demo-setup` stop with exit code 3 and the same terminal message.

## The saved result

**Download result** saves one JSON file, `verification-result-<report name>-<12 characters of the report's SHA-256>.json`. It holds:

- `verification`: exactly what the verifier returned, unchanged;
- `explanation`: the plain-language lines, reason meanings and limits shown on the page;
- `encryption_declarations`: the wording above, with the backend name and `security_bits` as stated by the signer, and `encryption_verified: false` (always);
- `engine`: the regaudit-fhe version, the API used, the result of the check against the published release, and the full text of the security limitation of published v0.2.1 (`security_limitation`), with the short warning the page shows (`security_limitation_short`);
- `fhe_notice`: "Signature verification does not verify that any FHE (encrypted) computation was executed.", present in every saved result;
- `report_file_name`, `report_sha256`, `checked_at`, `portal_version` and `not_a_claim`.

The report itself is not stored in the file.

## For the administrator

The page cannot change the trust rules. They live in a configuration file that is read once when the portal starts, so restart it after a change.

```json
{
  "trust_store": "trust-store.json",
  "profile": "confidential",
  "verifier_id": "your-organization",
  "max_age_days": 30,
  "replay_mode": "check",
  "replay_db": "replay.db"
}
```

Paths are relative to the configuration file.

- `trust_store` is made with `regaudit-fhe trust add`, once per key, using the fingerprint the issuer gave you by another route than the report. It must state the issuer of each key. The older trust-store forms that do not are refused, because they cannot tell the portal which issuer a key belongs to:

  ```
  .venv/bin/regaudit-fhe trust add --store trust-store.json --key-id KEY_ID --issuer "ISSUER NAME" \
    --public-key issuer.pub --fingerprint FINGERPRINT
  ```

- `profile` is `confidential` or `high-assurance`. `development` also works, and every result then says not to rely on it. The profile is chosen here by the administrator. No page, request or setting outside this file changes it.
- `verifier_id` is the name your organization is known by to report issuers. A report that names its intended recipients (an `audience`) is refused unless that list includes this `verifier_id`. A report that names no audience is not refused for this reason, except under `high-assurance`, which refuses any report that names no audience. The demo uses `demo-verifier`.
- `max_age_days` is the oldest report you will accept. Do not raise it while you keep using the same replay file: the published [replay limitations](../docs/advisories/replay-limitations-0.2.1.md) explain why.
- `replay_mode` is `check` or `record`. With `check`, looking at a report twice gives the same answer, and each result warns that the report was not recorded as used. With `record`, the second check of a report is refused as a repeat. Either way, repeat detection only knows what this portal's own replay file holds.

The configuration file, trust store, replay file and the folders holding them must belong to the account running the portal, or to root for the first two, and must not be writable by group or others. Otherwise the page says it is not ready and gives no verdicts. This is a basic start-up check the portal makes itself, from owner and permission bits. It is not the protection that the [security limitation](#security-limitation--published-v021) below says published v0.2.1 lacks, and it does not stop the same account, or an administrator, changing the files after start-up. Keep these files in a folder that only administrators can use.

Without `--config`, the portal looks in the standard per-user folder (see [Where the configuration is looked for](#where-the-configuration-is-looked-for)). The setup page, `/setup`, shows what is in place and what is not, read-only.

If the page says your own reports cannot be checked, nothing of yours can be verified. To see why, run:

```
.venv/bin/regaudit-portal check-config --config portal-config.json
```

`serve` and `check-config` also print the engine line.

### Running these commands from the macOS application

The macOS application does not put console commands on your computer's search path. Inside it, in `Contents/Resources/tools`, there is a small program for each of the two commands above, `regaudit-fhe` and `regaudit-portal`, which runs it with the application's own Python. For now they are run in Terminal, by their full path, with the same arguments as everywhere else in this section. For an application in `/Applications`:

```
'/Applications/Evidence Verification Portal.app/Contents/Resources/tools/regaudit-fhe' trust add \
  --store trust-store.json --key-id KEY_ID --issuer "ISSUER NAME" \
  --public-key issuer.pub --fingerprint FINGERPRINT
'/Applications/Evidence Verification Portal.app/Contents/Resources/tools/regaudit-portal' check-config
```

The name has spaces, so the path is in quotes. For an application under your home folder, write `~/` first and quote the rest, so the `~` still means your home folder: `~/'Applications/Evidence Verification Portal.app/Contents/Resources/tools/regaudit-fhe'`. `check-config` without `--config` looks in the standard location (see above). The setup page, `/setup`, shows both commands ready to copy, with the right path for the copy you are running, and the plain command names when the portal is not running from the application. It only shows them and runs nothing. Guided creation of the trust list in the browser is not built.

## Deployment

This is a tool for one computer. It has no sign-in, so it listens on `127.0.0.1` only and refuses requests for any other host name or from any other web page. Do not put it behind a proxy, publish its port, or run it on a shared server. Use a private Python environment, install only the published `regaudit-fhe` 0.2.1 (the portal refuses anything else), and keep the portal folder, its configuration, the trust store and the replay file in a folder that only administrators can use. The administrator, not the page, owns the trust rules. Uploaded reports are checked and not kept.

### Security limitation — published v0.2.1

Published regaudit-fhe v0.2.1 does not enforce the strict filesystem ownership and writable-permission protections for local trust-store and replay-state files introduced in the experimental code.

Users with sufficient filesystem access may be able to modify those files. A valid report signature does not prove that the signing key was enrolled by an authenticated administrator.

These protections are not included in the published v0.2.1 package. Do not rely on that version for security guarantees requiring them.

The same text is in [SECURITY.md](SECURITY.md), on the portal's own page behind "Read the full limitation" (`/security`, which works offline), and in every saved result. Signature verification also does not verify that any FHE (encrypted) computation was executed.

## What it does not do

There is no sign-in, no accounts, no billing, no hosted version, no installer and no licensing check. It is not a production deployment. Uploads are not stored, and the page loads nothing from outside this computer. The replay file holds only identifiers of recorded reports. It does not tell you whether a report's findings are correct, whether anything was encrypted, or whether a key has been withdrawn since your trust list was made: the trust list is a local file.

## Tests

In a new virtual environment, from this folder:

```
python3 -m venv .venv
.venv/bin/pip install ".[test]"
.venv/bin/pytest
```

The tests need the published engine, because the portal refuses any other, and `pip install ".[test]"` installs it from PyPI. Most tests need no git. The tests that matter for an installation need no git or tag and do not skip: they check that the installed engine reports 0.2.1, that its files hash to the pinned digest, and that the installer's own RECORD hashes agree with the files on disk. They fail, they do not skip, when the engine differs.

One test, `test_the_release_digest_is_the_one_the_v021_tag_has`, is a development-time cross-check of the pinned digest against `git archive v0.2.1`. It is not part of what the portal does. It needs a clone that has the tag, and it skips anywhere else, including an exported copy of this folder.
