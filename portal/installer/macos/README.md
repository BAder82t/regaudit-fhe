# macOS application (local evaluation build)

This builds the Evidence Verification Portal as a double-clickable macOS application for Apple silicon Macs running macOS 14 or newer. Opening it starts the portal on this computer only, opens the default browser at it, and stops the portal when the application quits. A person using it needs no Python installation and no terminal.

It is a **local evaluation build**: an experimental build, not a production-qualified release, and not for public distribution. By default it is signed ad hoc, which is enough to run on the Mac that built it. Such a build is not notarized, so macOS warns about it on any other computer. A build signed with a Developer ID Application certificate (see "Signing with a Developer ID" below) is meant to be notarized by Apple before it is handed to anyone.

## First launch

Opening the application for the first time, with nothing configured, shows the portal's welcome screen: try a synthetic sample (a demonstration with made-up data and a demonstration trust list), verify your own report (not available until an administrator has set up trust, and the portal says so), or read the administrator setup page. The application creates nothing in the account's own folders. While it runs it keeps a private temporary folder (about 13 MB) for Python's bytecode, which is removed when the portal stops. An administrator's configuration, when there is one, is read from `~/Library/Application Support/Evidence Verification Portal/portal-config.json`. Setting up trust still needs the existing `regaudit-fhe trust add` commands and a configuration file written by hand, run in Terminal. The application carries them as two small programs, `Contents/Resources/tools/regaudit-fhe` and `Contents/Resources/tools/regaudit-portal`, which the administrator setup page shows by their full path. Guided setup in the browser is not built.

## Install from the disk image

To install it from the disk image, we just need to drag Evidence Verification Portal onto the Applications folder in the same window and open it from Applications. This opens the browser and we are taken to the portal. The first screen offers a synthetic sample report. We would not need to use Terminal for this. The disk image also contains `READ ME FIRST.txt`, which says what to do if macOS will not open it. What it says depends on how the build is signed.

A Mac that did not build it would refuse to open an ad hoc build at first, because it is not notarized. The person would need to open System Settings, choose Privacy & Security, choose Open Anyway and type their password. Many people would not be comfortable with this, and this is why an ad hoc build is only for evaluation under direction. A Developer ID build that Apple has notarized opens with the usual macOS prompts. Its `READ ME FIRST.txt` says so, and says that a warning from macOS means the copy is not that build: the person should not bypass it, but delete the copy and ask the sender. The checksum check in `READ ME FIRST.txt` is done in Terminal. A person who does not use Terminal can skip it, and then they depend on knowing where the file came from.

## What is inside

Everything the application runs is inside the bundle:

- A relocatable CPython 3.12 (`runtime.json` pins the build and its SHA-256, which is also checked against the release's own `SHA256SUMS`).
- The exact wheels in `requirements.lock`, installed with `--no-deps --require-hashes --only-binary=:all:`, so nothing outside that list can be installed. They include the published regaudit-fhe 0.2.1 verification engine, installed the ordinary way as source files.
- The portal's own source.
- A small native launcher (`launcher/main.swift`). It picks a free port, starts the bundled Python with `-I -B` (no user site, no `PYTHON*` variables, and no bytecode written into the bundle, which would break its signature), waits until the portal answers, opens the browser, and stops the portal when the application quits or receives SIGTERM, SIGINT or SIGHUP. It holds the write end of a pipe on the portal's standard input and starts the portal with `--exit-when-input-closes`, so if the launcher is killed, even with SIGKILL, the portal notices and stops by itself. It has no window, reads and writes no reports, keys or settings, and keeps no log.
- `Contents/Resources/tools/`: the two administrator programs described above.
- An icon made from the VaultBytes mark (`icon/`).
- `Contents/Resources/BUILD_MANIFEST.json`: the portal commit and tree, the engine identity, the runtime and lock hashes, the launcher's hash before signing, the build time and the signing status. The hashes of the launcher and of the whole application after signing are in the `BUILD_MANIFEST.json` next to the disk image, because a signature seals the bundle's own files and cannot contain its own final hash.
- The disk image also holds `READ ME FIRST.txt`: what the application is, how to install and stop it, what to do if macOS will not open it (which depends on how the build is signed), and the approved security limitation text.

The portal's own engine check is unchanged and runs inside the bundle. The build refuses to finish unless that check passes there. A packaged engine that is modified, missing or not exactly the published 0.2.1 gives the "Verification unavailable" page, as it does in a normal install. Nothing in the launcher can override that.

## Build

On an Apple silicon Mac with Xcode or the command line tools (for `swiftc`), `codesign` and `hdiutil`, and network access while building:

    python3 build_app.py --out /path/to/empty/folder

It writes `Evidence Verification Portal.app`, a `.dmg`, `SHA256SUMS`, `READ ME FIRST.txt` and `BUILD_MANIFEST.json`, signed ad hoc. To sign with a Developer ID instead, see below. The build is not reproducible: the Swift compiler output differs between builds, so identify a build by its manifest and the hash of the file you were given. Add `--no-dmg` to skip the disk image. Then check the result without a browser (first run in an empty account, then a configured run):

    python3 smoke_test.py "/path/to/Evidence Verification Portal.app"

## Signing with a Developer ID

To sign with a Developer ID Application certificate whose private key is in the Keychain of the build Mac, add its full name, and its SHA-1 if the Keychain holds more than one certificate with that name:

    python3 build_app.py --out /path/to/empty/folder \
        --sign-identity "Developer ID Application: VaultBytes Innovations LTD (939QZ58TG5)" \
        --sign-identity-sha1 <SHA-1 of that certificate>

Every Mach-O file in the bundle is then signed on its own, the deepest first: the bundled Python, its libraries and extension modules, and those of the installed packages. Then the bundle is signed, which signs the launcher, and then the disk image. Each signature has a secure timestamp, and each Mach-O file and the bundle use the hardened runtime. There are no entitlements. A candidate built this way ran the smoke test and a full local check (samples, uploads, export, a tampered engine, stopping) with none, so library validation stays on. `--deep` is not used for signing. Nothing secret is passed to the build: codesign finds the key in the Keychain by the certificate's name or SHA-1.

`READ ME FIRST.txt` and `BUILD_MANIFEST.json` say how the build is signed. An ad hoc build says it is signed only ad hoc and not notarized. A Developer ID build names the certificate and says it is intended to be notarized by Apple before it is handed to anyone. After signing, the build checks every signature it made against the signing it was asked for, and it stops if they disagree, so a build can never describe itself as signed in a way it is not.

Notarization comes afterwards and is not part of the build. Submitting a disk image to Apple's notary tool uploads all of it. The ticket is then stapled to the disk image, and the result is checked with the stapler and with spctl on the stapled copy. The result belongs to that exact disk image. It is recorded with it and with its evidence, never inside the bundle, and a new build has to be notarized again. The first candidate signed this way, built from commit 8a410d5, was accepted by Apple's notary service.

## Updating the pinned wheels

Resolve with the bundled runtime's pip (`pip install --dry-run --ignore-installed --only-binary=:all: --report report.json 'regaudit-fhe[server]==0.2.1'`), write each name, version and `sha256` into `requirements.lock`, and review the diff. The engine line must stay at 0.2.1.

## Limits

- Apple silicon only, and macOS 14 or newer (the pinned numpy wheel needs it). No Intel build, no Linux, no Windows.
- The default build has no Developer ID signature and is not notarized. A build signed with a Developer ID has to be notarized and stapled before it goes to anyone else, and every new build has to be notarized again (see "Signing with a Developer ID" above).
- A stop request (Quit, SIGTERM, SIGINT, or the launcher's input closing) ends the portal with its private folder removed and no traceback, while it is starting, a moment after it started, or while an upload is still coming in. While the portal is starting it leaves at once and raises nothing inside the engine's libraries, because a library can catch such an interrupt and carry on (pydantic did). Before uvicorn takes over, a deadline of five seconds ends the portal if anything swallowed the stop. Once it is serving, uvicorn's graceful shutdown applies, and an upload that is still arriving gets three seconds before it is cut off, so the launcher's six-second wait is not used up. A second request while the portal is stopping changes nothing and prints no error. The same holds for the `regaudit-portal` command. Started with the launcher's `--exit-when-input-closes` option, the portal takes SIGTERM even if its parent had it ignored, and it unblocks SIGTERM and SIGINT if its parent had blocked them. An ignored SIGINT is left as it is. A stop that lands in the first fraction of a second after the process starts, before Python has run any of the portal's code (about 0.07 s measured on a Linux virtual machine, not yet measured on a Mac, and longer on a slow or busy computer), ends it by the signal itself with nothing left behind. If its parent had SIGTERM ignored, a SIGTERM in that first moment is ignored too, and the launcher's input closing is what then stops the portal. SIGKILL of the portal cannot be handled by any program and leaves the private folder (about 13 MB) in the temporary directory.
- If the launcher is killed with SIGKILL the portal stops by itself within a few seconds (it sees its standard input close), but a kill of the portal process alone is not detected by anything except the launcher, which then reports it and quits.
- The check that the engine is the published 0.2.1 covers the engine's installed source files. It does not cover the Python interpreter, the standard library, the other libraries or the portal's own files. Changing those inside the bundle is not detected, although it breaks the bundle's code signature and macOS may then refuse to open it.
- A launcher that opens a browser is still a local web page. Another account on the same Mac can reach it on `127.0.0.1`.
- The application has no update mechanism. A new version is a new download.
- macOS records a launch under the application's identifier. A leftover record from a process that was killed in the middle of a test can make `open -n` refuse for a while; a normal double-click reuses the running copy.
