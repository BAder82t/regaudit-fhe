# macOS application (local evaluation build)

This builds the Evidence Verification Portal as a double-clickable macOS application for Apple silicon Macs running macOS 14 or newer. Opening it starts the portal on this computer only, opens the default browser at it, and stops the portal when the application quits. A person using it needs no Python installation and no terminal.

It is a **local evaluation build**. It is signed ad hoc, which is enough to run on the Mac that built it. It is not signed with a Developer ID certificate and not notarized, so macOS will warn about it on any other computer. It is not for public distribution.

## First launch

Opening the application for the first time, with nothing configured, shows the portal's welcome screen: try a synthetic sample (a demonstration with made-up data and a demonstration trust list), verify your own report (not available until an administrator has set up trust, and the portal says so), or read the administrator setup page. The application creates nothing in the account's own folders. While it runs it keeps a private temporary folder (about 13 MB) for Python's bytecode, which is removed when the portal stops. An administrator's configuration, when there is one, is read from `~/Library/Application Support/Evidence Verification Portal/portal-config.json`. Setting up trust still needs the existing `regaudit-fhe trust add` commands and a configuration file written by hand, run in Terminal. The application carries them as two small programs, `Contents/Resources/tools/regaudit-fhe` and `Contents/Resources/tools/regaudit-portal`, which the administrator setup page shows by their full path. Guided setup in the browser is not built.

## What is inside

Everything the application runs is inside the bundle:

- A relocatable CPython 3.12 (`runtime.json` pins the build and its SHA-256, which is also checked against the release's own `SHA256SUMS`).
- The exact wheels in `requirements.lock`, installed with `--no-deps --require-hashes --only-binary=:all:`, so nothing outside that list can be installed. They include the published regaudit-fhe 0.2.1 verification engine, installed the ordinary way as source files.
- The portal's own source.
- A small native launcher (`launcher/main.swift`). It picks a free port, starts the bundled Python with `-I -B` (no user site, no `PYTHON*` variables, and no bytecode written into the bundle, which would break its signature), waits until the portal answers, opens the browser, and stops the portal when the application quits or receives SIGTERM, SIGINT or SIGHUP. It holds the write end of a pipe on the portal's standard input and starts the portal with `--exit-when-input-closes`, so if the launcher is killed, even with SIGKILL, the portal notices and stops by itself. It has no window, reads and writes no reports, keys or settings, and keeps no log.
- `Contents/Resources/tools/`: the two administrator programs described above.
- An icon made from the VaultBytes mark (`icon/`).
- `Contents/Resources/BUILD_MANIFEST.json`: the portal commit and tree, the engine identity, the runtime and lock hashes, the launcher's hash before signing, the build time and the signing status. The hashes of the launcher and of the whole application after signing are in the `BUILD_MANIFEST.json` next to the disk image, because a signature seals the bundle's own files and cannot contain its own final hash.
- The disk image also holds `READ ME FIRST.txt`: what the application is, how to install and stop it, what to do about macOS refusing a copy that is not notarized, and the approved security limitation text.

The portal's own engine check is unchanged and runs inside the bundle. The build refuses to finish unless that check passes there. A packaged engine that is modified, missing or not exactly the published 0.2.1 gives the "Verification unavailable" page, as it does in a normal install. Nothing in the launcher can override that.

## Build

On an Apple silicon Mac with Xcode or the command line tools (for `swiftc`), `codesign` and `hdiutil`, and network access while building:

    python3 build_app.py --out /path/to/empty/folder

It writes `Evidence Verification Portal.app`, a `.dmg`, `SHA256SUMS`, `READ ME FIRST.txt` and `BUILD_MANIFEST.json`. The build is not reproducible: the Swift compiler output differs between builds, so identify a build by its manifest and the hash of the file you were given. Add `--no-dmg` to skip the disk image. Then check the result without a browser (first run in an empty account, then a configured run):

    python3 smoke_test.py "/path/to/Evidence Verification Portal.app"

## Updating the pinned wheels

Resolve with the bundled runtime's pip (`pip install --dry-run --ignore-installed --only-binary=:all: --report report.json 'regaudit-fhe[server]==0.2.1'`), write each name, version and `sha256` into `requirements.lock`, and review the diff. The engine line must stay at 0.2.1.

## Limits

- Apple silicon only, and macOS 14 or newer (the pinned numpy wheel needs it). No Intel build, no Linux, no Windows.
- No Developer ID signature and no notarization. Both are needed before the application can go to anyone else, and the hardened runtime then needs the library-validation entitlement for the bundled compiled libraries.
- If the launcher is killed with SIGKILL the portal stops by itself within a few seconds (it sees its standard input close), but a kill of the portal process alone is not detected by anything except the launcher, which then reports it and quits.
- The check that the engine is the published 0.2.1 covers the engine's installed source files. It does not cover the Python interpreter, the standard library, the other libraries or the portal's own files. Changing those inside the bundle is not detected, although it breaks the bundle's code signature and macOS may then refuse to open it.
- A launcher that opens a browser is still a local web page. Another account on the same Mac can reach it on `127.0.0.1`.
- The application has no update mechanism. A new version is a new download.
- macOS records a launch under the application's identifier. A leftover record from a process that was killed in the middle of a test can make `open -n` refuse for a while; a normal double-click reuses the running copy.
