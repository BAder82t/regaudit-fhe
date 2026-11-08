"""Build the macOS application for the Evidence Verification Portal (Apple silicon, macOS 14 or newer).

    python3 build_app.py --out <empty folder> [--cache <folder>] [--no-dmg]
        [--sign-identity "Developer ID Application: NAME (TEAMID)" [--sign-identity-sha1 SHA1]]

Everything the application runs is inside the bundle: a relocatable CPython (checked against its published SHA-256),
the exact wheels in ``requirements.lock`` (installed with ``--require-hashes``), the portal's own source and a small
native launcher. The engine is therefore the published regaudit-fhe 0.2.1 installed the ordinary way, as source
files, and the portal's own engine check runs unchanged. The build refuses to continue if that check does not pass
inside the finished bundle.

This produces a LOCAL EVALUATION build. By default it is signed ad hoc, which is enough to run on the machine that built
it and is not a distributable signature: it is not notarized and macOS will warn about it on any other computer.

With --sign-identity it is signed with that Developer ID Application certificate from the keychain instead: every Mach-O
file on its own, the deepest first, then the bundle, then the disk image, each with the hardened runtime (not the disk
image) and a secure timestamp, and with no entitlements. The text in READ ME FIRST.txt and in the manifest follows the
signing mode, and the build checks the signatures it actually made against the mode it was asked for: it stops if they
disagree, so a build can never describe itself as signed in a way it is not. Notarization by Apple is a separate step
after the build. Nothing here records its result, which belongs with the notarized disk image and its evidence.

Needs network only while building. Standard library only.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

# These are a build script and its check: they run fixed commands (swiftc, codesign, hdiutil and the bundled pip) with
# no user input, and they fetch only the https URLs pinned in runtime.json, which are checked below.
# ruff: noqa: S603, S607, S310

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
PORTAL_DIR = HERE.parents[1]  # .../portal
APP_NAME = "Evidence Verification Portal"
BUNDLE_ID = "com.vaultbytes.evidence-verification-portal"
MIN_MACOS = "14.0"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run(cmd, check=True, text=True, **kw)


def git(*args: str) -> str:
    try:
        out = subprocess.run(
            ["git", *args], cwd=PORTAL_DIR, capture_output=True, text=True, check=True
        )
        return out.stdout.strip()
    except Exception:
        return ""


def fetch_runtime(runtime: dict, cache: Path) -> Path:
    for key in ("url", "sums_url"):
        if not runtime[key].startswith("https://github.com/"):
            raise SystemExit(f"{key} in runtime.json must be an https://github.com/ address")
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / runtime["name"]
    if not target.exists():
        print("downloading", runtime["url"], flush=True)
        with urllib.request.urlopen(runtime["url"], timeout=120) as resp, open(target, "wb") as fh:
            shutil.copyfileobj(resp, fh)
    actual = sha256_file(target)
    if actual != runtime["sha256"]:
        target.unlink()
        raise SystemExit(f"the Python runtime does not match its pinned SHA-256: {actual}")
    # Also check it against the release's own list of sums, so the pin is not only our own copy.
    with urllib.request.urlopen(runtime["sums_url"], timeout=60) as resp:
        sums = resp.read().decode()
    line = next((x for x in sums.splitlines() if x.endswith(runtime["name"])), "")
    if not line.startswith(runtime["sha256"]):
        raise SystemExit("the runtime is not in the release's SHA256SUMS with the pinned value")
    return target


def tree_digest(root: Path) -> str:
    """One SHA-256 over every file under ``root`` (path and content), links by their target."""
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root)).encode()
        if p.is_symlink():
            h.update(b"L" + rel + b"\0" + os.readlink(p).encode() + b"\0")
        elif p.is_file():
            h.update(b"F" + rel + b"\0" + sha256_file(p).encode() + b"\0")
    return h.hexdigest()


TOOL_TEMPLATE = """#!/bin/sh
# Runs {what} from inside the application, with the bundled Python and nothing from the user's environment.
self="$0"
while [ -L "$self" ]; do
  target="$(readlink "$self")"
  case "$target" in
    /*) self="$target" ;;
    *) self="$(dirname "$self")/$target" ;;
  esac
done
here="$(cd "$(dirname "$self")" && pwd -P)"
exec "$here/../python/bin/python3" -I -B -m {module} "$@"
"""

TOOLS = {
    "regaudit-fhe": ("regaudit-fhe", "regaudit_fhe.cli"),
    "regaudit-portal": ("regaudit-portal", "regaudit_portal"),
}


def approved_limitation() -> str:
    """The approved security limitation text, taken from the portal's own module so it cannot drift."""
    spec = importlib.util.spec_from_file_location(
        "portal_engine_text", PORTAL_DIR / "regaudit_portal" / "engine.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses in that module look themselves up here
    spec.loader.exec_module(module)
    return module.SECURITY_LIMITATION


_EVALUATION = {
    # The default build, signed ad hoc: this wording is unchanged from the first builds.
    None: """It is an evaluation build and not a finished product. It is not a regulatory certification
and not proof of encrypted computation. A valid signature does not show that any FHE
(encrypted) computation took place.""",
    "developer-id": """It is an experimental local evaluation build, not a production-qualified release. It is
not a regulatory certification and not proof of encrypted computation. A valid signature
does not show that any FHE (encrypted) computation took place.""",
}


def _opening_text(signed_by: str | None) -> str:
    """What to do if macOS does not open it, for the signing this build really has."""
    if signed_by is None:
        return """IF MACOS WILL NOT OPEN IT
This build is signed only ad hoc. It is not notarized by Apple, so macOS blocks a copy that
was downloaded or sent to you. This build is for evaluation under VaultBytes' direction.
Only continue if it came to you from VaultBytes and its SHA-256 matches the value you were
given (in Terminal: shasum -a 256 <the .dmg file>). Then open System Settings, Privacy &
Security, scroll to the message about "Evidence Verification Portal", choose "Open Anyway"
and enter your password."""
    return f"""SIGNING
This build is signed with {signed_by}.
It is intended to be notarized by Apple before it is handed to anyone. Install it the normal
way and answer the usual macOS prompts. If macOS says that it is from an unidentified
developer, that it cannot be checked for malicious software, or that it is damaged, then it
is not this build as VaultBytes made it: do not bypass the warning in System Settings or
change your security settings to open it. Delete it and ask the person who sent it to you.
You can also compare the disk image with the SHA-256 value you were given (in Terminal:
shasum -a 256 <the .dmg file>)."""


def read_me_first(portal_version: str, signed_by: str | None = None) -> str:
    """READ ME FIRST.txt. ``signed_by`` is the Developer ID Application certificate the build was signed with, or None
    for the default ad hoc build. It never states a notarization result: that comes after the build."""
    evaluation = _EVALUATION[None if signed_by is None else "developer-id"]
    return f"""Evidence Verification Portal {portal_version}  (local evaluation build)

WHAT THIS IS
A local app that checks signed regaudit-fhe reports on your own Mac. It opens in your web
browser and works only on this computer. It is made by VaultBytes Innovations Ltd.
{evaluation}

YOU NEED
A Mac with Apple silicon (M1 or newer) running macOS 14 or newer.

INSTALL
1. Drag "Evidence Verification Portal" onto the Applications folder next to it.
2. Open it from Applications. Your browser opens at the portal.
3. Choose "Try a sample report". The samples are made-up demonstration data.

{_opening_text(signed_by)}

TO STOP IT
Right-click its icon in the Dock and choose Quit, or press Command-Q while it is in front.
Closing the browser tab does not stop it.

YOUR OWN REPORTS
Checking your own reports needs an administrator to set up trust first. The "Administrator
setup" page in the portal explains how. Nothing is set up automatically, and the samples are
never trusted for your own reports.

{approved_limitation()}
"""


AD_HOC_SIGNING = "ad hoc only. Not signed for distribution and not notarized."
NOTARIZATION_NOTE = (
    "Not part of the build. Apple's notarization result belongs with the notarized disk image and its evidence, "
    "not inside the bundle."
)


def signing_statement(signed_by: str | None) -> str:
    """The manifest's "signing" entry, for the signing this build really has. It never states a notarization result."""
    if signed_by is None:
        return AD_HOC_SIGNING
    return (
        f"{signed_by}, every Mach-O file and the bundle, with the hardened runtime and a secure timestamp, no "
        "entitlements. Notarization by Apple is a separate step after the build and is not recorded here."
    )


# ----------------------------------------------------------------------------- Developer ID signing

_IDENTITY = re.compile(r"Developer ID Application: .+ \(([A-Z0-9]{10})\)")
_MACHO_MAGIC = {
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xfe\xed\xfa\xce",
    b"\xca\xfe\xba\xbe",
    b"\xca\xfe\xba\xbf",
}


def team_of(identity: str) -> str:
    """The team identifier in a Developer ID Application certificate's name. Anything else is refused."""
    found = _IDENTITY.fullmatch(identity)
    if not found:
        raise SystemExit(
            '--sign-identity must be the full name of a "Developer ID Application" certificate, for example '
            '"Developer ID Application: Example Ltd (ABCDE12345)"'
        )
    return found.group(1)


def signature_problem(
    details: str, signed_by: str | None, team: str | None, runtime: bool
) -> str | None:
    """What is wrong with a signature, from ``codesign -dvv`` output, for the signing that was asked for; or None.

    For the ad hoc build the signature must be ad hoc. For a Developer ID build its first authority must be that
    certificate, with its team, a secure timestamp and (for code) the hardened runtime.
    """
    lines = details.splitlines()
    adhoc = any(line.strip() == "Signature=adhoc" for line in lines)
    if signed_by is None:
        return (
            None if adhoc else "the build was to be signed ad hoc, but the signature is not ad hoc"
        )
    if adhoc:
        return "the signature is ad hoc, not the Developer ID that was asked for"
    authority = next((line.split("=", 1)[1] for line in lines if line.startswith("Authority=")), "")
    if authority != signed_by:
        return f"it is signed by {authority or 'nobody'}, not by {signed_by}"
    if f"TeamIdentifier={team}" not in lines:
        return f"its team is not {team}"
    if not any(line.startswith("Timestamp=") for line in lines):
        return "it has no secure timestamp"
    flags = next((line for line in lines if line.startswith("CodeDirectory")), "")
    if runtime and "runtime" not in flags:
        return "it does not use the hardened runtime"
    return None


def check_signature(
    path: Path, signed_by: str | None, team: str | None, runtime: bool = True
) -> None:
    details = subprocess.run(["codesign", "-dvv", str(path)], capture_output=True, text=True).stderr
    problem = signature_problem(details, signed_by, team, runtime)
    if problem is not None:
        raise SystemExit(f"{path}: {problem}. The build stops: it would describe itself wrongly.")


def check_certificate_sha1(path: Path, sha1: str) -> None:
    """The leaf certificate in the signature is the one chosen by its SHA-1. Only public certificates are read."""
    with tempfile.TemporaryDirectory() as tmp:
        prefix = str(Path(tmp) / "cert")
        subprocess.run(
            ["codesign", "-d", f"--extract-certificates={prefix}", str(path)],
            capture_output=True,
            check=True,
        )
        leaf = hashlib.sha1(Path(prefix + "0").read_bytes()).hexdigest()  # noqa: S324 - a certificate's name
    if leaf.lower() != sha1.lower():
        raise SystemExit(f"{path} is signed with a certificate whose SHA-1 is {leaf}, not {sha1}")


def macho_files(root: Path) -> list[Path]:
    """Every Mach-O file under ``root``, found by its header and confirmed by ``file``. Links are not followed."""
    found = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        with open(path, "rb") as fh:
            if fh.read(4) not in _MACHO_MAGIC:
                continue
        kind = subprocess.run(["file", "-b", str(path)], capture_output=True, text=True).stdout
        if "Mach-O" in kind:
            found.append(path)
    return found


def sign_with_developer_id(
    app: Path, identity: str, signed_by: str, team: str, sha1: str | None
) -> int:
    """Sign every nested Mach-O file on its own, the deepest first, then the bundle. No --deep. Returns how many."""
    main = app / "Contents" / "MacOS" / "launcher"
    nested = [p for p in macho_files(app) if p != main]
    base = ["codesign", "--force", "--sign", identity, "--timestamp", "--options", "runtime"]
    for path in sorted(nested, key=lambda p: (-len(p.relative_to(app).parts), str(p))):
        run([*base, str(path)])
    run([*base, str(app)])
    run(["codesign", "--verify", "--deep", "--strict", str(app)])
    for path in [app, *nested]:
        check_signature(path, signed_by, team)
    if sha1:
        check_certificate_sha1(app, sha1)
    return len(nested)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument(
        "--cache", default=str(Path.home() / ".cache" / "evidence-verification-portal-build")
    )
    ap.add_argument("--no-dmg", action="store_true")
    ap.add_argument(
        "--sign-identity",
        help='The full name of a "Developer ID Application" certificate in the keychain, for example '
        '"Developer ID Application: Example Ltd (ABCDE12345)". Without it the build is signed ad hoc.',
    )
    ap.add_argument(
        "--sign-identity-sha1",
        help="That certificate's SHA-1, to choose it when the keychain holds more than one with the name.",
    )
    args = ap.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("this build needs an Apple silicon Mac")
    signed_by: str | None = args.sign_identity
    team = team_of(signed_by) if signed_by is not None else None
    sha1 = args.sign_identity_sha1
    if sha1 is not None and (signed_by is None or not re.fullmatch(r"[0-9A-Fa-f]{40}", sha1)):
        raise SystemExit(
            "--sign-identity-sha1 is 40 hexadecimal characters, and needs --sign-identity"
        )
    if signed_by is not None:
        # Only the names and SHA-1s of the signing identities are listed; nothing secret is read.
        listed = subprocess.run(
            ["security", "find-identity", "-v", "-p", "codesigning"], capture_output=True, text=True
        ).stdout
        if f'"{signed_by}"' not in listed or (sha1 and sha1.upper() not in listed.upper()):
            raise SystemExit(f"the keychain has no valid signing identity {signed_by}")

    out = Path(args.out).resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"{out} is not empty")
    out.mkdir(parents=True, exist_ok=True)

    runtime = json.loads((HERE / "runtime.json").read_text())
    tarball = fetch_runtime(runtime, Path(args.cache))

    app = out / f"{APP_NAME}.app"
    contents = app / "Contents"
    resources = contents / "Resources"
    (contents / "MacOS").mkdir(parents=True)
    resources.mkdir(parents=True)

    # 1. The runtime
    with tarfile.open(tarball) as tf:
        tf.extractall(resources, filter="data")
    py = resources / "python" / "bin" / "python3"
    before = {p.name for p in (resources / "python" / "bin").iterdir()}
    known_bytecode = {p for p in (resources / "python").rglob("*.pyc")}

    # 2. The locked wheels, nothing else
    run(
        [
            str(py),
            "-I",
            "-B",
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-cache-dir",
            "--no-compile",
            "--disable-pip-version-check",
            "-r",
            str(HERE / "requirements.lock"),
        ]
    )
    for p in list(
        (resources / "python" / "bin").iterdir()
    ):  # scripts pip wrote carry the build path
        if p.name not in before:
            p.unlink()
    # Compiled files record the build machine's paths, so none are shipped for the installed packages. The portal
    # does not need them: it points Python's bytecode cache at a private folder before the engine and its own modules
    # are imported (modules the interpreter loads before that are not covered by this).
    for cache in list(
        next((resources / "python" / "lib").glob("python3*/site-packages")).rglob("__pycache__")
    ):
        shutil.rmtree(cache)

    # 3. The portal's own source (pure Python), file by file so every file can be listed
    site = next((resources / "python" / "lib").glob("python3*/site-packages"))
    # The runtime brings pip and nothing in the bundle needs it. Leaving it would let the bundle install more.
    for leftover in [site / "pip", *site.glob("pip-*.dist-info")]:
        shutil.rmtree(leftover)
    shutil.copytree(
        PORTAL_DIR / "regaudit_portal",
        site / "regaudit_portal",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )

    # 4. The portal's own check must pass inside the finished bundle
    probe = (
        "import json,regaudit_portal.engine as e; i=e.check_engine(); "
        "print(json.dumps({'ok':i.ok,'reason':i.reason,'engine':i.engine}))"
    )
    res = subprocess.run(
        [str(py), "-I", "-B", "-c", probe], capture_output=True, text=True, cwd="/"
    )
    print(res.stdout.strip(), res.stderr.strip()[-300:])
    identity = json.loads(res.stdout.strip().splitlines()[-1]) if res.stdout.strip() else {}
    if not identity.get("ok"):
        raise SystemExit(
            f"the engine inside the bundle is not the recognised release: {identity.get('reason')}"
        )

    # 5. The launcher
    launcher = contents / "MacOS" / "launcher"
    run(
        [
            "swiftc",
            "-O",
            "-swift-version",
            "5",
            "-target",
            f"arm64-apple-macos{MIN_MACOS}",
            "-o",
            str(launcher),
            str(HERE / "launcher" / "main.swift"),
            "-framework",
            "AppKit",
        ]
    )

    # 5b. The commands an administrator runs (trust-list creation and checking), as programs that need no setup
    tools = resources / "tools"
    tools.mkdir()
    for name, (what, module) in TOOLS.items():
        script = tools / name
        script.write_text(TOOL_TEMPLATE.format(what=what, module=module))
        script.chmod(0o755)

    # 5c. The icon: the VaultBytes mark on a white tile
    with tempfile.TemporaryDirectory() as tmp:
        maker = Path(tmp) / "make_icon"
        run(
            [
                "swiftc",
                "-O",
                "-o",
                str(maker),
                str(HERE / "icon" / "make_icon.swift"),
                "-framework",
                "AppKit",
            ]
        )
        run(
            [
                str(maker),
                str(HERE / "icon" / "vaultbytes-mark.svg"),
                str(Path(tmp) / "AppIcon.iconset"),
            ]
        )
        run(
            [
                "iconutil",
                "-c",
                "icns",
                "-o",
                str(resources / "AppIcon.icns"),
                str(Path(tmp) / "AppIcon.iconset"),
            ]
        )

    # 5d. Nothing in the bundle may carry bytecode that this build created: it records the build machine's paths,
    # and the portal does not rely on bytecode from inside the bundle.
    for pyc in list((resources / "python").rglob("*.pyc")):
        if pyc not in known_bytecode:
            pyc.unlink()
    for cache in sorted((resources / "python").rglob("__pycache__"), reverse=True):
        if cache.is_dir() and not any(cache.iterdir()):
            cache.rmdir()

    # 6. Info.plist
    portal_version = "0.0.1"
    for line in (PORTAL_DIR / "pyproject.toml").read_text().splitlines():
        if line.startswith("version"):
            portal_version = line.split("=")[1].strip().strip('"')
    plist = {
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleExecutable": "launcher",
        "CFBundleIconFile": "AppIcon",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": portal_version,
        "CFBundleVersion": git("rev-parse", "--short=12", "HEAD") or portal_version,
        "LSMinimumSystemVersion": MIN_MACOS,
        "NSHighResolutionCapable": True,
        "LSApplicationCategoryType": "public.app-category.utilities",
        "NSHumanReadableCopyright": "Copyright (C) 2026 VaultBytes Innovations Ltd. AGPL-3.0-or-later.",
    }
    with open(contents / "Info.plist", "wb") as fh:
        plistlib.dump(plist, fh)

    # 7. The build manifest: what exactly is in here
    portal_files = {
        str(p.relative_to(site)): sha256_file(p)
        for p in sorted((site / "regaudit_portal").rglob("*"))
        if p.is_file()
    }
    manifest = {
        "application": APP_NAME,
        "portal_version": portal_version,
        "portal_commit": git("rev-parse", "HEAD"),
        "portal_tree": git("rev-parse", "HEAD^{tree}"),
        "portal_tree_dirty": bool(git("status", "--porcelain", "--", ".")),
        "engine": identity.get("engine"),
        "runtime": {k: runtime[k] for k in ("name", "python", "release", "sha256")},
        "requirements_lock_sha256": sha256_file(HERE / "requirements.lock"),
        "portal_files_sha256": hashlib.sha256(
            json.dumps(portal_files, sort_keys=True).encode()
        ).hexdigest(),
        "launcher_sha256_before_signing": sha256_file(launcher),
        "built_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "built_on": {
            "macos": platform.mac_ver()[0],
            "arch": platform.machine(),
            "swift": subprocess.run(
                ["swiftc", "--version"], capture_output=True, text=True
            ).stdout.splitlines()[0],
        },
        "signing": signing_statement(signed_by),
        "reproducible_build": False,
        "note": "The signed hashes of the launcher and of the whole application are in the BUILD_MANIFEST.json next to the disk image: they cannot be recorded inside a bundle that the signature seals.",
        "minimum_macos": MIN_MACOS,
    }
    if signed_by is not None:
        manifest["notarization"] = NOTARIZATION_NOTE
    (resources / "BUILD_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )

    # 8. Seal the bundle: ad hoc by default, or with the Developer ID. Either way the signature actually made is checked
    # against the one the text above describes.
    if signed_by is None:
        run(["codesign", "--force", "--deep", "--sign", "-", str(app)])
        run(["codesign", "--verify", "--deep", "--strict", str(app)])
        check_signature(app, None, None)
    else:
        nested = sign_with_developer_id(app, sha1 or signed_by, signed_by, team, sha1)
    # The hashes of what was actually produced, after signing. They live here, outside the bundle, because a
    # bundle's signature seals its own files and cannot contain its own final hash.
    manifest["signed"] = {
        "launcher_sha256": sha256_file(launcher),
        "application_tree_sha256": tree_digest(app),
    }
    if signed_by is not None:
        manifest["signed"].update(
            {
                "identity": signed_by,
                "team": team,
                "identity_sha1": sha1,
                "nested_code_signed": nested,
            }
        )
    (out / "READ ME FIRST.txt").write_text(read_me_first(portal_version, signed_by))

    if not args.no_dmg:
        stage = out / "dmg-staging"
        stage.mkdir()
        shutil.copytree(app, stage / app.name, symlinks=True)
        os.symlink("/Applications", stage / "Applications")
        (stage / "READ ME FIRST.txt").write_text(read_me_first(portal_version, signed_by))
        kind = "LOCAL-BUILD" if signed_by is None else "LOCAL-BUILD-developer-id"
        dmg = out / f"Evidence-Verification-Portal-{portal_version}-macos-arm64-{kind}.dmg"
        run(
            [
                "hdiutil",
                "create",
                "-volname",
                APP_NAME,
                "-srcfolder",
                str(stage),
                "-ov",
                "-format",
                "UDZO",
                str(dmg),
            ],
            stdout=subprocess.DEVNULL,
        )
        shutil.rmtree(stage)
        if signed_by is not None:
            run(["codesign", "--force", "--sign", sha1 or signed_by, "--timestamp", str(dmg)])
            run(["codesign", "--verify", "--strict", str(dmg)])
            check_signature(dmg, signed_by, team, runtime=False)
        (out / "SHA256SUMS").write_text(f"{sha256_file(dmg)}  {dmg.name}\n")
        manifest["dmg"] = {"name": dmg.name, "sha256": sha256_file(dmg)}
    (out / "BUILD_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print("built", app, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
