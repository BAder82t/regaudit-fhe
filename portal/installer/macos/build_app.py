"""Build the macOS application for the Evidence Verification Portal (Apple silicon, macOS 14 or newer).

    python3 build_app.py --out <empty folder> [--cache <folder>] [--no-dmg]

Everything the application runs is inside the bundle: a relocatable CPython (checked against its published SHA-256),
the exact wheels in ``requirements.lock`` (installed with ``--require-hashes``), the portal's own source and a small
native launcher. The engine is therefore the published regaudit-fhe 0.2.1 installed the ordinary way, as source
files, and the portal's own engine check runs unchanged. The build refuses to continue if that check does not pass
inside the finished bundle.

This produces a LOCAL EVALUATION build. It is signed ad hoc, which is enough to run on the machine that built it and
is not a distributable signature: it is not notarized and macOS will warn about it on any other computer.

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
import json
import os
import platform
import plistlib
import shutil
import subprocess
import sys
import tarfile
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument(
        "--cache", default=str(Path.home() / ".cache" / "evidence-verification-portal-build")
    )
    ap.add_argument("--no-dmg", action="store_true")
    args = ap.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("this build needs an Apple silicon Mac")

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

    # 2. The locked wheels, nothing else
    run(
        [
            str(py),
            "-I",
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
    # The portal never loads bytecode from inside the bundle (it points Python's cache at a private folder), and
    # compiled files record the build machine's paths, so none are shipped for the installed packages.
    for cache in list(
        next((resources / "python" / "lib").glob("python3*/site-packages")).rglob("__pycache__")
    ):
        shutil.rmtree(cache)

    # 3. The portal's own source (pure Python), file by file so every file can be listed
    site = next((resources / "python" / "lib").glob("python3*/site-packages"))
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
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": portal_version,
        "CFBundleVersion": git("rev-parse", "--short=12", "HEAD") or portal_version,
        "LSMinimumSystemVersion": MIN_MACOS,
        "LSMultipleInstancesProhibited": True,
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
        "launcher_sha256": sha256_file(launcher),
        "built_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "built_on": {
            "macos": platform.mac_ver()[0],
            "arch": platform.machine(),
            "swift": subprocess.run(
                ["swiftc", "--version"], capture_output=True, text=True
            ).stdout.splitlines()[0],
        },
        "signing": "ad hoc only. Not signed for distribution and not notarized.",
        "minimum_macos": MIN_MACOS,
    }
    (resources / "BUILD_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )

    # 8. Seal the bundle (ad hoc)
    run(["codesign", "--force", "--deep", "--sign", "-", str(app)])
    run(["codesign", "--verify", "--deep", "--strict", str(app)])

    if not args.no_dmg:
        stage = out / "dmg-staging"
        stage.mkdir()
        shutil.copytree(app, stage / app.name, symlinks=True)
        os.symlink("/Applications", stage / "Applications")
        dmg = out / f"Evidence-Verification-Portal-{portal_version}-macos-arm64-LOCAL-BUILD.dmg"
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
        (out / "SHA256SUMS").write_text(f"{sha256_file(dmg)}  {dmg.name}\n")
        manifest["dmg"] = {"name": dmg.name, "sha256": sha256_file(dmg)}
        (out / "BUILD_MANIFEST.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
    print("built", app, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
