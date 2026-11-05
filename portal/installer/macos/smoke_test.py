"""Smoke test of a built application: it starts, answers on 127.0.0.1 only, verifies a synthetic sample, and stops the
portal cleanly when it is told to quit. Needs no browser: the launcher is started with --no-browser.

    python3 smoke_test.py "<path to Evidence Verification Portal.app>"

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

# A test of a built application: it runs the application and the bundled Python, with fixed arguments, and talks only
# to the 127.0.0.1 address the launcher prints.
# ruff: noqa: S603, S607, S310

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


def main(app_path: str) -> int:
    app = Path(app_path)
    launcher = app / "Contents" / "MacOS" / "launcher"
    py = app / "Contents" / "Resources" / "python" / "bin" / "python3"
    work = Path(tempfile.mkdtemp(prefix="portal-smoke-"))
    os.chmod(work, 0o700)
    home, tmp = work / "home", work / "tmp"
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp), "LANG": "en_US.UTF-8"}
    ok = True

    def check(name: str, passed: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and passed
        print(
            ("PASS " if passed else "FAIL ") + name + (f": {detail}" if detail else ""), flush=True
        )

    demo = work / "demo"
    r = subprocess.run(
        [str(py), "-I", "-m", "regaudit_portal", "demo-setup", str(demo)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    check("demo-setup with the bundled Python", r.returncode == 0, r.stderr.strip()[-120:])
    config = demo / "portal-config.json"

    p = subprocess.Popen(
        [str(launcher), "--no-browser", "--print-url", "--", "--config", str(config)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    url = ""
    t0 = time.time()
    while time.time() - t0 < 90:
        line = p.stdout.readline()
        if line.startswith("PORTAL_URL="):
            url = line.split("=", 1)[1].strip()
            break
        if p.poll() is not None:
            break
    check("launcher printed the URL", bool(url), f"{url} after {time.time() - t0:.1f}s")
    if not url:
        print("stderr:", p.stderr.read()[-500:])
        return 1
    check("URL is on 127.0.0.1", url.startswith("http://127.0.0.1:"))
    status = json.load(urllib.request.urlopen(url + "api/status", timeout=10))
    check("portal ready", status.get("ready") is True, json.dumps(status)[:120])

    port = url.rsplit(":", 1)[1].strip("/")
    lsof = subprocess.run(
        ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"], capture_output=True, text=True
    ).stdout
    check(
        "listening on 127.0.0.1 only",
        "127.0.0.1:" + port in lsof and "*:" + port not in lsof and "[::" not in lsof,
        lsof.strip().splitlines()[-1][-40:] if lsof.strip() else "",
    )

    sample = next(iter(sorted((demo / "sample-reports").glob("1-*.json"))), None)
    if sample:
        req = urllib.request.Request(
            url + "api/verify",
            data=sample.read_bytes(),
            headers={"Content-Type": "application/json", "Host": f"127.0.0.1:{port}"},
            method="POST",
        )
        verdict = json.load(urllib.request.urlopen(req, timeout=20))
        check(
            "a sample verifies through the bundled engine",
            verdict.get("verification", {}).get("trust_status") == "TRUSTED",
            verdict.get("verification", {}).get("trust_status", "")
            + " | engine "
            + str(verdict.get("engine", {}).get("version")),
        )

    before = list(tmp.glob("regaudit-portal-pyc-*"))
    check("private bytecode folder exists while running", len(before) == 1, str(len(before)))
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=20)
        check("launcher quits on SIGTERM", True, f"exit {p.returncode}")
    except subprocess.TimeoutExpired:
        p.kill()
        check("launcher quits on SIGTERM", False, "timed out")
    time.sleep(0.5)
    left = subprocess.run(
        ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"], capture_output=True, text=True
    ).stdout.strip()
    check("the portal stopped with it (port closed)", left == "", left[-60:])
    check("no private bytecode folder left", not list(tmp.glob("regaudit-portal-pyc-*")))
    print("RESULT", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
