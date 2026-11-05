"""Smoke test of a built application, without a browser (the launcher is started with --no-browser).

First run: a new account with nothing configured. The portal starts in welcome mode, offers the synthetic samples,
verifies them as demonstrations, refuses to verify anyone's own report, serves the read-only setup page, and creates
nothing on disk. Configured: with a configuration the application verifies a synthetic sample report as an upload.
Both stop the portal when told to quit.

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
import urllib.error
import urllib.request
from pathlib import Path

OK = True


def check(name: str, passed: bool, detail: str = "") -> None:
    global OK
    OK = OK and passed
    print(("PASS " if passed else "FAIL ") + name + (f": {detail}" if detail else ""), flush=True)


def call(url: str, data: bytes | None = None, method: str | None = None, port: str = ""):
    headers = {"Host": f"127.0.0.1:{port}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        url, data=data, headers=headers, method=method or ("POST" if data is not None else "GET")
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def start(launcher: Path, env: dict, extra: list[str]) -> tuple[subprocess.Popen, str]:
    p = subprocess.Popen(
        [str(launcher), "--no-browser", "--print-url", *extra],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    t0 = time.time()
    while time.time() - t0 < 90:
        line = p.stdout.readline()
        if line.startswith("PORTAL_URL="):
            url = line.split("=", 1)[1].strip()
            check(
                "launcher printed a 127.0.0.1 URL",
                url.startswith("http://127.0.0.1:"),
                f"{url} after {time.time() - t0:.1f}s",
            )
            return p, url
        if p.poll() is not None:
            break
    print("stderr:", p.stderr.read()[-500:])
    check("launcher printed a URL", False)
    raise SystemExit(1)


def listening(port: str) -> str:
    return subprocess.run(
        ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"], capture_output=True, text=True
    ).stdout.strip()


def stop(p: subprocess.Popen, port: str, tmp: Path) -> None:
    check(
        "one private bytecode folder while running",
        len(list(tmp.glob("regaudit-portal-pyc-*"))) == 1,
    )
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=20)
        check("launcher quits on SIGTERM", p.returncode == 0, f"exit {p.returncode}")
    except subprocess.TimeoutExpired:
        p.kill()
        check("launcher quits on SIGTERM", False, "timed out")
    time.sleep(0.5)
    check("the portal stopped with it (port closed)", listening(port) == "")
    check("no private bytecode folder left", not list(tmp.glob("regaudit-portal-pyc-*")))


def main(app_path: str) -> int:
    app = Path(app_path)
    launcher = app / "Contents" / "MacOS" / "launcher"
    py = app / "Contents" / "Resources" / "python" / "bin" / "python3"

    def fresh(prefix: str):
        work = Path(tempfile.mkdtemp(prefix=prefix))
        os.chmod(work, 0o700)
        home, tmp = work / "home", work / "tmp"
        home.mkdir(mode=0o700)
        tmp.mkdir(mode=0o700)
        return (
            work,
            home,
            tmp,
            {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp), "LANG": "en_US.UTF-8"},
        )

    print("--- first run: nothing configured")
    work, home, tmp, env = fresh("portal-smoke-first-")
    p, url = start(launcher, env, [])
    port = url.rsplit(":", 1)[1].strip("/")
    code, body = call(url + "api/status", port=port)
    status = json.loads(body)
    check(
        "welcome mode: not set up, five samples",
        code == 200 and status.get("state") == "not_set_up" and len(status.get("samples", [])) == 5,
        f"{status.get('state')} {len(status.get('samples', []))}",
    )
    check(
        "listening on 127.0.0.1 only",
        "127.0.0.1:" + port in listening(port)
        and "*:" + port not in listening(port)
        and "[::" not in listening(port),
    )
    expect = {"trusted": "TRUSTED", "untrusted-signer": "INVALID", "modified": "INVALID"}
    for sample in status["samples"]:
        code, body = call(f"{url}api/samples/{sample['id']}/verify", data=b"", port=port)
        result = json.loads(body) if code == 200 else {}
        label = result.get("synthetic_demonstration") is True
        verdict = (result.get("verification") or {}).get("trust_status")
        want = expect.get(sample["id"])
        check(
            f"sample {sample['id']}: synthetic label and the engine's verdict",
            code == 200 and label and (want is None or verdict == want),
            f"{code} {verdict}",
        )
    code, body = call(url + "api/verify", data=b"{}", port=port)
    check(
        "own-report verification is refused, with no verdict",
        code == 503 and b"trust_status" not in body,
        f"{code} {body[:80]!r}",
    )
    code, _ = call(url + "setup", port=port)
    check("the setup page is served", code == 200)
    code, _ = call(url + "api/setup", data=b"{}", port=port)
    check("the setup page cannot be written to", code in (405, 404), str(code))
    created = sorted(str(x.relative_to(home)) for x in home.rglob("*"))
    check("nothing was created in the account's home folder", created == [], str(created))
    stop(p, port, tmp)

    print("--- configured: an administrator's configuration and a synthetic report")
    work, home, tmp, env = fresh("portal-smoke-config-")
    demo = work / "demo"
    r = subprocess.run(
        [str(py), "-I", "-m", "regaudit_portal", "demo-setup", str(demo)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    check("demo-setup with the bundled Python", r.returncode == 0, r.stderr.strip()[-120:])
    p, url = start(launcher, env, ["--", "--config", str(demo / "portal-config.json")])
    port = url.rsplit(":", 1)[1].strip("/")
    status = json.loads(call(url + "api/status", port=port)[1])
    check(
        "portal ready with a configuration", status.get("ready") is True, str(status.get("ready"))
    )
    sample = next(iter(sorted((demo / "sample-reports").glob("1-*.json"))), None)
    if sample:
        code, body = call(url + "api/verify", data=sample.read_bytes(), port=port)
        result = json.loads(body) if code == 200 else {}
        check(
            "an uploaded report verifies through the bundled engine",
            (result.get("verification") or {}).get("trust_status") == "TRUSTED"
            and (result.get("engine") or {}).get("version") == "0.2.1",
            str((result.get("verification") or {}).get("trust_status")),
        )
    stop(p, port, tmp)
    print("RESULT", "PASS" if OK else "FAIL")
    return 0 if OK else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
