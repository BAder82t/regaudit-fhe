"""Smoke test of a built application, without a browser (the launcher is started with --no-browser).

First run: a new account with nothing configured. The portal starts in welcome mode, offers the synthetic samples,
verifies them as demonstrations, refuses to verify anyone's own report, serves the read-only setup page, and creates
nothing on disk. Demonstration: with the configuration demo-setup makes, the portal is in demonstration mode, not ready
for your own reports, and an uploaded sample report is verified and labelled as a demonstration. Customer: a setup plan
prepared by the portal for a made-up test issuer, applied with admin-apply, gives customer trust, under which that
issuer's signed report is trusted with no demonstration label and a demonstration sample is not. Each stops the portal
when told to quit.

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


def _builder_traces(app: Path) -> list[str]:
    """What of this machine would show if the build had leaked into the bundle: the account's name, its home folder, the
    temporary folder the build was made in and the folder the application sits in. Read here, not written down."""
    import getpass

    names = {
        getpass.getuser(),
        str(Path.home()),
        str(Path(tempfile.gettempdir()).resolve()),
        str(app.parent.resolve()),
    }
    return [flag for name in sorted(names) if len(name) > 3 for flag in ("-e", name)]


OK = True


# A made-up test issuer, the same as issuer 1 of the native dialog checklist's test kit. Only its public key and one
# report it signed are here: the private key was thrown away when the report was made, so nothing here can sign. The
# report is for the verifier id acme-verifier and was signed on 8 November 2026, so the plan below allows the longest
# age a plan can have, and this test keeps working for years.
TEST_ISSUER = "Test Issuer One Ltd"
TEST_KEY_ID = "test-issuer-1"
TEST_VERIFIER = "acme-verifier"
TEST_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEALJBpG7iX/Qsx9C4ql4M9gqRn+K4PA0ehOXNogNeyC/4=\n-----END PUBLIC KEY-----\n"
TEST_FINGERPRINT = "e0b812b4520eb947c1f89ec87890aaf4090717fd3be25e2effadd0579e80dbc6"  # as the issuer would tell you
WRONG_FINGERPRINT = TEST_FINGERPRINT[:-1] + "0"
TEST_REPORT = r"""{"schema": "regaudit-fhe.report.v2", "schema_version": "regaudit-fhe.report.v2", "algorithm_version": "0.2.1", "primitive": "drift", "backend": "plaintext", "parameter_set": {"backend": "plaintext", "backend_version": "", "coeff_mod_bit_sizes": [], "library_version": "0.2.1", "multiplicative_depth": 6, "poly_modulus_degree": 0, "scaling_factor_bits": 0, "security_bits": 128}, "parameter_set_hash": "9f6e012d6c51ca883991d1c1485883564a9642f92a74bba6bba656753a89b606", "regulations": ["EU_AI_ACT_ART15", "FDA_SAMD_PCCP", "BASEL_III"], "result": {"distance": 0.009999999999999995, "drift_bit": true, "w1_distance": 0.09999999999999998}, "input_commitments": [], "depth_budget": {"declared": 6, "consumed": 6}, "issued_at": "2026-11-08T17:13:39.709685+00:00", "issuer": "Test Issuer One Ltd", "key_id": "test-issuer-1", "public_key_fingerprint": "e0b812b4520eb947c1f89ec87890aaf4090717fd3be25e2effadd0579e80dbc6", "deployment_id": "synthetic-test", "audit_run_id": "667e49ad-c0c9-4aaa-a611-8a9e4bdc91fc", "trust_policy_version": 1, "receipt": {"sha256": "64df922b63e110390586870a47db7ea80beeaadffe6a0a4d1a2b173c93988e2e", "signature_alg": "Ed25519", "signature_b64": "gnyJOkhRnhvjk5CvFEkiSY14i0EugXKpsdZFq8TlWHykjVuFe3h3dPq1IBGHqrle2ZyBFk5nRRNYUhWMko/aBQ==", "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEALJBpG7iX/Qsx9C4ql4M9gqRn+K4PA0ehOXNogNeyC/4=\n-----END PUBLIC KEY-----\n"}, "audience": ["acme-verifier"]}"""
DEMONSTRATION_LABEL = "DEMONSTRATION \u2014 NOT CUSTOMER-TRUSTED"


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


def call_full(url: str, port: str):
    """Status, headers and body of a GET."""
    req = urllib.request.Request(url, headers={"Host": f"127.0.0.1:{port}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, {k.lower(): v for k, v in err.headers.items()}, err.read()


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
        # The real path: /var is a symbolic link on macOS, and admin-apply follows no link, as with a real home folder.
        work = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
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
    code, headers, body = call_full(url + "static/app.css", port)
    csp = headers.get("content-security-policy", "")
    check(
        "the stylesheet is served under a policy that allows local fonts only",
        code == 200 and "font-src 'self'" in csp and "http" not in csp,
        csp[:80],
    )
    code, headers, body = call_full(url + "static/fonts/inter-latin-wght-normal.woff2", port)
    check(
        "a bundled font is served",
        code == 200
        and headers.get("content-type", "").startswith("font/woff2")
        and body[:4] == b"wOF2",
        f"{code} {headers.get('content-type')}",
    )
    code, headers, body = call_full(url + "static/vaultbytes-mark.svg", port)
    check(
        "the VaultBytes mark is served",
        code == 200 and headers.get("content-type", "").startswith("image/svg+xml"),
        str(code),
    )
    commands = json.loads(call(url + "api/setup", port=port)[1]).get("commands", {})
    check(
        "the setup page names the administrator programs by their path inside the application",
        commands.get("in_application") is True
        and "Resources/tools/regaudit-fhe" in json.dumps(commands)
        and "Resources/tools/regaudit-portal" in json.dumps(commands),
        json.dumps(commands)[:120],
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

    print("--- demonstration: the configuration demo-setup makes, and a synthetic report")
    work, home, tmp, env = fresh("portal-smoke-config-")
    demo = work / "demo"
    r = subprocess.run(
        [str(py), "-I", "-B", "-m", "regaudit_portal", "demo-setup", str(demo)],
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
        "demonstration mode with demo-setup's configuration, not ready for your own reports",
        status.get("ready") is False
        and status.get("state") == "demonstration"
        and status.get("trust_mode") == "demonstration"
        and status.get("demonstration_label") == DEMONSTRATION_LABEL,
        f"{status.get('ready')} {status.get('state')} {status.get('trust_mode')}",
    )
    sample = next(iter(sorted((demo / "sample-reports").glob("1-*.json"))), None)
    check("demo-setup copied a sample report", sample is not None)
    if sample:
        code, body = call(url + "api/verify", data=sample.read_bytes(), port=port)
        result = json.loads(body) if code == 200 else {}
        check(
            "an uploaded report verifies through the bundled engine, labelled as a demonstration",
            (result.get("verification") or {}).get("trust_status") == "TRUSTED"
            and (result.get("engine") or {}).get("version") == "0.2.1"
            and result.get("synthetic_demonstration") is True
            and result.get("trust_mode") == "demonstration"
            and result.get("demonstration_label") == DEMONSTRATION_LABEL,
            f"{(result.get('verification') or {}).get('trust_status')} {result.get('trust_mode')}",
        )
    stop(p, port, tmp)

    print("--- customer: a setup plan prepared by the portal and applied with admin-apply")
    work, home, tmp, env = fresh("portal-smoke-customer-")
    # A real account always has this folder; admin-apply makes only the application's own folder inside it.
    (home / "Library" / "Application Support").mkdir(mode=0o700, parents=True)
    os.chmod(home / "Library", 0o700)
    p, url = start(launcher, env, [])
    port = url.rsplit(":", 1)[1].strip("/")

    def plan_request(fingerprint: str) -> bytes:
        return json.dumps(
            {
                "mode": "first-setup",
                "configuration": {
                    "profile": "confidential",
                    "verifier_id": TEST_VERIFIER,
                    "max_age_days": 3650,
                    "replay_mode": "check",
                },
                "issuers": [
                    {
                        "issuer": TEST_ISSUER,
                        "key_id": TEST_KEY_ID,
                        "public_key": TEST_PUBLIC_KEY,
                        "fingerprint": fingerprint,
                    }
                ],
            }
        ).encode()

    code, body = call(url + "api/setup/plan", data=plan_request(WRONG_FINGERPRINT), port=port)
    check(
        "a wrong fingerprint gives no plan, and the answer does not carry the key's fingerprint",
        code == 422
        and json.loads(body).get("error") == "fingerprint_mismatch"
        and TEST_FINGERPRINT.encode() not in body,
        f"{code} {body[:60]!r}",
    )
    code, body = call(url + "api/setup/plan", data=plan_request(TEST_FINGERPRINT), port=port)
    answer = json.loads(body) if code == 200 else {}
    check(
        "the portal prepares a customer setup plan with the right fingerprint",
        code == 200
        and answer.get("ok") is True
        and any('"trust_mode": "customer"' in w.get("text", "") for w in answer.get("writes", [])),
        f"{code} {body[:60]!r}",
    )
    plan_file = work / "setup-plan.json"
    plan_file.write_text(answer.get("plan_text", ""))
    stop(p, port, tmp)
    folder = home / "Library" / "Application Support" / "Evidence Verification Portal"

    def admin_apply(fingerprint: str) -> subprocess.CompletedProcess:
        # As the application's menu runs it: the bundled Python, no standard input, the plan's checksum given.
        return subprocess.run(
            [
                str(py),
                "-I",
                "-B",
                "-m",
                "regaudit_portal",
                "admin-apply",
                f"--expect-plan-sha256={answer.get('plan_sha256', '')}",
                f"--expect-fingerprint={TEST_KEY_ID}={fingerprint}",
                "--",
                str(plan_file),
            ],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
        )

    r = admin_apply(WRONG_FINGERPRINT)
    check(
        "admin-apply refuses a wrong fingerprint and writes nothing",
        r.returncode != 0 and not folder.exists(),
        f"exit {r.returncode} {r.stderr.strip()[-80:]}",
    )
    r = admin_apply(TEST_FINGERPRINT)
    written = json.loads((folder / "portal-config.json").read_text()) if r.returncode == 0 else {}
    check(
        "admin-apply with the issuer's fingerprint writes a customer configuration",
        r.returncode == 0 and written.get("trust_mode") == "customer",
        f"exit {r.returncode} {r.stderr.strip()[-80:]}",
    )
    p, url = start(launcher, env, [])  # no --config: the standard folder admin-apply wrote to
    port = url.rsplit(":", 1)[1].strip("/")
    status = json.loads(call(url + "api/status", port=port)[1])
    check(
        "customer mode: ready for your own reports, with no demonstration label",
        status.get("ready") is True
        and status.get("state") == "ready"
        and status.get("trust_mode") == "customer"
        and "demonstration_label" not in status,
        f"{status.get('ready')} {status.get('state')} {status.get('trust_mode')}",
    )
    code, body = call(url + "api/verify", data=TEST_REPORT.encode(), port=port)
    result = json.loads(body) if code == 200 else {}
    check(
        "the test issuer's report is trusted under customer trust, with no demonstration label",
        (result.get("verification") or {}).get("trust_status") == "TRUSTED"
        and result.get("synthetic_demonstration") is False
        and result.get("trust_mode") == "customer"
        and "demonstration_label" not in result,
        f"{code} {(result.get('verification') or {}).get('trust_status')} {result.get('trust_mode')}",
    )
    if sample:
        code, body = call(url + "api/verify", data=sample.read_bytes(), port=port)
        result = json.loads(body) if code == 200 else {}
        check(
            "a demonstration sample uploaded as your own report is not trusted under customer trust",
            code == 200
            and (result.get("verification") or {}).get("trust_status") not in (None, "TRUSTED"),
            f"{code} {(result.get('verification') or {}).get('trust_status')}",
        )
    stop(p, port, tmp)
    print("--- the launcher is killed: the portal must not be left running")
    work, home, tmp, env = fresh("portal-smoke-kill-")
    p, url = start(launcher, env, [])
    port = url.rsplit(":", 1)[1].strip("/")
    kids = subprocess.run(
        ["pgrep", "-P", str(p.pid)], capture_output=True, text=True
    ).stdout.split()
    check("the launcher has the portal as its child", len(kids) == 1, str(kids))
    p.kill()
    p.wait(timeout=10)
    stopped = False
    for _ in range(40):
        time.sleep(0.25)
        if listening(port) == "":
            stopped = True
            break
    check(
        "the portal stopped by itself after the launcher was killed (SIGKILL)",
        stopped,
        listening(port)[-60:],
    )
    time.sleep(0.5)
    check("and removed its private bytecode folder", not list(tmp.glob("regaudit-portal-pyc-*")))

    print("--- what is in the bundle")
    tools = app / "Contents" / "Resources" / "tools"
    for name in ("regaudit-fhe", "regaudit-portal"):
        r = subprocess.run(
            [str(tools / name), "--help"],
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True,
            text=True,
            timeout=60,
        )
        check(
            f"the administrator command {name} runs from inside the app",
            r.returncode == 0 and "usage" in r.stdout.lower(),
            r.stderr.strip()[-80:],
        )
    r = subprocess.run(
        [str(tools / "regaudit-fhe"), "trust", "add", "--help"],
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    check("trust add is reachable through it", r.returncode == 0 and "--fingerprint" in r.stdout)
    link_dir = Path(tempfile.mkdtemp(prefix="portal-smoke-link-"))
    (link_dir / "regaudit-fhe").symlink_to(tools / "regaudit-fhe")
    r = subprocess.run(
        [str(link_dir / "regaudit-fhe"), "--help"],
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    check(
        "an administrator program works when reached through a symbolic link",
        r.returncode == 0 and "usage" in r.stdout.lower(),
        r.stderr.strip()[-80:],
    )
    site = next((app / "Contents" / "Resources" / "python" / "lib").glob("python3*/site-packages"))
    check(
        "pip is not shipped", not (site / "pip").exists() and not list(site.glob("pip-*.dist-info"))
    )
    check("no bytecode is shipped for the installed packages", not list(site.rglob("__pycache__")))
    leaks = subprocess.run(
        ["grep", "-r", "-a", "-l", "-F", *_builder_traces(app), str(app)],
        capture_output=True,
        text=True,
    ).stdout.split()
    check(
        "no build machine paths or user names anywhere in the bundle", leaks == [], str(leaks[:2])
    )
    plist = (app / "Contents" / "Info.plist").read_bytes()
    check(
        "the application has an icon",
        (app / "Contents" / "Resources" / "AppIcon.icns").is_file() and b"AppIcon" in plist,
    )
    check(
        "the application does not forbid a second launch record",
        b"LSMultipleInstancesProhibited" not in plist,
    )

    sealed = subprocess.run(
        ["codesign", "--verify", "--deep", "--strict", str(app)], capture_output=True, text=True
    )
    check(
        "the bundle's signature still verifies after running it",
        sealed.returncode == 0,
        sealed.stderr.strip()[-100:],
    )
    stray = [
        str(x)
        for x in (app / "Contents" / "Resources" / "python" / "lib").rglob("__pycache__")
        if "site-packages" in str(x)
    ]
    check("running added no bytecode folder inside the bundle", stray == [], str(stray[:2]))
    print("RESULT", "PASS" if OK else "FAIL")
    return 0 if OK else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
