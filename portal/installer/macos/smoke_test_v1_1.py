"""Smoke test of a built application for what Product v1.1 added: clearer results, bounded batch verification, and the
verify-only boundary. It runs the packaged application, not the source checkout.

It uses the same launcher helpers as ``smoke_test.py`` (the application is started with --no-browser and only the
127.0.0.1 address it prints is contacted). It needs Node only to run the page's own functions as packaged; without Node that one
group is reported as NOT RUN, never as passed.

    python3 smoke_test_v1_1.py "<path to Evidence Verification Portal.app>"

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

# ruff: noqa: S603

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import smoke_test as base  # noqa: E402

NOT_RUN: list[str] = []
MB = 1 << 20


def skipped(name: str, why: str) -> None:
    NOT_RUN.append(name)
    print(f"NOT RUN {name}: {why}", flush=True)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def batch_body(files: list[tuple[str, bytes]]) -> bytes:
    return json.dumps({"files": [{"name": n, "content_b64": b64(c)} for n, c in files]}).encode()


def page_function_run(app_js: str, answer: dict) -> dict | None:
    """Run the page's own validateBatch and batchRows, taken from the packaged app.js, in Node."""
    node = shutil.which("node")
    if node is None:
        return None
    harness = r"""
const fs = require("fs"); const input = JSON.parse(fs.readFileSync(0, "utf8")); const s = input.source;
const cut = (a, b) => { const i = s.indexOf(a), j = s.indexOf(b); if (i < 0 || j < i) throw new Error("missing " + a); return s.slice(i, j); };
const code = cut("const STATEMENTS = [", "function render(body, fileName)") + "\n" + cut("const BATCH_SCHEMA", "function renderBatch(answer)");
const api = new Function(code + "\nreturn { validateBatch, batchRows, STATEMENTS };")();
process.stdout.write(JSON.stringify({ problems: api.validateBatch(input.answer), rows: api.batchRows(input.answer),
  words: api.STATEMENTS.map(([k, l, w]) => [k, l, Object.values(w)]) }));
"""
    done = subprocess.run(
        [node, "-e", harness],
        input=json.dumps({"source": app_js, "answer": answer}),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return json.loads(done.stdout) if done.returncode == 0 else None


def call_big(url: str, data: bytes, port: str):
    """POST a body the portal may refuse before reading it all. Returns the status, or None if the connection was closed
    without an answer. A refusal that resets the connection is a refusal, as long as the portal still answers afterwards."""
    import http.client

    host, _, p = url.split("//", 1)[1].partition("/")[0].partition(":")
    conn = http.client.HTTPConnection(host, int(p or port), timeout=30)
    try:
        conn.putrequest("POST", "/api/verify-batch", skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{port}")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(data)))
        conn.endheaders()
        try:
            conn.sock.sendall(data)
        except OSError:
            print("  (the portal closed the connection while the body was being sent)")
        try:
            return conn.getresponse().status
        except (OSError, http.client.HTTPException):
            return None
    finally:
        conn.close()


def main(app_path: str) -> int:
    app = Path(app_path)
    launcher = app / "Contents" / "MacOS" / "launcher"
    py = app / "Contents" / "Resources" / "python" / "bin" / "python3"
    check = base.check

    # ----- the bundle itself: what is and is not packaged -----------------------------------------------------------------
    print("--- the bundle: nothing for encrypted computation or decryption is packaged")
    site = next(
        (app / "Contents" / "Resources" / "python" / "lib").glob("python3*/site-packages"), None
    )
    check("the bundle's site-packages was found", site is not None)
    if site is not None:
        present = sorted(
            p.name
            for p in site.iterdir()
            if re.match(r"(?i)(tenseal|openfhe|seal|pybind11)", p.name)
        )
        check("no CKKS library is installed in the bundle", present == [], str(present))
    names = re.compile(
        r"(\.pem|\.key|\.p12|\.pfx|decryptor\.key|evaluator\.key|id_rsa|id_ed25519)$", re.I
    )
    resources = app / "Contents" / "Resources"
    in_own_files = [
        str(p.relative_to(app))
        for p in resources.rglob("*")
        if p.is_file()
        and names.search(p.name)
        # third-party packages may ship test certificates; our own packages and tools may not
        and ("python" not in p.relative_to(resources).parts[:1] or "regaudit_" in str(p))
    ]
    check(
        "no key file in the application's own resources", in_own_files == [], str(in_own_files[:5])
    )
    pem = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
    own_hits = []
    for folder in (resources / "tools", *(site.glob("regaudit_*") if site else [])):
        if folder.exists():
            for p in folder.rglob("*"):
                if p.is_file() and p.stat().st_size < 5 * MB and pem.search(p.read_bytes()):
                    own_hits.append(str(p.relative_to(app)))
    # The portal source holds the words "PRIVATE KEY" only in refusal text and test fixtures, never a block header.
    check("no private-key block in the portal's own files", own_hits == [], str(own_hits[:5]))

    # ----- run it in the demonstration configuration, which has real sample reports --------------------------------------
    print("--- batch verification and the verify-only boundary, in the packaged application")
    work = Path(tempfile.mkdtemp(prefix="portal-smoke-v11-")).resolve()
    os.chmod(work, 0o700)
    home, tmp = work / "home", work / "tmp"
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp), "LANG": "en_US.UTF-8"}
    demo = work / "demo"
    r = subprocess.run(
        [str(py), "-I", "-B", "-m", "regaudit_portal", "demo-setup", str(demo)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    check("demo-setup with the bundled Python", r.returncode == 0, r.stderr.strip()[-120:])
    reports = {p.name: p.read_bytes() for p in sorted((demo / "sample-reports").glob("*.json"))}
    check("demo-setup made the sample reports", len(reports) >= 6, str(len(reports)))
    marker = b"v11-retention-marker-6c1f2d9e"
    extra = None
    for raw in reports.values():
        try:
            extra = json.loads(raw)
            if isinstance(extra, dict) and "signature" in json.dumps(extra):
                break
        except ValueError:
            continue
    extra["deployment_id"] = (
        marker.decode()
    )  # a changed report: INVALID, and carrying text we can look for afterwards
    reports["marker.json"] = json.dumps(extra).encode()

    def snapshot(folder: Path) -> set[str]:
        return {str(p.relative_to(folder)) for p in folder.rglob("*")}

    home_before = snapshot(home) | {"demo/" + x for x in snapshot(demo)}
    p, url = base.start(launcher, env, ["--", "--config", str(demo / "portal-config.json")])
    port = url.rsplit(":", 1)[1].strip("/")
    try:
        code, body = base.call(url + "api/status", port=port)
        status = json.loads(body)
        limits = status.get("batch", {})
        check(
            "the status states the batch limits",
            code == 200
            and limits.get("max_files") == 20
            and limits.get("max_file_bytes") == MB
            and limits.get("max_total_bytes") == 8 * MB,
            str(limits),
        )

        # -- a mixed batch, each file as it is alone
        files = list(reports.items())
        code, body = base.call(url + "api/verify-batch", data=batch_body(files), port=port)
        answer = json.loads(body) if code == 200 else {}
        check(
            "a mixed batch is answered",
            code == 200 and answer.get("schema") == "regaudit-portal-batch/1",
            str(code),
        )
        entries = answer.get("files", [])
        check(
            "one result per file, in the order sent",
            [e.get("name") for e in entries] == [n for n, _ in files],
        )
        same, why = True, ""
        for (name, raw), entry in zip(files, entries, strict=False):
            try:
                c1, b1 = base.call(url + "api/verify", data=raw, port=port)
            except OSError:  # an oversized upload may be refused by closing the connection
                c1, b1 = 413, b"{}"
            alone = json.loads(b1) if c1 == 200 else {}
            if c1 == 200 and entry.get("ok"):
                same = same and entry["result"]["verification"] == alone["verification"]
                same = same and entry["result"]["statuses"] == alone["statuses"]
                same = (
                    same
                    and entry["report_sha256"]
                    == hashlib.sha256(raw).hexdigest()
                    == alone["report_sha256"]
                )
            else:
                same = same and c1 != 200 and not entry.get("ok")
            if not same and not why:
                why = name
        check(
            "each file's verdict, statements and digest equal the same bytes sent alone", same, why
        )
        verdicts = {
            e["name"]: e["result"]["verification"]["trust_status"] for e in entries if e.get("ok")
        }
        check(
            "the verdicts are the engine's: the trusted sample is TRUSTED in demonstration mode only as a demonstration",
            all(e["result"].get("synthetic_demonstration") is True for e in entries if e.get("ok"))
            and verdicts.get("marker.json") != "TRUSTED",
            str(verdicts)[:160],
        )
        check(
            "every statement set names the verdict the engine gave",
            all(
                e["result"]["statuses"]["verdict"] == e["result"]["verification"]["trust_status"]
                for e in entries
                if e.get("ok")
            ),
        )

        # -- the page code as packaged
        code, app_js = base.call(url + "static/app.js", port=port)
        run = page_function_run(app_js.decode(), answer) if code == 200 else None
        if run is None:
            skipped(
                "the packaged page's own consistency check",
                "Node is not installed or the page code was not found",
            )
        else:
            check(
                "the packaged page's consistency check accepts the real batch answer",
                run["problems"] == [],
                str(run["problems"]),
            )
            bad = json.loads(json.dumps(answer))
            bad["summary"]["total"] += 1
            tampered = page_function_run(app_js.decode(), bad)
            check(
                "and refuses the same answer with a wrong count",
                bool(tampered and tampered["problems"]),
            )
            forbidden = re.compile(
                r"\b(trusted|verified|authentic|genuine|secure|safe|certified|compliant|approved|proves?)\b",
                re.I,
            )
            words = [
                w
                for _k, label, ws in run["words"]
                for w in [label, *ws]
                if forbidden.search(w) and "not verified" not in w
            ]
            check(
                "no statement wording in the packaged page reads as a trust conclusion",
                words == [],
                str(words),
            )
            rows = {r["name"]: r for r in run["rows"]}
            check(
                "the page's rows carry the verifier's verdicts unchanged",
                all(rows[n]["verdict"] == v for n, v in verdicts.items()),
            )

        # -- the limits
        code, body = base.call(
            url + "api/verify-batch",
            data=batch_body([(f"f{i}", b"{}") for i in range(21)]),
            port=port,
        )
        check(
            "21 files are refused whole",
            code == 413 and json.loads(body).get("error") == "too_many_files",
            str(code),
        )
        one_over = json.dumps(
            {"files": [{"name": "big", "content_b64": b64(b" " * (MB + 1))}]}
        ).encode()
        code, body = base.call(url + "api/verify-batch", data=one_over, port=port)
        r2 = json.loads(body) if code == 200 else {}
        check(
            "a file over 1 MB is refused on its own and says so",
            (code in (200, 413))
            and (
                code == 413
                or (
                    r2["files"][0]["ok"] is False
                    and r2["files"][0]["error"]["error"] == "too_large"
                )
            ),
            str(code),
        )
        eight_plus = json.dumps(
            {"files": [{"name": f"b{i}", "content_b64": b64(b" " * MB)} for i in range(9)]}
        ).encode()
        code = call_big(url, eight_plus, port)
        check(
            "nine 1 MB files (over 8 MB together) are refused whole", code in (413, None), str(code)
        )
        code, _ = base.call(url + "api/status", port=port)
        check("and the portal still answers afterwards", code == 200, str(code))
        code, body = base.call(url + "api/verify-batch", data=b'{"files": []}', port=port)
        check("an empty batch is refused", code == 422, str(code))
        code, body = base.call(url + "api/verify-batch", data=b"not json", port=port)
        check(
            "a request that is not a batch is refused, with no traceback",
            code == 422 and b"Traceback" not in body,
            str(code),
        )
        code, body = base.call(url + "api/verify", data=b"\xff\xfe\x00 not a report", port=port)
        check(
            "a malformed single report is refused safely",
            code in (413, 415, 422) and b"Traceback" not in body,
            str(code),
        )
        try:
            code, body = base.call(url + "api/verify", data=b" " * (MB + 1), port=port)
        except OSError:
            code = None
        check("an oversized single report is refused", code in (413, None), str(code))

        # -- what the application does not offer
        print("--- nothing to decrypt, evaluate or make keys")
        blocked = [
            "api/decrypt",
            "api/evaluate",
            "api/keygen",
            "api/keys",
            "api/audit",
            "v1/audit/fairness",
            "v2/audit/fairness",
            "v1/verify",
            "openapi.json",
            "docs",
            "redoc",
        ]
        codes = {}
        for path in blocked:
            c, _ = base.call(url + path, port=port)
            c2, _ = base.call(url + path, data=b"{}", port=port)
            codes[path] = (c, c2)
        check(
            "none of those paths answers",
            all(a in (404, 405) and b in (404, 405) for a, b in codes.values()),
            str(codes),
        )
        code, html = base.call(url, port=port)
        text = html.decode()
        check(
            "the page says signature verification does not verify an encrypted computation",
            "does not verify that any FHE (encrypted) computation was executed" in text,
        )
        check(
            "the page has the batch picker and the five-statement area",
            'id="batch-files"' in text and 'id="statements"' in text,
        )

        # -- the loaded modules, by the bundled Python itself
        probe = (
            "import json, sys; import regaudit_portal; from regaudit_portal.app import build_app; "
            "from regaudit_portal.samples import load_samples; load_samples(); "
            "print(json.dumps(sorted(m for m in sys.modules if m.split('.')[0] in ('tenseal','openfhe') "
            "or m.startswith('regaudit_fhe.fhe') or m == 'regaudit_fhe.server')))"
        )
        r = subprocess.run(
            [str(py), "-I", "-B", "-c", probe],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        loaded = (
            json.loads(r.stdout.strip().splitlines()[-1])
            if r.returncode == 0
            else ["probe failed: " + r.stderr[-120:]]
        )
        check(
            "importing the portal with the bundled Python loads no encrypted-computation module",
            loaded == [],
            str(loaded),
        )

        # -- retention
        print("--- reports are not kept")
        c, _ = base.call(url + "api/verify-batch", data=batch_body(files), port=port)
        base.call(url + "api/verify", data=reports["marker.json"], port=port)
        kept = []
        for folder in (home, tmp, demo):
            for f in folder.rglob("*"):
                if f.is_file() and f.stat().st_size < 5 * MB:
                    data = f.read_bytes()
                    if marker in data or marker.decode() in b64(data):
                        kept.append(str(f.relative_to(work)))
        check(
            "no copy of an uploaded report exists in the account's home, temporary or setup folders",
            kept == [],
            str(kept[:3]),
        )
        after = snapshot(home) | {"demo/" + x for x in snapshot(demo)}
        # The repeat-check store named in the configuration is the one file checking may create.
        new_files = sorted(f for f in after - home_before if not f.startswith("demo/replay.db"))
        check(
            "checking created no file but the configured repeat-check store",
            new_files == [],
            str(new_files[:5]),
        )
    finally:
        base.stop(p, port, tmp)

    # ----- restart --------------------------------------------------------------------------------------------------------
    print("--- restart and error handling")
    p2, url2 = base.start(launcher, env, ["--", "--config", str(demo / "portal-config.json")])
    port2 = url2.rsplit(":", 1)[1].strip("/")
    try:
        code, body = base.call(url2 + "api/status", port=port2)
        again = json.loads(body)
        check(
            "after a restart the portal is in the same mode",
            code == 200 and again.get("state") == status.get("state"),
            again.get("state", ""),
        )
        code, body = base.call(url2 + "api/verify-batch", data=batch_body(files), port=port2)
        again_entries = json.loads(body).get("files", []) if code == 200 else []
        check(
            "and gives the same verdicts for the same files",
            [e["result"]["verification"]["trust_status"] for e in again_entries if e.get("ok")]
            == list(verdicts.values()),
        )
    finally:
        base.stop(p2, port2, tmp)
    broken = work / "broken-config.json"
    broken.write_text("{not json")
    os.chmod(broken, 0o600)
    p3, url3 = base.start(launcher, env, ["--", "--config", str(broken)])
    port3 = url3.rsplit(":", 1)[1].strip("/")
    try:
        code, body = base.call(url3 + "api/status", port=port3)
        st = json.loads(body)
        check(
            "a damaged configuration is refused, not trusted, and does not crash",
            code == 200 and st.get("ready") is not True,
            st.get("state", ""),
        )
        code, body = base.call(url3 + "api/verify", data=reports[next(iter(reports))], port=port3)
        check(
            "and no verdict is given for your own report under it",
            code != 200 or json.loads(body).get("synthetic_demonstration") is True,
            str(code),
        )
    finally:
        base.stop(p3, port3, tmp)

    print()
    if NOT_RUN:
        print("NOT RUN: " + "; ".join(NOT_RUN))
    print("RESULT " + ("PASS" if base.OK else "FAIL"))
    return 0 if base.OK else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
