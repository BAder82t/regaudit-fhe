"""The portal process cannot write, change or enrol trust: checked by construction, not only by behaviour.

* Every route and method of the portal is on an explicit list.
* The portal process (``regaudit_portal.app`` and everything it imports or calls while serving) never loads the apply
  module or the engine's command-line module that holds ``trust add``.
* No request opens a file for writing in the configuration folder. The one exception is the engine's own replay
  database, which ``replay_mode: record`` writes to by design, and it is named, not left open.
"""

from __future__ import annotations

import ast
import builtins
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import JSON_HEADERS, client_for, fake_home, issuer_signer, plan_request
from regaudit_portal.demo import create

PORTAL = Path(__file__).resolve().parents[1]
PACKAGE = PORTAL / "regaudit_portal"

ALLOWED = {
    ("/", frozenset({"GET", "HEAD"})),
    ("/static/{name}", frozenset({"GET", "HEAD"})),
    ("/static/fonts/{name}", frozenset({"GET", "HEAD"})),
    ("/security", frozenset({"GET", "HEAD"})),
    ("/setup", frozenset({"GET", "HEAD"})),
    ("/setup/plan", frozenset({"GET", "HEAD"})),
    ("/api/setup", frozenset({"GET", "HEAD"})),
    ("/api/status", frozenset({"GET", "HEAD"})),
    ("/api/verify", frozenset({"POST"})),
    ("/api/verify-batch", frozenset({"POST"})),
    ("/api/samples/{sample_id}/verify", frozenset({"POST"})),
    ("/api/setup/plan", frozenset({"POST"})),  # stateless: computes and returns, writes nothing
}


# ----------------------------------------------------------------------------- every route, on a list


@pytest.mark.parametrize("configured", [False, True])
def test_every_route_and_method_of_the_portal_is_on_the_allow_list(
    tmp_path, monkeypatch, configured
):
    fake_home(tmp_path, monkeypatch)
    config = create(tmp_path / "demo") / "portal-config.json" if configured else None
    app = client_for(config).app
    found = {(route.path, frozenset(route.methods)) for route in app.routes}
    assert found == ALLOWED
    assert app.docs_url is None and app.redoc_url is None and app.openapi_url is None


def test_the_only_post_routes_are_the_two_checks_and_the_stateless_plan():
    posts = {path for path, methods in ALLOWED if "POST" in methods}
    assert posts == {
        "/api/verify",
        "/api/verify-batch",
        "/api/samples/{sample_id}/verify",
        "/api/setup/plan",
    }
    assert not any(methods & {"PUT", "DELETE", "PATCH"} for _, methods in ALLOWED)


# ----------------------------------------------------------------------------- the portal never loads the apply code


_SERVE_EVERYTHING = r"""
import json, sys
from pathlib import Path
from fastapi.testclient import TestClient
from regaudit_portal.app import build_app
from regaudit_portal.demo import create
import regaudit_fhe as rf
from regaudit_fhe._keys import spki_fingerprint

root = create(sys.argv[1])
signer = rf.Signer.generate(issuer="Northwind Ltd", key_id="northwind-2026")
plan = {"mode": "first-setup",
        "configuration": {"profile": "confidential", "verifier_id": "v", "max_age_days": 30, "replay_mode": "record"},
        "issuers": [{"issuer": signer.issuer, "key_id": signer.key_id, "public_key": signer.public_key_pem(),
                     "fingerprint": spki_fingerprint(signer.public_key_pem())}]}
headers = {"content-type": "application/json"}
codes = []
for config in (None, str(root / "portal-config.json")):
    client = TestClient(build_app(config, port=8765), base_url="http://127.0.0.1:8765")
    for path in ("/", "/setup", "/setup/plan", "/security", "/api/setup", "/api/status", "/static/app.js",
                 "/static/plan.js", "/static/setup.js", "/static/app.css", "/static/vaultbytes-mark.svg",
                 "/static/fonts/inter-latin-wght-normal.woff2"):
        codes.append(client.get(path).status_code)
        codes.append(client.head(path).status_code)
    codes.append(client.post("/api/samples/trusted/verify").status_code)
    codes.append(client.post("/api/verify", content=(root / "sample-reports" / "1-trusted.json").read_bytes(),
                             headers=headers).status_code)
    codes.append(client.post("/api/setup/plan", content=json.dumps(plan).encode(), headers=headers).status_code)
    plan["mode"] = "add-issuers"; plan.pop("configuration", None)
    codes.append(client.post("/api/setup/plan", content=json.dumps(plan).encode(), headers=headers).status_code)
    codes.append(client.post("/api/setup/plan", content=b"{", headers=headers).status_code)
print(json.dumps({"codes": codes, "modules": sorted(m for m in sys.modules if m.startswith("regaudit"))}))
"""


def test_serving_every_route_never_loads_the_apply_module_or_the_trust_add_code(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    done = subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-c", _SERVE_EVERYTHING, str(tmp_path / "demo")],
        env={**os.environ, "HOME": str(home), "PYTHONPATH": str(PORTAL)},
        cwd=PORTAL, capture_output=True, text=True, timeout=180, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-2000:]
    found = json.loads(done.stdout.strip().splitlines()[-1])
    assert 200 in found["codes"] and 500 not in found["codes"]
    assert "regaudit_portal.app" in found["modules"] and "regaudit_portal.plan" in found["modules"]
    assert "regaudit_portal.admin" not in found["modules"]
    assert "regaudit_fhe.cli" not in found["modules"]


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = ("." * node.level) + (node.module or "")
            found.add(base)
            found |= {
                f"{base}.{alias.name}" if node.module else f"{base}{alias.name}"
                for alias in node.names
            }
        elif isinstance(node, ast.Call) and getattr(
            node.func, "attr", getattr(node.func, "id", "")
        ) in ("import_module", "__import__"):
            found |= {
                a.value
                for a in node.args
                if isinstance(a, ast.Constant) and isinstance(a.value, str)
            }
    return found


def test_only_the_command_line_entry_point_imports_the_apply_module():
    for path in sorted(PACKAGE.glob("*.py")):
        names = _imports(path)
        loads_admin = any(re.search(r"(^|\.)admin($|\.)", name) for name in names)
        loads_cli = any(name.startswith("regaudit_fhe.cli") for name in names)
        assert loads_admin is (path.name == "__main__.py"), path.name
        assert loads_cli is (path.name == "admin.py"), path.name
    main = (PACKAGE / "__main__.py").read_text()
    assert main.count("from . import admin") == 1
    assert '_ADMIN_COMMANDS = ("admin-describe", "admin-apply")' in main
    block = main[main.index("if args.command in _ADMIN_COMMANDS:\n        # Only these two") :]
    assert block.index("from . import admin") < block.index("return admin.run(args)")
    assert main.index("identity = check_engine()") < main.index("from . import admin")


def test_the_code_behind_the_stateless_routes_has_no_call_that_could_write():
    from test_setup import _called_names

    forbidden = {
        "open", "os.open", "os.mkdir", "os.makedirs", "os.remove", "os.unlink", "os.rename", "os.replace", "os.rmdir",
        "os.chmod", "os.fchmod", "os.symlink", "os.link", "os.write", "os.fsync", "SqliteReplayCache",
        "_create_replay_file", "load_portal", "cli.main",
    }  # fmt: skip
    endings = ("write_text", "write_bytes", "touch", "mkdir", "unlink", "rename", "rmdir", "chmod", "symlink_to",
               "writelines", "truncate", "flock")  # fmt: skip
    for name in ("plan.py", "setup.py", "profiles.py", "demonstration.py", "paths.py"):
        source = (PACKAGE / name).read_text()
        called = _called_names(source)
        assert not called & forbidden, (name, called & forbidden)
        assert not [
            c
            for c in called
            if c.endswith(endings) or c.startswith(("shutil.", "tempfile.", "sqlite3."))
        ], name
        imported = _imports(PACKAGE / name)
        assert not imported & {"shutil", "tempfile", "sqlite3", "fcntl", "subprocess"}, (
            name,
            imported,
        )
    route = (PACKAGE / "app.py").read_text()
    called = _called_names(route, {"prepare_plan", "plan_page"})
    assert called == {
        "_unavailable", "request.headers.get", "split", "strip", "_refusal", "limit.allow", "run_in_threadpool",
        "watch.seen", "asyncio.wait_for", "_read_limited", "logger.error", "type", "JSONResponse", "FileResponse",
    }, called  # fmt: skip


# ----------------------------------------------------------------------------- no request writes in the configuration folder


def _guard_folder(monkeypatch: pytest.MonkeyPatch, folder: Path, replay: Path) -> list[str]:
    """Make every way of writing raise when it points into ``folder``, except the engine opening its replay database."""
    folder, replay = folder.resolve(), replay.resolve()
    tried: list[str] = []

    def inside(path) -> bool:
        if isinstance(path, int):
            return False
        place = Path(os.fsdecode(path))
        place = place if place.is_absolute() else Path.cwd() / place
        resolved = place.resolve()
        return resolved == folder or folder in resolved.parents

    def refuse(what: str):
        tried.append(what)
        raise AssertionError(f"{what} was attempted in the configuration folder")

    real_open, real_os_open, real_connect = builtins.open, os.open, sqlite3.connect

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in str(mode) for flag in "wax+") and inside(file):
            refuse(f"open({file!r}, {mode!r})")
        return real_open(file, mode, *args, **kwargs)

    def guarded_os_open(path, flags, *args, dir_fd=None, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND) and (
            dir_fd is not None or inside(path)
        ):
            refuse(f"os.open({path!r})")
        return real_os_open(path, flags, *args, dir_fd=dir_fd, **kwargs)

    def guarded_connect(database, *args, **kwargs):
        if inside(database) and Path(os.fsdecode(database)).resolve() != replay:
            refuse(f"sqlite3.connect({database!r})")
        return real_connect(database, *args, **kwargs)

    def wrap(name: str, real):
        def guarded(*args, **kwargs):
            if (
                kwargs.get("dir_fd") is not None
                or kwargs.get("dst_dir_fd") is not None
                or any(isinstance(a, (str, bytes, os.PathLike)) and inside(a) for a in args)
            ):
                refuse(f"os.{name}")
            return real(*args, **kwargs)

        return guarded

    def wrap_path(name: str, real):
        def guarded(self, *args, **kwargs):
            writing = name != "open" or any(
                flag in str(args[0] if args else kwargs.get("mode", "r")) for flag in "wax+"
            )
            if writing and inside(self):
                refuse(f"Path.{name}")
            return real(self, *args, **kwargs)

        return guarded

    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(io, "open", guarded_open)
    monkeypatch.setattr(os, "open", guarded_os_open)
    for name in (
        "open",
        "write_text",
        "write_bytes",
        "touch",
        "mkdir",
        "unlink",
        "rename",
        "replace",
        "rmdir",
        "chmod",
        "symlink_to",
        "hardlink_to",
    ):
        monkeypatch.setattr(Path, name, wrap_path(name, getattr(Path, name)))
    monkeypatch.setattr(sqlite3, "connect", guarded_connect)
    for name in (
        "mkdir",
        "makedirs",
        "remove",
        "unlink",
        "rename",
        "replace",
        "rmdir",
        "chmod",
        "symlink",
        "link",
        "truncate",
        "utime",
        "chown",
    ):
        monkeypatch.setattr(os, name, wrap(name, getattr(os, name)))
    for name in ("copy", "copy2", "copyfile", "move", "rmtree", "copytree"):
        monkeypatch.setattr(shutil, name, wrap(f"shutil.{name}", getattr(shutil, name)))
    return tried


def _every_request(client, demo: Path) -> list[int]:
    codes = []
    for path in ("/", "/setup", "/setup/plan", "/security", "/api/setup", "/api/status", "/static/app.js",
                 "/static/plan.js", "/static/setup.js", "/static/fonts/inter-latin-wght-normal.woff2"):  # fmt: skip
        codes += [client.get(path).status_code, client.head(path).status_code]
    report = (demo / "sample-reports" / "1-trusted.json").read_bytes()
    codes.append(client.post("/api/verify", content=report, headers=JSON_HEADERS).status_code)
    codes.append(client.post("/api/samples/trusted/verify").status_code)
    good = json.dumps(plan_request([issuer_signer()])).encode()
    adding = json.dumps(plan_request([issuer_signer()], mode="add-issuers")).encode()
    for body in (good, adding, b"{", b"x" * 70000):
        codes.append(client.post("/api/setup/plan", content=body, headers=JSON_HEADERS).status_code)
    return codes


def test_no_request_opens_anything_for_writing_in_the_configuration_folder(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    demo = create(tmp_path / "demo")
    config = demo / "portal-config.json"
    data = json.loads(config.read_text())
    config.write_text(json.dumps({**data, "replay_mode": "record"}))
    client = client_for(config)
    kept = {
        name: ((demo / name).read_bytes(), (demo / name).stat().st_mtime_ns)
        for name in ("portal-config.json", "trust-store.json")
    }
    files_before = {p.name for p in demo.iterdir()}
    tried = _guard_folder(monkeypatch, demo, demo / "replay.db")
    codes = _every_request(client, demo)
    assert tried == [] and 500 not in codes and codes.count(200) > 20, (tried, codes)
    monkeypatch.undo()
    assert {
        name: ((demo / name).read_bytes(), (demo / name).stat().st_mtime_ns) for name in kept
    } == kept
    assert {p.name for p in demo.iterdir()} <= files_before | {"replay.db-journal"}


def test_the_guard_on_the_configuration_folder_is_real(tmp_path, monkeypatch):
    folder = tmp_path / "c"
    folder.mkdir()
    tried = _guard_folder(monkeypatch, folder, folder / "replay.db")
    with pytest.raises(AssertionError):
        (folder / "portal-config.json").write_text("{}")
    with pytest.raises(AssertionError):
        open(folder / "trust-store.json", "w")  # noqa: SIM115 - the attempt is the point
    with pytest.raises(AssertionError):
        os.open(folder / "trust-store.json", os.O_WRONLY | os.O_CREAT, 0o600)
    with pytest.raises(AssertionError):
        sqlite3.connect(folder / "other.db")
    sqlite3.connect(folder / "replay.db").close()  # the named replay database is allowed
    assert len(tried) == 4


# ----------------------------------------------------------------------------- the pages


def test_the_plan_page_script_sends_only_to_the_stateless_route_and_keeps_nothing_in_the_browser():
    script = (PACKAGE / "static" / "plan.js").read_text()
    assert set(re.findall(r'fetch\("([^"]+)"', script)) == {"/api/setup", "/api/setup/plan"}
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "localStorage", "sessionStorage", "indexedDB",
                   "document.cookie", "eval(", "new Function", "admin-apply", "XMLHttpRequest"):  # fmt: skip
        assert banned not in script, banned
    html = (PACKAGE / "static" / "plan.html").read_text()
    assert "<form" not in html and 'type="file"' not in html and "<script>" not in html
    assert html.count("<script ") == 1 and 'src="/static/plan.js"' in html


def test_the_plan_page_says_what_it_does_not_do():
    html = (PACKAGE / "static" / "plan.html").read_text()
    for said in (
        "It writes nothing, keeps nothing and enrols nothing",
        "You apply the plan yourself, outside the browser",
        "Do not copy it from this page",
        "Never paste a private key here",
        "Read the full limitation",
        "Signature verification does not verify that any FHE (encrypted) computation was executed.",
    ):
        assert said in html, said


def test_hidden_means_hidden_even_for_buttons_whose_style_sets_display():
    """A browser run found the plan page's 'Remove this issuer' button visible, and reachable by Tab, with one issuer:
    the style's display for buttons overrode the hidden attribute."""
    css = (PACKAGE / "static" / "app.css").read_text()
    assert "[hidden] { display: none !important; }" in css
    assert re.search(r"(?m)^button \{\n  display: inline-flex;", css), (
        "the rule that needed the override is still there"
    )
    script = (PACKAGE / "static" / "plan.js").read_text()
    assert 'set.querySelector("button").hidden = sets.length === 1;' in script


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is not installed")
def test_the_plan_page_never_sends_a_bare_ed25519_private_key_body():
    """The page's own check, run as the page runs it: a private key body without its header lines is caught too."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    body = "".join(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
        .strip()
        .splitlines()[1:-1]
    )
    public = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    script = (PACKAGE / "static" / "plan.js").read_text()
    line = next(line for line in script.splitlines() if line.startswith("const SECRET = "))
    done = subprocess.run(  # noqa: S603 - Node, evaluating the page's own expression on fixed inputs
        [shutil.which("node"), "-e", line + "\nconst i = JSON.parse(process.argv[1]);"
         "process.stdout.write(JSON.stringify(i.map((t) => SECRET.test(t))));", json.dumps([body, public, "Northwind Ltd"])],
        capture_output=True, text=True, timeout=60, check=True,
    )  # fmt: skip
    assert json.loads(done.stdout) == [True, False, False]
