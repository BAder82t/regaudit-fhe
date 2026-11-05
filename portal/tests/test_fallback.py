"""The "Verification unavailable" application: it starts without the engine, says so, and does nothing else."""

from __future__ import annotations

import ast
import http.client
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from regaudit_portal.fallback import PAGE, STATUS, make_server

import regaudit_fhe

PORTAL_FOLDER = Path(__file__).parents[1]
PACKAGE = Path(regaudit_fhe.__file__).parent
UNAVAILABLE_BODY = {"error": "unavailable", "state": "unavailable"}
PAGE_LINES = (
    "Evidence Verification Portal",
    "Verification unavailable",
    "The verification engine could not be loaded or its installation could not be validated.",
    "No verification was performed.",
    "Contact your administrator or follow the installation instructions. "
    "No uploaded report has been accepted or verified.",
)


def ask(port, method, path, *, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


@pytest.fixture
def fallback():
    server = make_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()
    thread.join(timeout=10)


# ----------------------------------------------------------------------------- what it serves


def test_the_page_says_the_approved_text_in_that_order_under_the_portals_own_name(fallback):
    status, headers, body = ask(fallback, "GET", "/")
    text = body.decode()
    assert status == 200 and headers["Content-Type"] == "text/html; charset=utf-8"
    positions = [text.index(line) for line in PAGE_LINES]
    assert positions == sorted(positions)
    assert (
        "<h1>Evidence Verification Portal</h1>" in text
        and "<h2>Verification unavailable</h2>" in text
    )
    assert not re.search(r"\baudit", text, re.IGNORECASE)
    assert (
        "http://" not in text
        and "https://" not in text
        and "<script" not in text
        and "<link" not in text
    )


def test_head_on_the_page_has_the_same_headers_and_no_body(fallback):
    got = ask(fallback, "GET", "/")
    status, headers, body = ask(fallback, "HEAD", "/")
    assert status == 200 and body == b""
    assert headers["Content-Length"] == got[1]["Content-Length"] == str(len(PAGE))
    assert headers["Content-Type"] == got[1]["Content-Type"]


def test_readiness_is_false_and_says_nothing_else(fallback):
    status, _, body = ask(fallback, "GET", "/api/status")
    assert status == 200 and body == STATUS
    assert json.loads(body) == {"ready": False, "state": "unavailable"}
    assert ask(fallback, "HEAD", "/api/status")[2] == b""


@pytest.mark.parametrize("path", ["/api/verify", "/api/export"])
@pytest.mark.parametrize("method", ["POST", "GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def test_verification_and_export_do_not_function_for_any_method(fallback, path, method):
    report = b'{"anything": "an upload"}'
    status, _, body = ask(
        fallback,
        method,
        path,
        body=None if method in ("GET", "HEAD") else report,
        headers={"Content-Type": "application/json"},
    )
    assert status == 503
    assert body == b"" if method == "HEAD" else json.loads(body) == UNAVAILABLE_BODY


def test_an_upload_is_never_read(fallback):
    """The server answers before the body arrives. If it tried to read 1 GB it would wait here until the timeout."""
    with socket.create_connection(("127.0.0.1", fallback), timeout=5) as raw:
        raw.sendall(
            f"POST /api/verify HTTP/1.1\r\nHost: 127.0.0.1:{fallback}\r\nContent-Type: application/json\r\n"
            "Content-Length: 1000000000\r\n\r\n".encode()
        )
        answer = b"".join(
            iter(lambda: raw.recv(65536), b"")
        )  # until the server closes the connection
    assert answer.startswith(b"HTTP/1.0 503") and b'"state": "unavailable"' in answer


def test_other_paths_and_methods_get_plain_refusals(fallback):
    for path in (
        "/static/app.js",
        "/static/app.css",
        "/security",
        "/anything",
        "/api/verify/x",
        "/docs",
        "/openapi.json",
    ):
        status, _, body = ask(fallback, "GET", path)
        assert status == 404 and json.loads(body) == {"error": "not_found"}, path
    for path in ("/", "/api/status"):
        status, headers, body = ask(fallback, "POST", path, body=b"{}")
        assert (
            status == 405
            and headers["Allow"] == "GET, HEAD"
            and json.loads(body) == {"error": "method_not_allowed"}
        )
    assert ask(fallback, "TRACE", "/")[0] == 501


# ----------------------------------------------------------------------------- errors the server library raises itself


def raw_exchange(port: int, payload: bytes) -> tuple[int, dict[str, str], bytes]:
    """Send bytes as they are and read until the server closes the connection."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        raw.sendall(payload)
        answer = b"".join(iter(lambda: raw.recv(65536), b""))
    head, _, body = answer.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {
        k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in lines[1:])
    }
    return int(lines[0].split()[1]), headers, body


def _unusual_requests(port: int) -> dict[str, tuple[bytes, int]]:
    host = f"Host: 127.0.0.1:{port}\r\n"
    many = "".join(f"X-{n}: 1\r\n" for n in range(150))
    return {
        "unknown method FOO": (f"FOO / HTTP/1.1\r\n{host}\r\n".encode(), 501),
        "TRACE": (f"TRACE / HTTP/1.1\r\n{host}\r\n".encode(), 501),
        "request line with junk after the version": (b"GET / HTTP/1.1 junk\r\n\r\n", 400),
        "one word": (b"GARBAGE\r\n\r\n", 400),
        "request line with no protocol version": (b"GET /\r\n\r\n", 400),
        "no protocol version, a path the page serves": (b"GET /api/status\r\n\r\n", 400),
        "no protocol version, with headers": (f"GET /\r\n{host}\r\n".encode(), 400),
        "old-style request that is not GET": (b"POST /\r\n\r\n", 400),
        "header that is too long": (
            f"GET / HTTP/1.1\r\n{host}X-Big: ".encode() + b"a" * 70000 + b"\r\n\r\n",
            431,
        ),
        "too many headers": (f"GET / HTTP/1.1\r\n{host}{many}\r\n".encode(), 431),
        "request line that is too long": (b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n", 414),
        "protocol version 2": (f"GET / HTTP/2.0\r\n{host}\r\n".encode(), 505),
    }


def _assert_the_same_headers_as_the_page(
    headers: dict[str, str], reference: dict[str, str], where: str
) -> None:
    assert "server" not in headers and "date" not in headers, (
        where,
        headers,
    )  # no software name or version
    for name in (
        "content-security-policy",
        "x-content-type-options",
        "referrer-policy",
        "cache-control",
    ):
        assert headers[name] == reference[name], (where, name)


def test_every_error_the_server_library_raises_gets_the_page_headers_and_a_fixed_body(fallback):
    page_headers = {k.lower(): v for k, v in ask(fallback, "GET", "/")[1].items()}
    for name, (payload, expected) in _unusual_requests(fallback).items():
        status, headers, body = raw_exchange(fallback, payload)
        assert status == expected, (name, status)
        _assert_the_same_headers_as_the_page(headers, page_headers, name)
        assert headers["content-type"] == "application/json" and headers["connection"] == "close", (
            name
        )
        assert body == b'{"error": "request_refused"}' and headers["content-length"] == str(
            len(body)
        ), name
        for word in ("Python", "BaseHTTP", "<html", "Error response", "Error code", "explain"):
            assert word not in body.decode(), (name, word)


def test_an_error_answer_to_a_head_request_has_the_headers_and_no_body(fallback):
    host = f"Host: 127.0.0.1:{fallback}\r\n"
    status, headers, body = raw_exchange(
        fallback, f"HEAD / HTTP/1.1\r\n{host}X-Big: ".encode() + b"a" * 70000 + b"\r\n\r\n"
    )
    assert (
        status == 431
        and body == b""
        and "server" not in headers
        and headers["x-content-type-options"] == "nosniff"
    )


def test_every_status_the_fallback_can_send_has_the_same_security_headers_and_no_software_name(
    fallback,
):
    page_headers = {k.lower(): v for k, v in ask(fallback, "GET", "/")[1].items()}
    seen = set()
    host = f"Host: 127.0.0.1:{fallback}\r\n"
    requests = {
        "page": f"GET / HTTP/1.1\r\n{host}\r\n",
        "status": f"GET /api/status HTTP/1.1\r\n{host}\r\n",
        "refused host": "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n",
        "not found": f"GET /nothing HTTP/1.1\r\n{host}\r\n",
        "wrong method": f"POST / HTTP/1.1\r\n{host}Content-Length: 0\r\n\r\n",
        "verify": f"POST /api/verify HTTP/1.1\r\n{host}Content-Length: 0\r\n\r\n",
        "export": f"POST /api/export HTTP/1.1\r\n{host}Content-Length: 0\r\n\r\n",
    }
    for name, text in requests.items():
        status, headers, _ = raw_exchange(fallback, text.encode())
        seen.add(status)
        _assert_the_same_headers_as_the_page(headers, page_headers, name)
    for name, (payload, _) in _unusual_requests(fallback).items():
        status, headers, _ = raw_exchange(fallback, payload)
        seen.add(status)
        _assert_the_same_headers_as_the_page(headers, page_headers, name)
    assert seen == {200, 400, 403, 404, 405, 414, 431, 501, 503, 505}


# ----------------------------------------------------------------------------- who may talk to it


def test_a_foreign_host_or_origin_is_refused_everywhere(fallback):
    for path in ("/", "/api/status", "/api/verify", "/api/export"):
        for headers in (
            {"Host": "evil.example"},
            {"Host": "evil.example:80"},
            {"Host": f"127.0.0.1:{fallback + 1}"},
            {"Host": f"127.0.0.1:{fallback}", "Origin": "https://evil.example"},
            {"Host": f"localhost:{fallback}", "Origin": f"http://evil.example:{fallback}"},
        ):
            status, _, body = ask(
                fallback, "POST" if path.startswith("/api/v") else "GET", path, headers=headers
            )
            assert status == 403 and json.loads(body) == {"error": "bad_host"}, (path, headers)
    assert ask(fallback, "GET", "/", headers={"Host": f"localhost:{fallback}"})[0] == 200
    assert (
        ask(
            fallback,
            "GET",
            "/",
            headers={"Host": f"127.0.0.1:{fallback}", "Origin": f"http://localhost:{fallback}"},
        )[0]
        == 200
    )


def test_it_listens_on_this_computer_only(fallback):
    server = make_server(0)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()


def test_every_answer_carries_the_security_headers_and_a_style_hash_instead_of_unsafe_inline(
    fallback,
):
    import base64
    import hashlib

    for method, path in (
        ("GET", "/"),
        ("GET", "/api/status"),
        ("POST", "/api/verify"),
        ("GET", "/nope"),
    ):
        _, headers, _ = ask(fallback, method, path)
        policy = headers["Content-Security-Policy"]
        assert (
            "default-src 'none'" in policy and "unsafe" not in policy and "script-src" not in policy
        )
        assert (
            headers["X-Content-Type-Options"] == "nosniff"
            and headers["Cache-Control"] == "no-store"
        )
        assert "Server" not in headers and "Date" not in headers  # no server software or version
    style = re.search(rb"<style>(.*?)</style>", PAGE, re.S).group(1)
    expected = base64.b64encode(hashlib.sha256(style).digest()).decode()
    assert f"'sha256-{expected}'" in ask(fallback, "GET", "/")[1]["Content-Security-Policy"]


def test_no_body_it_sends_names_a_path_a_version_or_any_configuration(fallback, tmp_path):
    bodies = [
        ask(fallback, "GET", "/")[2],
        ask(fallback, "GET", "/api/status")[2],
        ask(fallback, "POST", "/api/verify", body=b"{}")[2],
        ask(fallback, "POST", "/api/export", body=b"{}")[2],
        ask(fallback, "GET", "/missing")[2],
        ask(fallback, "POST", "/", body=b"{}")[2],
        ask(fallback, "GET", "/", headers={"Host": "evil.example"})[2],
    ]
    forbidden = (
        str(tmp_path), str(PORTAL_FOLDER), str(PACKAGE), os.getcwd(), sys.prefix, "0.2", "regaudit_fhe", "Traceback",
        "trust-store", "trust_store", "replay", "profile", "verifier_id", "ENGINE_", ".py", "/Users", "/private",
    )  # fmt: skip
    for body in bodies:
        text = body.decode()
        for word in forbidden:
            assert word not in text, (word, text[:80])


# ----------------------------------------------------------------------------- it needs nothing the engine needs


def test_the_fallback_and_the_engine_check_use_the_standard_library_only():
    for name in ("fallback.py", "engine.py"):
        tree = ast.parse((PORTAL_FOLDER / "regaudit_portal" / name).read_text())
        modules = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module
        }
        assert modules <= set(sys.stdlib_module_names), (
            name,
            modules - set(sys.stdlib_module_names),
        )
    main = (PORTAL_FOLDER / "regaudit_portal" / "__main__.py").read_text()
    top = [line for line in main.splitlines() if line.startswith(("import ", "from "))]
    assert any(line.startswith("from .engine import") for line in top)
    assert all(
        not any(x in line for x in ("regaudit_fhe", ".config", ".app", ".demo")) for line in top
    ), top


def test_they_import_with_the_engine_and_its_libraries_made_unimportable():
    code = (
        "import sys\n"
        "for name in ('regaudit_fhe', 'numpy', 'fastapi', 'uvicorn', 'cryptography', 'jsonschema', 'pydantic'):\n"
        "    sys.modules[name] = None\n"
        "import regaudit_portal.fallback, regaudit_portal.engine, regaudit_portal.__main__\n"
        "server = regaudit_portal.fallback.make_server(0)\n"
        "print(regaudit_portal.engine.check_engine().reason, server.server_address[0])\n"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=60, check=False, env=dict(os.environ, PYTHONPATH=str(PORTAL_FOLDER)),
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["ENGINE_MISSING", "127.0.0.1"]


# ----------------------------------------------------------------------------- serve starts it by itself


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _damaged_copy(tmp_path: Path, how: str) -> Path:
    copy = tmp_path / "regaudit_fhe"
    shutil.copytree(PACKAGE, copy, ignore=shutil.ignore_patterns("__pycache__"))
    if how == "modified":
        with (copy / "verification.py").open("a") as handle:
            handle.write("\n# changed\n")
    elif how == "wrong-version":
        init = copy / "__init__.py"
        init.write_text(init.read_text().replace('__version__ = "0.2.1"', '__version__ = "0.2.2"'))
    elif how == "missing-file":
        (copy / "verification.py").unlink()
    elif how == "unreadable":
        (copy / "trust.py").chmod(0)
    return copy


class Running:
    """A ``serve`` process. It prints its "open http" line only once it is listening, so reading that line is the wait."""

    def __init__(
        self, tmp_path: Path, args: list[str], *, python_args=None, path_first: Path | None = None
    ):
        self.port = _free_port()
        self.errors = tmp_path / f"stderr-{self.port}.txt"
        # The portal's private bytecode folder is made in the temporary directory. Giving each process its own lets the
        # tests see whether it was removed, and leaves nothing behind in the real one.
        self.temp = tmp_path / f"temp-{self.port}"
        self.temp.mkdir()
        paths = [str(path_first)] if path_first else []
        env = dict(
            os.environ,
            PYTHONPATH=os.pathsep.join([*paths, str(PORTAL_FOLDER)]),
            TMPDIR=str(self.temp),
        )
        command = [
            sys.executable,
            *(python_args or ["-m", "regaudit_portal"]),
            *args,
            "--port",
            str(self.port),
        ]
        self.process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            command,
            stdout=subprocess.PIPE,
            stderr=self.errors.open("w"),
            text=True,
            env=env,
            cwd=tmp_path,
        )
        watchdog = threading.Timer(90, self.process.kill)
        watchdog.start()
        self.lines = []
        try:
            for line in self.process.stdout:  # type: ignore[union-attr]
                self.lines.append(line.rstrip())
                if line.startswith("open http"):
                    break
        finally:
            watchdog.cancel()

    @property
    def stderr(self) -> str:
        return self.errors.read_text()

    def leftovers(self) -> list[str]:
        """What this process left in its temporary directory. After any normal stop it is nothing."""
        return sorted(path.name for path in self.temp.iterdir())

    def stop(self, sig: int = signal.SIGTERM) -> int:
        """Send a signal as ``kill`` or Ctrl-C would, wait for the exit, and return the exit code."""
        if self.process.poll() is None:
            self.process.send_signal(sig)
        code = self.process.wait(timeout=30)
        if self.process.stdout and not self.process.stdout.closed:
            self.lines += (
                self.process.stdout.read().splitlines()
            )  # whatever was printed after the start line
            self.process.stdout.close()
        return code

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_exc):
        self.stop()
        if exc_type is None:
            assert self.leftovers() == [], "the portal left its private bytecode folder behind"


def _assert_unavailable(running: Running, tmp_path: Path, detail_words: tuple[str, ...]):
    assert running.process.poll() is None, running.stderr
    assert any(line.startswith("open http") and "unavailable" in line for line in running.lines), (
        running.lines
    )
    status, _, page = ask(running.port, "GET", "/")
    assert (
        status == 200
        and b"Verification unavailable" in page
        and b"No verification was performed." in page
    )
    assert b"Choose a signed report" not in page
    assert ask(running.port, "GET", "/api/status")[2] == STATUS
    sample = b'{"schema": "regaudit-fhe.report.v2"}'
    verify = ask(
        running.port,
        "POST",
        "/api/verify",
        body=sample,
        headers={"Content-Type": "application/json"},
    )
    export = ask(
        running.port,
        "POST",
        "/api/export",
        body=sample,
        headers={"Content-Type": "application/json"},
    )
    assert verify[0] == export[0] == 503 and json.loads(verify[2]) == UNAVAILABLE_BODY
    for body in (page, verify[2], export[2]):
        assert str(tmp_path).encode() not in body and b"Traceback" not in body
    terminal = running.stderr
    assert terminal.startswith("not usable: verification unavailable: ")
    for word in detail_words:
        assert word in terminal, (word, terminal)
    assert "Traceback" not in terminal


@pytest.mark.parametrize(
    ("how", "reason"),
    [
        ("modified", "ENGINE_NOT_RECOGNISED"),
        ("wrong-version", "ENGINE_NOT_RECOGNISED"),
        ("missing-file", "ENGINE_NOT_RECOGNISED"),
        pytest.param(
            "unreadable",
            "ENGINE_UNREADABLE",
            marks=pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file"),
        ),
    ],
)
def test_serve_starts_the_fallback_by_itself_when_the_installed_engine_is_damaged(
    tmp_path, demo, how, reason
):
    copy = _damaged_copy(tmp_path, how)
    try:
        with Running(
            tmp_path, ["serve", "--config", str(demo / "portal-config.json")], path_first=tmp_path
        ) as running:
            _assert_unavailable(running, tmp_path, (reason, str(copy)))
    finally:
        (copy / "trust.py").chmod(0o600)


def test_serve_starts_the_fallback_when_the_engine_is_not_installed(tmp_path, demo):
    script = (
        "import sys; sys.modules['regaudit_fhe'] = None\n"
        "from regaudit_portal.__main__ import main\n"
        "raise SystemExit(main(sys.argv[1:]))"
    )
    with Running(
        tmp_path,
        ["serve", "--config", str(demo / "portal-config.json")],
        python_args=["-c", script],
    ) as running:
        _assert_unavailable(running, tmp_path, ("ENGINE_MISSING", "not installed"))


def test_serve_starts_the_fallback_when_the_integrity_computation_fails(tmp_path, demo):
    script = (
        "import sys\n"
        "import regaudit_portal.engine as engine\n"
        "def crash(_folder): raise RuntimeError('hash failed')\n"
        "engine.files_digest = crash\n"
        "from regaudit_portal.__main__ import main\n"
        "raise SystemExit(main(sys.argv[1:]))"
    )
    with Running(
        tmp_path,
        ["serve", "--config", str(demo / "portal-config.json")],
        python_args=["-c", script],
    ) as running:
        _assert_unavailable(running, tmp_path, ("ENGINE_CHECK_FAILED", "RuntimeError: hash failed"))


def test_the_fallback_cannot_bind_a_port_that_is_taken_and_then_says_nothing_to_open(
    tmp_path, demo
):
    _damaged_copy(tmp_path, "modified")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(tmp_path), str(PORTAL_FOLDER)]))
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        out = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [
                sys.executable, "-m", "regaudit_portal", "serve", "--config", str(demo / "portal-config.json"),
                "--port", str(taken.getsockname()[1]),
            ],
            capture_output=True, text=True, timeout=60, check=False, env=env, cwd=tmp_path,
        )  # fmt: skip
    assert out.returncode == 1 and "open http" not in out.stdout
    assert "cannot listen on 127.0.0.1" in out.stderr


@pytest.mark.parametrize("command", ["check-config", "demo-setup"])
def test_the_other_commands_stop_with_exit_code_3_and_no_traceback(tmp_path, demo, command):
    _damaged_copy(tmp_path, "modified")
    args = {
        "check-config": ["check-config", "--config", str(demo / "portal-config.json")],
        "demo-setup": ["demo-setup", str(tmp_path / "demo-out")],
    }[command]
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(tmp_path), str(PORTAL_FOLDER)]))
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "regaudit_portal", *args],
        capture_output=True, text=True, timeout=60, check=False, env=env, cwd=tmp_path,
    )  # fmt: skip
    assert out.returncode == 3, out.stderr
    assert out.stderr.startswith("not usable: verification unavailable: ENGINE_NOT_RECOGNISED")
    assert (
        "Traceback" not in out.stderr + out.stdout and "pip install --force-reinstall" in out.stderr
    )
    assert not (tmp_path / "demo-out").exists()


# ----------------------------------------------------------------------------- stopping it


def _stopped_cleanly(running: Running, code: int, expected_code: int) -> None:
    assert code == expected_code, (code, running.stderr)
    assert running.lines[-1] == "the portal has stopped.", running.lines
    assert running.stderr == "" or running.stderr.startswith(
        "not usable: verification unavailable"
    ), running.stderr
    assert "Traceback" not in running.stderr and "KeyboardInterrupt" not in running.stderr
    assert running.leftovers() == [], "the private bytecode folder was left behind"


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM], ids=["ctrl-c", "kill"])
def test_the_portal_stops_cleanly_on_ctrl_c_and_on_kill_and_removes_its_bytecode_folder(
    tmp_path, demo, sig
):
    with Running(tmp_path, ["serve", "--config", str(demo / "portal-config.json")]) as running:
        assert running.process.poll() is None, running.stderr
        assert running.leftovers() != [], (
            "the folder exists while the portal runs, so the check below means something"
        )
        assert json.loads(ask(running.port, "GET", "/api/status")[2])["ready"] is True
        code = running.stop(sig)
        _stopped_cleanly(running, code, 0)
        assert running.stderr == ""


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM], ids=["ctrl-c", "kill"])
def test_the_unavailable_page_stops_cleanly_too_and_exits_with_3(tmp_path, demo, sig):
    _damaged_copy(tmp_path, "modified")
    with Running(
        tmp_path, ["serve", "--config", str(demo / "portal-config.json")], path_first=tmp_path
    ) as running:
        assert running.leftovers() != []
        _stopped_cleanly(running, running.stop(sig), 3)


def test_a_hard_kill_is_the_one_stop_that_can_leave_the_folder_and_the_documents_say_so(
    tmp_path, demo
):
    """SIGKILL cannot be caught. The documents say so instead of claiming it is handled."""
    with Running(tmp_path, ["serve", "--config", str(demo / "portal-config.json")]) as running:
        running.process.send_signal(signal.SIGKILL)
        running.process.wait(timeout=30)
        assert running.process.returncode == -signal.SIGKILL
        assert len(running.leftovers()) == 1
        for folder in running.temp.iterdir():  # the test removes what it caused
            shutil.rmtree(folder)
    for name in ("README.md", "SECURITY.md"):
        text = (PORTAL_FOLDER / name).read_text()
        assert "killed hard" in text and "SIGKILL" in text and "temporary folder" in text, name


# ----------------------------------------------------------------------------- a file changed during a slow upload


def test_an_engine_file_changed_while_a_slow_upload_is_arriving_gives_no_verdict(tmp_path, demo):
    """The engine passes when the upload starts and has been changed before the last byte arrives."""
    copy = tmp_path / "regaudit_fhe"
    shutil.copytree(
        PACKAGE, copy, ignore=shutil.ignore_patterns("__pycache__")
    )  # identical, so the portal accepts it
    report = (demo / "sample-reports" / "1-trusted.json").read_bytes()
    half = len(report) // 2
    head = (
        f"POST /api/verify HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(report)}\r\n\r\n"
    )
    with Running(
        tmp_path, ["serve", "--config", str(demo / "portal-config.json")], path_first=tmp_path
    ) as running:
        assert running.process.poll() is None, running.stderr
        assert json.loads(ask(running.port, "GET", "/api/status")[2])["ready"] is True
        with socket.create_connection(("127.0.0.1", running.port), timeout=30) as slow:
            slow.sendall(head.format(port=running.port).encode() + report[:half])
            # Another request on its own connection comes back only after this one has been taken up by the server.
            assert json.loads(ask(running.port, "GET", "/api/status")[2])["ready"] is True
            with (copy / "verification.py").open("a") as handle:
                handle.write("\n# changed while the upload was arriving\n")
            slow.sendall(report[half:])
            answer = b"".join(iter(lambda: slow.recv(65536), b""))
        status_line, _, rest = answer.partition(b"\r\n")
        body = rest.partition(b"\r\n\r\n")[2]
        assert b" 503 " in status_line, answer[:200]
        assert json.loads(body)["state"] == "unavailable"
        assert b'"verification"' not in body and b"TRUSTED" not in body and b'"engine"' not in body
        assert str(tmp_path).encode() not in answer
        assert json.loads(ask(running.port, "GET", "/api/status")[2]) == {
            "ready": False,
            "state": "unavailable",
        }
        assert "ENGINE_NOT_RECOGNISED" in running.stderr


# ----------------------------------------------------------------------------- recovery


def test_after_the_right_engine_is_back_and_the_portal_restarted_the_normal_portal_works(
    tmp_path, demo
):
    config = str(demo / "portal-config.json")
    copy = _damaged_copy(tmp_path, "modified")
    with Running(tmp_path, ["serve", "--config", config], path_first=tmp_path) as broken:
        assert ask(broken.port, "GET", "/api/status")[2] == STATUS
        status, _, body = ask(
            broken.port, "POST", "/api/verify",
            body=(demo / "sample-reports" / "1-trusted.json").read_bytes(), headers={"Content-Type": "application/json"},
        )  # fmt: skip
        assert status == 503 and b"verification" not in body
    shutil.rmtree(copy)  # the correct engine is the installed one again
    with Running(tmp_path, ["serve", "--config", config]) as normal:
        assert normal.process.poll() is None, normal.stderr
        assert any(
            "engine: Verdicts are produced by regaudit-fhe 0.2.1" in line for line in normal.lines
        )
        assert any(
            line.startswith("open http") and "unavailable" not in line for line in normal.lines
        )
        status = json.loads(ask(normal.port, "GET", "/api/status")[2])
        assert (
            status["ready"] is True
            and status["engine"]["version"] == "0.2.1"
            and "state" not in status
        )
        body = ask(
            normal.port, "POST", "/api/verify",
            body=(demo / "sample-reports" / "1-trusted.json").read_bytes(), headers={"Content-Type": "application/json"},
        )  # fmt: skip
        assert body[0] == 200 and json.loads(body[2])["verification"]["trust_status"] == "TRUSTED"
        assert b"Choose a signed report" in ask(normal.port, "GET", "/")[2]
        assert "not usable" not in normal.stderr


# ----------------------------------------------------------------------------- the normal page knows the state too


def test_the_unavailable_panel_and_the_saving_check_are_on_the_normal_page():
    html = (PORTAL_FOLDER / "regaudit_portal" / "static" / "index.html").read_text()
    panel = html[
        html.index('<section id="unavailable"') : html.index(
            "</section>", html.index('<section id="unavailable"')
        )
    ]
    for line in (
        "Verification unavailable",
        "The verification engine could not be loaded or its installation could not be validated.",
        "No verification was performed.",
        "Contact your administrator or follow the installation instructions. "
        "No uploaded report has been accepted or verified.",
    ):
        assert line in panel
    script = (PORTAL_FOLDER / "regaudit_portal" / "static" / "app.js").read_text()
    assert 'body.state === "unavailable"' in script
    saving = script[
        script.index("async function download()") : script.index("async function start()")
    ]
    assert (
        'fetch("/api/status")' in saving and "status.ready" in saving
    )  # no export unless the engine passes now


def test_when_the_page_learns_the_engine_has_stopped_passing_it_clears_every_identity_and_policy_text():
    script = (PORTAL_FOLDER / "regaudit_portal" / "static" / "app.js").read_text()
    body = script[script.index("function unavailable()") : script.index("function fail(")]
    for hidden in ("upload", "result", "failure", "not-ready", "record-notice", "saved"):
        assert f'show("{hidden}", false)' in body, hidden
    assert 'show("unavailable", true)' in body
    cleared = re.search(r"for \(const id of \[(.*?)\]\)", body, re.S)
    assert cleared, "the texts are cleared by id"
    ids = set(re.findall(r'"([^"]+)"', cleared.group(1)))
    assert {
        "policy",
        "claim",
        "engine-summary",
        "engine-scope",
        "check-key",
        "raw",
        "verdict",
        "result-file",
    } <= ids
    assert '$(id).textContent = ""' in body
    html = (PORTAL_FOLDER / "regaudit_portal" / "static" / "index.html").read_text()
    for name in ids:
        assert f'id="{name}"' in html, name
