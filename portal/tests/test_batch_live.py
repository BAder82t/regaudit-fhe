"""A batch against a real server: a client that goes away, a client that is too slow, and what a large upload leaves
open or on disk. The in-process client used elsewhere cannot show these."""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
import regaudit_portal.app as app_module
import regaudit_portal.batch as batch_module
import uvicorn
from helpers import make_portal, signed_report

MB = 1 << 20


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@contextmanager
def serving(config: Path):
    port = free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app_module.build_app(config, port=port),
            host="127.0.0.1",
            port=port,
            log_level="error",
            lifespan="off",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started
    try:
        yield port
    finally:
        server.should_exit = True
        thread.join(10)


def batch_request(
    port: int, reports: list[bytes], *, declared: int | None = None
) -> tuple[bytes, bytes]:
    body = json.dumps(
        {
            "files": [
                {"name": f"r{i}.json", "content_b64": base64.b64encode(r).decode()}
                for i, r in enumerate(reports)
            ]
        }
    ).encode()
    head = (
        f"POST /api/verify-batch HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {declared if declared is not None else len(body)}\r\n\r\n"
    ).encode()
    return head, body


def read_response(sock: socket.socket) -> tuple[int, dict]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    status = int(head.split()[1])
    length = next(
        (
            int(line.split(b":")[1])
            for line in head.split(b"\r\n")
            if line.lower().startswith(b"content-length")
        ),
        0,
    )
    while len(rest) < length:
        chunk = sock.recv(65536)
        if not chunk:
            break
        rest += chunk
    return status, json.loads(rest) if rest else {}


def test_a_batch_over_a_real_connection_matches_the_in_process_answer(tmp_path):
    config, signer = make_portal(tmp_path / "p")
    with serving(config) as port:
        reports = [signed_report(signer) for _ in range(5)]
        head, body = batch_request(port, reports)
        with socket.create_connection(("127.0.0.1", port)) as sock:
            sock.sendall(head + body)
            status, answer = read_response(sock)
    assert status == 200 and answer["summary"]["trusted"] == 5 and answer["complete"] is True


def test_a_client_that_goes_away_stops_the_server_after_the_file_in_progress(tmp_path, monkeypatch):
    config, signer = make_portal(tmp_path / "p")
    settings = json.loads(config.read_text())
    settings["replay_mode"] = "record"
    config.write_text(json.dumps(settings))
    real = app_module._verify_between_checks
    started, finished = [], []

    def slow(*args):
        started.append(time.monotonic())
        time.sleep(0.4)
        try:
            return real(*args)
        finally:
            finished.append(time.monotonic())

    monkeypatch.setattr(app_module, "_verify_between_checks", slow)
    with serving(config) as port:
        reports = [signed_report(signer) for _ in range(12)]
        head, body = batch_request(port, reports)
        sock = socket.create_connection(("127.0.0.1", port))
        sock.sendall(head + body)
        deadline = time.monotonic() + 10
        while not started and time.monotonic() < deadline:
            time.sleep(0.01)
        assert started
        sock.close()  # the client is gone, with the first file being checked
        time.sleep(0.4 * 4)  # long enough for several more, if the server went on
        done = len(finished)
    assert 1 <= done <= 3, done  # the one in progress finished; it did not go on through all twelve
    import sqlite3

    with sqlite3.connect(f"file:{config.parent / 'replay.db'}?mode=ro", uri=True) as conn:
        tables = [r[0] for r in conn.execute("select name from sqlite_master where type='table'")]
        rows = sum(conn.execute(f"select count(*) from {t}").fetchone()[0] for t in tables)  # noqa: S608
    # Exactly the reports whose check completed are recorded: no more, and none for a file that never started.
    assert rows == done


def test_a_client_that_stops_sending_is_cut_off_and_nothing_is_verified(tmp_path, monkeypatch):
    config, signer = make_portal(tmp_path / "p")
    monkeypatch.setattr(app_module, "BODY_TIMEOUT_S", 0.5)
    calls = []
    real = app_module._verify_between_checks
    monkeypatch.setattr(
        app_module, "_verify_between_checks", lambda *a: calls.append(1) or real(*a)
    )
    with serving(config) as port:
        head, body = batch_request(port, [signed_report(signer) for _ in range(3)])
        with socket.create_connection(("127.0.0.1", port)) as sock:
            sock.sendall(head + body[: len(body) // 2])  # then nothing
            sock.settimeout(10)
            status, answer = read_response(sock)
    assert status == 408 and answer["error"] == "too_slow" and calls == []


def test_a_declared_length_over_the_limit_is_refused_without_reading_the_body(tmp_path):
    config, _ = make_portal(tmp_path / "p")
    with serving(config) as port:
        head, _ = batch_request(port, [b"{}"], declared=batch_module.MAX_BODY_BYTES + 1)
        with socket.create_connection(("127.0.0.1", port)) as sock:
            sock.sendall(head)
            sock.settimeout(10)
            status, answer = read_response(sock)
    assert status == 413 and answer["error"] == "too_large"


# ----------------------------------------------------------------------------- disk: a separate process

NO_DISK = r"""
import json, os, socket, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[3])
import regaudit_portal.app as app_module
import uvicorn, threading
config, tmp = Path(sys.argv[1]), Path(sys.argv[2])
s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
server = uvicorn.Server(uvicorn.Config(app_module.build_app(config, port=port), host="127.0.0.1", port=port, log_level="error", lifespan="off"))
threading.Thread(target=server.run, daemon=True).start()
while not server.started: time.sleep(0.02)
print(json.dumps({"port": port}), flush=True)
sys.stdin.readline()
"""


def writable_files(pid: int) -> list[str] | None:
    """Files the process holds open for writing, where that can be listed."""
    if sys.platform.startswith("linux"):
        found = []
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                target = os.readlink(f"/proc/{pid}/fd/{fd}")
                flags = int(
                    Path(f"/proc/{pid}/fdinfo/{fd}").read_text().split("flags:")[1].split()[0], 8
                )
            except (OSError, IndexError, ValueError):
                continue
            if target.startswith("/") and (flags & 3) in (1, 2):
                found.append(target)
        return sorted(found)
    out = subprocess.run(  # noqa: S603
        ["lsof", "-p", str(pid), "-Fan"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    found, access = [], ""
    for line in out.splitlines():
        if line.startswith("a"):
            access = line[1:]
        elif line.startswith("n") and access in ("w", "u") and line[1:].startswith("/"):
            found.append(line[1:])
    return sorted(found)


@pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX process")
def test_a_large_batch_upload_neither_holds_a_file_open_nor_leaves_one_in_the_temporary_folder(
    tmp_path,
):
    config, signer = make_portal(tmp_path / "p")
    scratch = tmp_path / "tmp"
    scratch.mkdir(mode=0o700)
    env = {**os.environ, "TMPDIR": str(scratch), "PYTHONDONTWRITEBYTECODE": "1"}
    root = str(Path(__file__).parents[1])
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-B", "-c", NO_DISK, str(config), str(scratch), root],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        port = json.loads(process.stdout.readline())["port"]
        before = writable_files(process.pid)
        # About 8 MB of reports in a batch, sent slowly in pieces so there is time to look while it is half there.
        reports = [signed_report(signer)] + [b" " * (MB - 8) + b"{}      "] * 7
        head, body = batch_request(port, reports)
        assert len(body) > 9 * MB - MB
        mid = []
        with socket.create_connection(("127.0.0.1", port)) as sock:
            sock.sendall(head)
            step = len(body) // 8
            for i in range(0, len(body), step):
                sock.sendall(body[i : i + step])
                time.sleep(0.05)
                if i == 4 * step:
                    mid = writable_files(process.pid)
            sock.settimeout(30)
            status, answer = read_response(sock)
        after = writable_files(process.pid)
        # The portal's own private bytecode folder (see regaudit_portal/__init__.py) is not an upload and holds only .pyc files.
        leftovers = sorted(
            str(p.relative_to(scratch))
            for p in scratch.rglob("*")
            if p.is_file()
            and not (
                p.suffix == ".pyc"
                and p.relative_to(scratch).parts[0].startswith("regaudit-portal-pyc")
            )
        )
    finally:
        process.stdin.write("\n")
        process.stdin.flush()
        process.wait(timeout=20)
    assert status == 200 and answer["summary"]["total"] == 8
    new_during = [f for f in mid if f not in before]
    new_after = [f for f in after if f not in before]
    # No temporary file of any kind was opened for writing while the body arrived or after the answer.
    assert new_during == [] and new_after == [], (new_during, new_after)
    assert leftovers == []


def test_the_open_file_listing_used_above_really_sees_a_file_open_for_writing(tmp_path):
    target = tmp_path / "held.txt"
    with open(target, "w") as held:
        held.write("x")
        seen = writable_files(os.getpid())
    assert str(target.resolve()) in seen or str(target) in seen
