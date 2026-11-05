"""The "Verification unavailable" application. It runs when the engine is missing, cannot be loaded, or fails its check.

It uses the standard library only and imports nothing from the engine or from any module that does, so it starts
whatever state the installation is in. It does no verification and reads no upload: every verification or export
request is refused before its body is touched. It says nothing about configuration, versions or paths. What failed is
printed in the administrator's terminal and never sent to a browser.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import base64
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"  # local only, as the portal itself

_STYLE = (
    ":root{color-scheme:light dark}"
    "body{margin:0 auto;max-width:760px;padding:24px 16px 48px;font:16px/1.5 system-ui,-apple-system,sans-serif;"
    "background:#f6f7f8;color:#1c2126}"
    "h1{margin:0 0 20px;font-size:26px}"
    ".panel{padding:20px;background:#fdf3d8;color:#6b4e00;border:1px solid #d6dbe0;border-radius:8px}"
    ".panel h2{margin:0 0 12px;font-size:18px}.panel p{margin:0 0 10px}.panel p:last-child{margin:0}"
    "@media (prefers-color-scheme:dark){body{background:#15181c;color:#e7eaed}"
    ".panel{background:#3b3013;color:#f0d68c;border-color:#343b43}}"
)
_STYLE_HASH = base64.b64encode(hashlib.sha256(_STYLE.encode("utf-8")).digest()).decode("ascii")
PAGE = (
    '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
    "<title>Evidence Verification Portal</title>\n"
    f"<style>{_STYLE}</style>\n</head>\n<body>\n"
    "<h1>Evidence Verification Portal</h1>\n"
    '<section class="panel" role="alert">\n'
    "<h2>Verification unavailable</h2>\n"
    "<p>The verification engine could not be loaded or its installation could not be validated.</p>\n"
    "<p>No verification was performed.</p>\n"
    "<p>Contact your administrator or follow the installation instructions. "
    "No uploaded report has been accepted or verified.</p>\n"
    "</section>\n</body>\n</html>\n"
).encode()
STATUS = json.dumps({"ready": False, "state": "unavailable"}).encode("utf-8")
_UNAVAILABLE = json.dumps({"error": "unavailable", "state": "unavailable"}).encode("utf-8")
_NOT_FOUND = json.dumps({"error": "not_found"}).encode("utf-8")
_BAD_HOST = json.dumps({"error": "bad_host"}).encode("utf-8")
_BAD_METHOD = json.dumps({"error": "method_not_allowed"}).encode("utf-8")
# What every error raised by the server library itself (an unknown method, a malformed request line, a header that is
# too long, an unsupported protocol version) gets: one fixed body, the same headers as everything else, and no
# software name, version or HTML.
_REFUSED = json.dumps({"error": "request_refused"}).encode("utf-8")
_HEADERS = {
    "Content-Security-Policy": (
        f"default-src 'none'; style-src 'sha256-{_STYLE_HASH}'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
# Paths that would verify or export, a bundled sample included. Any method on them gets the same refusal, and no body
# is read.
_REFUSED_PATHS = frozenset({"/api/verify", "/api/export"})
_REFUSED_PREFIX = "/api/samples/"


class _Handler(BaseHTTPRequestHandler):
    timeout = 10  # a client that stalls does not hold a thread
    protocol_version = "HTTP/1.0"  # one request per connection, so an unread body can never be taken as the next request

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - the name the base class uses
        """Nothing is logged: a request line could carry a path or a report name."""

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """Replace the library's error page, which names the software and its version and has no security headers."""
        self.close_connection = True
        self.request_version = (
            "HTTP/1.0"  # a malformed request line leaves HTTP/0.9, which sends no headers at all
        )
        self._send(
            code, _REFUSED, "application/json", head=getattr(self, "command", None) == "HEAD"
        )

    def _send(
        self, status: int, body: bytes, content_type: str, *, head: bool, allow: str | None = None
    ) -> None:
        self.send_response_only(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in _HEADERS.items():
            self.send_header(name, value)
        if allow is not None:
            self.send_header("Allow", allow)
        self.send_header("Connection", "close")
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _allowed_host(self) -> bool:
        port = self.server.server_address[1]
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        origin = self.headers.get("Origin")
        return self.headers.get("Host") in hosts and (
            origin is None or origin in {f"http://{h}" for h in hosts}
        )

    def _answer(self) -> None:
        method = self.command.upper()
        head = method == "HEAD"
        path = self.path.split("?", 1)[0]
        # A request line with no protocol version, such as "GET /", is refused like any other malformed request.
        if self.request_version == "HTTP/0.9":
            self.send_error(400)
        elif not self._allowed_host():
            self._send(403, _BAD_HOST, "application/json", head=head)
        elif path in _REFUSED_PATHS or path.startswith(_REFUSED_PREFIX):
            self._send(503, _UNAVAILABLE, "application/json", head=head)
        elif path in ("/", "/api/status"):
            if method not in ("GET", "HEAD"):
                self._send(405, _BAD_METHOD, "application/json", head=head, allow="GET, HEAD")
            elif path == "/":
                self._send(200, PAGE, "text/html; charset=utf-8", head=head)
            else:
                self._send(200, STATUS, "application/json", head=head)
        else:
            self._send(404, _NOT_FOUND, "application/json", head=head)

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _answer


class FallbackServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(port: int) -> FallbackServer:
    """Bind the fallback to this computer only. Raises ``OSError`` if the port cannot be bound."""
    return FallbackServer((HOST, port), _Handler)
