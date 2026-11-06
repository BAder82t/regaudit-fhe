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

# The look of the portal's own pages, with no file to fetch: the system's fonts instead of the bundled ones, and the
# same colours, spacing and shapes. The page is allowed this one inline style and nothing else, by its hash.
_STYLE = (
    ":root{color-scheme:light}*{box-sizing:border-box}"
    "body{margin:0;min-height:100vh;display:flex;flex-direction:column;background:#fff;color:#1a1a1a;"
    "font:16px/1.7 system-ui,-apple-system,'Segoe UI',sans-serif}"
    ".bar{background:#fff;border-bottom:2px solid #06f}"
    ".wrap{width:100%;max-width:924px;margin:0 auto;padding:0 32px}"
    ".bar .wrap{display:flex;align-items:center;min-height:64px}"
    ".logo{display:inline-flex;align-items:center;gap:8px;"
    "font:700 24px/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:1px}"
    ".logo svg{width:40px;height:40px}"
    "main{flex:1 0 auto;width:100%;max-width:924px;margin:0 auto;padding:32px 32px 64px}"
    "h1{margin:0 0 8px;font:700 clamp(32px,5vw,48px)/1.2 system-ui,-apple-system,'Segoe UI',sans-serif;"
    "letter-spacing:-.02em}"
    ".rule{width:80px;height:3px;margin:0 0 32px;background:linear-gradient(135deg,#4a90e2,#4dd0e1)}"
    ".panel{padding:32px;background:#fff3d6;color:#6b4200;border:1px solid #6b4200;border-left-width:6px;"
    "border-radius:8px}"
    ".panel h2{margin:0 0 16px;font:700 24px/1.2 system-ui,-apple-system,'Segoe UI',sans-serif}"
    ".panel p{margin:0 0 16px}.panel p:last-child{margin:0}"
    "footer{position:relative;padding:32px 0;background:#f7f9fc;color:#4a5568;font-size:14px;line-height:1.6}"
    "footer:before{content:'';position:absolute;top:0;left:0;right:0;height:3px;"
    "background:linear-gradient(90deg,#4dd0e1,#4a90e2,#4dd0e1)}"
    "footer p{margin:0}"
    "@media (max-width:600px){.wrap,main{padding-left:16px;padding-right:16px}.panel{padding:16px}"
    ".logo{font-size:20px}h1{font-size:32px}}"
)
_STYLE_HASH = base64.b64encode(hashlib.sha256(_STYLE.encode("utf-8")).digest()).decode("ascii")
# The VaultBytes mark, drawn here so the page needs no file of any kind.
_MARK = (
    '<svg viewBox="0 0 32 32" width="40" height="40" fill="none" aria-hidden="true" focusable="false">'
    '<rect width="32" height="32" fill="#fff"/>'
    '<rect x="4" y="4" width="24" height="24" stroke="#06f" stroke-width="2"/>'
    '<rect x="8" y="8" width="16" height="16" stroke="#06f" stroke-width="2"/>'
    '<circle cx="16" cy="16" r="4" fill="#06f"/>'
    '<path d="M16 0v4M16 28v4M0 16h4M28 16h4" stroke="#06f" stroke-width="2"/></svg>'
)
PAGE = (
    '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
    "<title>Evidence Verification Portal</title>\n"
    f"<style>{_STYLE}</style>\n</head>\n<body>\n"
    f'<header class="bar"><div class="wrap"><span class="logo">{_MARK}VaultBytes</span></div></header>\n'
    "<main>\n"
    "<h1>Evidence Verification Portal</h1>\n"
    '<div class="rule"></div>\n'
    '<section class="panel" role="alert">\n'
    "<h2>Verification unavailable</h2>\n"
    "<p>The verification engine could not be loaded or its installation could not be validated.</p>\n"
    "<p>No verification was performed.</p>\n"
    "<p>Contact your administrator or follow the installation instructions. "
    "No uploaded report has been accepted or verified.</p>\n"
    "</section>\n</main>\n"
    '<footer><div class="wrap"><p>&copy; 2026 VaultBytes Innovations Ltd.</p></div></footer>\n'
    "</body>\n</html>\n"
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
