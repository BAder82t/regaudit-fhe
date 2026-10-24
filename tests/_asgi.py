"""Test helper: an ASGI wrapper that sets the peer address the server sees.

Starlette's TestClient reports the peer as ``("testclient", 50000)``, which is
not an IP address. The development self-signed check looks at the real peer, so
tests that exercise it must say where the peer is.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

LOOPBACK_URL = "http://127.0.0.1:8000"


_UNSET: Any = object()


class WithPeer:
    def __init__(
        self,
        app: Any,
        peer: tuple[str, int] | None = ("127.0.0.1", 50000),
        server: Any = _UNSET,
    ) -> None:
        self.app = app
        self.peer = peer
        self.server = server

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            scope = {**scope, "client": self.peer}
            if self.server is not _UNSET:
                scope["server"] = self.server
        await self.app(scope, receive, send)


def client_for(
    app: Any, *, base_url: str = LOOPBACK_URL, peer=("127.0.0.1", 50000), server: Any = _UNSET
) -> TestClient:
    return TestClient(WithPeer(app, peer, server), base_url=base_url)
