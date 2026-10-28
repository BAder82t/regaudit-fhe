"""Resource bounds for the HTTP server: an admission gate.

Both pieces exist because JSON Schema validation of a large array is CPU-bound pure Python that cannot be
interrupted: the request-size limit alone (1 MiB) still allows about 500 000 array elements, which costs
seconds of CPU per request. The structure limits refuse such inputs before any expensive work starts, and
the gate bounds how many expensive operations run (and how many wait) at the same time, refusing the rest
immediately instead of queueing without bound.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import deque

__all__ = ["AdmissionGate", "GateRefused"]


class GateRefused(Exception):
    """The gate could not admit the operation. ``reason`` is ``queue_full`` or ``queue_wait_timeout``."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AdmissionGate:
    """Bounded concurrency with a bounded, time-limited wait queue. Single event loop only.

    At most ``max_running`` holders; at most ``max_waiting`` callers wait, each for at most ``wait_s``.
    Anyone else is refused at once with :class:`GateRefused`. A slot is returned with :meth:`release`,
    which the caller must schedule for when the *work* ends (not when the request ends): a request that
    times out does not free capacity while its thread is still running, so abandoned work cannot pile up.
    """

    def __init__(self, max_running: int, max_waiting: int, wait_s: float) -> None:
        if max_running < 1 or max_waiting < 0 or wait_s < 0:
            raise ValueError("invalid admission gate bounds")
        self.max_running = max_running
        self.max_waiting = max_waiting
        self.wait_s = wait_s
        self.running = 0
        self._waiters: deque[asyncio.Future[None]] = deque()

    @property
    def waiting(self) -> int:
        return len(self._waiters)

    async def acquire(self) -> None:
        if self.running < self.max_running and not self._waiters:
            self.running += 1
            return
        if len(self._waiters) >= self.max_waiting:
            raise GateRefused("queue_full")
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[None] = loop.create_future()
        self._waiters.append(fut)

        def _expire() -> None:
            if not fut.done():
                fut.set_exception(GateRefused("queue_wait_timeout"))

        timer = loop.call_later(self.wait_s, _expire)
        try:
            await fut
        except BaseException:
            granted = fut.done() and not fut.cancelled() and fut.exception() is None
            with contextlib.suppress(ValueError):
                self._waiters.remove(fut)
            if granted:
                # The slot was handed to us just as we were cancelled: give it back.
                self.release()
            raise
        finally:
            timer.cancel()

    def release(self) -> None:
        while self._waiters:
            fut = self._waiters.popleft()
            if not fut.done():
                fut.set_result(None)  # hand the slot over; ``running`` is unchanged
                return
        self.running -= 1
