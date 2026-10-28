"""Resource bounds for the HTTP server: input structure limits and an admission gate.

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
from dataclasses import dataclass
from typing import Any

__all__ = [
    "AdmissionGate",
    "GateRefused",
    "InputLimitError",
    "InputLimits",
    "check_input_bounds",
]


@dataclass(frozen=True)
class InputLimits:
    """Structural limits applied to a parsed audit payload before schema validation.

    ``max_array_elements`` bounds every JSON array (and the member count of every object) on its own,
    ``max_total_elements`` bounds the sum of all array lengths in the payload, and ``max_depth`` bounds the
    nesting (the document root is depth 1). Two further limits bound *work*, not size, for the two
    primitives whose cost is super-linear in the input: ``max_concordance_samples`` (the concordance
    circuit does O(n^2) vector work) and ``max_disagreement_models`` (O(M^2) pairwise terms). The defaults
    and their derivation are in docs/DEPLOYMENT.md, "Resource bounds".

    Every limit must be a positive integer: a value that would disable a bound is refused, not accepted.
    """

    max_array_elements: int = 131072
    max_total_elements: int = 524288
    max_depth: int = 4
    max_concordance_samples: int = 8192
    max_disagreement_models: int = 32

    def __post_init__(self) -> None:
        for name in (
            "max_array_elements",
            "max_total_elements",
            "max_depth",
            "max_concordance_samples",
            "max_disagreement_models",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


class InputLimitError(ValueError):
    """A payload exceeds a configured structural limit. ``limit`` names the setting, never a payload value."""

    def __init__(self, limit: str, maximum: int) -> None:
        super().__init__(f"{limit} exceeded (maximum {maximum})")
        self.limit = limit
        self.maximum = maximum


def _length(value: Any) -> int | None:
    return len(value) if isinstance(value, list) else None


def check_input_bounds(payload: Any, limits: InputLimits, primitive: str | None = None) -> None:
    """Raise :class:`InputLimitError` if ``payload`` exceeds ``limits``.

    Iterative (no recursion). A container is counted before its children are visited, so the work is
    bounded by about ``max_total_elements`` plus the object members, each object capped at
    ``max_array_elements``. When ``primitive`` is given, the cost limit of that primitive is applied too.
    """
    total = 0
    stack: list[tuple[Any, int]] = [(payload, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise InputLimitError("max_json_depth", limits.max_depth)
        if isinstance(node, dict):
            children: Any = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        n = len(node)
        if n > limits.max_array_elements:
            raise InputLimitError("max_array_elements", limits.max_array_elements)
        if isinstance(node, list):  # object members are bounded per object, array elements in total
            total += n
            if total > limits.max_total_elements:
                raise InputLimitError("max_total_elements", limits.max_total_elements)
        for child in children:
            if isinstance(child, (dict, list)):
                stack.append((child, depth + 1))
    if isinstance(payload, dict):
        if primitive == "concordance":
            for key in ("risk", "time", "event"):
                n_c = _length(payload.get(key))
                if n_c is not None and n_c > limits.max_concordance_samples:
                    raise InputLimitError("max_concordance_samples", limits.max_concordance_samples)
        elif primitive == "disagreement":
            n_m = _length(payload.get("model_polynomials"))
            if n_m is not None and n_m > limits.max_disagreement_models:
                raise InputLimitError("max_disagreement_models", limits.max_disagreement_models)


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
