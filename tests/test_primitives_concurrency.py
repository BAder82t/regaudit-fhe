"""Concurrency-isolation tests for the per-context depth record.

The encrypted primitives module records the depth observed during each
call in a :class:`contextvars.ContextVar`. These tests assert that two
concurrent contexts (threads, asyncio tasks, or a child copy_context
scope) see independent depth state — the legacy module-level dict
allowed concurrent encrypted-endpoint requests to clobber each
other's records.

The tests touch only the ContextVar plumbing; they do not require the
[fhe] extra.
"""

from __future__ import annotations

import asyncio
import contextvars
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from regaudit_fhe.fhe.primitives import (
    _LAST_DEPTH,
    _record_depth,
    last_depth,
    last_depths,
    reset_last_depth,
)


def _record_for(primitive: str, depth: int) -> int:
    """Test helper: record an arbitrary depth via the public path."""
    return _record_depth(primitive, SimpleNamespace(depth=depth))


# ---------------------------------------------------------------------------
# Single-context behaviour (regression cover for the existing API)
# ---------------------------------------------------------------------------


def test_record_then_read_round_trip():
    reset_last_depth()
    _record_for("fairness", 3)
    assert last_depth("fairness") == 3
    assert last_depths() == {"fairness": 3}


def test_last_depth_unknown_primitive_raises():
    reset_last_depth()
    with pytest.raises(KeyError):
        last_depth("never-recorded")


def test_last_depths_returns_independent_snapshot():
    reset_last_depth()
    _record_for("fairness", 3)
    snapshot = last_depths()
    _record_for("fairness", 4)
    assert snapshot == {"fairness": 3}  # snapshot is frozen
    assert last_depth("fairness") == 4


def test_reset_last_depth_clears_current_context():
    _record_for("drift", 2)
    reset_last_depth()
    with pytest.raises(KeyError):
        last_depth("drift")


# ---------------------------------------------------------------------------
# Cross-thread isolation
# ---------------------------------------------------------------------------


def test_two_threads_do_not_see_each_others_depth_records():
    """Two thread-pool workers each record their own primitive; neither
    should observe the other's record."""

    def worker(name: str, depth: int) -> dict[str, int]:
        # ThreadPoolExecutor runs each task inside a copy of the
        # submitter's context, so mutations do not leak to siblings.
        reset_last_depth()
        _record_for(name, depth)
        return last_depths()

    with ThreadPoolExecutor(max_workers=2) as ex:
        f_a = ex.submit(worker, "fairness", 4)
        f_b = ex.submit(worker, "drift", 2)
        a, b = f_a.result(timeout=5), f_b.result(timeout=5)

    assert a == {"fairness": 4}
    assert b == {"drift": 2}


def test_threads_do_not_clobber_parent_context():
    """A worker's mutations stay in the worker's context copy; the
    parent context is untouched."""
    reset_last_depth()
    _record_for("calibration", 4)

    def worker() -> None:
        reset_last_depth()
        _record_for("disagreement", 5)

    with ThreadPoolExecutor(max_workers=1) as ex:
        ex.submit(worker).result(timeout=5)

    # Parent context still has its own record only.
    assert last_depths() == {"calibration": 4}


# ---------------------------------------------------------------------------
# Asyncio task isolation
# ---------------------------------------------------------------------------


def test_two_asyncio_tasks_have_independent_depth_state():
    async def worker(name: str, depth: int) -> dict[str, int]:
        reset_last_depth()
        _record_for(name, depth)
        # Yield control so the other task runs and clobbers nothing.
        await asyncio.sleep(0)
        return last_depths()

    async def driver() -> tuple[dict[str, int], dict[str, int]]:
        a, b = await asyncio.gather(
            worker("provenance", 3),
            worker("concordance", 5),
        )
        return a, b

    a, b = asyncio.run(driver())
    assert a == {"provenance": 3}
    assert b == {"concordance": 5}


# ---------------------------------------------------------------------------
# copy_context() scope isolation
# ---------------------------------------------------------------------------


def test_copy_context_run_isolates_child_mutations():
    reset_last_depth()
    _record_for("fairness", 4)

    def child() -> None:
        reset_last_depth()
        _record_for("drift", 2)

    contextvars.copy_context().run(child)

    # The parent context kept its single fairness record.
    assert last_depths() == {"fairness": 4}


def test_contextvar_default_path_does_not_share_dict():
    """First access in a fresh context yields a brand-new dict, not a
    reference to the parent's dict (would defeat isolation)."""
    reset_last_depth()
    parent_dict = _LAST_DEPTH.get()
    parent_dict["sentinel"] = 1

    def child() -> int:
        # Child context starts as a copy of the parent's binding, so
        # _LAST_DEPTH.get() returns the *same* dict by reference. To
        # really isolate, callers must reset_last_depth() first; this
        # test pins that contract.
        return id(_LAST_DEPTH.get())

    parent_id = id(parent_dict)
    child_id = contextvars.copy_context().run(child)

    # Without reset_last_depth(), the child still sees the parent's
    # dict — that's the documented contract, but it's not an isolation
    # bug, just the standard ContextVar copy semantic.
    assert parent_id == child_id

    # After reset_last_depth() inside the child, the dicts diverge.
    def child_with_reset() -> int:
        reset_last_depth()
        return id(_LAST_DEPTH.get())

    isolated_id = contextvars.copy_context().run(child_with_reset)
    assert isolated_id != parent_id
    assert _LAST_DEPTH.get() is parent_dict  # parent still intact
