"""Test path to the product's gate, and a test double for an independent store.

**Everything that uses ``MemoryCasStore`` or ``verify_with_revocation`` from this module is simulated evidence.**
This ``verify_with_revocation`` is the product's private ``_run_gate``, which does not qualify the store or the
profile, so that the algorithm can be exercised under ``high-assurance``. The product's public path refuses that.
"""

from __future__ import annotations

from pathlib import Path

from regaudit_fhe._revocation_gate import *  # noqa: F403
from regaudit_fhe._revocation_gate import MODE_OFF, Decision, _run_gate
from regaudit_fhe._revocation_state import *  # noqa: F403
from regaudit_fhe._revocation_state import FileStateStore
from regaudit_fhe._trust_lifecycle import MigrationRefused as MigrationRefused
from regaudit_fhe._trust_lifecycle import migrate_store as migrate_store
from regaudit_fhe.verification import verify


def verify_with_revocation(env, policy, ctx, *, presented=None) -> Decision:
    """The private path. ``off`` is the same as the public one."""
    if ctx.mode == MODE_OFF:
        return Decision(verify(env, policy), None)
    return _run_gate(env, policy, ctx, presented=presented, _unqualified_test_path=True)


class SimulatedCrash(BaseException):
    """Test hook: the process died at this point. BaseException so that no cleanup handler runs."""


class MemoryCasStore:
    """TEST DOUBLE for an independent compare-and-set service. Nothing like it is qualified or shipped."""

    scope = "INDEPENDENT_CAS"

    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}
        self.down = False

    def read(self, issuer: str) -> bytes | None:
        if self.down:
            raise StateUnavailable("store unreachable")  # noqa: F405
        return self.data.get(issuer)

    def cas(self, issuer: str, expected: bytes | None, new: bytes) -> bool:
        if self.down:
            raise StateUnavailable("store unreachable")  # noqa: F405
        if self.data.get(issuer) != expected:
            return False
        self.data[issuer] = new
        return True


class FileCasStore(FileStateStore):
    """The product's file store, with an in-process crash at a chosen commit point."""

    def __init__(self, directory: str | Path, crash_at: str | None = None) -> None:
        super().__init__(directory)
        self.crash_at = crash_at

    def _fault(self, point: str) -> None:
        if self.crash_at == point:
            raise SimulatedCrash(point)
