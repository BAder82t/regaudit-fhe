"""Security-maintenance regressions that need no optional extra: one-time warning, examples.

The server-dependent ones live in ``test_server_security_maintenance.py``."""

from __future__ import annotations

import re
import threading
import warnings
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
import regaudit_fhe.reports as reports

ROOT = Path(__file__).resolve().parent.parent


def _self_signed_envelope():
    signer = rf.Signer.generate(issuer="acme", key_id="k1")
    report = rf.audit_fairness(
        np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([1.0, 0.0]), np.array([0.0, 1.0])
    )
    return rf.envelope("fairness", report, signer=signer)


# ---------------------------------------------------------------------------
# One-time weak-verification warning (CodeQL #35)
# ---------------------------------------------------------------------------


def test_weak_receipt_warning_fires_once_then_stays_quiet():
    env = _self_signed_envelope()
    reports._WEAK_WARNING.reset()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert rf.verify_receipt(env) is True
        assert rf.verify_receipt(env) is True
    weak = [w for w in caught if "does NOT authenticate" in str(w.message)]
    assert len(weak) == 1 and issubclass(weak[0].category, UserWarning)


def test_weak_receipt_warning_is_exactly_once_across_threads():
    env = _self_signed_envelope()
    reports._WEAK_WARNING.reset()
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        rf.verify_receipt(env)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert len([w for w in caught if "does NOT authenticate" in str(w.message)]) == 1


def test_warning_is_not_emitted_when_trust_material_is_supplied():
    env = _self_signed_envelope()
    signer_pem = env.receipt["public_key_pem"]
    reports._WEAK_WARNING.reset()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert rf.verify_receipt(env, trusted_keys={"k1": signer_pem}, strict=True) is True
    assert not [w for w in caught if "does NOT authenticate" in str(w.message)]


def test_the_module_no_longer_mutates_a_global_for_the_warning():
    source = (ROOT / "src/regaudit_fhe/reports.py").read_text(encoding="utf-8")
    assert "global _VERIFY_RECEIPT_WEAK_WARNED" not in source


# ---------------------------------------------------------------------------
# Examples use the recommended API, not the deprecated `.valid`
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", sorted((ROOT / "examples").glob("*.py")), ids=lambda p: p.name)
def test_examples_do_not_read_the_deprecated_valid_attribute(path):
    text = path.read_text(encoding="utf-8")
    assert not re.search(r"\b(?:outcome|out|bad|result|res)\.valid\b", text), path.name
