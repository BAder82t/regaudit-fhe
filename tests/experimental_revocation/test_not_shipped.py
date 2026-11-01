"""What must stay true while signed revocation is experimental.

This replaces the guard that kept the format out of ``src/`` altogether. The code now exists, off by default, and
these are the promises that still hold: nothing registered, nothing exported, the default path untouched, and the
revocation-aware high-assurance profile unavailable.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import numpy as np
import pytest

import regaudit_fhe as rf
from regaudit_fhe import _revocation_gate as gate
from regaudit_fhe import _revocation_state as state
from regaudit_fhe.cli import build_parser
from regaudit_fhe.replay import SqliteReplayCache
from regaudit_fhe.report_v2 import envelope_v2
from regaudit_fhe.verification import PolicyError, VerificationPolicy, VerificationResult

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "regaudit_fhe"

# Sorted rf.__all__ and the schema list at d648910, the master this branch starts from.
ALL_AT_MASTER = "9ed66cdb16c32b32983394ab52226bd14412dda0f952c4d3ea881b9112bb0dd7"
SCHEMAS_AT_MASTER = (
    "envelope", "envelope.v2", "fairness.input", "fairness.output", "provenance.input", "provenance.output",
    "concordance.input", "concordance.output", "calibration.input", "calibration.output", "drift.input",
    "drift.output", "disagreement.input", "disagreement.output",
)  # fmt: skip


def test_nothing_is_registered_or_shipped_in_the_schema_list():
    assert rf.list_schemas() == SCHEMAS_AT_MASTER
    assert sorted(p.name for p in (SRC / "schemas").iterdir() if "revocation" in p.name) == []
    assert "revocation" not in (SRC / "schemas.py").read_text(encoding="utf-8")


def test_nothing_new_is_exported_from_the_top_level():
    assert hashlib.sha256(json.dumps(sorted(rf.__all__)).encode()).hexdigest() == ALL_AT_MASTER
    assert not [n for n in rf.__all__ if "revocation" in n.lower()]
    assert not [n for n in dir(rf) if "revocation" in n.lower() and not n.startswith("_")]


def test_importing_the_package_loads_no_revocation_code():
    code = "import regaudit_fhe, sys; print([m for m in sys.modules if 'revocation' in m])"
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=120
    )
    assert out.stdout.strip() == "[]"


def test_the_engine_knows_nothing_of_revocation():
    for name in ("verification.py", "trusted.py", "server.py", "trust.py", "reports.py", "report_v2.py"):
        assert "_revocation" not in (SRC / name).read_text(encoding="utf-8"), name
    fields = set(VerificationPolicy.__dataclass_fields__) | set(
        VerificationResult.__dataclass_fields__
    )
    assert not [f for f in fields if "revocation" in f]


def test_the_cli_default_is_off():
    args = build_parser().parse_args(["verify", "-i", "r.json"])
    assert args.revocation_mode == "off" and args.policy_evidence is False


def test_no_store_can_declare_itself_independent(tmp_path):
    """A flag on an object is self-attestation, so there is no such attribute and no argument can enable the mode."""
    for cls in (state.FileStateStore,):
        assert not hasattr(cls, "independent")
    assert "independent=" not in (SRC / "_revocation_gate.py").read_text(encoding="utf-8")


class _ClaimsEverything(state.FileStateStore):
    independent = True
    durable = True
    compare_and_set = True
    scope = "INDEPENDENT_CAS"


@pytest.mark.parametrize("store_class", [state.FileStateStore, _ClaimsEverything])
@pytest.mark.parametrize("mode", [gate.MODE_REQUIRED, gate.MODE_ADVISORY])
def test_high_assurance_with_any_mode_is_unavailable_whatever_store_is_passed(
    tmp_path, store_class, mode
):
    signer = rf.Signer.generate(issuer="acme", key_id="k")
    env = envelope_v2(
        "drift",
        rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])),
        signer=signer,
        deployment_id="p",
        audience=["reg"],
    )
    pol = VerificationPolicy(
        profile="high-assurance",
        trust_store=rf.TrustStore.from_dict(
            {
                "entries": {
                    "k": {
                        "issuer": "acme",
                        "public_key_pem": signer.public_key_pem(),
                        "status": "active",
                    }
                }
            }
        ),
        max_age=timedelta(days=1),
        replay_mode="record",
        replay_cache=SqliteReplayCache(tmp_path / "r.db"),
        verifier_id="reg",
    )
    ctx = gate.RevocationContext(mode, store_class(tmp_path), {})
    with pytest.raises(PolicyError, match="REVOCATION_HIGH_ASSURANCE_UNAVAILABLE"):
        gate.verify_with_revocation(env, pol, ctx)


def test_a_store_other_than_the_shipped_one_is_refused_on_the_public_path(tmp_path):
    signer = rf.Signer.generate(issuer="acme", key_id="k")
    env = envelope_v2(
        "drift",
        rf.audit_drift(np.array([0.5, 0.5]), np.array([0.4, 0.6])),
        signer=signer,
        deployment_id="p",
    )
    pol = VerificationPolicy(
        trust_store=rf.TrustStore.from_dict(
            {
                "entries": {
                    "k": {
                        "issuer": "acme",
                        "public_key_pem": signer.public_key_pem(),
                        "status": "active",
                    }
                }
            }
        )
    )
    ctx = gate.RevocationContext(gate.MODE_REQUIRED, _ClaimsEverything(tmp_path), {})
    with pytest.raises(PolicyError, match="only the shipped"):
        gate.verify_with_revocation(env, pol, ctx)


def test_list_derived_history_is_not_in_the_product():
    text = "".join(
        p.read_text(encoding="utf-8") for p in SRC.glob("_revocation*.py")
    )
    assert "TrustHistory" not in text and "derive_trust_history" not in text
