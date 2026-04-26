"""regaudit-fhe — encrypted regulatory audit primitives at CKKS depth six.

A single import surface gives access to all six audit primitives. Each
primitive exposes a plaintext oracle (for testing and reference) and a
depth-budgeted slot-vector circuit that mirrors the on-encrypted execution
under CKKS.

Example
-------
>>> import numpy as np
>>> from regaudit_fhe import audit_fairness
>>> y_true = np.array([1, 0, 1, 1, 0, 1, 0, 0], dtype=float)
>>> y_pred = np.array([1, 0, 1, 0, 0, 1, 1, 0], dtype=float)
>>> group_a = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=float)
>>> group_b = 1.0 - group_a
>>> report = audit_fairness(y_true, y_pred, group_a, group_b)
>>> report.threshold_breached
False

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from . import (ecmd_jps, ecp_qssp, esc_cia, etk_fpa_hbc, ew1_cdsf, egf_imss,
                reports, schemas)
from .schemas import (SchemaError, list_schemas, load_schema, validate,
                       validate_envelope, validate_input, validate_output)
from ._slot import MAX_DEPTH, DepthBudgetExceeded, SlotVec
from .ecmd_jps import DisagreementReport, disagreement_circuit_d6, disagreement_oracle
from .ecp_qssp import ConformalReport, conformal_circuit_d6, conformal_oracle
from .esc_cia import CIndexReport, c_index_circuit_d6, c_index_oracle
from .etk_fpa_hbc import ProvenanceReport, topk_provenance_circuit_d6, topk_provenance_oracle
from .ew1_cdsf import DriftReport, cvm_oracle, w1_circuit_d6, w1_oracle
from .egf_imss import FairnessReport, fairness_circuit_d6, fairness_oracle
from .reports import (AuditEnvelope, ParameterSet, REGULATION_MAP, Signer,
                      TimestampAuthority, VerificationOutcome,
                      canonical_json, commit_input, commitments_for,
                      envelope, verify_envelope, verify_receipt)

__version__ = "0.0.7"


audit_fairness = fairness_circuit_d6
audit_provenance = topk_provenance_circuit_d6
audit_concordance = c_index_circuit_d6
audit_calibration = conformal_circuit_d6
audit_drift = w1_circuit_d6
audit_disagreement = disagreement_circuit_d6


__all__ = [
    "__version__",
    "MAX_DEPTH",
    "DepthBudgetExceeded",
    "SlotVec",
    "audit_fairness",
    "audit_provenance",
    "audit_concordance",
    "audit_calibration",
    "audit_drift",
    "audit_disagreement",
    "fairness_circuit_d6",
    "fairness_oracle",
    "FairnessReport",
    "topk_provenance_circuit_d6",
    "topk_provenance_oracle",
    "ProvenanceReport",
    "c_index_circuit_d6",
    "c_index_oracle",
    "CIndexReport",
    "conformal_circuit_d6",
    "conformal_oracle",
    "ConformalReport",
    "w1_circuit_d6",
    "w1_oracle",
    "cvm_oracle",
    "DriftReport",
    "disagreement_circuit_d6",
    "disagreement_oracle",
    "DisagreementReport",
    "egf_imss",
    "etk_fpa_hbc",
    "esc_cia",
    "ecp_qssp",
    "ew1_cdsf",
    "ecmd_jps",
    "reports",
    "AuditEnvelope",
    "ParameterSet",
    "REGULATION_MAP",
    "Signer",
    "TimestampAuthority",
    "VerificationOutcome",
    "canonical_json",
    "commit_input",
    "commitments_for",
    "envelope",
    "verify_envelope",
    "verify_receipt",
    "schemas",
    "SchemaError",
    "list_schemas",
    "load_schema",
    "validate",
    "validate_envelope",
    "validate_input",
    "validate_output",
]
