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

from . import ecmd_jps, ecp_qssp, egf_imss, esc_cia, etk_fpa_hbc, ew1_cdsf, reports, schemas
from ._slot import MAX_DEPTH, DepthBudgetExceeded, SlotVec
from .ecmd_jps import DisagreementReport, disagreement_circuit_d6, disagreement_oracle
from .ecp_qssp import ConformalReport, conformal_circuit_d6, conformal_oracle
from .egf_imss import FairnessReport, fairness_circuit_d6, fairness_oracle
from .esc_cia import CIndexReport, c_index_circuit_d6, c_index_oracle
from .etk_fpa_hbc import ProvenanceReport, topk_provenance_circuit_d6, topk_provenance_oracle
from .ew1_cdsf import DriftReport, cvm_oracle, w1_circuit_d6, w1_oracle
from .reports import (
    REGULATION_MAP,
    AuditEnvelope,
    ParameterSet,
    Signer,
    TimestampAuthority,
    VerificationOutcome,
    canonical_json,
    commit_input,
    commitments_for,
    envelope,
    verify_envelope,
    verify_envelope_or_raise,
    verify_receipt,
)
from .schemas import (
    SchemaError,
    list_schemas,
    load_schema,
    validate,
    validate_envelope,
    validate_input,
    validate_output,
)
from .trust import (
    EnvelopeVerificationError,
    HashMismatch,
    InvalidSignature,
    RevokedIssuer,
    TimestampInvalid,
    TrustStore,
    TrustStoreError,
    UntrustedIssuer,
    WrongParameterSet,
)

__version__ = "0.0.7"


audit_fairness = fairness_circuit_d6
audit_provenance = topk_provenance_circuit_d6
audit_concordance = c_index_circuit_d6
audit_calibration = conformal_circuit_d6
audit_drift = w1_circuit_d6
audit_disagreement = disagreement_circuit_d6


__all__ = [
    "MAX_DEPTH",
    "REGULATION_MAP",
    "AuditEnvelope",
    "CIndexReport",
    "ConformalReport",
    "DepthBudgetExceeded",
    "DisagreementReport",
    "DriftReport",
    "EnvelopeVerificationError",
    "FairnessReport",
    "HashMismatch",
    "InvalidSignature",
    "ParameterSet",
    "ProvenanceReport",
    "RevokedIssuer",
    "SchemaError",
    "Signer",
    "SlotVec",
    "TimestampAuthority",
    "TimestampInvalid",
    "TrustStore",
    "TrustStoreError",
    "UntrustedIssuer",
    "VerificationOutcome",
    "WrongParameterSet",
    "__version__",
    "audit_calibration",
    "audit_concordance",
    "audit_disagreement",
    "audit_drift",
    "audit_fairness",
    "audit_provenance",
    "c_index_circuit_d6",
    "c_index_oracle",
    "canonical_json",
    "commit_input",
    "commitments_for",
    "conformal_circuit_d6",
    "conformal_oracle",
    "cvm_oracle",
    "disagreement_circuit_d6",
    "disagreement_oracle",
    "ecmd_jps",
    "ecp_qssp",
    "egf_imss",
    "envelope",
    "esc_cia",
    "etk_fpa_hbc",
    "ew1_cdsf",
    "fairness_circuit_d6",
    "fairness_oracle",
    "list_schemas",
    "load_schema",
    "reports",
    "schemas",
    "topk_provenance_circuit_d6",
    "topk_provenance_oracle",
    "validate",
    "validate_envelope",
    "validate_input",
    "validate_output",
    "verify_envelope",
    "verify_envelope_or_raise",
    "verify_receipt",
    "w1_circuit_d6",
    "w1_oracle",
]
