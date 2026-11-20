"""Presentation-only claim labels for a verified report.

A signature check says which key signed which bytes. It does not say that what the bytes claim is true. Nothing a
report signs today establishes that a computation ran under encryption, and no independent check exists, so every
verdict carries the same two statements:

* ``Encrypted execution not established.``
* ``A signed report can authenticate a claim without proving that claim is true.``

This module reads a parsed report (and, for wording only, the verdict's ``trust_status``) and returns plain strings.
It never feeds back into a decision: no function here is called by ``verify``, none changes ``accepted``,
``trust_status``, a reason code, an exit code or an HTTP status, and none adds a key to the default JSON verdict.

Rules the labels follow:

* ``security_bits``, ``multiplicative_depth``, ``poly_modulus_degree`` and ``backend`` are parameters the signer
  declared. They are never read as evidence that encrypted computation ran.
* The absence of encrypted-execution evidence is labelled "not established". It is never labelled "plaintext". A
  report whose ``backend`` field is ``plaintext`` is described as "declares a plaintext backend" because that field
  is also the default value a producer signs when nobody set it.
* The label text comes from a fixed table. Text a signer controls is never echoed, so a report cannot write its
  own label. Only a backend name from a closed list is shown, and then as a declaration.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from typing import Any

CLAIM_ASSESSMENT_VERSION = 1

# The exact sentence shown wherever a verdict is shown.
NOT_ESTABLISHED = "Encrypted execution not established."
# The maintainer's invariant, shown beside it.
INVARIANT = "A signed report can authenticate a claim without proving that claim is true."
FHE_TESTS_NOTE = (
    "Successful FHE tests in this repository do not by themselves prove that an arbitrary signed report was "
    "produced through FHE."
)

# The seven kinds of statement, in display order. The values are fixed text, never built from report content.
OBSERVED_BY_TRUSTED = "Execution mode observed by a trusted component: none. No signed field and no independent check records one."
ESTABLISHED_FROM_EVIDENCE = (
    "Execution mode established from the available evidence: cannot be established."
)
CONFIGURATION = (
    "Cryptographic configuration: backend, security_bits, multiplicative_depth and the other parameters are values "
    "the signer declared. They were not measured here and are not evidence that encrypted execution happened."
)
INDEPENDENTLY_ESTABLISHED = "Independently established computational properties: none."
UNSUPPORTED = (
    "Unsupported or unverified claims: that the computation ran encrypted, that the results are correct, that "
    "privacy holds, and that any regulation is met."
)

_AUTH_TRUSTED = (
    "Authenticated report content: these exact report bytes were signed by a key in your trust store. "
    "That says who signed them, not that what they say is true."
)
_AUTH_NOT_TRUSTED = (
    "Authenticated report content: none. This report was not accepted as signed by a trusted issuer, so its "
    "contents are only what the file says."
)
_AUTH_UNKNOWN = (
    "Authenticated report content: only what a signature check on the report can show, and only if a trust store "
    "you control names the signing key. A signature shows who signed, not that the content is true."
)

_FHE_BACKENDS = frozenset({"tenseal-ckks", "openfhe-ckks", "lattigo-ckks"})

_DECLARED_PLAINTEXT = (
    "Execution mode declared in the report: the report declares a plaintext backend. This is a declaration, and "
    "'plaintext' is also the default a producer signs when no backend was chosen."
)
_DECLARED_NOT_STATED = "Execution mode declared in the report: the report names no backend."
_DECLARED_UNRECOGNIZED = "Execution mode declared in the report: the report names a backend this verifier does not recognise."


def _declared_fhe(name: str) -> str:
    return (
        f"Execution mode declared in the report: the report declares an FHE backend ({name}). This is a "
        "declaration by the signer. It is not an observation, and the parameters that go with it do not make it one."
    )


def declared_backend_kind(backend: Any) -> str:
    """``plaintext_declared``, ``fhe_declared``, ``unrecognized`` or ``not_stated`` (never the signer's text)."""
    if not isinstance(backend, str) or not backend:
        return "not_stated"
    if backend == "plaintext":
        return "plaintext_declared"
    if backend in _FHE_BACKENDS:
        return "fhe_declared"
    return "unrecognized"


def _declared_line(backend: Any) -> str:
    kind = declared_backend_kind(backend)
    if kind == "plaintext_declared":
        return _DECLARED_PLAINTEXT
    if kind == "fhe_declared":
        return _declared_fhe(str(backend))
    if kind == "unrecognized":
        return _DECLARED_UNRECOGNIZED
    return _DECLARED_NOT_STATED


def _authenticated_line(trust_status: str | None, accepted: bool | None) -> str:
    if trust_status is None:
        return _AUTH_UNKNOWN
    if trust_status == "TRUSTED" and accepted is not False:
        return _AUTH_TRUSTED
    return _AUTH_NOT_TRUSTED


def assess(
    report: Any, *, trust_status: str | None = None, accepted: bool | None = None
) -> dict[str, Any]:
    """The label set for one parsed report. Strings only; the verdict is an input to the wording and nothing else.

    ``report`` is an ``AuditEnvelope`` or ``AuditEnvelopeV2`` (any object with a ``backend`` attribute works).
    """
    backend = getattr(report, "backend", None)
    kind = declared_backend_kind(backend)
    return {
        "claim_assessment_version": CLAIM_ASSESSMENT_VERSION,
        "encrypted_execution": "not_established",
        "statement": NOT_ESTABLISHED,
        "invariant": INVARIANT,
        "execution_mode": {
            "observed_by_trusted_component": "none",
            "declared_in_report": kind,
            "established_from_evidence": "cannot_be_established",
        },
        "cryptographic_configuration": "declared_by_signer_not_verified",
        "authenticated_report_content": "signature_and_trust_rules_only",
        "independently_established_properties": [],
        "unsupported_or_unverified_claims": [
            "encrypted_execution",
            "result_correctness",
            "privacy",
            "regulatory_compliance",
        ],
        "lines": claim_lines(report, trust_status=trust_status, accepted=accepted),
    }


def claim_lines(
    report: Any, *, trust_status: str | None = None, accepted: bool | None = None
) -> list[str]:
    """The same labels as display text, one statement per line, in a fixed order."""
    return [
        NOT_ESTABLISHED,
        INVARIANT,
        OBSERVED_BY_TRUSTED,
        _declared_line(getattr(report, "backend", None)),
        ESTABLISHED_FROM_EVIDENCE,
        CONFIGURATION,
        _authenticated_line(trust_status, accepted),
        INDEPENDENTLY_ESTABLISHED,
        UNSUPPORTED,
        FHE_TESTS_NOTE,
    ]


def stderr_block(
    report: Any, *, trust_status: str | None = None, accepted: bool | None = None
) -> str:
    """The text the command line writes to stderr after a verdict."""
    lines = claim_lines(report, trust_status=trust_status, accepted=accepted)
    return "claims:\n" + "".join(f"  - {line}\n" for line in lines)
