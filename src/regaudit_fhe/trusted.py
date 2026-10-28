"""Explicit trusted verification: one question, three answers.

:func:`verify_trusted` answers "was this report signed by a key in the trust store I
supplied, and is the JSON I hold exactly what was signed?". The verdict is one of

* ``TRUSTED``: integrity holds, the key is registered in the supplied trust store and
  its lifecycle, scope and policy checks pass, and the report was parsed strictly.
* ``SELF_SIGNED_ONLY``: integrity holds but nothing authenticates the issuer. Reported
  for completeness; with a trust store supplied the engine does not normally produce it.
* ``INVALID``: anything else, including a report whose JSON is ambiguous or not in the
  canonical form it was signed in.

Only ``TRUSTED`` is an acceptance. The result object refuses ``bool()`` so that
``if verify_trusted(...)`` cannot silently treat every verdict as true; use ``.trusted``.

``TRUSTED`` means "signed by a key in YOUR trust store". It does not say the audit is
correct, complete or compliant, and it is not a regulatory or production assurance.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import CanonicalError
from .report_v2 import AuditEnvelopeV2, EnvelopeFormatError, parse_envelope_strict
from .reports import AuditEnvelope
from .trust import TrustStore
from .verification import VerificationPolicy, VerificationResult, verify

__all__ = ["TrustVerdict", "TrustedVerification", "verify_trusted"]


class TrustVerdict(str, enum.Enum):
    TRUSTED = "TRUSTED"
    SELF_SIGNED_ONLY = "SELF_SIGNED_ONLY"
    INVALID = "INVALID"


@dataclass(frozen=True)
class TrustedVerification:
    """Outcome of :func:`verify_trusted`. Branch on ``verdict`` or ``trusted``."""

    verdict: TrustVerdict
    reasons: tuple[str, ...]
    detail: str = ""
    result: VerificationResult | None = None

    @property
    def trusted(self) -> bool:
        """True only for ``TRUSTED``. The one acceptance flag."""
        return self.verdict is TrustVerdict.TRUSTED

    def __bool__(self) -> bool:
        raise TypeError(
            "TrustedVerification has no truth value; use .trusted or compare .verdict "
            "(SELF_SIGNED_ONLY and INVALID are both refusals)"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "trusted": self.trusted,
            "reasons": list(self.reasons),
            "detail": self.detail,
            "result": self.result.to_dict() if self.result is not None else None,
        }


def _refused(code: str, detail: str) -> TrustedVerification:
    return TrustedVerification(TrustVerdict.INVALID, (code,), detail)


def verify_trusted(
    report: str | bytes | Mapping[str, Any] | AuditEnvelope | AuditEnvelopeV2,
    trust_store: TrustStore,
    *,
    policy: VerificationPolicy | None = None,
) -> TrustedVerification:
    """Strictly parse ``report`` and verify it against ``trust_store``.

    ``trust_store`` is required and must be a :class:`~regaudit_fhe.trust.TrustStore`;
    ``None`` or anything else raises ``TypeError`` rather than falling back to
    self-signed checking. ``policy`` supplies the other knobs (profile, audience,
    maximum age, replay cache, ...). The ``trust_store`` argument always wins over
    ``policy.trust_store``, and ``allow_self_signed`` is forced off.

    Pass the report as text or bytes to get duplicate-key detection. A mapping or an
    envelope object is re-serialised and checked for plain, finite, canonical JSON.

    Malformed or ambiguous reports return ``INVALID`` (they do not raise).
    ``VerificationUnavailable`` and ``PolicyError`` still propagate: they mean the
    verifier is misconfigured, which is not a verdict about the report.
    """
    if not isinstance(trust_store, TrustStore):
        raise TypeError(
            "verify_trusted() needs a regaudit_fhe.TrustStore; to check a self-signed report "
            "for development use verify_report(..., VerificationPolicy(allow_self_signed=True))"
        )
    base = policy if policy is not None else VerificationPolicy()
    effective = dataclasses.replace(base, trust_store=trust_store, allow_self_signed=False)

    source: Any = (
        report.to_dict() if isinstance(report, AuditEnvelope | AuditEnvelopeV2) else report
    )
    try:
        env = parse_envelope_strict(source)
    except (EnvelopeFormatError, CanonicalError) as exc:
        return _refused("MALFORMED_REPORT", str(exc))

    try:
        result = verify(env, effective)
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        # A hostile value the engine did not expect is a refusal, never an exception.
        # (PolicyError / VerificationUnavailable are RuntimeError subclasses and propagate.)
        return _refused("VERIFICATION_ERROR", f"{type(exc).__name__}: {exc}")

    reasons = tuple(result.blocking_reasons or result.reasons)
    if (
        result.accepted
        and result.trust_status == "TRUSTED"
        and result.integrity_valid
        and result.issuer_trusted
    ):
        return TrustedVerification(TrustVerdict.TRUSTED, reasons, "", result)
    if result.trust_status == "SELF_SIGNED_ONLY":
        return TrustedVerification(TrustVerdict.SELF_SIGNED_ONLY, reasons, "", result)
    return TrustedVerification(TrustVerdict.INVALID, reasons, "", result)
