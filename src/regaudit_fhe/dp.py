"""Differential-privacy output perturbation for released audit scalars.

FHE protects the *inputs* of an audit while they are computed on; it does
nothing for the *output*. Every primitive in this library decrypts a small
set of aggregate scalars — a demographic-parity gap, a bucket aggregate, a
disagreement variance — and those released aggregates can themselves leak
information about individuals when groups are small (a parity gap computed
over a five-person subgroup is close to a membership oracle).

This module adds calibrated noise to the *released* aggregates so the
published envelope satisfies (epsilon)- or (epsilon, delta)-differential
privacy with respect to one record. It is deliberately *not* automatic:
the privacy guarantee depends entirely on a correct per-output
**sensitivity** bound, which is a modelling decision the library cannot
make for the deployer. The caller supplies the sensitivity; this module
supplies the mechanism, the calibration, and the composition accounting,
and records exactly what was applied in a machine-readable ``dp`` block
that travels in the signed envelope.

What this module guarantees
---------------------------
Given a correct sensitivity ``s`` for an output and a fresh draw:

  - **Laplace**: adding ``Laplace(0, s / epsilon)`` noise gives
    ``epsilon``-DP for that release.
  - **Gaussian**: adding ``N(0, sigma^2)`` with
    ``sigma = s * sqrt(2 ln(1.25 / delta)) / epsilon`` gives
    ``(epsilon, delta)``-DP for that release (analytic-classic bound).

What it does NOT do
-------------------
  - It does not derive sensitivity for you. Pass a bound you can defend.
  - It does not protect boolean / categorical audit outputs (a
    breach bit); those need a separate randomised-response treatment the
    caller must opt into explicitly.
  - DP and the FHE input protection are independent layers. Applying DP
    does not weaken or replace the envelope signature or commitments.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import dataclasses
import math
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import numpy as np

LAPLACE = "laplace"
GAUSSIAN = "gaussian"
MECHANISMS = (LAPLACE, GAUSSIAN)


class DPError(ValueError):
    """Raised when a differential-privacy parameter is invalid."""


def _check_epsilon(epsilon: float) -> float:
    eps = float(epsilon)
    if not math.isfinite(eps) or eps <= 0.0:
        raise DPError(f"epsilon must be a finite positive float, got {epsilon!r}")
    return eps


def _check_sensitivity(sensitivity: float) -> float:
    s = float(sensitivity)
    if not math.isfinite(s) or s <= 0.0:
        raise DPError(f"sensitivity must be a finite positive float, got {sensitivity!r}")
    return s


def _check_delta(delta: float) -> float:
    d = float(delta)
    if not (0.0 < d < 1.0):
        raise DPError(f"delta must lie in the open interval (0, 1), got {delta!r}")
    return d


def make_rng(seed: int | None = None) -> np.random.Generator:
    """Return a NumPy ``Generator``.

    When ``seed`` is ``None`` the generator is seeded from the operating
    system CSPRNG (:func:`secrets.randbits`) so production releases are
    non-reproducible; tests pass an explicit integer seed for
    determinism.
    """
    if seed is None:
        seed = secrets.randbits(128)
    return np.random.default_rng(seed)


def laplace_scale(*, sensitivity: float, epsilon: float) -> float:
    """Laplace scale ``b = sensitivity / epsilon`` for ``epsilon``-DP."""
    return _check_sensitivity(sensitivity) / _check_epsilon(epsilon)


def gaussian_sigma(*, sensitivity: float, epsilon: float, delta: float) -> float:
    """Gaussian standard deviation for ``(epsilon, delta)``-DP.

    Uses the classic analytic bound
    ``sigma = s * sqrt(2 ln(1.25 / delta)) / epsilon``. Valid for
    ``epsilon <= 1``; for larger ``epsilon`` it remains a conservative
    (over-noising) choice rather than an under-noising one.
    """
    s = _check_sensitivity(sensitivity)
    eps = _check_epsilon(epsilon)
    d = _check_delta(delta)
    return s * math.sqrt(2.0 * math.log(1.25 / d)) / eps


@dataclass(frozen=True)
class DPSpec:
    """A differential-privacy release policy for one numeric output.

    ``sensitivity`` is the L1 (Laplace) or L2 (Gaussian) bound on how
    much the output can change when one record is added or removed. It
    is the deployer's responsibility to supply a correct bound; the
    privacy guarantee is only as sound as this value.
    """

    sensitivity: float
    epsilon: float
    mechanism: str = LAPLACE
    delta: float = 0.0

    def __post_init__(self) -> None:
        _check_sensitivity(self.sensitivity)
        _check_epsilon(self.epsilon)
        if self.mechanism not in MECHANISMS:
            raise DPError(f"mechanism must be one of {MECHANISMS}, got {self.mechanism!r}")
        if self.mechanism == GAUSSIAN:
            _check_delta(self.delta)
        elif self.delta != 0.0:
            raise DPError("delta is only meaningful for the gaussian mechanism")

    def noise_scale(self) -> float:
        """Standard noise parameter: Laplace ``b`` or Gaussian ``sigma``."""
        if self.mechanism == LAPLACE:
            return laplace_scale(sensitivity=self.sensitivity, epsilon=self.epsilon)
        return gaussian_sigma(sensitivity=self.sensitivity, epsilon=self.epsilon, delta=self.delta)

    def metadata(self) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "mechanism": self.mechanism,
            "epsilon": float(self.epsilon),
            "sensitivity": float(self.sensitivity),
            "noise_scale": float(self.noise_scale()),
        }
        if self.mechanism == GAUSSIAN:
            meta["delta"] = float(self.delta)
        return meta


def privatize_value(value: float, spec: DPSpec, rng: np.random.Generator) -> float:
    """Return ``value`` plus one calibrated noise draw under ``spec``."""
    scale = spec.noise_scale()
    if spec.mechanism == LAPLACE:
        noise = float(rng.laplace(loc=0.0, scale=scale))
    else:
        noise = float(rng.normal(loc=0.0, scale=scale))
    return float(value) + noise


@dataclass
class PrivacyAccountant:
    """Tracks cumulative privacy loss across releases.

    Uses **basic (sequential) composition**: epsilons add, deltas add.
    This is the conservative, always-valid accountant. Deployers running
    many correlated releases under a tight budget may substitute an
    advanced-composition or RDP accountant; basic composition never
    under-reports the spend.
    """

    epsilon_budget: float | None = None
    delta_budget: float | None = None
    spent_epsilon: float = 0.0
    spent_delta: float = 0.0
    releases: list[dict[str, Any]] = field(default_factory=list)

    def charge(self, spec: DPSpec, *, label: str = "") -> None:
        new_eps = self.spent_epsilon + spec.epsilon
        new_delta = self.spent_delta + (spec.delta if spec.mechanism == GAUSSIAN else 0.0)
        if self.epsilon_budget is not None and new_eps > self.epsilon_budget + 1e-12:
            raise DPError(f"epsilon budget exceeded: {new_eps:.6g} > {self.epsilon_budget:.6g}")
        if self.delta_budget is not None and new_delta > self.delta_budget + 1e-18:
            raise DPError(f"delta budget exceeded: {new_delta:.6g} > {self.delta_budget:.6g}")
        self.spent_epsilon = new_eps
        self.spent_delta = new_delta
        entry = dict(spec.metadata())
        if label:
            entry["label"] = label
        self.releases.append(entry)

    def remaining_epsilon(self) -> float | None:
        if self.epsilon_budget is None:
            return None
        return max(0.0, self.epsilon_budget - self.spent_epsilon)

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "composition": "basic",
            "spent_epsilon": float(self.spent_epsilon),
            "spent_delta": float(self.spent_delta),
            "release_count": len(self.releases),
        }
        if self.epsilon_budget is not None:
            out["epsilon_budget"] = float(self.epsilon_budget)
        if self.delta_budget is not None:
            out["delta_budget"] = float(self.delta_budget)
        return out


def privatize_report(
    report: Any,
    specs: Mapping[str, DPSpec],
    *,
    rng: np.random.Generator | None = None,
    accountant: PrivacyAccountant | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Apply per-field DP noise to the numeric outputs of a report.

    ``report`` is any of the primitive ``*Report`` dataclasses (or a
    plain mapping). ``specs`` maps a numeric field name to its
    :class:`DPSpec`. Each named field is replaced by a noised draw;
    fields absent from ``specs`` are released unchanged (the caller is
    declaring them non-sensitive or already-public). Booleans and
    non-numeric fields named in ``specs`` raise :class:`DPError` rather
    than silently passing through.

    Returns ``(privatized_report, dp_block)`` where ``dp_block`` is a
    JSON-serialisable record of exactly what was applied — suitable for
    passing to :func:`regaudit_fhe.reports.envelope` so the published
    envelope is honest about the noise it carries.
    """
    rng = rng or make_rng()
    is_dataclass = dataclasses.is_dataclass(report) and not isinstance(report, type)
    if is_dataclass:
        fields = {f.name for f in dataclasses.fields(report)}
        values = {name: getattr(report, name) for name in fields}
    elif isinstance(report, Mapping):
        values = dict(report)
        fields = set(values)
    else:
        raise DPError("report must be a dataclass instance or a mapping")

    applied: dict[str, dict[str, Any]] = {}
    for name, spec in specs.items():
        if name not in fields:
            raise DPError(f"report has no field {name!r}")
        raw = values[name]
        if isinstance(raw, bool) or not isinstance(raw, (int, float, np.integer, np.floating)):
            raise DPError(
                f"field {name!r} is not a real-valued scalar; DP output "
                f"perturbation applies to numeric aggregates only"
            )
        values[name] = privatize_value(float(raw), spec, rng)
        if accountant is not None:
            accountant.charge(spec, label=name)
        applied[name] = spec.metadata()

    if is_dataclass:
        privatized = dataclasses.replace(report, **{k: values[k] for k in fields})
    else:
        privatized = values

    dp_block: dict[str, Any] = {
        "applied": True,
        "fields": applied,
    }
    if accountant is not None:
        dp_block["accounting"] = accountant.summary()
    return privatized, dp_block
