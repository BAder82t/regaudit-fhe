"""The synthetic demonstration: a few signed reports, a demonstration trust list, and the policy that checks them.

Everything here is package data made by ``tools/make_demo_samples.py`` with a throwaway key that was discarded, so nothing
in the package can sign anything. The demonstration policy is used only for these samples, chosen by their id from the
list. It is never used for a report somebody uploads: that is checked against the administrator's policy or refused.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from importlib import resources
from typing import Any

from regaudit_fhe.canonical import CanonicalError, loads_strict
from regaudit_fhe.trust import TrustStore, TrustStoreError
from regaudit_fhe.verification import PolicyError, VerificationPolicy

DEMONSTRATION_ISSUER = "DEMO-ONLY synthetic issuer"
_MAX_SAMPLE_BYTES = 1 << 20
_ID = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")


class SamplesProblem(Exception):
    """The bundled demonstration cannot be used. The samples are then refused, as everything else would be."""


@dataclass(frozen=True)
class Sample:
    id: str
    title: str
    description: str
    file: str


@dataclass(frozen=True)
class Samples:
    items: tuple[Sample, ...]
    policy: VerificationPolicy

    def get(self, sample_id: str) -> Sample | None:
        """Only an id from the list. Nothing a client sends is ever used as a file name."""
        return next((item for item in self.items if item.id == sample_id), None)

    def read(self, sample: Sample) -> bytes:
        data = resources.files(__package__).joinpath("samples", sample.file).read_bytes()
        if len(data) > _MAX_SAMPLE_BYTES:
            raise SamplesProblem("a bundled sample is far larger than a report")
        return data

    def listing(self) -> list[dict[str, str]]:
        return [{"id": s.id, "title": s.title, "description": s.description} for s in self.items]


def _read(*parts: str) -> Any:
    try:
        return loads_strict(
            resources.files(__package__).joinpath("samples", *parts).read_bytes(),
            max_bytes=_MAX_SAMPLE_BYTES,
        )
    except (OSError, CanonicalError, RecursionError, UnicodeDecodeError) as exc:
        raise SamplesProblem(
            f"the bundled demonstration file {'/'.join(parts)} cannot be read: {exc}"
        ) from exc


def demonstration_policy(trust_list: dict[str, Any], verifier_id: str) -> VerificationPolicy:
    """The policy for the bundled samples: the demonstration trust list, and nothing the administrator configured.

    The development profile has no maximum age and no replay record, so a demonstration report neither expires nor is
    refused as a repeat. The wide clock allowance stops a computer with a wrong clock from calling a sample "from the
    future". This policy never sees an upload.
    """
    try:
        return VerificationPolicy(
            profile="development",
            trust_store=TrustStore.from_dict(trust_list),
            verifier_id=verifier_id,
            clock_skew=timedelta(days=36500),
            check_provenance=True,
        )
    except (TrustStoreError, PolicyError) as exc:
        raise SamplesProblem(f"the demonstration trust list cannot be used: {exc}") from exc


def load_samples() -> Samples:
    """Read the list, the demonstration trust list and the policy. Any doubt raises :class:`SamplesProblem`."""
    manifest = _read("index.json")
    try:
        trust_list = _read(manifest["trust_list"])
        items = tuple(
            Sample(entry["id"], entry["title"], entry["description"], entry["file"])
            for entry in manifest["samples"]
        )
        verifier_id = manifest["verifier_id"]
    except (KeyError, TypeError) as exc:
        raise SamplesProblem(
            f"the demonstration list is not in the expected form: {exc!r}"
        ) from exc
    if not items or len({item.id for item in items}) != len(items):
        raise SamplesProblem("the demonstration list is empty or repeats an id")
    for item in items:
        if not _ID.fullmatch(item.id) or not item.file.startswith("reports/") or ".." in item.file:
            raise SamplesProblem(
                "the demonstration list names something that is not a bundled report"
            )
    return Samples(items, demonstration_policy(trust_list, verifier_id))
