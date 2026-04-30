"""JSON Schema loader + validator.

Bundles the schemas under ``schemas/`` at install time; each primitive
input, primitive output, and the audit envelope itself has a Draft
2020-12 schema pinned to a specific URL, and every CLI / HTTP entry
point validates against the corresponding schema before invoking the
audit primitive.

Pinning a schema version is the regulator-facing contract: an auditor
can pin ``regaudit-fhe.report.v1`` and reject envelopes that fail
``validate_envelope``.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from functools import cache
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

PRIMITIVES = ("fairness", "provenance", "concordance",
              "calibration", "drift", "disagreement")
DIRECTIONS = ("input", "output")


class SchemaError(ValueError):
    """Raised when a payload fails JSON Schema validation."""


def _candidate_schema_dirs() -> list[Path]:
    """Locate the bundled schemas directory.

    Order tried:
      1. The installed package data (``importlib.resources``).
      2. The repository's top-level ``schemas/`` directory (used in
         editable installs and tests).
    """
    out: list[Path] = []
    pkg_dir = Path(__file__).parent
    out.append(pkg_dir / "schemas")
    out.append(pkg_dir.parent.parent.parent / "schemas")
    out.append(Path.cwd() / "schemas")
    return out


@cache
def _schemas_dir() -> Path:
    for cand in _candidate_schema_dirs():
        if cand.is_dir():
            return cand
    raise FileNotFoundError(
        "Could not locate the regaudit-fhe schemas/ directory."
    )


@cache
def load_schema(name: str) -> dict[str, Any]:
    """Load a schema by name. Names follow the convention
    ``<primitive>.<direction>`` for primitives and ``envelope`` for
    the audit envelope.
    """
    if name == "envelope":
        path = _schemas_dir() / "envelope.schema.json"
    elif "." in name:
        primitive, direction = name.split(".", 1)
        if primitive not in PRIMITIVES or direction not in DIRECTIONS:
            raise KeyError(f"unknown schema {name!r}")
        path = _schemas_dir() / f"{primitive}.{direction}.schema.json"
    else:
        raise KeyError(
            f"schema name must be 'envelope' or '<primitive>.<direction>'; "
            f"got {name!r}"
        )
    with path.open("r") as fh:
        return cast(dict[str, Any], json.load(fh))


def list_schemas() -> tuple[str, ...]:
    out = ["envelope"]
    for p in PRIMITIVES:
        for d in DIRECTIONS:
            out.append(f"{p}.{d}")
    return tuple(out)


def validate(name: str, payload: Mapping[str, Any]) -> None:
    """Validate ``payload`` against the named schema. Raises
    :class:`SchemaError` with the location of the first violation."""
    schema = load_schema(name)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(dict(payload)), key=lambda e: e.path)
    if not errors:
        return
    msgs = []
    for err in errors:
        loc = "/".join(str(p) for p in err.absolute_path) or "<root>"
        msgs.append(f"{loc}: {err.message}")
    raise SchemaError(
        f"payload does not conform to schema {name!r}: " + "; ".join(msgs)
    )


def validate_input(primitive: str, payload: Mapping[str, Any]) -> None:
    validate(f"{primitive}.input", payload)


def validate_output(primitive: str, payload: Mapping[str, Any]) -> None:
    validate(f"{primitive}.output", payload)


def validate_envelope(payload: Mapping[str, Any]) -> None:
    validate("envelope", payload)
