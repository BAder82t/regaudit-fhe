"""Strict canonical JSON policy for ``report.v2``.

``report.v1`` used :func:`regaudit_fhe.reports.canonical_json`, which is
lenient (it silently stringifies non-string keys and accepts whatever
``json`` accepts). That behaviour is frozen: v1 signatures verify against
those exact bytes. ``report.v2`` uses this stricter policy instead.

Serialisation (``canonical_bytes``)
    * UTF-8, keys sorted by code point, ``","`` / ``":"`` separators, no
      whitespace, non-ASCII characters emitted as-is.
    * Only ``dict`` (with ``str`` keys), ``list``/``tuple``, ``str``, ``int``,
      ``float`` (finite), ``bool`` and ``None`` are accepted.
    * ``NaN``, ``Infinity``, lone surrogates, bytes, sets, non-string keys and
      nesting deeper than :data:`MAX_DEPTH` are refused.
    * ``1``, ``1.0`` and ``true`` are distinct values and stay distinct.

Parsing (``loads_strict``)
    * Duplicate object keys, ``NaN`` / ``Infinity`` constants, numbers that
      overflow to infinity, a UTF-8 BOM, invalid UTF-8, lone surrogates,
      trailing data, excessive depth and oversized input are refused.

Open point, not decided here: numbers are formatted by Python's shortest
round-trip ``repr``. A non-Python verifier would need RFC 8785 number
formatting before ``report.v2`` can claim cross-implementation stability.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
from typing import Any

MAX_DEPTH = 64

MAX_INPUT_BYTES = 4 * 1024 * 1024


class CanonicalError(ValueError):
    """The value or text violates the v2 canonicalisation policy."""


def decode_canonical_b64(text: str, *, length: int | None = None) -> bytes:
    """Decode standard-alphabet base64, accepting only the canonical text.

    Re-encoding the decoded bytes must reproduce ``text`` exactly, so unused
    trailing bits, whitespace, newlines and stray characters cannot be varied
    to change the text without changing the bytes. Raises ``ValueError``.
    """
    if not isinstance(text, str) or not text:
        raise ValueError("base64 must be a non-empty string")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not valid base64") from exc
    if base64.b64encode(raw).decode("ascii") != text:
        raise ValueError("not canonical base64")
    if length is not None and len(raw) != length:
        raise ValueError(f"must decode to {length} bytes")
    return raw


def check_value(value: Any, depth: int = 0) -> None:
    """Raise :class:`CanonicalError` unless ``value`` obeys the v2 policy."""
    if depth > MAX_DEPTH:
        raise CanonicalError(f"nesting deeper than {MAX_DEPTH}")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalError("non-finite number")
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CanonicalError("string is not valid Unicode (lone surrogate)") from exc
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            check_value(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"object key {key!r} is not a string")
            check_value(key, depth + 1)
            check_value(item, depth + 1)
        return
    raise CanonicalError(f"unsupported type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Return the single canonical byte encoding of ``value`` (v2 policy)."""
    check_value(value, 0)
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:  # pragma: no cover - guarded above
        raise CanonicalError(str(exc)) from exc


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise CanonicalError(f"duplicate object key {key!r}")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise CanonicalError(f"non-finite constant {name}")


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise CanonicalError(f"number {text!r} overflows to a non-finite value")
    return value


def loads_strict(data: str | bytes, *, max_bytes: int = MAX_INPUT_BYTES) -> Any:
    """Parse JSON under the v2 policy; raise :class:`CanonicalError` on any violation."""
    if isinstance(data, bytes | bytearray):
        raw = bytes(data)
        if len(raw) > max_bytes:
            raise CanonicalError(f"input size {len(raw)} exceeds {max_bytes} bytes")
        if raw.startswith(b"\xef\xbb\xbf"):
            raise CanonicalError("UTF-8 byte order mark is not permitted")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CanonicalError("input is not valid UTF-8") from exc
    else:
        text = data
        if len(text.encode("utf-8", errors="replace")) > max_bytes:
            raise CanonicalError(f"input size exceeds {max_bytes} bytes")
        if text.startswith("﻿"):
            raise CanonicalError("byte order mark is not permitted")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
        )
    except CanonicalError:
        raise
    except RecursionError as exc:
        raise CanonicalError(f"nesting deeper than {MAX_DEPTH}") from exc
    except ValueError as exc:
        raise CanonicalError(f"malformed JSON: {exc}") from exc
    # Depth, key types and lone surrogates (json accepts "\ud800") are checked
    # once, on the parsed value, by the same rules the serialiser applies.
    check_value(value, 0)
    return value
