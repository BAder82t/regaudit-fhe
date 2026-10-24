"""Shared strict RFC 3339 timestamp parsing (dependency-free)."""

from __future__ import annotations

import re
from datetime import datetime

# Date, "T" (or "t"), time with optional fraction of at most 6 digits, and a
# "Z"/"z" or +hh:mm / -hh:mm offset. Basic format, space separators, offsets
# with seconds and sub-microsecond fractions are not accepted.
_RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d{1,6})?"
    r"([Zz]|[+-]\d{2}:\d{2})$"
)


def parse_rfc3339(value: str) -> datetime:
    """Parse a strict RFC 3339 timestamp; it must carry a UTC offset."""
    if not isinstance(value, str) or not _RFC3339.match(value):
        raise ValueError(f"not an RFC 3339 timestamp: {value!r}")
    text = value[:-1] + "+00:00" if value[-1] in "Zz" else value
    text = text.replace("t", "T", 1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"not an RFC 3339 timestamp: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"timestamp {value!r} has no UTC offset")
    return parsed
