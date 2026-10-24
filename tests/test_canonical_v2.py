"""Strict canonical JSON policy used by ``report.v2``.

Every refusal has a positive control that differs only in the property under
test.
"""

from __future__ import annotations

import math

import pytest

from regaudit_fhe.canonical import (
    MAX_DEPTH,
    CanonicalError,
    canonical_bytes,
    loads_strict,
)

# ---------------------------------------------------------------------------
# canonical_bytes
# ---------------------------------------------------------------------------


def test_canonical_bytes_is_sorted_compact_utf8():
    assert canonical_bytes({"b": 1, "a": [1, 2], "é": "ü"}) == '{"a":[1,2],"b":1,"é":"ü"}'.encode()


def test_canonical_bytes_distinguishes_int_float_and_bool():
    assert canonical_bytes({"x": 1}) != canonical_bytes({"x": 1.0})
    assert canonical_bytes({"x": 1}) != canonical_bytes({"x": True})


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_canonical_bytes_refuses_non_finite_numbers(bad):
    assert canonical_bytes({"x": 1.5})  # control
    with pytest.raises(CanonicalError):
        canonical_bytes({"x": bad})


def test_canonical_bytes_refuses_non_string_keys():
    """json would silently turn 1 into "1", making {1: a} collide with {"1": a}."""
    assert canonical_bytes({"1": "a"})  # control
    with pytest.raises(CanonicalError):
        canonical_bytes({1: "a"})


def test_canonical_bytes_refuses_nested_non_string_keys():
    with pytest.raises(CanonicalError):
        canonical_bytes({"a": [{2: "x"}]})


def test_canonical_bytes_refuses_lone_surrogates():
    assert canonical_bytes({"x": "\U0001f600"})  # control: a real astral character
    with pytest.raises(CanonicalError):
        canonical_bytes({"x": "\ud800"})


def test_canonical_bytes_refuses_unsupported_types():
    with pytest.raises(CanonicalError):
        canonical_bytes({"x": b"bytes"})
    with pytest.raises(CanonicalError):
        canonical_bytes({"x": {1, 2}})


def test_canonical_bytes_refuses_excessive_depth():
    ok: object = "leaf"
    for _ in range(MAX_DEPTH - 1):
        ok = [ok]
    assert canonical_bytes({"k": ok})
    too_deep: object = "leaf"
    for _ in range(MAX_DEPTH + 5):
        too_deep = [too_deep]
    with pytest.raises(CanonicalError):
        canonical_bytes({"k": too_deep})


# ---------------------------------------------------------------------------
# loads_strict
# ---------------------------------------------------------------------------


def test_loads_strict_parses_plain_json():
    assert loads_strict('{"a": 1, "b": [true, null, 2.5]}') == {"a": 1, "b": [True, None, 2.5]}
    assert loads_strict(b'{"a": "\xc3\xa9"}') == {"a": "é"}


def test_loads_strict_refuses_duplicate_keys():
    assert loads_strict('{"a": 1, "b": 2}')  # control
    with pytest.raises(CanonicalError, match="duplicate"):
        loads_strict('{"a": 1, "a": 2}')


def test_loads_strict_refuses_nested_duplicate_keys():
    with pytest.raises(CanonicalError, match="duplicate"):
        loads_strict('{"outer": {"k": 1, "k": 1}}')


def test_loads_strict_refuses_duplicates_that_differ_only_by_escape():
    """ "a" and "\\u0061" are the same key after decoding."""
    with pytest.raises(CanonicalError, match="duplicate"):
        loads_strict('{"a": 1, "\\u0061": 2}')


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_loads_strict_refuses_non_finite_constants(literal):
    assert loads_strict('{"x": 1}')  # control
    with pytest.raises(CanonicalError):
        loads_strict('{"x": ' + literal + "}")


def test_loads_strict_refuses_overflowing_floats():
    """1e999 parses to inf in plain json.loads without calling parse_constant."""
    with pytest.raises(CanonicalError):
        loads_strict('{"x": 1e999}')


def test_loads_strict_refuses_invalid_utf8():
    assert loads_strict(b'{"x": "ok"}')  # control
    with pytest.raises(CanonicalError):
        loads_strict(b'{"x": "\xff"}')


def test_loads_strict_refuses_utf8_bom():
    with pytest.raises(CanonicalError):
        loads_strict(b'\xef\xbb\xbf{"x": 1}')


def test_loads_strict_refuses_lone_surrogate_escape():
    with pytest.raises(CanonicalError):
        loads_strict('{"x": "\\ud800"}')


def test_loads_strict_refuses_trailing_garbage_and_malformed():
    for text in ('{"x": 1} {"y": 2}', '{"x": 1,}', "", "{"):
        with pytest.raises(CanonicalError):
            loads_strict(text)


def test_loads_strict_refuses_oversized_input():
    with pytest.raises(CanonicalError, match="size"):
        loads_strict('{"x": "' + "a" * 100 + '"}', max_bytes=50)


def test_loads_strict_refuses_excessive_depth():
    deep = "[" * (MAX_DEPTH + 5) + "]" * (MAX_DEPTH + 5)
    with pytest.raises(CanonicalError):
        loads_strict(deep)


def test_roundtrip_is_stable():
    obj = {"b": [1, 2.5, "x"], "a": {"z": None, "y": True}}
    once = canonical_bytes(obj)
    assert canonical_bytes(loads_strict(once)) == once
