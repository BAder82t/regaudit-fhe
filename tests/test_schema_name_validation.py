"""Only exact, known schema names reach the filesystem (CodeQL py/path-injection #38 traced to this).

``load_schema(name)`` is reachable with caller input from ``GET /v1/schemas/{name}`` and
``regaudit-fhe schema NAME``. The path is built only from the two literal names or from a primitive and a
direction that are both members of the fixed ``PRIMITIVES`` / ``DIRECTIONS`` tuples, so no part of the
caller's string can reach the path.
"""

from __future__ import annotations

import pytest

from regaudit_fhe import schemas
from regaudit_fhe.schemas import DIRECTIONS, PRIMITIVES, load_schema

HOSTILE = [
    "", ".", "..", "../envelope", "envelope/../envelope", "envelope.v2/../../x", "envelope.v3", "ENVELOPE",
    "envelope ", "envelope\x00", "fairness", "fairness.", ".input", "fairness.input.json", "fairness.input/..",
    "fairness.input\x00", "fairness.input ", "Fairness.input", "../fairness.input", "fairness../input",
    "fairness.input.schema.json", "/etc/passwd", "C:\\x", "fairness.input\n", "fairness.in\u0435put",
]  # fmt: skip


@pytest.mark.parametrize("name", HOSTILE)
def test_hostile_schema_names_are_refused_before_any_path_is_built(name, monkeypatch):
    def no_dir():
        raise AssertionError("the schemas directory must not be consulted for an unknown name")

    monkeypatch.setattr(schemas, "_schemas_dir", no_dir)
    load_schema.cache_clear()
    try:
        with pytest.raises(KeyError):
            load_schema(name)
    finally:
        load_schema.cache_clear()


def test_every_accepted_name_resolves_inside_the_schemas_directory():
    base = schemas._schemas_dir().resolve()
    for name in schemas.list_schemas():
        load_schema.cache_clear()
        assert load_schema(name)
    for p in PRIMITIVES:
        for d in DIRECTIONS:
            assert (base / f"{p}.{d}.schema.json").resolve().parent == base
