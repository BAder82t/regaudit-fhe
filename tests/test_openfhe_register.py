"""``regaudit_fhe.fhe.openfhe.register()`` stays callable, and registering it does not need an import cycle."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from regaudit_fhe.fhe import backends, openfhe
from regaudit_fhe.fhe.openfhe import register


def test_register_adds_the_backend_and_is_repeatable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(backends._REGISTRY, "openfhe-ckks", backends._REGISTRY["openfhe-ckks"])
    before = {b.name for b in backends.all_backends()}
    assert register() is None
    assert register() is None
    assert {b.name for b in backends.all_backends()} == before
    backend = backends.get_backend("openfhe-ckks")
    assert backend.experimental is True
    assert backend.available is openfhe.available()


def test_register_without_openfhe_gives_an_unavailable_backend_that_refuses_clearly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(backends._REGISTRY, "openfhe-ckks", backends._REGISTRY["openfhe-ckks"])
    monkeypatch.setattr(openfhe, "_HAVE_OPENFHE", False)
    register()
    backend = backends.get_backend("openfhe-ckks")
    assert backend.available is False
    assert "openfhe-ckks" not in backends.available_backends()
    for use in (backend.require, backend.build_context, lambda: backend.slotvec_cls):
        with pytest.raises(backends.BackendError, match="not available"):
            use()


def _fresh(code: str, *, path: Path | None = None) -> dict[str, object]:
    env = dict(os.environ)
    if path is not None:
        env["PYTHONPATH"] = os.pathsep.join(filter(None, (str(path), env.get("PYTHONPATH"))))
    out = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-c", code], capture_output=True, text=True, env=env, check=True
    )
    return json.loads(out.stdout)


LISTING = (
    "import json; from regaudit_fhe.fhe import backends as b; "
    "print(json.dumps({x.name: x.available for x in b.all_backends()}))"
)


@pytest.mark.parametrize(
    "first_import",
    ["regaudit_fhe.fhe.openfhe", "regaudit_fhe.fhe.backends", "regaudit_fhe.fhe"],
)
def test_the_registry_is_complete_whichever_module_a_process_imports_first(
    first_import: str,
) -> None:
    listing = _fresh(f"import {first_import}; {LISTING}")
    assert set(listing) == {"openfhe-ckks", "tenseal-ckks"}


def test_register_is_callable_first_thing_in_a_new_process() -> None:
    listing = _fresh(f"from regaudit_fhe.fhe.openfhe import register; register(); {LISTING}")
    assert set(listing) == {"openfhe-ckks", "tenseal-ckks"}


@pytest.mark.parametrize(
    ("stub", "expected"),
    [("", True), ("raise OSError('broken native library')\n", False)],
    ids=["importable", "broken"],
)
def test_the_availability_probe_catches_every_import_failure(
    tmp_path: Path, stub: str, expected: bool
) -> None:
    (tmp_path / "openfhe.py").write_text(stub, encoding="utf-8")
    assert _fresh(LISTING, path=tmp_path)["openfhe-ckks"] is expected


def test_backends_does_not_import_openfhe_back() -> None:
    tree = ast.parse(Path(backends.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported |= {node.module or ""} | {alias.name for alias in node.names}
    assert "openfhe" not in imported
