"""The built distributions must contain the runtime JSON Schemas, and an *installed* copy must work.

Regression for a packaging defect: the wheel and the sdist shipped without ``schemas/*.schema.json``
(they are data files, not Python modules), so an installed package could not validate any payload.
The ordinary suite never noticed because it runs from a source checkout, where the files exist.

These tests therefore build the distributions from a private copy of the packaging inputs, unpack the
wheel into a temporary directory, and exercise it in a subprocess whose working directory is outside
the repository. The subprocess asserts that ``regaudit_fhe`` was imported from the unpacked wheel, not
from the source tree.

They need the ``setuptools>=70.1`` build backend, which the ``dev`` extra provides; nothing is downloaded.
If it is missing the tests are skipped locally and fail under ``CI``, so the guard cannot silently
disappear.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import zipfile
from pathlib import Path

import pytest

from regaudit_fhe.schemas import DIRECTIONS, PRIMITIVES, list_schemas

ROOT = Path(__file__).resolve().parents[1]
PKG_SCHEMAS = ROOT / "src" / "regaudit_fhe" / "schemas"
COPY_ITEMS = (
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "LICENSE-COMMERCIAL.md",
    "MANIFEST.in",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "src",
)


def _expected_schema_files() -> set[str]:
    names = {"envelope.schema.json", "envelope.v2.schema.json"}
    names |= {f"{p}.{d}.schema.json" for p in PRIMITIVES for d in DIRECTIONS}
    return names


def _have_backend(python: str) -> bool:
    probe = "import setuptools, setuptools.build_meta; from setuptools.command import bdist_wheel"
    return (
        subprocess.run(  # noqa: S603 - fixed argv, no shell
            [python, "-c", probe], capture_output=True, check=False
        ).returncode
        == 0
    )


def _give_up(message: str):
    if os.environ.get("CI"):
        pytest.fail(message)
    pytest.skip(message)


def _build(python: str, workdir: Path, kind: str, source: Path) -> Path:
    """Run the PEP 517 backend directly (no network, no `build` package) and return the artifact."""
    out = Path(tempfile.mkdtemp(prefix=f"out-{kind}-", dir=workdir))
    code = f"import sys; from setuptools import build_meta as b; print(b.build_{kind}(sys.argv[1]))"
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [python, "-c", code, str(out)],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        _give_up(f"could not build the {kind}: {proc.stderr.strip()[-400:]}")
    return out / proc.stdout.strip().splitlines()[-1]


def _private_copy(dest: Path) -> Path:
    dest.mkdir()
    for item in COPY_ITEMS:
        src = ROOT / item
        if not src.exists():
            continue
        if src.is_dir():
            shutil.copytree(
                src,
                dest / item,
                ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", "*.pyc"),
            )
        else:
            shutil.copy2(src, dest / item)
    return dest


@pytest.fixture(scope="module")
def dists(tmp_path_factory):
    work = tmp_path_factory.mktemp("dist")
    src = _private_copy(work / "src")
    python = sys.executable
    if not _have_backend(python):
        _give_up(
            'setuptools>=70.1 is not installed in this environment (it is part of the "dev" extra)'
        )
    sdist = _build(python, work, "sdist", src)
    wheel = _build(python, work, "wheel", src)
    # The sdist must be able to produce a wheel on its own.
    unpacked = work / "from-sdist"
    unpacked.mkdir()
    if not hasattr(tarfile, "data_filter"):
        # Never fall back to an unfiltered extraction: the filter is in 3.12+ and was back-ported to
        # 3.10.12 and 3.11.4.
        _give_up(
            "this interpreter's tarfile has no extraction filters (needs 3.10.12+, 3.11.4+ or 3.12+)"
        )
    with tarfile.open(sdist) as tf:
        tf.extractall(unpacked, filter="data")
    (root,) = [p for p in unpacked.iterdir() if p.is_dir()]
    wheel_from_sdist = _build(python, work, "wheel", root)
    return {"work": work, "sdist": sdist, "wheel": wheel, "wheel_from_sdist": wheel_from_sdist}


def _wheel_schema_files(path: Path) -> set[str]:
    with zipfile.ZipFile(path) as zf:
        return {
            Path(n).name
            for n in zf.namelist()
            if n.startswith("regaudit_fhe/schemas/") and n.endswith(".json")
        }


def test_source_tree_has_exactly_the_expected_schema_files():
    assert {p.name for p in PKG_SCHEMAS.glob("*.json")} == _expected_schema_files()
    assert len(list_schemas()) == len(_expected_schema_files())


def test_top_level_schemas_directory_is_identical_to_the_packaged_one():
    """The repository keeps a second copy (the Dockerfile copies it). It must not drift."""
    top = ROOT / "schemas"
    if not top.is_dir():
        pytest.skip("no top-level schemas/ directory (not a source checkout)")
    assert {p.name for p in top.glob("*.json")} == {p.name for p in PKG_SCHEMAS.glob("*.json")}
    for packaged in PKG_SCHEMAS.glob("*.json"):
        assert (top / packaged.name).read_bytes() == packaged.read_bytes(), packaged.name


def test_wheel_contains_every_runtime_schema(dists):
    assert _wheel_schema_files(dists["wheel"]) == _expected_schema_files()


def test_sdist_contains_every_runtime_schema(dists):
    with tarfile.open(dists["sdist"]) as tf:
        names = {
            Path(n).name
            for n in tf.getnames()
            if "/src/regaudit_fhe/schemas/" in n and n.endswith(".json")
        }
    assert names == _expected_schema_files()


def test_wheel_built_from_the_sdist_contains_every_runtime_schema(dists):
    assert _wheel_schema_files(dists["wheel_from_sdist"]) == _expected_schema_files()


_SMOKE = textwrap.dedent(
    """
    import sys, json
    from datetime import datetime, timezone
    from pathlib import Path

    target = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(target))
    import regaudit_fhe as rf
    from regaudit_fhe import schemas

    here = Path(rf.__file__).resolve()
    assert target in here.parents, f"regaudit_fhe was not imported from the unpacked wheel: {here}"
    assert not Path("schemas").exists(), "the working directory must not provide schemas"

    # 1. every schema loads from the installed package
    for name in schemas.list_schemas():
        assert schemas.load_schema(name)["$schema"]
    assert schemas.load_schema("envelope.v2")["$id"].endswith("/v2/envelope.json")

    import numpy as np
    report = rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]), np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]), np.array([0.0, 0.0, 1.0, 1.0]),
    )
    signer = rf.Signer.generate(issuer="smoke", key_id="k1")

    # 2. report.v1: sign, validate against the envelope schema, verify with trust material
    v1 = rf.envelope("fairness", report, signer=signer)
    schemas.validate_envelope(v1.to_dict())
    out = rf.verify_envelope(v1, trusted_keys={"k1": signer.public_key_pem()})
    assert out.trust_status == "TRUSTED", out.trust_status

    # 3. report.v2: sign, validate against its schema, round-trip, verify (self-signed => not accepted)
    v2 = rf.envelope_v2(
        "fairness", report, signer=signer, deployment_id="smoke-dep",
        audit_run_id="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f7",
        issued_at=datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc),
    )
    schemas.validate_envelope_v2(v2.to_dict())
    again = rf.parse_envelope(json.loads(json.dumps(v2.to_dict())))
    res = rf.verify_report(again, rf.VerificationPolicy(allow_self_signed=True))
    assert res.integrity_valid and res.trust_status == "SELF_SIGNED_ONLY" and res.accepted is False

    # 4. input validation (used by every audit) works
    schemas.validate_input("fairness", {
        "y_true": [1, 0], "y_pred": [1, 0], "group_a": [1, 0], "group_b": [0, 1]})
    print("SMOKE-OK", here)
    """
)


def test_installed_wheel_works_outside_the_source_tree(dists, tmp_path):
    target = tmp_path / "site"
    with zipfile.ZipFile(dists["wheel"]) as zf:
        zf.extractall(target)  # noqa: S202 - own wheel built a moment ago
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    assert ROOT not in cwd.resolve().parents
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", _SMOKE, str(target)],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "SMOKE-OK" in proc.stdout


def test_a_wheel_without_schemas_is_detected(dists, tmp_path):
    """Negative control: strip the schemas from an unpacked wheel; the smoke run must fail."""
    target = tmp_path / "site"
    with zipfile.ZipFile(dists["wheel"]) as zf:
        zf.extractall(target)  # noqa: S202 - own wheel built a moment ago
    shutil.rmtree(target / "regaudit_fhe" / "schemas")
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", _SMOKE, str(target)],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "schemas directory is missing" in proc.stderr


def test_loader_ignores_a_schemas_directory_in_the_working_directory(dists, tmp_path):
    """No silent fallback: a ./schemas directory next to the caller must not stand in for the package's."""
    target = tmp_path / "site"
    with zipfile.ZipFile(dists["wheel"]) as zf:
        zf.extractall(target)  # noqa: S202 - own wheel built a moment ago
    shutil.rmtree(target / "regaudit_fhe" / "schemas")
    cwd = tmp_path / "elsewhere"
    (cwd / "schemas").mkdir(parents=True)
    for f in PKG_SCHEMAS.glob("*.json"):
        shutil.copy2(f, cwd / "schemas" / f.name)
    code = (
        "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]);"
        "from regaudit_fhe.schemas import load_schema;"
        "load_schema('envelope.v2')"
    )
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code, str(target)],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0 and "FileNotFoundError" in proc.stderr


# --- scripts/smoke_installed_wheel.py: it must pass on a real installed wheel and refuse each misuse ------------

SMOKE = ROOT / "scripts" / "smoke_installed_wheel.py"
_RUNNER = (
    "import runpy, sys; sys.path.insert(0, sys.argv[1]); sys.argv = [sys.argv[0]] + sys.argv[2:];"
    f"runpy.run_path({str(SMOKE)!r}, run_name='__main__')"
)


def _smoke(
    dists,
    tmp_path,
    *,
    folder="site-packages",
    version="0.0.901",
    forbid=(),
    schemas_in_cwd=False,
    strip=False,
):
    target = tmp_path / folder
    with zipfile.ZipFile(dists["wheel"]) as zf:
        zf.extractall(target)  # noqa: S202 - own wheel built a moment ago
    if strip:
        shutil.rmtree(target / "regaudit_fhe" / "schemas")
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    if schemas_in_cwd:
        (cwd / "schemas").mkdir()
    argv = [sys.executable, "-c", _RUNNER, str(target), "--version", version]
    for f in forbid:
        argv += ["--forbid-path", str(f)]
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)  # noqa: S603


@pytest.mark.skipif(not SMOKE.is_file(), reason="scripts/ is not part of this checkout")
class TestSmokeScript:
    def test_passes_on_an_unpacked_wheel(self, dists, tmp_path):
        r = _smoke(dists, tmp_path)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "smoke ok" in r.stdout

    def test_refuses_a_wrong_expected_version(self, dists, tmp_path):
        r = _smoke(dists, tmp_path, version="9.9.9")
        assert r.returncode != 0 and "installed version" in r.stderr

    def test_refuses_a_package_that_is_not_in_site_packages(self, dists, tmp_path):
        r = _smoke(dists, tmp_path, folder="somewhere-else")
        assert r.returncode != 0 and "not in site-packages" in r.stderr

    def test_refuses_a_package_inside_a_forbidden_path(self, dists, tmp_path):
        r = _smoke(dists, tmp_path, forbid=[tmp_path])
        assert r.returncode != 0 and "imported from" in r.stderr

    def test_refuses_a_working_directory_that_provides_schemas(self, dists, tmp_path):
        r = _smoke(dists, tmp_path, schemas_in_cwd=True)
        assert r.returncode != 0 and "must not contain a schemas/" in r.stderr

    def test_fails_on_a_wheel_without_its_schemas(self, dists, tmp_path):
        r = _smoke(dists, tmp_path, strip=True)
        assert r.returncode != 0 and "FileNotFoundError" in r.stderr
