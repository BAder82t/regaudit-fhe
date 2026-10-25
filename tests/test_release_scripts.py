"""scripts/check_release_metadata.py: it must pass a consistent release and refuse each inconsistency."""

from __future__ import annotations

import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_release_metadata.py"
if not SCRIPT.is_file():
    pytest.skip("scripts/ is not part of this checkout", allow_module_level=True)


def _module():
    spec = importlib.util.spec_from_file_location("check_release_metadata", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _module()
SCHEMAS = sorted(M.EXPECTED_SCHEMAS)


def _root(tmp_path: Path, pyproject="0.1.0", init="0.1.0", lib="0.1.0") -> Path:
    root = tmp_path / "root"
    (root / "src/regaudit_fhe").mkdir(parents=True)
    (root / "pyproject.toml").write_text(f'[project]\nname = "x"\nversion = "{pyproject}"\n')
    (root / "src/regaudit_fhe/__init__.py").write_text(f'__version__ = "{init}"\n')
    (root / "src/regaudit_fhe/reports.py").write_text(f'LIB_VERSION: str = "{lib}"\n')
    return root


def _wheel(path: Path, version="0.1.0", schemas=None, py_typed=True):
    names = SCHEMAS if schemas is None else schemas
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            f"regaudit_fhe-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: x\nVersion: {version}\n",
        )
        for n in names:
            zf.writestr(f"regaudit_fhe/schemas/{n}", "{}")
        if py_typed:
            zf.writestr("regaudit_fhe/py.typed", "")


def _sdist(path: Path, version="0.1.0", schemas=None, py_typed=True, extra=None, omit=None):
    top = f"regaudit_fhe-{version}"
    names = SCHEMAS if schemas is None else schemas

    def add(tf, name, data=b""):
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))

    with tarfile.open(path, "w:gz") as tf:
        for support in (
            "tests/_asgi.py",
            "tests/vectors/report_v2/vectors.json",
            "tests/test_installed_distribution.py",
            "scripts/check_release_metadata.py",
            "scripts/smoke_installed_wheel.py",
        ):
            if support not in (omit or ()):
                add(tf, f"{top}/{support}")
        add(tf, f"{top}/PKG-INFO", f"Metadata-Version: 2.4\nName: x\nVersion: {version}\n".encode())
        for n in names:
            add(tf, f"{top}/src/regaudit_fhe/schemas/{n}", b"{}")
        if py_typed:
            add(tf, f"{top}/src/regaudit_fhe/py.typed")
        if extra:
            extra(tf, top)


def _dist(tmp_path: Path, **kw) -> Path:
    d = tmp_path / "dist"
    d.mkdir()
    _wheel(d / "regaudit_fhe-0.1.0-py3-none-any.whl", **kw.get("wheel", {}))
    _sdist(d / "regaudit_fhe-0.1.0.tar.gz", **kw.get("sdist", {}))
    return d


def _run(root, dist, tag="v0.1.0"):
    argv = ["--root", str(root), "--dist", str(dist)]
    if tag:
        argv += ["--tag", tag]
    return M.main(argv)


def test_a_consistent_release_passes(tmp_path, capsys):
    assert _run(_root(tmp_path), _dist(tmp_path)) == 0
    assert "release check ok" in capsys.readouterr().out


def test_a_rehearsal_without_a_tag_passes(tmp_path):
    assert _run(_root(tmp_path), _dist(tmp_path), tag="") == 0


@pytest.mark.parametrize(
    "tag", ["v0.1.1", "0.1.0", "v0.1.0rc1", "refs/tags/v0.1.0", "v0.1", "v0.1.0 "]
)
def test_a_wrong_or_malformed_tag_is_refused(tmp_path, tag):
    assert _run(_root(tmp_path), _dist(tmp_path), tag=tag) == 1


@pytest.mark.parametrize("which", ["pyproject", "init", "lib"])
def test_source_versions_that_disagree_are_refused(tmp_path, which):
    root = _root(tmp_path, **{which: "0.1.1"})
    assert _run(root, _dist(tmp_path)) == 1


def test_a_wheel_with_the_wrong_version_is_refused(tmp_path, capsys):
    assert _run(_root(tmp_path), _dist(tmp_path, wheel={"version": "0.0.8"})) == 1
    assert "METADATA Version 0.0.8" in capsys.readouterr().err


def test_an_sdist_with_the_wrong_version_is_refused(tmp_path):
    assert _run(_root(tmp_path), _dist(tmp_path, sdist={"version": "0.0.8"})) == 1


def test_the_original_defect_a_wheel_without_schemas_is_refused(tmp_path, capsys):
    assert _run(_root(tmp_path), _dist(tmp_path, wheel={"schemas": []})) == 1
    assert "schema files differ" in capsys.readouterr().err


def test_an_sdist_without_one_schema_is_refused(tmp_path):
    assert _run(_root(tmp_path), _dist(tmp_path, sdist={"schemas": SCHEMAS[1:]})) == 1


def test_an_unexpected_schema_file_is_refused(tmp_path):
    assert (
        _run(_root(tmp_path), _dist(tmp_path, wheel={"schemas": [*SCHEMAS, "evil.schema.json"]}))
        == 1
    )


def test_a_wheel_without_py_typed_is_refused(tmp_path):
    assert _run(_root(tmp_path), _dist(tmp_path, wheel={"py_typed": False})) == 1


def test_an_sdist_without_py_typed_is_refused(tmp_path):
    assert _run(_root(tmp_path), _dist(tmp_path, sdist={"py_typed": False})) == 1


def test_extra_files_in_dist_are_refused(tmp_path):
    d = _dist(tmp_path)
    (d / "notes.txt").write_text("x")
    assert _run(_root(tmp_path), d) == 1


def test_two_wheels_are_refused(tmp_path):
    d = _dist(tmp_path)
    _wheel(d / "regaudit_fhe-0.1.0-py2.py3-none-any.whl")
    assert _run(_root(tmp_path), d) == 1


def test_a_missing_dist_directory_is_refused(tmp_path):
    assert _run(_root(tmp_path), tmp_path / "nope") == 1


def test_an_sdist_with_a_symlink_member_is_refused(tmp_path):
    def evil(tf, top):
        ti = tarfile.TarInfo(f"{top}/link")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/passwd"
        tf.addfile(ti)

    assert _run(_root(tmp_path), _dist(tmp_path, sdist={"extra": evil})) == 1


def test_the_real_repository_sources_agree_on_one_version():
    root = SCRIPT.parents[1]
    assert len(set(M.source_versions(root).values())) == 1


@pytest.mark.parametrize(
    "missing",
    ["tests/_asgi.py", "tests/vectors/report_v2/vectors.json", "scripts/smoke_installed_wheel.py"],
)
def test_an_sdist_that_cannot_run_the_test_suite_is_refused(tmp_path, missing, capsys):
    assert _run(_root(tmp_path), _dist(tmp_path, sdist={"omit": [missing]})) == 1
    assert "cannot run the test suite" in capsys.readouterr().err
