#!/usr/bin/env python3
"""Check that a release's identities agree and that the built distributions are complete.

Standard library only; it never imports ``regaudit_fhe`` (it must be able to judge a broken build).

    python scripts/check_release_metadata.py --dist dist [--tag v0.1.0] [--root .]

Checks (any failure exits non-zero with a message):
  * the version written in ``pyproject.toml``, ``regaudit_fhe/__init__.py`` and ``reports.py``
    (``LIB_VERSION``) is one and the same;
  * when ``--tag vX.Y.Z`` is given it equals that version, and the tag has the strict form;
  * ``--dist`` holds exactly one wheel and one sdist, nothing else;
  * wheel METADATA ``Version`` and the sdist ``PKG-INFO`` ``Version`` equal that version;
  * both distributions contain exactly the expected runtime schema files and ``py.typed``;
  * the sdist contains the test helpers and data the test suite needs, so it can run the suite itself.
"""

from __future__ import annotations

import argparse
import re
import sys
import tarfile
import zipfile
from pathlib import Path

PRIMITIVES = ("fairness", "provenance", "concordance", "calibration", "drift", "disagreement")
EXPECTED_SCHEMAS = {"envelope.schema.json", "envelope.v2.schema.json"} | {
    f"{p}.{d}.schema.json" for p in PRIMITIVES for d in ("input", "output")
}
STRICT_TAG = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+)$")


def _first(pattern: str, text: str, what: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise SystemExit(f"FAIL: cannot find {what}")
    return match.group(1)


def source_versions(root: Path) -> dict[str, str]:
    return {
        "pyproject.toml": _first(
            r'^version\s*=\s*"([^"]+)"',
            (root / "pyproject.toml").read_text(encoding="utf-8"),
            "pyproject version",
        ),
        "regaudit_fhe/__init__.py": _first(
            r'^__version__\s*=\s*"([^"]+)"',
            (root / "src/regaudit_fhe/__init__.py").read_text(encoding="utf-8"),
            "__version__",
        ),
        "regaudit_fhe/reports.py": _first(
            r'^LIB_VERSION:\s*str\s*=\s*"([^"]+)"',
            (root / "src/regaudit_fhe/reports.py").read_text(encoding="utf-8"),
            "LIB_VERSION",
        ),
    }


def _schema_names(names: list[str], marker: str) -> set[str]:
    return {Path(n).name for n in names if marker in n and n.endswith(".schema.json")}


DIST_INFO_FILES = {"METADATA", "WHEEL", "RECORD", "entry_points.txt", "top_level.txt"}


def _allowed_wheel_member(name: str, version: str) -> bool:
    """Only package code, the typed marker, the 14 schemas and the standard dist-info files."""
    if name.startswith("regaudit_fhe/"):
        rest = name[len("regaudit_fhe/") :]
        if rest == "py.typed" or (rest.endswith(".py") and ".." not in Path(rest).parts):
            return True
        return (
            rest.startswith("schemas/")
            and Path(rest).name in EXPECTED_SCHEMAS
            and rest.count("/") == 1
        )
    info = f"regaudit_fhe-{version}.dist-info/"
    if name.startswith(info):
        rest = name[len(info) :]
        return rest in DIST_INFO_FILES or (
            rest.startswith("licenses/") and rest.count("/") == 1 and rest != "licenses/"
        )
    return False


def check_wheel(path: Path, version: str) -> list[str]:
    problems: list[str] = []
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        meta = [n for n in names if n.endswith(".dist-info/METADATA")]
        if len(meta) != 1:
            return [f"{path.name}: expected one METADATA file, found {len(meta)}"]
        meta_text = zf.read(meta[0]).decode("utf-8")
        got = _first(r"^Version:\s*(\S+)", meta_text, "wheel Version")
        if _first(r"^Name:\s*(\S+)", meta_text, "wheel Name") != "regaudit-fhe":
            problems.append(f"{path.name}: METADATA Name is not regaudit-fhe")
        stray = [n for n in names if not _allowed_wheel_member(n, version)]
        if stray:
            problems.append(
                f"{path.name}: members outside regaudit_fhe/ and its dist-info: {stray[:5]}"
            )
        if got != version:
            problems.append(f"{path.name}: METADATA Version {got} != {version}")
        schemas = _schema_names(names, "regaudit_fhe/schemas/")
        if schemas != EXPECTED_SCHEMAS:
            problems.append(
                f"{path.name}: schema files differ (missing {sorted(EXPECTED_SCHEMAS - schemas)}, "
                f"unexpected {sorted(schemas - EXPECTED_SCHEMAS)})"
            )
        if "regaudit_fhe/py.typed" not in names:
            problems.append(f"{path.name}: py.typed is missing")
        bad = [n for n in names if n.startswith("/") or ".." in Path(n).parts]
        if bad:
            problems.append(f"{path.name}: unsafe member names {bad[:3]}")
    return problems


def check_sdist(path: Path, version: str) -> list[str]:
    problems: list[str] = []
    with tarfile.open(path) as tf:
        members = tf.getmembers()
        names = [m.name for m in members]
        bad = [m.name for m in members if not (m.isreg() or m.isdir())]
        if bad:
            problems.append(f"{path.name}: non-regular members {bad[:3]}")
        unsafe = [n for n in names if n.startswith("/") or ".." in Path(n).parts]
        if unsafe:
            problems.append(f"{path.name}: unsafe member names {unsafe[:3]}")
        info = [n for n in names if n.count("/") == 1 and n.endswith("/PKG-INFO")]
        if len(info) != 1:
            return [*problems, f"{path.name}: expected one top-level PKG-INFO, found {len(info)}"]
        got_file = tf.extractfile(info[0])
        assert got_file is not None
        pkg_info = got_file.read().decode("utf-8")
        got = _first(r"^Version:\s*(\S+)", pkg_info, "sdist Version")
        if _first(r"^Name:\s*(\S+)", pkg_info, "sdist Name") != "regaudit-fhe":
            problems.append(f"{path.name}: PKG-INFO Name is not regaudit-fhe")
        top = f"regaudit_fhe-{version}"
        stray = [n for n in names if n != top and not n.startswith(top + "/")]
        if stray:
            problems.append(f"{path.name}: members outside {top}/: {stray[:5]}")
        if got != version:
            problems.append(f"{path.name}: PKG-INFO Version {got} != {version}")
        schemas = _schema_names(names, "/src/regaudit_fhe/schemas/")
        if schemas != EXPECTED_SCHEMAS:
            problems.append(
                f"{path.name}: schema files differ (missing {sorted(EXPECTED_SCHEMAS - schemas)}, "
                f"unexpected {sorted(schemas - EXPECTED_SCHEMAS)})"
            )
        if not any(n.endswith("/src/regaudit_fhe/py.typed") for n in names):
            problems.append(f"{path.name}: py.typed is missing")
        needed = (
            "tests/_asgi.py",
            "tests/vectors/report_v2/vectors.json",
            "tests/test_installed_distribution.py",
            "scripts/check_release_metadata.py",
            "scripts/smoke_installed_wheel.py",
            "CHANGELOG.md",
        )
        for suffix in needed:
            if not any(
                n.count("/") == suffix.count("/") + 1 and n.endswith("/" + suffix) for n in names
            ):
                problems.append(
                    f"{path.name}: the sdist cannot run the test suite, {suffix} is missing"
                )
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--dist", required=True, type=Path)
    ap.add_argument(
        "--tag", default="", help="expected tag, strict form vX.Y.Z (omit for a rehearsal)"
    )
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = ap.parse_args(argv)

    problems: list[str] = []
    versions = source_versions(args.root)
    distinct = set(versions.values())
    if len(distinct) != 1:
        problems.append(f"source version strings disagree: {versions}")
    version = next(iter(sorted(distinct)))

    if args.tag:
        match = STRICT_TAG.match(args.tag)
        if not match:
            problems.append(f"tag {args.tag!r} is not of the form vX.Y.Z")
        elif match.group(1) != version:
            problems.append(f"tag {args.tag} does not match the package version {version}")

    files = sorted(p for p in args.dist.iterdir() if p.is_file()) if args.dist.is_dir() else []
    wheels = [p for p in files if p.suffix == ".whl"]
    sdists = [p for p in files if p.name.endswith(".tar.gz")]
    others = [p.name for p in files if p not in wheels and p not in sdists]
    if len(wheels) != 1 or len(sdists) != 1 or others:
        problems.append(
            f"{args.dist} must hold exactly one wheel and one sdist (found {len(wheels)} wheel(s), "
            f"{len(sdists)} sdist(s), other files {others})"
        )
    else:
        problems += check_wheel(wheels[0], version)
        problems += check_sdist(sdists[0], version)

    if problems:
        print("RELEASE CHECK FAILED", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(
        f"release check ok: version {version}; 1 wheel + 1 sdist; {len(EXPECTED_SCHEMAS)} schemas in each"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
