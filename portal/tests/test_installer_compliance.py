"""The macOS build's optional licence notices (--compliance-dir), checked with a small made-up notices folder.

Without the option nothing changes. With it, only the files the folder's manifest marks SHIP-CANDIDATE are copied, each
checked against its SHA-256 first, and never anything under evidence/. They go into a visible folder next to the
application on the disk image and into the application itself, with a plain read-me, and READ ME FIRST.txt says where
they are. A Developer ID build refuses notices that still hold a draft placeholder unless told otherwise. The build
manifest records only the status, the number of files and the hash of the folder's manifest, never a path.
"""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1] / "installer" / "macos"
spec = importlib.util.spec_from_file_location("build_app_compliance", HERE / "build_app.py")
build_app = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = build_app
spec.loader.exec_module(build_app)

NAME = "Developer ID Application: Example Ltd (ABCDE12345)"
PLACEHOLDER = "[FOR COUNSEL" + ": something to settle]"
PIP_PART = (
    "PART 3. PIP SECTION (only while pip ships)\n"
    "------------------------------------------\n"
    "===== BEGIN PIP SECTION =====\n"
    "- pip 1.0 | MIT\n"
    "===== END PIP SECTION =====\n"
)


def make_folder(root: Path, *, draft: bool = False, extra_rows: list[str] | None = None) -> Path:
    """A made-up notices folder: notices, a licence text, a source offer, the pip part and folder, private evidence,
    a file the manifest does not list, and the manifest itself."""
    folder = root / "notices"
    files = {
        "THIRD_PARTY_NOTICES.txt": "NOTICES\n\nPART 1. ONE\n- one | MIT\n\nPART 2. TWO\n- two | BSD\n\n"
        + PIP_PART,
        "SOURCE_OFFER.txt": "Source: ask us." + (f" {PLACEHOLDER}" if draft else "") + "\n",
        "licences/one/LICENSE": "MIT licence text\n",
        "licences/two/LICENSE": "BSD licence text\n",
        "pip-section/notices-pip.txt": PIP_PART,
        "pip-section/licences-pip/LICENSE.txt": "pip licence text\n",
        "PRIVATE_NOTES.md": "private notes\n",
        "evidence/list.txt": "private evidence\n",
        "evidence/flagged-ship-by-mistake.txt": "still private\n",
        "UNLISTED.txt": "not in the manifest\n",
    }
    flags = {
        "PRIVATE_NOTES.md": "PRIVATE-EVIDENCE",
        "evidence/list.txt": "PRIVATE-EVIDENCE",
        "evidence/flagged-ship-by-mistake.txt": "SHIP-CANDIDATE",
    }
    rows = ["# sha256  flag  path. A made-up manifest for the test."]
    for name, text in files.items():
        path = folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if name != "UNLISTED.txt":
            sha = hashlib.sha256(text.encode()).hexdigest()
            rows.append(f"{sha}  {flags.get(name, 'SHIP-CANDIDATE')}  {name}")
    rows += extra_rows or []
    (folder / "bundle-manifest.txt").write_text("\n".join(rows) + "\n")
    return folder


def files_under(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}


SHIPPED = {
    "THIRD_PARTY_NOTICES.txt",
    "SOURCE_OFFER.txt",
    "licences/one/LICENSE",
    "licences/two/LICENSE",
    "pip-section/notices-pip.txt",
    "pip-section/licences-pip/LICENSE.txt",
}


# ----------------------------------------------------------------------------- without the option, nothing changes


def test_without_the_option_the_build_is_as_before():
    args = build_app.arguments(["--out", "somewhere"])
    assert args.compliance_dir is None
    assert args.allow_compliance_placeholders is False and args.without_pip_notices is False
    for signed_by in (None, NAME):
        text = build_app.read_me_first("0.0.1", signed_by)
        assert text == build_app.read_me_first("0.0.1", signed_by, False)
        assert "Licences" not in text and "licence" not in text.lower().replace(
            "security limitation", ""
        )
    source = inspect.getsource(build_app.main)
    # Every step of the notices is behind the option.
    for step in (
        "write_licences(compliance,",
        "manifest.update(compliance.manifest_entries())",
        "shutil.copytree(resources / LICENCES_IN_APP, stage / LICENCES_FOLDER)",
    ):
        line = next(ln for ln in source.splitlines() if step in ln)
        before = source[: source.index(line)].rstrip().splitlines()[-1]
        assert "compliance is not None" in before or "licensed" in before, step


def test_the_other_notices_options_need_the_folder():
    source = inspect.getsource(build_app.main)
    assert (
        "--allow-compliance-placeholders and --without-pip-notices need --compliance-dir" in source
    )


# ----------------------------------------------------------------------------- what is copied


def test_only_the_files_marked_to_ship_are_copied_and_never_evidence(tmp_path):
    folder = make_folder(tmp_path)
    compliance = build_app.check_compliance(
        folder, signed_by=None, allow_placeholders=False, without_pip=False
    )
    written = build_app.write_licences(compliance, tmp_path / "Licences")
    assert files_under(tmp_path / "Licences") == SHIPPED | {build_app.LICENCES_README}
    assert set(written) == SHIPPED | {build_app.LICENCES_README}
    for name in SHIPPED:
        assert (tmp_path / "Licences" / name).read_bytes() == (folder / name).read_bytes()
    assert compliance.draft is False


def test_a_file_that_does_not_match_its_hash_stops_everything_before_anything_is_copied(tmp_path):
    folder = make_folder(tmp_path)
    (folder / "licences" / "two" / "LICENSE").write_text("changed\n")
    with pytest.raises(SystemExit, match="does not match the SHA-256"):
        build_app.check_compliance(
            folder, signed_by=None, allow_placeholders=False, without_pip=False
        )
    assert not (tmp_path / "Licences").exists()


def test_a_file_changed_after_the_check_stops_the_copy(tmp_path):
    folder = make_folder(tmp_path)
    compliance = build_app.check_compliance(
        folder, signed_by=None, allow_placeholders=False, without_pip=False
    )
    (folder / "SOURCE_OFFER.txt").write_text("changed after the check\n")
    with pytest.raises(SystemExit, match="does not match the SHA-256"):
        build_app.write_licences(compliance, tmp_path / "Licences")


@pytest.mark.parametrize(
    "row",
    [
        "0" * 64 + "  SHIP-CANDIDATE  ../outside.txt",
        "0" * 64 + "  SHIP-CANDIDATE  /etc/hosts",
        "0" * 64 + "  MAYBE  licences/one/LICENSE",
        "not-a-hash  SHIP-CANDIDATE  x.txt",
    ],
)
def test_a_malformed_manifest_line_stops_the_build(tmp_path, row):
    folder = make_folder(tmp_path, extra_rows=[row])
    with pytest.raises(SystemExit):
        build_app.check_compliance(
            folder, signed_by=None, allow_placeholders=False, without_pip=False
        )


def test_a_listed_file_that_is_a_link_or_missing_stops_the_build(tmp_path):
    folder = make_folder(tmp_path)
    target = folder / "licences" / "one" / "LICENSE"
    data = target.read_bytes()
    target.unlink()
    (tmp_path / "elsewhere").write_bytes(data)
    os.symlink(tmp_path / "elsewhere", target)
    with pytest.raises(SystemExit, match="not a regular file"):
        build_app.check_compliance(
            folder, signed_by=None, allow_placeholders=False, without_pip=False
        )
    target.unlink()
    with pytest.raises(SystemExit, match="not a regular file"):
        build_app.check_compliance(
            folder, signed_by=None, allow_placeholders=False, without_pip=False
        )


def test_a_folder_without_a_manifest_or_without_files_to_ship_is_refused(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(SystemExit, match=r"no bundle-manifest\.txt"):
        build_app.check_compliance(
            empty, signed_by=None, allow_placeholders=False, without_pip=False
        )
    (empty / "bundle-manifest.txt").write_text("# nothing\n")
    with pytest.raises(SystemExit, match="marks no file SHIP-CANDIDATE"):
        build_app.check_compliance(
            empty, signed_by=None, allow_placeholders=False, without_pip=False
        )


# ----------------------------------------------------------------------------- draft placeholders


def test_a_developer_id_build_refuses_draft_notices_unless_told_otherwise(tmp_path):
    folder = make_folder(tmp_path, draft=True)
    with pytest.raises(SystemExit, match="draft placeholders") as refused:
        build_app.check_compliance(
            folder, signed_by=NAME, allow_placeholders=False, without_pip=False
        )
    assert "SOURCE_OFFER.txt" in str(refused.value) and "--allow-compliance-placeholders" in str(
        refused.value
    )
    allowed = build_app.check_compliance(
        folder, signed_by=NAME, allow_placeholders=True, without_pip=False
    )
    assert allowed.draft is True
    assert allowed.manifest_entries()["compliance"] == "draft, contains placeholders"


@pytest.mark.parametrize(
    "marker",
    [
        *build_app.COMPLIANCE_MARKERS,
        "[for counsel",  # any case
        "draft for counsel review",
        "[COUNSEL: settle this",
        "[name to be confirmed",  # any bracket about counsel or a confirmation
        "[ask Counsel later",
    ],
)
def test_each_placeholder_marker_is_caught(tmp_path, marker):
    folder = make_folder(tmp_path)
    offer = folder / "SOURCE_OFFER.txt"
    offer.write_text(f"Write to {marker}]\n")
    manifest = folder / "bundle-manifest.txt"
    rows = [
        (
            f"{hashlib.sha256(offer.read_bytes()).hexdigest()}  SHIP-CANDIDATE  SOURCE_OFFER.txt"
            if line.endswith("  SOURCE_OFFER.txt")
            else line
        )
        for line in manifest.read_text().splitlines()
    ]
    manifest.write_text("\n".join(rows) + "\n")
    with pytest.raises(SystemExit, match="draft placeholders"):
        build_app.check_compliance(
            folder, signed_by=NAME, allow_placeholders=False, without_pip=False
        )


def test_the_marker_list_holds_every_marker_the_guard_must_refuse():
    for marker in (
        "[FOR COUNSEL",
        "[contact to be added",
        "[copyright holder to be confirmed",
        "[holder to be confirmed",
        "[Counsel:",
        "DRAFT FOR COUNSEL",
    ):
        assert marker in build_app.COMPLIANCE_MARKERS, marker
        assert build_app.has_placeholder(f"text {marker} more]"), marker
        assert build_app.has_placeholder(f"text {marker.lower()} more]"), marker


@pytest.mark.parametrize(
    "text",
    [
        "Copyright [yyyy] [name of copyright owner]",  # the Apache licence's own appendix
        "Licensed under the MIT licence. [See LICENSE.]",
        "The counsel of the project is not a placeholder, and nothing here is to be confirmed.",
    ],
)
def test_ordinary_licence_text_is_not_taken_for_a_placeholder(text):
    assert not build_app.has_placeholder(text)


def test_an_ad_hoc_build_takes_draft_notices_and_says_so_loudly(tmp_path):
    folder = make_folder(tmp_path, draft=True)
    compliance = build_app.check_compliance(
        folder, signed_by=None, allow_placeholders=False, without_pip=False
    )
    assert compliance.draft is True
    build_app.write_licences(compliance, tmp_path / "Licences")
    readme = (tmp_path / "Licences" / build_app.LICENCES_README).read_text()
    assert "Some of these files are drafts" in readme
    assert "Do not give this build to anyone." in build_app.draft_warning()
    source = inspect.getsource(build_app.main)
    assert (
        source.count("print(draft_warning(), flush=True)") == 2
    )  # when it starts and when it ends


def test_complete_notices_are_not_called_drafts_and_nothing_claims_compliance(tmp_path):
    folder = make_folder(tmp_path)
    compliance = build_app.check_compliance(
        folder, signed_by=NAME, allow_placeholders=False, without_pip=False
    )
    build_app.write_licences(compliance, tmp_path / "Licences")
    readme = (tmp_path / "Licences" / build_app.LICENCES_README).read_text()
    pointer = build_app.read_me_first("0.0.1", NAME, True)
    entries = json.dumps(compliance.manifest_entries())
    assert "draft" not in readme.lower() and "draft" not in entries
    for text in (readme, pointer, entries):
        for claim in ("compliant", "complies", "compliance is met", "fully licensed", "meets all"):
            assert claim not in text.lower(), claim


# ----------------------------------------------------------------------------- pip notices


def test_without_pip_notices_the_pip_folder_and_the_pip_part_are_left_out(tmp_path):
    folder = make_folder(tmp_path)
    compliance = build_app.check_compliance(
        folder, signed_by=None, allow_placeholders=False, without_pip=True
    )
    build_app.write_licences(compliance, tmp_path / "Licences")
    got = files_under(tmp_path / "Licences")
    assert not any(name.startswith("pip-section/") for name in got)
    notices = (tmp_path / "Licences" / "THIRD_PARTY_NOTICES.txt").read_text()
    assert "PIP SECTION" not in notices and "pip 1.0" not in notices
    assert notices.endswith("PART 2. TWO\n- two | BSD\n")
    assert compliance.manifest_entries()["compliance_pip_notices"] == "left out"
    # The copy is changed, the folder is not.
    assert "PIP SECTION" in (folder / "THIRD_PARTY_NOTICES.txt").read_text()


def test_unclear_pip_markers_stop_the_build(tmp_path):
    folder = make_folder(tmp_path)
    notices = folder / "THIRD_PARTY_NOTICES.txt"
    notices.write_text(notices.read_text() + "===== BEGIN PIP SECTION =====\n")
    manifest = folder / "bundle-manifest.txt"
    sha = hashlib.sha256(notices.read_bytes()).hexdigest()
    rows = [
        f"{sha}  SHIP-CANDIDATE  THIRD_PARTY_NOTICES.txt"
        if line.endswith("  THIRD_PARTY_NOTICES.txt")
        else line
        for line in manifest.read_text().splitlines()
    ]
    manifest.write_text("\n".join(rows) + "\n")
    with pytest.raises(SystemExit, match="exactly one pip part"):
        build_app.check_compliance(
            folder, signed_by=None, allow_placeholders=False, without_pip=True
        )


# ----------------------------------------------------------------------------- where it goes, and what is said


def test_the_folder_goes_next_to_the_application_on_the_disk_image_and_inside_it():
    source = inspect.getsource(build_app.main)
    assert "write_licences(compliance, resources / LICENCES_IN_APP)" in source
    assert "shutil.copytree(resources / LICENCES_IN_APP, stage / LICENCES_FOLDER)" in source
    assert "shutil.copytree(resources / LICENCES_IN_APP, out / LICENCES_FOLDER)" in source
    # Inside the application before it is sealed, and copied out only after.
    assert source.index("write_licences(compliance,") < source.index("# 8. Seal the bundle")
    assert source.index("stage / LICENCES_FOLDER") > source.index("# 8. Seal the bundle")
    assert build_app.LICENCES_FOLDER == "Licences and source"
    assert build_app.LICENCES_IN_APP == "Licences"


def test_the_two_copies_are_the_same_files(tmp_path):
    import shutil

    folder = make_folder(tmp_path)
    compliance = build_app.check_compliance(
        folder, signed_by=None, allow_placeholders=False, without_pip=True
    )
    resources = tmp_path / "Resources"
    resources.mkdir()
    build_app.write_licences(compliance, resources / build_app.LICENCES_IN_APP)
    stage = tmp_path / "stage"
    stage.mkdir()
    shutil.copytree(resources / build_app.LICENCES_IN_APP, stage / build_app.LICENCES_FOLDER)
    inside = resources / build_app.LICENCES_IN_APP
    outside = stage / build_app.LICENCES_FOLDER
    assert files_under(inside) == files_under(outside)
    for name in files_under(inside):
        assert (inside / name).read_bytes() == (outside / name).read_bytes()


@pytest.mark.parametrize("signed_by", [None, NAME])
def test_read_me_first_points_to_the_folder_in_both_signing_modes(signed_by):
    text = build_app.read_me_first("0.0.1", signed_by, True)
    assert "LICENCES AND SOURCE" in text
    assert '"Licences and source" next to the application' in text
    assert "Contents/Resources/Licences" in text
    # It sits before the approved limitation, which still ends the text word for word.
    assert text.index("LICENCES AND SOURCE") < text.index(build_app.approved_limitation())
    assert text.endswith(build_app.approved_limitation() + "\n")


def test_the_developer_id_text_with_notices_still_never_says_ad_hoc_or_open_anyway():
    text = build_app.read_me_first("0.0.1", NAME, True)
    assert "ad hoc" not in text.lower() and "Open Anyway" not in text
    assert f"This build is signed with {NAME}." in text


def test_the_manifest_records_only_the_status_the_count_and_the_manifest_hash(tmp_path):
    folder = make_folder(tmp_path / "private place with a name")
    compliance = build_app.check_compliance(
        folder, signed_by=None, allow_placeholders=False, without_pip=False
    )
    entries = compliance.manifest_entries()
    assert set(entries) == {
        "compliance",
        "compliance_files_copied",
        "compliance_manifest_sha256",
        "compliance_pip_notices",
    }
    assert entries["compliance_files_copied"] == len(SHIPPED)
    assert (
        entries["compliance_manifest_sha256"]
        == hashlib.sha256((folder / "bundle-manifest.txt").read_bytes()).hexdigest()
    )
    text = json.dumps(entries)
    assert "private place" not in text and str(tmp_path) not in text and "/" not in text
