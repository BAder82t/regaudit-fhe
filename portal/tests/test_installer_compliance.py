"""The macOS build's optional licence notices (--compliance-dir), checked with a small made-up notices folder.

Without the option nothing changes. With it, only the files the folder's manifest marks SHIP-CANDIDATE are copied, each
checked against its SHA-256 first, and never anything under evidence/. They go into a visible folder next to the
application on the disk image and into the application itself, with a plain read-me, and READ ME FIRST.txt says where
they are. A Developer ID build refuses notices that still hold a draft placeholder, and needs counsel's sign-off for
exactly this manifest, unless told otherwise. The build manifest records only the status, the number of files and the
hash of the folder's manifest, never a path.
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
        "Evidence/odd-case.txt": "private evidence in a folder named in another case\n",
        "UNLISTED.txt": "not in the manifest\n",
    }
    flags = {
        "PRIVATE_NOTES.md": "PRIVATE-EVIDENCE",
        "evidence/list.txt": "PRIVATE-EVIDENCE",
        "Evidence/odd-case.txt": "PRIVATE-EVIDENCE",
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


def rehash(folder: Path) -> None:
    """Give every line of the folder's manifest the SHA-256 of its file as it is now, flags unchanged."""
    manifest = folder / "bundle-manifest.txt"
    rows = []
    for line in manifest.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            rows.append(line)
            continue
        _sha, flag, name = line.split(maxsplit=2)
        rows.append(f"{hashlib.sha256((folder / name).read_bytes()).hexdigest()}  {flag}  {name}")
    manifest.write_text("\n".join(rows) + "\n")


def sign_off(folder: Path, **lines: str | None) -> Path:
    """Counsel's sign-off for the folder's manifest as it is now; a line given as None is left out."""
    sha = hashlib.sha256((folder / "bundle-manifest.txt").read_bytes()).hexdigest()
    fields = {
        "Bundle revision": "1",
        "Manifest sha256": sha,
        "Counsel name": "A. Made-Up Counsel",
        "Date": "2026-11-09",
        "Scope": "this made-up test folder",
        "Statement": "Approved for this test.",
        **lines,
    }
    path = folder / build_app.SIGNOFF
    path.write_text("".join(f"{k}: {v}\n" for k, v in fields.items() if v is not None))
    return path


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
    assert allowed.draft is True and allowed.overridden is True and allowed.warn is True
    assert allowed.manifest_entries()["compliance"] == "draft, not signed off"


@pytest.mark.parametrize(
    "marker",
    [
        *build_app.COMPLIANCE_MARKERS,
        "[for counsel",  # any case
        "draft for counsel review",
        "[COUNSEL: settle this",
        "[name to be confirmed",  # any bracket about counsel or a confirmation
        "[ask Counsel later",
        "[FOR\nCOUNSEL",  # across a line break
        "DRAFT   FOR\tCOUNSEL",  # other white space
        "\uff3bFOR COUNSEL",  # a fullwidth bracket
        "\uff24\uff32\uff21\uff26\uff34 FOR COUNSEL",  # fullwidth letters
        "(short form, ask counsel)",  # round brackets
        "{counsel: settle}",  # curly brackets
        "\uff08counsel to settle\uff09",  # fullwidth round brackets
        "\u3010counsel\u3011",  # lenticular brackets
        "has Not Been Reviewed By Counsel yet",
        "holder: to be\nconfirmed",
        "TODO: add the contact",
        "the address is TBC",
        "FIXME",
        "This is a Draft.",
    ],
)
def test_each_placeholder_marker_is_caught(tmp_path, marker):
    folder = make_folder(tmp_path)
    (folder / "SOURCE_OFFER.txt").write_text(f"Write to {marker}]\n")
    rehash(folder)
    sign_off(folder)  # so that the placeholder alone is what refuses the build
    with pytest.raises(SystemExit, match="draft placeholders") as refused:
        build_app.check_compliance(
            folder, signed_by=NAME, allow_placeholders=False, without_pip=False
        )
    assert "sign-off is not in order" not in str(refused.value)


def test_the_marker_list_holds_every_marker_the_guard_must_refuse():
    for marker in (
        "[FOR COUNSEL",
        "[contact to be added",
        "[copyright holder to be confirmed",
        "[holder to be confirmed",
        "[Counsel:",
        "DRAFT FOR COUNSEL",
        "not been reviewed by counsel",
        "to be confirmed",
    ):
        assert marker in build_app.COMPLIANCE_MARKERS, marker
        assert build_app.has_placeholder(f"text {marker} more]"), marker
        assert build_app.has_placeholder(f"text {marker.lower()} more]"), marker
        # An explicit marker counts in a licence text too.
        assert build_app.has_placeholder(f"text {marker.upper()} more]", licence_text=True), marker
    assert set(build_app.DRAFT_WORDS) == {"tbc", "todo", "fixme", "draft"}


@pytest.mark.parametrize(
    "text",
    [
        "Copyright [yyyy] [name of copyright owner]",  # the Apache licence's own appendix
        "Licensed under the MIT licence. [See LICENSE.]",
        "Consult your own legal counsel before relying on this.",
        "Copyright (c) 2020 The Authors. All rights reserved.",
        "The drafted text and its todos are not words on their own.",
    ],
)
def test_ordinary_licence_text_is_not_taken_for_a_placeholder(text):
    assert not build_app.has_placeholder(text)
    assert not build_app.has_placeholder(text, licence_text=True)


@pytest.mark.parametrize("word", ["draft", "TODO", "tbc", "FixMe"])
def test_the_draft_words_alone_are_not_looked_for_in_upstream_licence_texts(tmp_path, word):
    """A licence text is a copy of an upstream text, where "draft" can be ordinary prose (the GPL speaks of drafts)."""
    assert build_app.has_placeholder(f"see the {word} here")
    assert not build_app.has_placeholder(f"see the {word} here", licence_text=True)
    folder = make_folder(tmp_path)
    (folder / "licences" / "one" / "LICENSE").write_text(f"An upstream {word} of the licence.\n")
    rehash(folder)
    sign_off(folder)
    compliance = build_app.check_compliance(
        folder, signed_by=NAME, allow_placeholders=False, without_pip=False
    )
    assert (
        compliance.draft is False
        and compliance.status == "no placeholder marker found, sign-off file matches this manifest"
    )


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
    sign_off(folder)
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


# ----------------------------------------------------------------------------- text that cannot be checked


@pytest.mark.parametrize(
    "data",
    [
        "UTF-16 text".encode("utf-16"),  # with its byte order mark
        b"plain\x00text",
        b"caf\xe9 in Latin-1",
    ],
)
def test_a_file_that_is_not_plain_utf8_stops_the_build(tmp_path, data):
    folder = make_folder(tmp_path)
    (folder / "licences" / "two" / "LICENSE").write_bytes(data)
    rehash(folder)
    with pytest.raises(SystemExit, match="cannot be checked as text"):
        build_app.check_compliance(
            folder, signed_by=None, allow_placeholders=False, without_pip=False
        )


# ----------------------------------------------------------------------------- evidence and links


@pytest.mark.parametrize("name", ["evidence/x.txt", "Evidence/x.txt", "EVIDENCE/x.txt"])
def test_a_manifest_that_marks_evidence_to_ship_is_refused_in_any_case(tmp_path, name):
    folder = make_folder(tmp_path)
    (folder / name).parent.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text("private\n")
    sha = hashlib.sha256(b"private\n").hexdigest()
    with open(folder / "bundle-manifest.txt", "a") as manifest:
        manifest.write(f"{sha}  SHIP-CANDIDATE  {name}\n")
    with pytest.raises(SystemExit, match="nothing under evidence/ is ever shipped"):
        build_app.check_compliance(
            folder, signed_by=None, allow_placeholders=False, without_pip=False
        )


def test_private_evidence_in_another_case_is_listed_but_never_copied(tmp_path):
    folder = make_folder(tmp_path)
    compliance = build_app.check_compliance(
        folder, signed_by=None, allow_placeholders=False, without_pip=False
    )
    build_app.write_licences(compliance, tmp_path / "Licences")
    copied = files_under(tmp_path / "Licences")
    assert not any(name.casefold().startswith("evidence/") for name in copied)


@pytest.mark.parametrize("target", ["outside", "inside"])
def test_a_folder_reached_through_a_link_stops_the_build(tmp_path, target):
    folder = make_folder(tmp_path)
    real = folder / "licences" / "one"
    moved = (tmp_path / "elsewhere") if target == "outside" else (folder / "moved-one")
    real.rename(moved)
    os.symlink(moved, real)
    with pytest.raises(SystemExit, match="through a link"):
        build_app.check_compliance(
            folder, signed_by=None, allow_placeholders=False, without_pip=False
        )


# ----------------------------------------------------------------------------- counsel's sign-off


def test_a_resolved_and_signed_off_folder_is_accepted_for_a_developer_id_build(tmp_path):
    folder = make_folder(tmp_path)
    sign_off(folder)
    compliance = build_app.check_compliance(
        folder, signed_by=NAME, allow_placeholders=False, without_pip=False
    )
    assert compliance.signed_off and not compliance.draft and not compliance.overridden
    assert (
        compliance.manifest_entries()["compliance"]
        == "no placeholder marker found, sign-off file matches this manifest"
    )
    build_app.write_licences(compliance, tmp_path / "Licences")
    assert build_app.SIGNOFF not in files_under(tmp_path / "Licences")  # private, never copied


@pytest.mark.parametrize(
    "change, said",
    [
        (None, "there is no COUNSEL_SIGNOFF.txt"),
        ({"Manifest sha256": "0" * 64}, "names another manifest"),
        ({"Manifest sha256": None}, "no single line 'Manifest sha256: <64 hex>'"),
        ({"Counsel name": None, "Counsel": "TBC"}, "placeholder or a draft word"),
        ({"Statement": "todo"}, "placeholder or a draft word"),
        ({"Statement": "Approved (counsel to confirm wording)."}, "placeholder or a draft word"),
        ({"Counsel name": ""}, "no Counsel line filled in"),
        ({"Counsel name": None}, "no Counsel line filled in"),
        ({"Date": "2026-13-40"}, "no Date: YYYY-MM-DD"),
        ({"Date": "9 November 2026"}, "no Date: YYYY-MM-DD"),
        ({"Statement": None}, "no Statement filled in"),
        ({"Statement": "[FOR COUNSEL: wording]"}, "still holds a placeholder"),
    ],
)
def test_a_developer_id_build_needs_counsels_sign_off_for_this_manifest(tmp_path, change, said):
    folder = make_folder(tmp_path)
    if change is not None:
        sign_off(folder, **change)
    with pytest.raises(SystemExit, match="sign-off is not in order") as refused:
        build_app.check_compliance(
            folder, signed_by=NAME, allow_placeholders=False, without_pip=False
        )
    assert said in str(refused.value)
    # An ad hoc build goes ahead, and says it is not signed off.
    ad_hoc = build_app.check_compliance(
        folder, signed_by=None, allow_placeholders=False, without_pip=False
    )
    assert ad_hoc.status == "no placeholder marker found, no matching sign-off file"


def test_a_sign_off_for_an_earlier_manifest_no_longer_counts(tmp_path):
    folder = make_folder(tmp_path)
    sign_off(folder)
    (folder / "licences" / "two" / "LICENSE").write_text("changed licence text\n")
    rehash(folder)  # a changed file means a changed manifest
    with pytest.raises(SystemExit, match="names another manifest"):
        build_app.check_compliance(
            folder, signed_by=NAME, allow_placeholders=False, without_pip=False
        )


def test_a_manifest_that_lists_the_sign_off_is_refused(tmp_path):
    folder = make_folder(tmp_path)
    with open(folder / "bundle-manifest.txt", "a") as manifest:
        manifest.write(f"{'0' * 64}  PRIVATE-EVIDENCE  COUNSEL_SIGNOFF.txt\n")
    with pytest.raises(SystemExit, match="private and never listed"):
        build_app.check_compliance(
            folder, signed_by=None, allow_placeholders=False, without_pip=False
        )


def test_the_override_skips_placeholders_and_sign_off_but_is_recorded_and_said_loudly(tmp_path):
    folder = make_folder(tmp_path)  # complete notices, but no sign-off
    compliance = build_app.check_compliance(
        folder, signed_by=NAME, allow_placeholders=True, without_pip=False
    )
    assert compliance.overridden and compliance.warn
    assert compliance.manifest_entries()["compliance"] == "draft, not signed off"
    assert "counsel has not signed them off" in build_app.draft_warning()
    source = inspect.getsource(build_app.main)
    assert (
        source.count("if compliance.warn:") == 1
        and "compliance.warn:" in source.split("built", 1)[1]
    )


def _manifest_sha(folder: Path) -> str:
    return hashlib.sha256((folder / "bundle-manifest.txt").read_bytes()).hexdigest()


def test_a_hash_outside_the_dedicated_line_does_not_count(tmp_path):
    folder = make_folder(tmp_path)
    sha = _manifest_sha(folder)
    path = sign_off(folder, **{"Manifest sha256": None})
    for extra in (
        f"# Manifest sha256: {sha}\n",  # in a comment
        f"Scope: the folder whose manifest is {sha}\n",  # elsewhere in the text
        f"Bundle manifest sha256: {sha}\n",  # under another name
        f"Manifest sha256: {sha} (current)\n",  # not alone on its line
    ):
        signed = path.read_text()
        path.write_text(signed + extra)
        with pytest.raises(SystemExit, match="no single line 'Manifest sha256: <64 hex>'"):
            build_app.check_compliance(
                folder, signed_by=NAME, allow_placeholders=False, without_pip=False
            )
        path.write_text(signed)


def test_an_upper_case_hash_counts_on_the_dedicated_line_only(tmp_path):
    folder = make_folder(tmp_path)
    sha = _manifest_sha(folder).upper()
    sign_off(folder, **{"Manifest sha256": sha})
    accepted = build_app.check_compliance(
        folder, signed_by=NAME, allow_placeholders=False, without_pip=False
    )
    assert accepted.signed_off is True
    path = sign_off(folder, **{"Manifest sha256": None})
    path.write_text(path.read_text() + f"# Manifest sha256: {sha}\n")
    with pytest.raises(SystemExit, match="no single line"):
        build_app.check_compliance(
            folder, signed_by=NAME, allow_placeholders=False, without_pip=False
        )


def test_two_manifest_lines_are_refused_even_if_one_matches(tmp_path):
    folder = make_folder(tmp_path)
    path = sign_off(folder)
    path.write_text(path.read_text() + f"Manifest sha256: {'0' * 64}\n")
    with pytest.raises(SystemExit, match="no single line"):
        build_app.check_compliance(
            folder, signed_by=NAME, allow_placeholders=False, without_pip=False
        )


def test_the_build_says_the_sign_off_is_a_process_guard_not_legal_approval(tmp_path):
    note = build_app.SIGNOFF_NOTE
    assert "process guard" in note and "not legal authentication or approval" in note
    source = inspect.getsource(build_app.main)
    assert 'print(f"licence notices: {compliance.status}. {SIGNOFF_NOTE}", flush=True)' in source
    folder = make_folder(tmp_path)
    with pytest.raises(SystemExit) as refused:
        build_app.check_compliance(
            folder, signed_by=NAME, allow_placeholders=False, without_pip=False
        )
    assert note in str(refused.value)
    readme = (HERE / "README.md").read_text()
    assert "process guard" in readme and "not legal authentication or approval" in readme
