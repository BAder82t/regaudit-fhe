"""What the macOS build says about its own signing is what it really has, and it never states a notarization result.

The default build is signed ad hoc and says exactly what it always said. A build signed with a Developer ID names the
certificate, says it is intended to be notarized, and never tells anyone to bypass macOS. Neither text, nor the manifest,
carries a notarization result, a submission id or a checksum: those belong with a notarized disk image, not in a build.
The build checks the signatures it made against the signing it was asked for, and stops if they disagree.
"""

from __future__ import annotations

import importlib.util
import inspect
import re
import sys
from pathlib import Path

import pytest
from regaudit_portal import engine

HERE = Path(__file__).resolve().parents[1] / "installer" / "macos"
spec = importlib.util.spec_from_file_location("build_app_under_test", HERE / "build_app.py")
build_app = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = build_app
spec.loader.exec_module(build_app)

NAME = "Developer ID Application: VaultBytes Innovations LTD (939QZ58TG5)"
AD_HOC = build_app.read_me_first("0.0.1", None)
DEVELOPER_ID = build_app.read_me_first("0.0.1", NAME)
CLAIMS = (
    "is notarized",
    "has been notarized",
    "was notarized",
    "accepted by apple",
    "was accepted",
    "notarised",
)
EARLIER = ("ae1738f1-de37-4a9e-93a6-7d0b7a93f7db", "52bab7c9", "e50d25de6e9346ee")


def _no_ids_or_checksums(text: str) -> None:
    assert not re.search(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text, re.I
    ), text
    assert not re.search(r"\b[0-9a-f]{32,}\b", text, re.I), text
    for earlier in EARLIER:
        assert earlier not in text


def test_the_ad_hoc_text_says_ad_hoc_and_never_claims_a_developer_id_or_notarization():
    assert "This build is signed only ad hoc. It is not notarized by Apple" in AD_HOC
    assert "Developer ID" not in AD_HOC and "intended to be notarized" not in AD_HOC
    for claim in CLAIMS:
        assert claim not in AD_HOC.lower(), claim


def test_the_developer_id_text_names_the_certificate_and_never_says_ad_hoc_or_open_anyway():
    assert f"This build is signed with {NAME}." in DEVELOPER_ID
    assert "It is intended to be notarized by Apple before it is handed to anyone." in DEVELOPER_ID
    assert "experimental local evaluation build, not a production-qualified release" in DEVELOPER_ID
    assert "answer the usual macOS prompts" in DEVELOPER_ID
    assert (
        "do not bypass the warning" in DEVELOPER_ID and "ask the person who sent it" in DEVELOPER_ID
    )
    lowered = DEVELOPER_ID.lower()
    assert (
        "ad hoc" not in lowered
        and "open anyway" not in lowered
        and "enter your password" not in lowered
    )
    for claim in CLAIMS:
        assert claim not in lowered, claim


def test_no_text_or_manifest_entry_carries_a_submission_id_or_a_checksum():
    for text in (
        AD_HOC,
        DEVELOPER_ID,
        build_app.signing_statement(None),
        build_app.signing_statement(NAME),
        build_app.NOTARIZATION_NOTE,
    ):
        _no_ids_or_checksums(text)
    source = (HERE / "build_app.py").read_text()
    for earlier in EARLIER:
        assert earlier not in source


def test_the_manifest_statement_follows_the_signing_and_states_no_notarization_result():
    assert (
        build_app.signing_statement(None)
        == "ad hoc only. Not signed for distribution and not notarized."
    )
    signed = build_app.signing_statement(NAME)
    assert signed.startswith(NAME) and "not recorded here" in signed and "ad hoc" not in signed
    assert (
        "hardened runtime" in signed
        and "secure timestamp" in signed
        and "no entitlements" in signed
    )
    for text in (signed, build_app.NOTARIZATION_NOTE):
        for claim in CLAIMS:
            assert claim not in text.lower(), claim


def test_both_texts_carry_the_approved_limitation_word_for_word():
    for text in (AD_HOC, DEVELOPER_ID):
        assert engine.SECURITY_LIMITATION in text
        assert text.rstrip("\n").endswith(engine.SECURITY_LIMITATION.rstrip("\n"))


def test_only_a_developer_id_application_certificate_is_accepted():
    assert build_app.team_of(NAME) == "939QZ58TG5"
    for wrong in (
        "Apple Development: Someone (UX5WMAX9UX)",
        "Developer ID Installer: VaultBytes Innovations LTD (939QZ58TG5)",
        "Developer ID Application: VaultBytes Innovations LTD",
        "Developer ID Application: VaultBytes Innovations LTD (939qz58tg5)",
        "-",
    ):
        with pytest.raises(SystemExit):
            build_app.team_of(wrong)


AD_HOC_DETAILS = "Executable=/x/launcher\nIdentifier=launcher\nCodeDirectory v=20400 size=1 flags=0x2(adhoc) hashes=1+0\nSignature=adhoc\nTeamIdentifier=not set\n"
SIGNED_DETAILS = (
    "Executable=/x/launcher\nIdentifier=com.vaultbytes.evidence-verification-portal\n"
    "CodeDirectory v=20500 size=503 flags=0x10000(runtime) hashes=8+3 location=embedded\n"
    f"Signature size=9073\nAuthority={NAME}\nAuthority=Developer ID Certification Authority\nAuthority=Apple Root CA\n"
    "Timestamp=8 Nov 2026 at 2:41:56 pm\nTeamIdentifier=939QZ58TG5\n"
)


def test_the_signature_check_accepts_only_the_signing_that_was_asked_for():
    check = build_app.signature_problem
    assert check(AD_HOC_DETAILS, None, None, True) is None
    assert check(SIGNED_DETAILS, NAME, "939QZ58TG5", True) is None
    assert check(SIGNED_DETAILS, None, None, True) is not None  # the text would say ad hoc
    assert (
        check(AD_HOC_DETAILS, NAME, "939QZ58TG5", True) is not None
    )  # the text would name the certificate
    other = "Developer ID Application: Someone Else (ABCDE12345)"
    assert check(SIGNED_DETAILS, other, "ABCDE12345", True) is not None
    assert check(
        SIGNED_DETAILS.replace("TeamIdentifier=939QZ58TG5", "TeamIdentifier=ZZZZZZZZZZ"),
        NAME,
        "939QZ58TG5",
        True,
    )
    assert check(
        SIGNED_DETAILS.replace("Timestamp=8 Nov 2026 at 2:41:56 pm\n", ""), NAME, "939QZ58TG5", True
    )
    no_runtime = SIGNED_DETAILS.replace("flags=0x10000(runtime)", "flags=0x0(none)")
    assert check(no_runtime, NAME, "939QZ58TG5", True) is not None
    assert check(no_runtime, NAME, "939QZ58TG5", False) is None  # a disk image has no runtime flag


def test_the_build_checks_what_it_signed_in_both_modes_and_keeps_the_ad_hoc_commands():
    source = (HERE / "build_app.py").read_text()
    assert (
        '["codesign", "--force", "--deep", "--sign", "-", str(app)]' in source
    )  # the ad hoc seal, as before
    assert "check_signature(app, None, None)" in source
    assert "check_signature(path, signed_by, team)" in source
    assert "check_signature(dmg, signed_by, team, runtime=False)" in source
    assert (
        "read_me_first(portal_version, signed_by)" in source
        and "signing_statement(signed_by)" in source
    )
    signing = inspect.getsource(build_app.sign_with_developer_id)
    assert '"--timestamp", "--options", "runtime"' in signing
    assert '"--deep", "--sign"' not in signing and "--entitlements" not in signing


def test_the_installer_readme_describes_both_signing_modes_and_no_longer_says_signing_is_not_done():
    readme = (HERE / "README.md").read_text()
    assert (
        "## Signing with a Developer ID" in readme
        and "Signing for distribution (not done)" not in readme
    )
    assert "No Developer ID signature and no notarization." not in readme
    assert "a new build has to be notarized again" in readme
    _no_ids_or_checksums(readme)
