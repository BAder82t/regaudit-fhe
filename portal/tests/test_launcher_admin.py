"""The macOS launcher's Administrator setup: native chooser and alert, no trust logic of its own, and the quit, SIGTERM
and SIGKILL behaviour unchanged. The native dialogs themselves need a person at the screen; this checks the source.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PORTAL = Path(__file__).resolve().parents[1]
SWIFT = PORTAL / "installer" / "macos" / "launcher" / "main.swift"


def test_the_launcher_menu_offers_administrator_setup_with_a_native_chooser_and_alert():
    source = SWIFT.read_text()
    assert (
        'menu.addItem(withTitle: "Administrator setup\\u{2026}", action: #selector(administratorSetup)'
        in source
    )
    assert "NSOpenPanel()" in source and "allowedContentTypes = [.json]" in source
    assert "canChooseDirectories = false" in source and "allowsMultipleSelection = false" in source
    assert "NSAlert()" in source and 'NSTextField(string: "")' in source
    assert "WebKit" not in source and "WKWebView" not in source


def test_the_launcher_runs_describe_then_apply_with_exactly_what_was_typed():
    source = SWIFT.read_text()
    assert 'runTool(["admin-describe", "--json", "--", plan.path])' in source
    assert 'var arguments = ["admin-apply", "--expect-plan-sha256=\\(digest)"]' in source
    assert 'arguments.append("--expect-fingerprint=\\(keyId)=\\(field.stringValue)")' in source
    assert 'arguments += ["--", plan.path]' in source
    assert "p.standardInput = FileHandle.nullDevice" in source
    assert source.count("--expect-fingerprint") == 1 and source.count("admin-apply") >= 1


def test_the_launcher_makes_no_trust_decision_of_its_own():
    source = SWIFT.read_text()
    code = "\n".join(line for line in source.splitlines() if not line.strip().startswith("//"))
    for banned in ("CryptoKit", "CommonCrypto", "CC_SHA256", "SHA256", "Insecure.", "computed_fingerprint",
                   "lowercased()", "uppercased()", "trust-store.json", "portal-config.json", "createDirectory",
                   "createFile", "write(to:", "FileHandle(forWritingAtPath"):  # fmt: skip
        assert banned not in code, banned
    assert not re.search(r"stringValue\s*[=!]=", code), (
        "the launcher must not compare what was typed"
    )
    assert "applied.status == 0" in code  # the only decision: what Python's exit status says


def test_the_launcher_has_no_option_or_variable_that_could_skip_the_typed_fingerprint():
    source = SWIFT.read_text()
    options = source[source.index("func parseOptions()") : source.index("/// A free port")]
    assert set(re.findall(r'case "([^"]+)"', options)) == {"--no-browser", "--print-url", "--"}
    read = set(re.findall(r'env\["(\w+)"\]', source)) | set(
        re.findall(r"for key in \[([^\]]+)\]", source)[0]
        .replace('"', "")
        .replace(" ", "")
        .split(",")
    )
    assert read == {"LANG", "HOME", "USER", "TMPDIR"}


def test_quit_sigterm_and_sigkill_handling_of_the_launcher_are_unchanged():
    source = SWIFT.read_text()
    assert (
        """    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        quitting = true
        guard let p = process, p.isRunning else { return .terminateNow }
        p.terminate()  // SIGTERM: the portal stops cleanly and removes its private bytecode folder
        // Wait here, on the main thread, for up to six seconds. The application is quitting and has no window, and a
        // deferred terminate would need the main queue, which is not serviced while AppKit waits for it.
        let end = Date().addingTimeInterval(6)
        while p.isRunning && Date() < end { Thread.sleep(forTimeInterval: 0.05) }
        if p.isRunning { kill(p.processIdentifier, SIGKILL) }
        return .terminateNow
    }"""
        in source
    )
    assert (
        """        for sig in [SIGTERM, SIGINT, SIGHUP] {
            signal(sig, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            source.setEventHandler { NSApp.terminate(nil) }
            source.resume()
            signalSources.append(source)
        }"""
        in source
    )
    start = source[
        source.index("func startPortal()") : source.index("/// Ask the portal for its status")
    ]
    assert '"--exit-when-input-closes"' in start and "let input = Pipe()" in start
    assert "inputPipe = input" in start and "p.standardInput = input" in start
    assert "if quitting || proc !== process { return }" in source


@pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("swiftc") is None, reason="needs swiftc on macOS"
)
def test_the_launcher_type_checks():
    done = subprocess.run(  # noqa: S603 - the Swift compiler, type-checking only: it writes no output file
        [shutil.which("swiftc") or "swiftc", "-typecheck", "-swift-version", "5", "-target", "arm64-apple-macos14", str(SWIFT)],
        capture_output=True, text=True, timeout=300, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-3000:]
