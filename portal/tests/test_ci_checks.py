"""The Portal CI job fails on an unexpected skip, a failure or a missing test: check the checker itself."""

import importlib.util
import textwrap
from pathlib import Path

CI = Path(__file__).resolve().parents[1] / "ci"
spec = importlib.util.spec_from_file_location("check_skips", CI / "check_skips.py")
check_skips = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_skips)


def junit(tmp_path, body):
    path = tmp_path / "junit.xml"
    path.write_text(
        f'<testsuites><testsuite name="x">{textwrap.dedent(body)}</testsuite></testsuites>'
    )
    return path


def test_all_passing_is_accepted(tmp_path):
    xml = junit(tmp_path, '<testcase classname="a" name="t1"/><testcase classname="a" name="t2"/>')
    assert check_skips.check(xml, [], 2) == []


def test_an_unexpected_skip_is_a_problem(tmp_path):
    xml = junit(
        tmp_path,
        '<testcase classname="a" name="t1"/><testcase classname="a" name="t2"><skipped message="node missing"/></testcase>',
    )
    problems = check_skips.check(xml, [], 1)
    assert any("unexpected skip" in p for p in problems)


def test_a_listed_skip_reason_is_accepted(tmp_path):
    xml = junit(
        tmp_path,
        '<testcase classname="a" name="t1"/><testcase classname="a" name="t2"><skipped message="root can read any file"/></testcase>',
    )
    assert check_skips.check(xml, ["^root can read"], 1) == []


def test_too_few_tests_is_a_problem(tmp_path):
    xml = junit(tmp_path, '<testcase classname="a" name="t1"/>')
    assert any("at least 5" in p for p in check_skips.check(xml, [], 5))


def test_a_failure_is_a_problem(tmp_path):
    xml = junit(tmp_path, '<testcase classname="a" name="t1"><failure message="x"/></testcase>')
    assert any("failed" in p for p in check_skips.check(xml, [], 0))


def test_the_lock_pins_every_package_by_hash_and_the_published_engine():
    text = (CI / "requirements-ci.lock").read_text()
    pins = [ln for ln in text.splitlines() if "==" in ln and not ln.startswith("#")]
    assert len(pins) >= 30
    assert "regaudit-fhe==0.2.1 \\" in text
    assert text.count("--hash=sha256:") == len(pins)
    assert not any(">" in ln or "<" in ln or "~=" in ln for ln in pins)


WORKFLOW = CI.parents[1] / ".github" / "workflows" / "portal.yml"
TESTS = Path(__file__).resolve().parent


def pins(text):
    """Each pinned line with the hash line that follows it."""
    rows = text.splitlines()
    return [(ln, rows[i + 1]) for i, ln in enumerate(rows) if "==" in ln and not ln.startswith("#")]


def test_the_launcher_lock_is_pytest_alone_copied_from_the_ci_lock():
    launcher = pins((CI / "requirements-launcher.lock").read_text())
    whole = pins((CI / "requirements-ci.lock").read_text())
    assert [ln.split("==")[0] for ln, _ in launcher] == [
        "Pygments",
        "iniconfig",
        "packaging",
        "pluggy",
        "pytest",
    ]
    for row in launcher:
        assert row in whole, row  # the same version and the same hash, byte for byte
        assert row[1].strip().startswith("--hash=sha256:")


def test_the_one_allowed_skip_is_the_swift_type_check():
    assert check_skips.lines(CI / "allowed_skips.txt") == ["^needs swiftc on macOS$"]
    # The reason is written in two places: the type check (test_launcher_admin.py) and the native launcher runs
    # (test_launcher_instance.py, one marker shared by its tests). Both need the Swift compiler.
    reason = "reason=" + '"needs swiftc on macOS"'
    users = {p.name: p.read_text().count(reason) for p in TESTS.glob("test_*.py")}
    assert {name: n for name, n in users.items() if n} == {
        "test_launcher_admin.py": 1,
        "test_launcher_instance.py": 1,
    }


def test_the_macos_job_runs_the_type_check_alone_with_no_skip_allowed():
    text = WORKFLOW.read_text()
    linux, macos = text.split("\n  launcher-macos:\n")
    assert "runs-on: macos-" in macos and "runs-on: ubuntu-" in linux
    # The same pinned actions as the ubuntu job, and nothing installed but the hash-pinned lock.
    for action in (
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
    ):
        assert action in linux and action in macos
    installs = [ln for ln in macos.splitlines() if "pip install" in ln]
    assert installs == [
        '          "$RUNNER_TEMP/venv/bin/python" -m pip install --require-hashes --only-binary=:all: --no-deps '
        "--no-cache-dir -r portal/ci/requirements-launcher.lock"
    ]
    assert (
        '"$GITHUB_WORKSPACE/portal/tests/test_launcher_admin.py::test_the_launcher_type_checks" --noconftest'
        in macos
    )
    assert macos.count("-m pytest") == 1
    assert (
        'check_skips.py "$RUNNER_TEMP/launcher-junit.xml" /dev/null "$RUNNER_TEMP/minimum.txt"'
        in macos
    )
    assert "printf '1\\n' > \"$RUNNER_TEMP/minimum.txt\"" in macos


def test_with_no_allowed_reason_the_type_check_may_not_be_skipped(tmp_path):
    xml = junit(
        tmp_path,
        '<testcase classname="tests.test_launcher_admin" name="test_the_launcher_type_checks">'
        '<skipped message="needs swiftc on macOS"/></testcase>',
    )
    problems = check_skips.check(xml, check_skips.lines(Path("/dev/null")), 1)
    assert any("unexpected skip" in p for p in problems)
    assert any("at least 1" in p for p in problems)
