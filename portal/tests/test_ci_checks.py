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
