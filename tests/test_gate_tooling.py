"""The test gate itself: the guard must trip when it should and stay quiet when it should.

Unit tests drive ``tests/_gate.py`` with hand-made outcomes. End-to-end tests run a real inner pytest session
(a subprocess, in a scratch directory, with its own manifest) so that a fake mandatory test that skips really
makes the exit status non-zero ("guard-off" evidence), and a declared optional skip really does not.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import _gate, _gate_identity, _gate_manifest

ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------------------------------
# Unit tests on the classifier and the verdict
# ---------------------------------------------------------------------------------------------------


def env(**kw):
    base = dict(
        platform="linux",
        os_name="posix",
        python=(3, 12, 0),
        missing=frozenset({"openfhe"}),
        versions={"tenseal": "0.3.18", "openfhe": None},
        is_root=False,
        require_tenseal=False,
        strict_optional_skips=False,
        root=ROOT,
    )
    base.update(kw)
    return _gate.Environment(**base)


def manifest(sec=None, ten=None, rules=None):
    return SimpleNamespace(
        SECURITY_GATE_MODULES=sec if sec is not None else {"tests/sec.py": {"min_tests": 2}},
        TENSEAL_REQUIRED_MODULES=ten if ten is not None else {},
        EXPECTED_SKIPS=rules if rules is not None else [],
        BACKEND_QUALIFICATION={
            "openfhe-ckks": {
                "module": "openfhe",
                "modules": ["tests/ofhe.py"],
                "not_qualified_because": "no test executed",
            }
        },
        UNTESTED_NOTES=["note"],
    )


MAC_RULE = {
    "id": "macos-acl",
    "kind": "platform",
    "reason": "^macOS ACLs$",
    "nodeid": ["tests/sec.py::*", "tests/other.py::*"],
    "when": {"platform_not": ["darwin"]},
    "gate_ok": True,
}
FASTAPI_RULE = {
    "id": "no-fastapi",
    "kind": "dependency",
    "reason": "could not import 'fastapi'",
    "when": {"missing": ["fastapi"]},
}


def oc(nodeid, outcome, reason="", tier=None):
    return _gate.Outcome(nodeid, outcome, reason, tier)


def run(outcomes, collected, m=None, e=None):
    return _gate.evaluate(outcomes, collected, m or manifest(), e or env())


def codes(ledger):
    return {v["code"] for v in ledger["violations"]}


SEC = _gate.TIER_SECURITY


def test_all_mandatory_tests_passing_passes_the_gate():
    out = [oc("tests/sec.py::a", "passed", tier=SEC), oc("tests/sec.py::b", "passed", tier=SEC)]
    ledger = run(out, {"tests/sec.py": 2})
    assert ledger["verdict"] == "PASS"
    assert ledger["counts"]["required_passed"] == 2
    assert ledger["violations"] == []


def test_guard_off_a_mandatory_test_that_skips_fails_the_gate():
    out = [
        oc("tests/sec.py::a", "passed", tier=SEC),
        oc("tests/sec.py::b", "skipped", "because", SEC),
    ]
    ledger = run(out, {"tests/sec.py": 2})
    assert ledger["verdict"] == "FAIL"
    assert codes(ledger) == {"REQUIRED_UNEXPECTEDLY_SKIPPED"}
    assert ledger["counts"]["required_unexpected_skipped"] == 1


def test_a_mandatory_test_skipped_for_a_missing_dependency_still_fails():
    out = [oc("tests/sec.py::a", "skipped", "could not import 'fastapi': nope", SEC)]
    ledger = run(
        out,
        {"tests/sec.py": 2},
        manifest(rules=[FASTAPI_RULE]),
        env(missing=frozenset({"fastapi"})),
    )
    assert "REQUIRED_UNEXPECTEDLY_SKIPPED" in codes(ledger)
    assert ledger["skips"][0]["blocked_by"] == "fastapi"


def test_a_failed_mandatory_test_fails_the_gate():
    out = [oc("tests/sec.py::a", "failed", tier=SEC), oc("tests/sec.py::b", "passed", tier=SEC)]
    assert "REQUIRED_FAILED" in codes(run(out, {"tests/sec.py": 2}))


def test_an_xfailed_mandatory_test_does_not_count_as_executed():
    out = [oc("tests/sec.py::a", "xfailed", tier=SEC), oc("tests/sec.py::b", "passed", tier=SEC)]
    assert "REQUIRED_FAILED" in codes(run(out, {"tests/sec.py": 2}))


def test_an_optional_skip_declared_for_this_platform_does_not_fail_the_gate():
    out = [
        oc("tests/sec.py::a", "passed", tier=SEC),
        oc("tests/sec.py::b", "passed", tier=SEC),
        oc("tests/other.py::mac", "skipped", "macOS ACLs"),
    ]
    ledger = run(out, {"tests/sec.py": 2}, manifest(rules=[MAC_RULE]))
    assert ledger["verdict"] == "PASS"
    assert ledger["counts"]["intentional_skipped"] == 1
    assert ledger["skips"][0]["rule"] == "macos-acl"


def test_a_declared_platform_skip_of_a_mandatory_test_passes_only_on_that_platform():
    out = [
        oc("tests/sec.py::a", "passed", tier=SEC),
        oc("tests/sec.py::mac", "skipped", "macOS ACLs", SEC),
    ]
    m = manifest(rules=[MAC_RULE])
    on_linux = run(out, {"tests/sec.py": 2}, m, env(platform="linux"))
    assert on_linux["verdict"] == "PASS"
    assert on_linux["counts"]["intentional_skipped"] == 1
    on_mac = run(out, {"tests/sec.py": 2}, m, env(platform="darwin"))
    assert (
        on_mac["verdict"] == "FAIL"
    )  # the test must run on macOS, so the skip is not declared there


def test_a_dependency_skip_is_reported_as_blocked_and_never_declares_a_mandatory_skip():
    rule = dict(FASTAPI_RULE, gate_ok=True)
    out = [oc("tests/other.py::x", "skipped", "could not import 'fastapi': x")]
    ledger = run(
        [
            *out,
            oc("tests/sec.py::a", "passed", tier=SEC),
            oc("tests/sec.py::b", "passed", tier=SEC),
        ],
        {"tests/sec.py": 2},
        manifest(rules=[rule]),
        env(missing=frozenset({"fastapi"})),
    )
    assert ledger["verdict"] == "PASS"
    assert ledger["counts"]["blocked_by_dependency"] == 1
    mandatory = run(
        [oc("tests/sec.py::a", "skipped", "could not import 'fastapi': x", SEC)],
        {"tests/sec.py": 2},
        manifest(rules=[rule]),
        env(missing=frozenset({"fastapi"})),
    )
    assert "REQUIRED_UNEXPECTEDLY_SKIPPED" in codes(mandatory)


def test_an_undeclared_optional_skip_is_reported_and_fails_only_in_strict_mode():
    out = [
        oc("tests/sec.py::a", "passed", tier=SEC),
        oc("tests/sec.py::b", "passed", tier=SEC),
        oc("tests/other.py::x", "skipped", "some new reason"),
    ]
    lenient = run(out, {"tests/sec.py": 2})
    assert lenient["verdict"] == "PASS"
    assert lenient["counts"]["optional_undeclared_skipped"] == 1
    strict = run(out, {"tests/sec.py": 2}, e=env(strict_optional_skips=True))
    assert codes(strict) == {"OPTIONAL_SKIP_NOT_DECLARED"}


def test_a_rule_whose_condition_does_not_hold_declares_nothing():
    out = [
        oc("tests/sec.py::a", "passed", tier=SEC),
        oc("tests/sec.py::b", "passed", tier=SEC),
        oc("tests/other.py::mac", "skipped", "macOS ACLs"),
    ]
    ledger = run(out, {"tests/sec.py": 2}, manifest(rules=[MAC_RULE]), env(platform="darwin"))
    assert ledger["counts"]["optional_undeclared_skipped"] == 1


def test_a_missing_mandatory_module_fails_the_gate():
    ledger = run([], {})
    assert codes(ledger) == {"REQUIRED_TESTS_MISSING"}


def test_a_mandatory_module_with_fewer_tests_than_its_floor_fails_the_gate():
    out = [oc("tests/sec.py::a", "passed", tier=SEC)]
    ledger = run(out, {"tests/sec.py": 1})
    assert codes(ledger) == {"REQUIRED_TESTS_MISSING"}


def test_a_mandatory_module_skipped_at_collection_fails_the_gate_twice_over():
    out = [
        _gate.Outcome(
            "tests/sec.py", "skipped", "could not import 'fastapi'", SEC, module_level=True
        )
    ]
    ledger = run(out, {})
    assert codes(ledger) == {"REQUIRED_UNEXPECTEDLY_SKIPPED", "REQUIRED_TESTS_MISSING"}


def test_the_tenseal_tier_is_mandatory_only_in_require_mode():
    ten = {"tests/fhe.py": {"min_tests": 1}}
    tenseal_skip = oc(
        "tests/fhe.py::t", "skipped", "could not import 'tenseal': x", _gate.TIER_TENSEAL
    )
    rule = {
        "id": "no-tenseal",
        "kind": "dependency",
        "reason": "could not import 'tenseal'",
        "when": {"missing": ["tenseal"]},
    }
    base = [oc("tests/sec.py::a", "passed", tier=SEC), oc("tests/sec.py::b", "passed", tier=SEC)]
    m = manifest(ten=ten, rules=[rule])
    off = run([*base, tenseal_skip], {"tests/sec.py": 2}, m, env(missing=frozenset({"tenseal"})))
    assert off["verdict"] == "PASS"
    assert off["counts"]["blocked_by_dependency"] == 1
    on = run(
        [*base, tenseal_skip],
        {"tests/sec.py": 2},
        m,
        env(missing=frozenset({"tenseal"}), require_tenseal=True),
    )
    assert on["verdict"] == "FAIL"
    assert {
        "TENSEAL_REQUIRED_BUT_MISSING",
        "REQUIRED_UNEXPECTEDLY_SKIPPED",
        "REQUIRED_TESTS_MISSING",
    } <= codes(on)


def test_in_require_mode_a_tenseal_skip_in_an_optional_module_also_fails():
    rule = {
        "id": "x",
        "kind": "dependency",
        "reason": "could not import 'tenseal'",
        "when": {"missing": ["tenseal"]},
    }
    out = [
        oc("tests/sec.py::a", "passed", tier=SEC),
        oc("tests/sec.py::b", "passed", tier=SEC),
        oc("tests/optional.py::t", "skipped", "could not import 'tenseal': x"),
    ]
    ledger = run(out, {"tests/sec.py": 2}, manifest(rules=[rule]), env(require_tenseal=True))
    assert codes(ledger) == {"TENSEAL_TEST_SKIPPED"}


def test_an_unexecuted_backend_is_never_qualified():
    ledger = run([], {})
    b = ledger["backends"]["openfhe-ckks"]
    assert b["status"] == "NOT QUALIFIED"
    skipped = run(
        [oc("tests/ofhe.py", "skipped", "could not import 'openfhe'")],
        {},
        manifest(),
        env(missing=frozenset({"openfhe"})),
    )
    assert skipped["backends"]["openfhe-ckks"]["status"] == "NOT QUALIFIED"
    ran = run([oc("tests/ofhe.py::t", "passed")], {}, manifest(), env(missing=frozenset()))
    assert ran["backends"]["openfhe-ckks"]["status"] == "executed"
    partly = run(
        [oc("tests/ofhe.py::t", "passed"), oc("tests/ofhe.py::u", "skipped", "x")],
        {},
        manifest(),
        env(missing=frozenset()),
    )
    assert partly["backends"]["openfhe-ckks"]["status"] == "NOT QUALIFIED"


def test_an_empty_condition_never_holds_and_an_unknown_key_is_an_error():
    assert not _gate.condition_holds({}, env())
    with pytest.raises(ValueError):
        _gate.condition_holds({"nonsense": 1}, env())


def test_the_ledger_is_json_and_the_text_names_every_violation():
    ledger = run([oc("tests/sec.py::a", "skipped", "r", SEC)], {"tests/sec.py": 2})
    json.dumps(ledger)
    text = _gate.render_text(ledger)
    assert "TEST GATE: FAIL" in text and "REQUIRED_UNEXPECTEDLY_SKIPPED" in text
    assert "NOT QUALIFIED" in text


# ---------------------------------------------------------------------------------------------------
# The reviewed manifest is well formed
# ---------------------------------------------------------------------------------------------------


def test_every_mandatory_module_in_the_manifest_exists_and_has_a_reason():
    for table in (_gate_manifest.SECURITY_GATE_MODULES, _gate_manifest.TENSEAL_REQUIRED_MODULES):
        for module, meta in table.items():
            assert (ROOT / module).is_file(), module
            assert isinstance(meta["min_tests"], int) and meta["min_tests"] > 0
            assert meta["why"], module
    assert not set(_gate_manifest.SECURITY_GATE_MODULES) & set(
        _gate_manifest.TENSEAL_REQUIRED_MODULES
    )


def test_every_expected_skip_rule_is_well_formed():
    ids = [r["id"] for r in _gate_manifest.EXPECTED_SKIPS]
    assert len(ids) == len(set(ids))
    kinds = {*_gate.INTENTIONAL_KINDS, _gate.KIND_DEPENDENCY}
    for r in _gate_manifest.EXPECTED_SKIPS:
        assert r["kind"] in kinds
        assert r["when"], r["id"]
        re.compile(r["reason"])
        _gate.condition_holds(r["when"], env())  # raises on an unknown condition key
        assert r.get("note"), r["id"]
        if r.get("gate_ok"):
            assert r["kind"] in (_gate.KIND_PLATFORM, _gate.KIND_ENVIRONMENT), r["id"]


def test_the_security_gate_marker_is_applied_to_the_listed_modules(tmp_path):
    proc = _inner(
        tmp_path,
        ["tests/test_trust_store_strict_json.py", "--collect-only", "-m", "security_gate", "-q"],
        cwd=ROOT,
        gate=False,
        plugin=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    floor = _gate_manifest.SECURITY_GATE_MODULES["tests/test_trust_store_strict_json.py"][
        "min_tests"
    ]
    assert f"test_trust_store_strict_json.py: {floor}" in proc.stdout


# ---------------------------------------------------------------------------------------------------
# End to end: a real inner pytest session (guard-off evidence)
# ---------------------------------------------------------------------------------------------------


def _inner(tmp_path, args, cwd=None, extra_env=None, gate=True, code=None, plugin=True):
    env_ = {k: v for k, v in os.environ.items() if not k.startswith(("REGAUDIT_", "PYTEST_"))}
    env_["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(ROOT / "src")])
    env_.update(extra_env or {})
    cmd = [sys.executable, "-c", code] if code else [sys.executable, "-m", "pytest"]
    base = [] if code else ["-p", "no:cacheprovider"]
    if plugin and not code:
        base += ["-p", "tests._gate_plugin"]  # in the repo itself tests/conftest.py loads it
    if gate:
        base += ["--gate", "--gate-dir", str(tmp_path / "ledger")]
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [*cmd, *base, *args],
        cwd=cwd or tmp_path,
        env=env_,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


MANIFEST_SRC = """
SECURITY_GATE_MODULES = {{"test_sec.py": {{"min_tests": {floor}, "why": "fake"}}}}
TENSEAL_REQUIRED_MODULES = {{"test_fhe.py": {{"min_tests": 1, "why": "fake"}}}}
EXPECTED_SKIPS = [
    {{"id": "declared", "kind": "environment", "reason": "declared optional skip",
     "when": {{"data_dependent": True}}, "note": "fake"}},
    {{"id": "declared-gate", "kind": "platform", "reason": "declared mandatory skip",
     "nodeid": ["test_sec.py::test_two"],
     "when": {{"platform_not": ["no-such-platform"]}}, "gate_ok": True, "note": "fake"}},
    {{"id": "no-tenseal", "kind": "dependency", "reason": "no TenSEAL here",
     "when": {{"data_dependent": True}}, "blocked_by": "tenseal", "note": "fake"}},
]
BACKEND_QUALIFICATION = {{"openfhe-ckks": {{"module": "openfhe", "modules": ["test_ofhe.py"],
                         "not_qualified_because": "no test executed"}}}}
UNTESTED_NOTES = ["fake"]
SCOPES = {{"full": {{"description": "fake", "full_suite": True}}}}
"""


def _write_inventory(tmp_path):
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [
            sys.executable,
            str(ROOT / "scripts" / "gate_inventory.py"),
            "--write",
            "--no-env-check",
            "--root",
            str(tmp_path),
            "--manifest",
            str(tmp_path / "manifest.py"),
            "--out",
            str(tmp_path / "inventory.json"),
            ".",
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": os.pathsep.join([str(ROOT), str(ROOT / "src")])},
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def _project(tmp_path, sec_body, floor=2, extra_files=None, inventory_from=None):
    """Write the synthetic project. The inventory is generated from ``inventory_from`` (the reviewed, GOOD
    state) when given, else from the files as written; the run is then compared with it."""
    (tmp_path / "pytest.ini").write_text("[pytest]\naddopts = -q\n", encoding="utf-8")
    (tmp_path / "manifest.py").write_text(MANIFEST_SRC.format(floor=floor), encoding="utf-8")
    (tmp_path / "test_fhe.py").write_text("def test_fhe():\n    assert True\n", encoding="utf-8")
    first = inventory_from if inventory_from is not None else sec_body
    (tmp_path / "test_sec.py").write_text(textwrap.dedent(first), encoding="utf-8")
    for name, body in (extra_files or {}).items():
        (tmp_path / name).write_text(textwrap.dedent(body), encoding="utf-8")
    _write_inventory(tmp_path)
    (tmp_path / "test_sec.py").write_text(textwrap.dedent(sec_body), encoding="utf-8")
    return {
        "REGAUDIT_GATE_MANIFEST": str(tmp_path / "manifest.py"),
        "REGAUDIT_GATE_INVENTORY": str(tmp_path / "inventory.json"),
    }


def _ledger(tmp_path):
    return json.loads((tmp_path / "ledger" / "test-gate-ledger.json").read_text(encoding="utf-8"))


GOOD = """
    def test_one():
        assert True

    def test_two():
        assert True
"""


def test_e2e_a_passing_mandatory_suite_exits_zero_and_writes_the_ledger(tmp_path):
    e = _project(tmp_path, GOOD)
    proc = _inner(tmp_path, ["."], extra_env=e)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    ledger = _ledger(tmp_path)
    assert ledger["verdict"] == "PASS"
    assert ledger["counts"]["required_passed"] == 2
    assert (
        (tmp_path / "ledger" / "test-gate-ledger.txt").read_text(encoding="utf-8").startswith("=")
    )


def test_e2e_guard_off_a_mandatory_test_that_skips_makes_the_run_fail(tmp_path):
    e = _project(
        tmp_path,
        """
        import pytest

        def test_one():
            assert True

        @pytest.mark.skip(reason="somebody turned this off")
        def test_two():
            assert True
        """,
    )
    proc = _inner(tmp_path, ["."], extra_env=e)
    assert proc.returncode != 0, proc.stdout
    ledger = _ledger(tmp_path)
    assert ledger["verdict"] == "FAIL"
    assert codes(ledger) == {"REQUIRED_UNEXPECTEDLY_SKIPPED"}
    assert ledger["counts"]["required_unexpected_skipped"] == 1
    assert "UNEXPECTEDLY" in proc.stdout.upper()


def test_e2e_a_mandatory_module_that_cannot_be_imported_is_not_a_quiet_skip(tmp_path):
    e = _project(
        tmp_path,
        """
        import pytest
        pytest.importorskip("no_such_optional_package_xyz")

        def test_one():
            assert True
        """,
        inventory_from=GOOD,
    )
    proc = _inner(tmp_path, ["."], extra_env=e)
    assert proc.returncode != 0
    assert {"REQUIRED_UNEXPECTEDLY_SKIPPED", "REQUIRED_TESTS_MISSING"} <= codes(_ledger(tmp_path))


def test_e2e_a_declared_optional_skip_does_not_fail_the_run(tmp_path):
    e = _project(
        tmp_path,
        GOOD,
        extra_files={
            "test_optional.py": """
            import pytest

            def test_optional():
                pytest.skip("declared optional skip")
            """
        },
    )
    proc = _inner(tmp_path, ["."], extra_env=e)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    ledger = _ledger(tmp_path)
    assert ledger["verdict"] == "PASS"
    assert ledger["counts"]["intentional_skipped"] == 1
    assert ledger["skips"][0]["rule"] == "declared"


def test_e2e_a_mandatory_skip_the_manifest_declares_for_the_platform_passes(tmp_path):
    e = _project(
        tmp_path,
        """
        import pytest

        def test_one():
            assert True

        def test_two():
            pytest.skip("declared mandatory skip")
        """,
    )
    proc = _inner(tmp_path, ["."], extra_env=e)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _ledger(tmp_path)["counts"]["intentional_skipped"] == 1


def test_e2e_deleting_a_mandatory_test_fails_the_run(tmp_path):
    three = GOOD + "\n    def test_three():\n        assert True\n"
    e = _project(tmp_path, GOOD, floor=3, inventory_from=three)
    proc = _inner(tmp_path, ["."], extra_env=e)
    assert proc.returncode != 0
    assert codes(_ledger(tmp_path)) == {"REQUIRED_TESTS_MISSING"}


def test_e2e_a_missing_mandatory_file_fails_the_run(tmp_path):
    e = _project(tmp_path, GOOD)
    (tmp_path / "test_sec.py").unlink()
    proc = _inner(tmp_path, ["."], extra_env=e)
    assert proc.returncode != 0
    assert codes(_ledger(tmp_path)) == {"REQUIRED_TESTS_MISSING", "SCOPE_MODULE_NOT_COLLECTED"}


def test_e2e_a_failing_mandatory_test_fails_the_run(tmp_path):
    e = _project(
        tmp_path,
        """
        def test_one():
            assert True

        def test_two():
            assert False
        """,
    )
    proc = _inner(tmp_path, ["."], extra_env=e)
    assert proc.returncode != 0
    assert "REQUIRED_FAILED" in codes(_ledger(tmp_path))


def test_e2e_without_the_gate_flag_nothing_is_written_and_nothing_is_enforced(tmp_path):
    e = _project(tmp_path, "def test_one():\n    pass\n", floor=9)
    proc = _inner(tmp_path, ["."], extra_env=e, gate=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (tmp_path / "ledger").exists()


def test_e2e_require_tenseal_mode_forbids_a_tenseal_skip(tmp_path):
    fhe_skip = {
        "test_fhe.py": """
        import pytest

        def test_fhe():
            pytest.skip("no TenSEAL here")
        """
    }
    e = _project(tmp_path, GOOD, extra_files=fhe_skip)
    off = _inner(tmp_path, ["."], extra_env=e)
    assert off.returncode == 0, off.stdout + off.stderr
    assert _ledger(tmp_path)["counts"]["blocked_by_dependency"] == 1
    # An empty stand-in package makes TenSEAL importable for the inner run, so this test checks the skip rule
    # whether or not the real package is installed. Without it, a missing TenSEAL makes the gate refuse to start
    # (covered by the next test) and no new ledger is written.
    stub = tmp_path / "tenseal_stub"
    (stub / "tenseal").mkdir(parents=True)
    (stub / "tenseal" / "__init__.py").write_text("", encoding="utf-8")
    on_env = {
        **e,
        "REGAUDIT_REQUIRE_TENSEAL": "1",
        "PYTHONPATH": os.pathsep.join([str(ROOT), str(ROOT / "src"), str(stub)]),
    }
    (
        tmp_path / "ledger" / "test-gate-ledger.json"
    ).unlink()  # a stale ledger must not decide this test
    on = _inner(tmp_path, ["."], extra_env=on_env)
    assert on.returncode != 0
    assert "REQUIRED_UNEXPECTEDLY_SKIPPED" in codes(_ledger(tmp_path))


def test_e2e_require_tenseal_mode_refuses_to_start_when_tenseal_cannot_be_imported(tmp_path):
    e = _project(tmp_path, GOOD)
    code = (
        "import sys\n"
        "sys.modules['tenseal'] = None\n"  # makes find_spec('tenseal') report it as absent
        "import pytest\n"
        "sys.exit(pytest.main(['-p', 'no:cacheprovider', '-p', 'tests._gate_plugin', '--gate', "
        f"'--gate-dir', {str(tmp_path / 'ledger')!r}, '.']))\n"
    )
    proc = _inner(
        tmp_path, [], extra_env={**e, "REGAUDIT_REQUIRE_TENSEAL": "1"}, gate=False, code=code
    )
    assert proc.returncode != 0
    assert "REGAUDIT_REQUIRE_TENSEAL=1" in proc.stderr + proc.stdout


# ---------------------------------------------------------------------------------------------------
# Inventory, scopes and rule scoping (identity-based gate)
# ---------------------------------------------------------------------------------------------------

INVENTORY = ROOT / "tests" / "_gate_inventory.json"


def test_every_gate_ok_rule_names_its_tests_and_anchors_its_reason():
    for r in _gate_manifest.EXPECTED_SKIPS:
        if r.get("gate_ok"):
            assert _gate_identity.rule_is_scoped(r), f"{r['id']}: gate_ok needs a scoped nodeid"
            assert str(r["reason"]).startswith("^"), f"{r['id']}: gate_ok reason must be anchored"
            assert r["kind"] in (_gate.KIND_PLATFORM, _gate.KIND_ENVIRONMENT)
            assert r["note"]


def test_no_data_dependent_rule_can_excuse_a_mandatory_test_unless_it_names_it():
    for r in _gate_manifest.EXPECTED_SKIPS:
        if "data_dependent" in r["when"]:
            assert _gate_identity.rule_is_scoped(r), r["id"]


def test_an_unscoped_rule_never_excuses_a_mandatory_test_even_with_gate_ok():
    unscoped = dict(MAC_RULE, nodeid="*")
    del unscoped["nodeid"]
    for rule in (unscoped, dict(MAC_RULE, nodeid="*"), dict(MAC_RULE, nodeid=["*"])):
        out = [
            oc("tests/sec.py::a", "passed", tier=SEC),
            oc("tests/sec.py::mac", "skipped", "macOS ACLs", SEC),
        ]
        ledger = run(out, {"tests/sec.py": 2}, manifest(rules=[rule]), env(platform="linux"))
        assert "REQUIRED_UNEXPECTEDLY_SKIPPED" in codes(ledger)


def test_a_rule_scoped_to_other_tests_does_not_excuse_this_one():
    rule = dict(MAC_RULE, nodeid=["tests/other.py::*"])
    out = [
        oc("tests/sec.py::a", "passed", tier=SEC),
        oc("tests/sec.py::mac", "skipped", "macOS ACLs", SEC),
    ]
    ledger = run(out, {"tests/sec.py": 2}, manifest(rules=[rule]), env(platform="linux"))
    assert "REQUIRED_UNEXPECTEDLY_SKIPPED" in codes(ledger)


def test_node_id_globs_treat_brackets_literally():
    assert _gate_identity.glob_match("t.py::f[a-b]", "t.py::f[a-b]")
    assert not _gate_identity.glob_match("t.py::f[a]", "t.py::f[a-b]")
    assert _gate_identity.glob_match("t.py::f[x]", "t.py::*")


def test_the_inventory_scopes_match_the_manifest_scopes():
    inv = _gate_identity.load_inventory(INVENTORY)
    assert set(inv["scopes"]) == set(_gate_manifest.SCOPES)
    declared = set(_gate_manifest.SECURITY_GATE_MODULES) | set(
        _gate_manifest.TENSEAL_REQUIRED_MODULES
    )
    assert set(inv["modules"]) == declared
    for name, meta in _gate_manifest.SCOPES.items():
        mods = set(inv["scopes"][name]["modules"])
        assert mods == declared - set(meta.get("exclude_modules", {})), name
        for module, reason in meta.get("exclude_modules", {}).items():
            assert module in declared and reason, (name, module)
    assert inv["scopes"]["full"]["full_suite"] is True
    assert set(inv["scopes"]["full"]["modules"]) == declared


def test_the_count_floors_equal_the_inventory_counts():
    """Floors are only a supplemental diagnostic now, but a stale one would mislead: keep them exact."""
    inv = _gate_identity.load_inventory(INVENTORY)
    for table in (_gate_manifest.SECURITY_GATE_MODULES, _gate_manifest.TENSEAL_REQUIRED_MODULES):
        for module, meta in table.items():
            assert meta["min_tests"] == len(inv["modules"][module]["ids"]), module


def test_every_inventory_id_has_a_body_hash():
    inv = _gate_identity.load_inventory(INVENTORY)
    for module, entry in inv["modules"].items():
        keys = {_gate_identity.function_key(i) for i in entry["ids"]}
        assert keys == set(entry["functions"]), module
        for h in entry["functions"].values():
            assert re.fullmatch(r"[0-9a-f]{64}", h), (module, h)
            assert h != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _facts(**kw):
    inv = {
        "schema": _gate_identity.INVENTORY_SCHEMA,
        "modules": {
            "tests/sec.py": {
                "tier": "security",
                "ids": ["a", "b"],
                "functions": {"a": "h1", "b": "h2"},
            }
        },
        "scopes": {
            "full": {
                "modules": ["tests/sec.py"],
                "full_suite": True,
                "all_modules": ["tests/sec.py"],
            }
        },
    }
    base = dict(
        scope="full",
        inventory=inv,
        selected=["tests/sec.py::a", "tests/sec.py::b"],
        deselected=[],
        hashes={"tests/sec.py::a": "h1", "tests/sec.py::b": "h2"},
        modules_seen={"tests/sec.py"},
    )
    base.update(kw)
    return _gate.RunFacts(**base)


def _run_facts(facts, outcomes=None):
    m = manifest()
    m.SCOPES = {"full": {"description": "d", "full_suite": True}}
    outs = outcomes or [
        oc("tests/sec.py::a", "passed", tier=SEC),
        oc("tests/sec.py::b", "passed", tier=SEC),
    ]
    return _gate.evaluate(outs, {"tests/sec.py": 2}, m, env(), facts)


def test_facts_all_present_executed_and_unchanged_passes_with_a_full_account():
    led = _run_facts(_facts())
    assert led["verdict"] == "PASS"
    sc = led["scope"]
    assert (
        sc["expected"],
        sc["collected"],
        sc["deselected"],
        sc["executed"],
        sc["passed"],
        sc["failed"],
    ) == (2, 2, 0, 2, 2, 0)


def test_facts_a_deselected_mandatory_test_is_named_in_the_ledger():
    led = _run_facts(
        _facts(selected=["tests/sec.py::b"], deselected=["tests/sec.py::a"]),
        [oc("tests/sec.py::b", "passed", tier=SEC)],
    )
    assert {"REQUIRED_TESTS_DESELECTED", "DESELECTED_TESTS"} <= codes(led)
    assert led["scope"]["missing_mandatory"]["deselected"] == ["tests/sec.py::a"]


def test_facts_collected_but_not_executed_fails():
    led = _run_facts(_facts(), [oc("tests/sec.py::a", "passed", tier=SEC)])
    assert "REQUIRED_TESTS_NOT_EXECUTED" in codes(led)
    assert led["scope"]["missing_mandatory"]["not_executed"] == ["tests/sec.py::b"]


def test_facts_a_changed_hash_fails_and_a_stopped_run_fails():
    led = _run_facts(
        _facts(
            hashes={"tests/sec.py::a": "other", "tests/sec.py::b": "h2"},
            stopped="stopping after 1 failures",
        )
    )
    assert {"TEST_BODY_CHANGED", "RUN_STOPPED_EARLY"} <= codes(led)


def test_facts_an_unknown_scope_fails():
    led = _run_facts(_facts(scope="nope"))
    assert "UNKNOWN_SCOPE" in codes(led)


def test_the_body_hash_ignores_formatting_but_not_content():
    a = _gate_identity.normalise_source("    def f():\n        return 1   \n\n")
    b = _gate_identity.normalise_source("def f():\n    return 1\n")
    c = _gate_identity.normalise_source("def f():\n    pass\n")
    assert a == b != c
