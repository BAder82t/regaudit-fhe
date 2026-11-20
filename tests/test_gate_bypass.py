"""Guard-off tests for the test gate: every way to stop the required tests from running must FAIL the gate.

Each test builds a small synthetic project, generates its inventory with ``scripts/gate_inventory.py`` from the
GOOD state, applies one bypass, and runs a real inner pytest session. The gate has to exit non-zero with a clear
code. The positive cases (a full run passes, a declared partial scope passes) are here too.
See ``docs/TEST_GATES.md``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "gate_inventory.py"

pytestmark = pytest.mark.skipif(not SCRIPT.exists(), reason="scripts/ is not part of this checkout")

MANIFEST = """
SECURITY_GATE_MODULES = {
    "test_sec.py": {"min_tests": 4, "why": "fake"},
    "test_other.py": {"min_tests": 1, "why": "fake"},
}
TENSEAL_REQUIRED_MODULES = {"test_fhe.py": {"min_tests": 1, "why": "fake"}}
EXPECTED_SKIPS = [
    {"id": "skip-for-data", "kind": "environment", "reason": "^group degeneracy$",
     "nodeid": ["test_optional.py::*"], "when": {"data_dependent": True}, "note": "fake"},
    {"id": "named-mandatory", "kind": "platform", "reason": "^named mandatory skip$",
     "nodeid": ["test_sec.py::test_two"], "when": {"platform_not": ["no-such-platform"]},
     "gate_ok": True, "note": "fake"},
    {"id": "unscoped-gate-ok", "kind": "platform", "reason": "^unscoped skip$",
     "when": {"platform_not": ["no-such-platform"]}, "gate_ok": True, "note": "fake"},
    {"id": "wide-data", "kind": "environment", "reason": "^wide data skip$",
     "when": {"data_dependent": True}, "gate_ok": True, "note": "fake"},
]
BACKEND_QUALIFICATION = {}
UNTESTED_NOTES = ["fake"]
SCOPES = {
    "full": {"description": "everything", "full_suite": True},
    "partial": {"description": "only test_sec.py", "exclude_modules": {"test_other.py": "not in this CI job"}},
}
"""

FILES = {
    "pytest.ini": "[pytest]\naddopts = -q\n",
    "manifest.py": MANIFEST,
    "test_sec.py": """
        import pytest

        def test_one():
            assert 1 + 1 == 2

        def test_two():
            assert "a".upper() == "A"

        @pytest.mark.parametrize("x", ["a", "b"])
        def test_param(x):
            assert x in ("a", "b")
    """,
    "test_other.py": "def test_other():\n    assert True\n",
    "test_optional.py": "def test_optional():\n    assert True\n",
    "test_fhe.py": "def test_fhe():\n    assert True\n",
}

FILES = {k: textwrap.dedent(v).lstrip("\n") for k, v in FILES.items()}


def _write(project: Path, name: str, body: str) -> None:
    (project / name).write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")


@pytest.fixture(scope="module")
def good_project(tmp_path_factory):
    proj = tmp_path_factory.mktemp("good")
    for name, body in FILES.items():
        _write(proj, name, body)
    env = _base_env()
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [
            sys.executable,
            str(SCRIPT),
            "--write",
            "--no-env-check",
            "--root",
            str(proj),
            "--manifest",
            str(proj / "manifest.py"),
            "--out",
            str(proj / "inventory.json"),
            ".",
        ],
        cwd=proj,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proj


@pytest.fixture
def project(good_project, tmp_path):
    dest = tmp_path / "p"
    shutil.copytree(
        good_project, dest, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache")
    )
    return dest


def _base_env(extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("REGAUDIT_", "PYTEST_"))}
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(ROOT / "src")])
    env.update(extra or {})
    return env


def gate(project, args=(), *, gate_args=("--gate",), extra_env=None, cache=False):
    """Run a real inner pytest in ``project`` with its own manifest and inventory."""
    env = _base_env(
        {
            "REGAUDIT_GATE_MANIFEST": str(project / "manifest.py"),
            "REGAUDIT_GATE_INVENTORY": str(project / "inventory.json"),
            **(extra_env or {}),
        }
    )
    cmd = [sys.executable, "-m", "pytest", "-p", "tests._gate_plugin"]
    if not cache:
        cmd += ["-p", "no:cacheprovider"]
    cmd += [*gate_args, "--gate-dir", str(project / "ledger"), *args]
    return subprocess.run(  # noqa: S603 - fixed argv
        cmd, cwd=project, env=env, capture_output=True, text=True, timeout=300, check=False
    )


def ledger(project):
    return json.loads((project / "ledger" / "test-gate-ledger.json").read_text(encoding="utf-8"))


def codes(project):
    return {v["code"] for v in ledger(project)["violations"]}


def assert_fails(proc, project, *expected_codes):
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    led = ledger(project)
    assert led["verdict"] == "FAIL", out
    assert set(expected_codes) <= codes(project), (codes(project), out)


# ---------------------------------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------------------------------


def test_a_full_run_passes_and_the_ledger_accounts_for_every_required_test(project):
    proc = gate(project, ["."])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    led = ledger(project)
    sc = led["scope"]
    assert led["verdict"] == "PASS"
    assert sc["name"] == "full" and sc["claims_full_suite"] is True
    # test_sec: 4 ids, test_other: 1; the TenSEAL tier (test_fhe) is not required without REGAUDIT_REQUIRE_TENSEAL
    assert (sc["expected"], sc["collected"], sc["deselected"]) == (5, 5, 0)
    assert (sc["executed"], sc["passed"], sc["failed"], sc["skipped"]) == (5, 5, 0, [])
    assert sc["missing_mandatory"] == {"not_collected": [], "deselected": [], "not_executed": []}
    assert sc["unexpected_extra"] == []
    assert led["invocation"]["args"][-1] == "."
    assert "TEST GATE: PASS" in proc.stdout


def test_the_tenseal_tier_identities_are_required_only_in_require_mode(project):
    proc = gate(project, ["."], extra_env={"REGAUDIT_REQUIRE_TENSEAL": "1"})
    if proc.returncode != 0 and "cannot be imported" in proc.stdout + proc.stderr:
        pytest.skip("could not import 'tenseal'")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert ledger(project)["scope"]["expected"] == 6


def test_a_declared_partial_scope_passes_without_claiming_the_full_suite(project):
    (project / "test_other.py").unlink()
    proc = gate(project, ["."], gate_args=("--gate-scope", "partial"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    sc = ledger(project)["scope"]
    assert sc["name"] == "partial" and sc["claims_full_suite"] is False
    assert sc["expected"] == 4
    assert "PARTIAL scope" in proc.stdout


def test_a_partial_scope_is_still_held_to_its_own_identities(project):
    (project / "test_sec.py").unlink()
    proc = gate(project, ["."], gate_args=("--gate-scope", "partial"))
    assert_fails(proc, project, "REQUIRED_TESTS_MISSING")


def test_the_full_scope_fails_when_a_module_the_partial_scope_leaves_out_is_missing(project):
    (project / "test_other.py").unlink()
    proc = gate(project, ["."])
    assert_fails(proc, project, "REQUIRED_TESTS_MISSING", "SCOPE_MODULE_NOT_COLLECTED")


def test_without_the_gate_a_selection_option_is_allowed_and_nothing_is_written(project):
    proc = gate(project, [".", "-k", "not test_one", "-m", "not security_gate"], gate_args=())
    assert proc.returncode in (0, 5), proc.stdout + proc.stderr
    assert not (project / "ledger").exists()
    ok = gate(project, [".", "-m", "security_gate"], gate_args=())
    assert ok.returncode == 0, ok.stdout + ok.stderr


def test_the_environment_switch_enables_the_full_scope(project):
    proc = gate(
        project, [".", "-k", "not test_one"], gate_args=(), extra_env={"REGAUDIT_GATE": "1"}
    )
    assert proc.returncode != 0, proc.stdout


def test_an_unknown_scope_is_refused(project):
    proc = gate(project, ["."], gate_args=("--gate-scope", "no-such-scope"))
    assert proc.returncode != 0
    assert "unknown gate scope" in proc.stdout + proc.stderr
    assert_fails(proc, project, "INVOCATION_REFUSED")


# ---------------------------------------------------------------------------------------------------
# (1) to (6): invocations that stop the required tests from running
# ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        pytest.param([".", "-k", "not test_one"], id="k-expression"),
        pytest.param([".", "--deselect", "test_sec.py::test_one"], id="deselect-nodeid"),
        pytest.param(
            [".", "--deselect", "test_sec.py::test_param[a]"], id="deselect-parametrised-id"
        ),
        pytest.param([".", "-m", "not security_gate"], id="marker-not-security-gate"),
        pytest.param([".", "-m", "security_gate"], id="marker-security-gate-only"),
        pytest.param([".", "--collect-only"], id="collect-only"),
        pytest.param([".", "--co"], id="co-abbreviation"),
        pytest.param([".", "--setup-only"], id="setup-only"),
        pytest.param([".", "--setup-plan"], id="setup-plan"),
    ],
)
def test_a_selection_or_dry_run_option_is_refused_before_anything_runs(project, args):
    proc = gate(project, args)
    assert_fails(proc, project, "INVOCATION_REFUSED")
    assert proc.returncode == 4  # pytest usage error: nothing ran
    assert "refuses this invocation" in proc.stdout + proc.stderr
    assert "passed" not in proc.stdout


def test_addopts_from_the_environment_cannot_smuggle_a_filter_in(project):
    proc = gate(project, ["."], extra_env={"PYTEST_ADDOPTS": "-k 'not test_one'"})
    assert_fails(proc, project, "INVOCATION_REFUSED")


def test_addopts_from_the_ini_file_cannot_smuggle_a_filter_in(project):
    (project / "pytest.ini").write_text(
        "[pytest]\naddopts = -q -k 'not test_one'\n", encoding="utf-8"
    )
    proc = gate(project, ["."])
    assert_fails(proc, project, "INVOCATION_REFUSED")


@pytest.mark.parametrize("flag", ["--lf", "--ff", "--sw", "--sw-skip"])
def test_the_cache_driven_partial_run_options_are_refused(project, flag):
    proc = gate(project, [".", flag], cache=True)
    assert_fails(proc, project, "INVOCATION_REFUSED")


def test_a_partial_scope_refuses_selection_options_too(project):
    (project / "test_other.py").unlink()
    proc = gate(project, [".", "-k", "not test_one"], gate_args=("--gate-scope", "partial"))
    assert_fails(proc, project, "INVOCATION_REFUSED")


@pytest.mark.parametrize(
    "paths",
    [
        pytest.param(["test_other.py"], id="single-file"),
        pytest.param(["test_sec.py"], id="other-single-file"),
        pytest.param(["test_sec.py", "test_other.py"], id="all-mandatory-files-but-not-the-rest"),
        pytest.param(["test_sec.py::test_one", "test_sec.py::test_two"], id="node-ids"),
    ],
)
def test_narrowing_the_suite_by_path_fails_the_gate(project, paths):
    proc = gate(project, paths)
    assert_fails(proc, project)
    out = proc.stdout + proc.stderr
    assert "INVOCATION_REFUSED" in out or {
        "REQUIRED_TESTS_MISSING",
        "SCOPE_MODULE_NOT_COLLECTED",
    } & codes(project)


def test_stopping_at_the_first_failure_is_not_a_full_run(project):
    _write(project, "test_sec.py", FILES["test_sec.py"] + "\ndef test_boom():\n    assert False\n")
    proc = gate(project, [".", "-x"])
    assert_fails(proc, project, "REQUIRED_FAILED")
    c = codes(project)
    assert (
        "RUN_STOPPED_EARLY" in c
        or "REQUIRED_TESTS_NOT_EXECUTED" in c
        or "REQUIRED_TESTS_MISSING" in c
    )


def test_maxfail_truncation_is_recorded_and_fails(project):
    _write(
        project,
        "test_sec.py",
        FILES["test_sec.py"]
        + "\ndef test_a_boom():\n    assert False\n\ndef test_b_boom():\n    assert False\n",
    )
    proc = gate(project, [".", "--maxfail=1"])
    assert_fails(proc, project, "REQUIRED_FAILED", "RUN_STOPPED_EARLY")


# ---------------------------------------------------------------------------------------------------
# (7): collection errors
# ---------------------------------------------------------------------------------------------------


def test_an_import_error_in_a_mandatory_module_fails_the_gate(project):
    _write(project, "test_sec.py", "import no_such_module_xyz\n")
    proc = gate(project, ["."])
    assert proc.returncode != 0
    assert {"REQUIRED_TESTS_MISSING", "COLLECTION_ERROR"} <= codes(project)


def test_a_collection_error_in_an_optional_module_fails_the_gate_even_if_pytest_carries_on(project):
    _write(project, "test_optional.py", "import no_such_module_xyz\n")
    proc = gate(project, [".", "--continue-on-collection-errors"])
    assert_fails(proc, project, "COLLECTION_ERROR")


# ---------------------------------------------------------------------------------------------------
# (8): undeclared skips
# ---------------------------------------------------------------------------------------------------


ONE = "def test_one():\n    assert 1 + 1 == 2\n"


@pytest.mark.parametrize(
    "replacement",
    [
        pytest.param("@pytest.mark.skip(reason='turned off')\n" + ONE, id="skip-marker"),
        pytest.param("def test_one():\n    pytest.skip('in the body')\n", id="skip-in-body"),
        pytest.param(
            "@pytest.fixture\ndef f():\n    pytest.skip('in a fixture')\n\ndef test_one(f):\n    assert True\n",
            id="skip-in-fixture",
        ),
        pytest.param("@pytest.mark.skipif(True, reason='conditional')\n" + ONE, id="skipif"),
        pytest.param(
            "def test_one():\n    pytest.importorskip('no_such_pkg_xyz')\n",
            id="importorskip-in-body",
        ),
        pytest.param("def test_one():\n    pytest.xfail('expected failure')\n", id="xfail"),
    ],
)
def test_an_undeclared_skip_or_xfail_of_a_mandatory_test_fails_the_gate(project, replacement):
    base = textwrap.dedent(FILES["test_sec.py"]).lstrip("\n")
    _write(project, "test_sec.py", base.replace(ONE.strip(), replacement.strip()))
    proc = gate(project, ["."])
    assert proc.returncode != 0, proc.stdout
    assert {"REQUIRED_UNEXPECTEDLY_SKIPPED", "REQUIRED_FAILED"} & codes(project)


def test_a_module_level_importorskip_in_a_mandatory_module_fails_the_gate(project):
    _write(
        project,
        "test_sec.py",
        "import pytest\npytest.importorskip('no_such_pkg_xyz')\n" + FILES["test_sec.py"],
    )
    proc = gate(project, ["."])
    assert_fails(proc, project, "REQUIRED_UNEXPECTEDLY_SKIPPED", "REQUIRED_TESTS_MISSING")


# ---------------------------------------------------------------------------------------------------
# (9): a changed body
# ---------------------------------------------------------------------------------------------------


def test_a_mandatory_test_body_replaced_by_pass_fails_the_gate(project):
    src = FILES["test_sec.py"].replace("assert 1 + 1 == 2", "pass")
    _write(project, "test_sec.py", src)
    proc = gate(project, ["."])
    assert_fails(proc, project, "TEST_BODY_CHANGED")
    assert ledger(project)["scope"]["body_changed"] == ["test_sec.py::test_one"]
    assert ledger(project)["scope"]["passed"] == 5  # the count floor alone would have passed


def test_a_body_change_in_a_parametrised_test_is_caught_for_every_id(project):
    _write(project, "test_sec.py", FILES["test_sec.py"].replace('assert x in ("a", "b")', "pass"))
    proc = gate(project, ["."])
    assert_fails(proc, project, "TEST_BODY_CHANGED")
    assert ledger(project)["scope"]["body_changed"] == [
        "test_sec.py::test_param[a]",
        "test_sec.py::test_param[b]",
    ]


def test_a_formatting_only_change_does_not_change_the_body_hash(project):
    src = FILES["test_sec.py"].replace("assert 1 + 1 == 2", "assert 1 + 1 == 2   \n\n\n")
    _write(project, "test_sec.py", src)
    proc = gate(project, ["."])
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_helper_that_a_test_calls_is_not_covered_by_the_body_hash(project):
    """Documented limit: only the function's own text is hashed."""
    _write(
        project,
        "test_sec.py",
        "def _check():\n    return True\n\n"
        + FILES["test_sec.py"].replace("assert 1 + 1 == 2", "assert _check()"),
    )
    base = gate(project, ["."])
    assert_fails(base, project, "TEST_BODY_CHANGED")  # this edit changed the test's own text...
    _write(
        project,
        "test_sec.py",
        "def _check():\n    return False\n\n"
        + FILES["test_sec.py"].replace("assert 1 + 1 == 2", "assert _check()"),
    )
    # ...but once the inventory is regenerated for the new text, weakening only the helper is invisible.
    regen = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT),
            "--write",
            "--no-env-check",
            "--root",
            str(project),
            "--manifest",
            str(project / "manifest.py"),
            "--out",
            str(project / "inventory.json"),
            ".",
        ],
        cwd=project,
        env=_base_env(),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert regen.returncode == 0, regen.stderr
    _write(
        project,
        "test_sec.py",
        "def _check():\n    return True\n\n"
        + FILES["test_sec.py"].replace("assert 1 + 1 == 2", "assert _check()"),
    )
    proc = gate(project, ["."])
    assert proc.returncode == 0, (
        proc.stdout + proc.stderr
    )  # helper changed, test text did not: not detected


# ---------------------------------------------------------------------------------------------------
# inventory drift, both directions
# ---------------------------------------------------------------------------------------------------


def test_deleting_one_test_and_adding_another_in_the_same_module_is_a_difference(project):
    src = FILES["test_sec.py"].replace("def test_two():", "def test_renamed():")
    _write(project, "test_sec.py", src)
    proc = gate(project, ["."])
    assert_fails(proc, project, "REQUIRED_TESTS_MISSING", "INVENTORY_UNEXPECTED_TESTS")


def test_an_added_test_in_a_mandatory_module_needs_a_reviewed_inventory_update(project):
    _write(project, "test_sec.py", FILES["test_sec.py"] + "\ndef test_new():\n    assert True\n")
    proc = gate(project, ["."])
    assert_fails(proc, project, "INVENTORY_UNEXPECTED_TESTS")


def test_a_new_parametrised_id_is_a_difference(project):
    _write(project, "test_sec.py", FILES["test_sec.py"].replace('["a", "b"]', '["a", "b", "c"]'))
    proc = gate(project, ["."])
    assert_fails(proc, project, "INVENTORY_UNEXPECTED_TESTS")


def test_a_dropped_parametrised_id_is_a_difference(project):
    _write(project, "test_sec.py", FILES["test_sec.py"].replace('["a", "b"]', '["a"]'))
    proc = gate(project, ["."])
    assert_fails(proc, project, "REQUIRED_TESTS_MISSING")


def test_the_inventory_script_check_reports_drift_in_both_directions(project):
    def check():
        return subprocess.run(  # noqa: S603
            [
                sys.executable,
                str(SCRIPT),
                "--check",
                "--no-env-check",
                "--root",
                str(project),
                "--manifest",
                str(project / "manifest.py"),
                "--out",
                str(project / "inventory.json"),
                ".",
            ],
            cwd=project,
            env=_base_env(),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )

    assert check().returncode == 0
    _write(project, "test_sec.py", FILES["test_sec.py"] + "\ndef test_new():\n    assert True\n")
    added = check()
    assert added.returncode == 1 and "collected, not in the inventory" in added.stderr
    _write(project, "test_sec.py", FILES["test_sec.py"].replace("def test_two():", "def test_x():"))
    renamed = check()
    assert renamed.returncode == 1
    assert (
        "in the inventory, not collected" in renamed.stderr
        and "collected, not in the inventory" in renamed.stderr
    )


# ---------------------------------------------------------------------------------------------------
# (10): a skip rule is bound to the tests it names
# ---------------------------------------------------------------------------------------------------


def test_a_data_dependent_rule_for_another_file_cannot_excuse_a_mandatory_test(project):
    # "group degeneracy" is declared, but only for test_optional.py::*
    _write(
        project,
        "test_other.py",
        "def test_other():\n    import pytest\n    pytest.skip('group degeneracy')\n",
    )
    proc = gate(project, ["."])
    assert_fails(proc, project, "REQUIRED_UNEXPECTEDLY_SKIPPED")
    sk = ledger(project)["skips"]
    assert [s["category"] for s in sk] == ["required_unexpected_skipped"]


def test_the_same_reason_on_the_optional_test_the_rule_names_is_declared(project):
    _write(
        project,
        "test_optional.py",
        "def test_optional():\n    import pytest\n    pytest.skip('group degeneracy')\n",
    )
    proc = gate(project, ["."])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert ledger(project)["skips"][0]["rule"] == "skip-for-data"


def test_a_rule_that_names_one_mandatory_test_excuses_that_test_and_no_other(project):
    named = FILES["test_sec.py"].replace(
        "def test_two():",
        "def test_two():\n    import pytest\n    pytest.skip('named mandatory skip')\n    ",
        1,
    )
    _write(project, "test_sec.py", named)
    # test_two changed its own text: regenerate so only the skip decision is under test
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT),
            "--write",
            "--no-env-check",
            "--root",
            str(project),
            "--manifest",
            str(project / "manifest.py"),
            "--out",
            str(project / "inventory.json"),
            ".",
        ],
        cwd=project,
        env=_base_env(),
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    ok = gate(project, ["."])
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert ledger(project)["skips"][0]["rule"] == "named-mandatory"
    # the same reason on a different mandatory test is not excused
    _write(
        project,
        "test_other.py",
        "def test_other():\n    import pytest\n    pytest.skip('named mandatory skip')\n",
    )
    bad = gate(project, ["."])
    assert "REQUIRED_UNEXPECTEDLY_SKIPPED" in codes(project), bad.stdout


@pytest.mark.parametrize("reason", ["unscoped skip", "wide data skip"])
def test_a_gate_ok_rule_with_no_scoped_nodeid_never_excuses_a_mandatory_test(project, reason):
    _write(
        project,
        "test_other.py",
        f"def test_other():\n    import pytest\n    pytest.skip({reason!r})\n",
    )
    proc = gate(project, ["."])
    assert_fails(proc, project, "REQUIRED_UNEXPECTEDLY_SKIPPED")


def test_x_with_everything_passing_is_an_ordinary_full_run(project):
    """-x is not refused: it only matters when it truncates, and then the run is recorded as stopped."""
    proc = gate(project, [".", "-x"])
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_module_the_partial_scope_leaves_out_is_optional_in_that_run(project):
    """test_other.py is mandatory in the full scope; the partial scope declares it out, so its skip is not a violation."""
    _write(
        project,
        "test_other.py",
        "def test_other():\n    import pytest\n    pytest.skip('whatever')\n",
    )
    partial = gate(project, ["."], gate_args=("--gate-scope", "partial"))
    assert partial.returncode == 0, partial.stdout + partial.stderr
    full = gate(project, ["."])
    assert_fails(full, project, "REQUIRED_UNEXPECTEDLY_SKIPPED")
