"""The reviewed data behind the test gate. Edit it deliberately, in review: it is the list of what must run.

See ``docs/TEST_GATES.md``. Nothing here changes product behaviour."""

from __future__ import annotations

# Mandatory security modules. Every test in them carries the ``security_gate`` marker (applied by the plugin, so the
# test files need no edit). ``min_tests`` is the number collected when the list was reviewed: a mandatory module
# that collects fewer fails the gate, so deleting a security test cannot pass silently. Raise it when tests are added;
# lowering it needs a stated reason in the commit.
SECURITY_GATE_MODULES: dict[str, dict[str, object]] = {
    # storage policy (a strict profile refuses a store another account can change)
    "tests/test_storage_policy_paths.py": {"min_tests": 100, "why": "storage policy"},
    "tests/test_trust_store_storage_policy.py": {"min_tests": 89, "why": "storage policy"},
    "tests/test_replay_storage_policy.py": {"min_tests": 85, "why": "storage policy"},
    # trust store (enrolment, lifecycle, issuer binding, strict parsing)
    "tests/test_trust_store.py": {"min_tests": 19, "why": "trust store"},
    "tests/test_trust_entries.py": {"min_tests": 35, "why": "trust store"},
    "tests/test_trust_hardening.py": {"min_tests": 30, "why": "trust store"},
    "tests/test_trust_history_floor.py": {"min_tests": 17, "why": "trust store"},
    "tests/test_trust_lifecycle.py": {"min_tests": 31, "why": "trust store"},
    "tests/test_trust_lifecycle_qualification.py": {"min_tests": 283, "why": "trust store"},
    "tests/test_trust_store_exact_class.py": {"min_tests": 29, "why": "trust store"},
    "tests/test_trust_store_strict_json.py": {"min_tests": 7, "why": "trust store"},
    "tests/test_f09_development_label.py": {"min_tests": 15, "why": "trust store"},
    "tests/test_f09_issuer_substitution.py": {"min_tests": 74, "why": "trust store"},
    "tests/test_f09_store_migration.py": {"min_tests": 81, "why": "trust store"},
    "tests/test_issuer_name_rule.py": {"min_tests": 337, "why": "trust store"},
    "tests/test_migration_operator_declared.py": {"min_tests": 65, "why": "trust store"},
    "tests/test_guidance_for_strict_users.py": {"min_tests": 10, "why": "trust store"},
    "tests/test_secure_profile_v1.py": {"min_tests": 34, "why": "trust store"},
    # replay protection (record-if-absent, expiry, policy floor, migration)
    "tests/test_replay_local.py": {"min_tests": 21, "why": "replay protection"},
    "tests/test_replay_expiry_edge.py": {"min_tests": 12, "why": "replay protection"},
    "tests/test_replay_policy_floor.py": {"min_tests": 15, "why": "replay protection"},
    "tests/test_replay_shared_and_omitted.py": {"min_tests": 10, "why": "replay protection"},
    "tests/test_replay_migration.py": {"min_tests": 76, "why": "replay protection"},
    # report / envelope verification (verdicts, strict parsing, signatures, tamper, forged and self-signed evidence)
    "tests/test_verification_engine.py": {"min_tests": 77, "why": "report / envelope verification"},
    "tests/test_verify_trusted.py": {"min_tests": 24, "why": "report / envelope verification"},
    "tests/test_valid_signature_is_not_trusted_signer.py": {
        "min_tests": 5,
        "why": "report / envelope verification",
    },
    "tests/test_report_v2.py": {"min_tests": 113, "why": "report / envelope verification"},
    "tests/test_report_v2_vectors.py": {"min_tests": 38, "why": "report / envelope verification"},
    "tests/test_canonical_v2.py": {"min_tests": 25, "why": "report / envelope verification"},
    "tests/test_schema_v2.py": {"min_tests": 17, "why": "report / envelope verification"},
    "tests/test_schema_validation.py": {"min_tests": 27, "why": "report / envelope verification"},
    "tests/test_schema_name_validation.py": {
        "min_tests": 26,
        "why": "report / envelope verification",
    },
    "tests/test_envelope_object_exact_types.py": {
        "min_tests": 98,
        "why": "report / envelope verification",
    },
    "tests/test_envelope_robustness.py": {"min_tests": 21, "why": "report / envelope verification"},
    "tests/test_envelope_signatures.py": {"min_tests": 11, "why": "report / envelope verification"},
    "tests/test_published_0_1_0_vectors.py": {
        "min_tests": 84,
        "why": "report / envelope verification",
    },
    "tests/test_provenance_consistency.py": {
        "min_tests": 35,
        "why": "report / envelope verification",
    },
    "tests/test_public_api_v2.py": {"min_tests": 21, "why": "report / envelope verification"},
    "tests/test_legacy_bool_apis_deprecation.py": {
        "min_tests": 8,
        "why": "report / envelope verification",
    },
    "tests/test_ai_run.py": {"min_tests": 40, "why": "report / envelope verification"},
    "tests/test_evidence_policy.py": {"min_tests": 38, "why": "report / envelope verification"},
    "tests/test_response_mode.py": {"min_tests": 14, "why": "report / envelope verification"},
    "tests/test_key_provider.py": {"min_tests": 5, "why": "report / envelope verification"},
    "tests/test_security_maintenance.py": {
        "min_tests": 13,
        "why": "report / envelope verification",
    },
    # revocation (file store, hostile sequences, public gate, CLI exit codes)
    "tests/test_revocation_cli_store_exit_codes.py": {"min_tests": 55, "why": "revocation"},
    "tests/test_revocation_file_store.py": {"min_tests": 20, "why": "revocation"},
    "tests/test_revocation_hostile_sequences.py": {"min_tests": 59, "why": "revocation"},
    "tests/test_revocation_public_gate.py": {"min_tests": 27, "why": "revocation"},
    "tests/test_revocation_tooling_and_cli.py": {"min_tests": 30, "why": "revocation"},
    # parser and input limits (bounded input, no signing of garbage)
    "tests/test_input_limit_bypass.py": {"min_tests": 68, "why": "parser and input limits"},
    "tests/test_provenance_and_config_limits.py": {
        "min_tests": 151,
        "why": "parser and input limits",
    },
    "tests/test_defensive_patch_011.py": {"min_tests": 34, "why": "parser and input limits"},
    "tests/test_server_body_limits.py": {"min_tests": 10, "why": "parser and input limits"},
    # CLI verdict and exit-code contract (real processes)
    "tests/test_cli_verify_exit_codes.py": {
        "min_tests": 46,
        "why": "CLI verdict and exit-code contract",
    },
    "tests/test_cli_verify_configuration.py": {
        "min_tests": 10,
        "why": "CLI verdict and exit-code contract",
    },
    "tests/test_trust_add_storage.py": {
        "min_tests": 8,
        "why": "storage policy: trust add writes, locks and permissions",
    },
    "tests/test_cli_trust_workflow.py": {
        "min_tests": 16,
        "why": "CLI verdict and exit-code contract",
    },
    "tests/test_cli_verify_output_no_secrets.py": {
        "min_tests": 3,
        "why": "CLI verdict and exit-code contract",
    },
    "tests/test_cli_signed_path_limits.py": {
        "min_tests": 2,
        "why": "CLI verdict and exit-code contract",
    },
    "tests/test_cli_audit_diagnostics.py": {
        "min_tests": 10,
        "why": "CLI verdict and exit-code contract",
    },
    "tests/test_phase3a_contract.py": {
        "min_tests": 55,
        "why": "CLI verdict and exit-code contract",
    },
    # HTTP verify and server trust paths (fail closed, auth, hardening)
    "tests/test_server_trust.py": {"min_tests": 71, "why": "HTTP verify and server trust paths"},
    "tests/test_server_hardening.py": {
        "min_tests": 32,
        "why": "HTTP verify and server trust paths",
    },
    "tests/test_server_security_maintenance.py": {
        "min_tests": 28,
        "why": "HTTP verify and server trust paths",
    },
}

# Modules whose tests need TenSEAL. Mandatory only under REGAUDIT_REQUIRE_TENSEAL=1 (then a skip or a missing
# module fails the gate); otherwise a missing TenSEAL is reported as 'blocked by dependency'.
TENSEAL_REQUIRED_MODULES: dict[str, dict[str, object]] = {
    "tests/test_tenseal_backend.py": {
        "min_tests": 8,
        "why": "ciphertext/plaintext equivalence on real TenSEAL",
    },
    "tests/test_fhe_equivalence_matrix.py": {
        "min_tests": 32,
        "why": "four-property equivalence matrix on TenSEAL",
    },
    "tests/test_precision_bounds.py": {
        "min_tests": 18,
        "why": "precision bounds enforced against the encrypted backend",
    },
    "tests/test_property_based.py": {
        "min_tests": 8,
        "why": "Hypothesis invariants over the TenSEAL backend",
    },
    "tests/test_params_validation.py": {
        "min_tests": 17,
        "why": "CKKSParams rules, TenSEAL-side cases",
    },
    "tests/test_ckks_producer_claims.py": {
        "min_tests": 63,
        "why": "B-12: a signed parameter set must not overclaim (TenSEAL cases)",
    },
    "tests/test_backends.py": {
        "min_tests": 6,
        "why": "backend registry prefers TenSEAL when it is installed",
    },
}

# Skips that are expected, per environment. A skip is "intentional" only if a rule matches its reason AND its
# ``when`` condition holds on the machine running the tests. Nothing is declared for a platform that can run the
# test: e.g. the macOS ACL tests are declared only for non-macOS, so a macOS runner that skips them fails the gate.
#
# kind:  platform | optional-backend | layout | environment  -> counted as "intentionally skipped"
#        dependency                                           -> counted as "blocked by unavailable dependency"
# gate_ok: the rule may also excuse a MANDATORY (security_gate) test. Only platform/environment rules can.
#          Dependency and optional-backend rules never do: a security test cannot be blocked by a missing package.
# Rules are tried in order; the first whose reason, nodeid and condition all match is the one reported.
EXPECTED_SKIPS: list[dict[str, object]] = [
    # --- platform --------------------------------------------------------------------------------
    {
        "id": "macos-acl-tests",
        "kind": "platform",
        "reason": "macOS ACLs",
        "when": {"platform_not": ["darwin"]},
        "gate_ok": True,
        "note": "macOS-only ACL tests (storage policy, trust store, revocation store); run on the macOS CI entries",
    },
    {
        "id": "linux-acl-tests",
        "kind": "platform",
        "reason": "needs Linux POSIX ACLs and setfacl",
        "when": {"platform_not": ["linux"]},
        "gate_ok": True,
        "note": "Linux-only ACL test for trust add; runs on the Ubuntu CI entries, where a skip fails the gate",
    },
    {
        "id": "posix-only-tests",
        "kind": "platform",
        "reason": "^(POSIX permissions|flock and SIGKILL)$",
        "when": {"os_name_not": ["posix"]},
        "gate_ok": True,
        "note": "POSIX permission bits, flock and SIGKILL; never expected on the Linux and macOS CI entries",
    },
    {
        "id": "windows-permission-and-symlink-tests",
        "kind": "platform",
        "reason": "^(POSIX permission bits|symlinks|POSIX permission bits and symlinks)$",
        "when": {"os_name_not": ["posix"]},
        "gate_ok": True,
        "note": "trust-lifecycle tests that need POSIX permission bits or symlinks",
    },
    {
        "id": "no-mkfifo",
        "kind": "platform",
        "reason": "needs mkfifo",
        "when": {"absent_attr": ["mkfifo"]},
        "gate_ok": True,
        "note": "named pipes are not available on this platform",
    },
    {
        "id": "no-dev-fd",
        "kind": "platform",
        "reason": "needs /dev/fd",
        "when": {"absent_file": ["/dev/fd"]},
        "gate_ok": True,
        "note": "/dev/fd is not available on this platform",
    },
    # --- environment -----------------------------------------------------------------------------
    {
        "id": "root-owned-file-needs-non-root",
        "kind": "environment",
        "reason": "needs a root-owned file and a non-root user",
        "when": {"running_as_root": True},
        "gate_ok": True,
        "note": "the test needs a non-root user; a root runner (a container) cannot run it",
    },
    {
        "id": "group-degeneracy",
        "kind": "environment",
        "reason": "^group degeneracy",
        "when": {"data_dependent": True},
        "gate_ok": True,
        "note": "a seeded random sample drew an empty group; deterministic per seed, not per machine",
    },
    {
        "id": "primitive-has-no-breach-indicator",
        "kind": "environment",
        "reason": "has no boolean breach indicator$",
        "when": {"data_dependent": True},
        "gate_ok": True,
        "note": "the equivalence matrix skips the breach-flip check for the three primitives that return no boolean indicator; fixed by the test data, not by the machine",
    },
    {
        "id": "python-lt-3-11-no-tomllib",
        "kind": "environment",
        "reason": "needs tomllib",
        "when": {"python_lt": [3, 11]},
        "gate_ok": True,
        "note": "tomllib is in the standard library from Python 3.11",
    },
    {
        "id": "no-bash-or-git",
        "kind": "environment",
        "reason": "(bash is required|needs bash and git)",
        "when": {"absent_executable": ["bash"]},
        "gate_ok": True,
        "note": "the shell-driven tests need bash",
    },
    # --- layout (an sdist or a partial checkout) --------------------------------------------------
    {
        "id": "no-docs-directory",
        "kind": "layout",
        "reason": "(docs/ is not part of this checkout|docs/WALKTHROUGH.md is not part of this checkout|not a full source checkout)",
        "when": {"absent_path": ["docs/WALKTHROUGH.md"]},
        "note": "an sdist has no docs/WALKTHROUGH.md",
    },
    {
        "id": "no-scripts-directory",
        "kind": "layout",
        "reason": "scripts/ is not part of this checkout",
        "when": {"absent_path": ["scripts"]},
        "note": "an sdist has no scripts/",
    },
    {
        "id": "no-workflows",
        "kind": "layout",
        "reason": "(workflows are not part of this checkout|not a full source checkout)",
        "when": {"absent_path": [".github/workflows"]},
        "note": "an sdist has no .github/",
    },
    {
        "id": "no-top-level-schemas",
        "kind": "layout",
        "reason": "no top-level schemas/ directory",
        "when": {"absent_path": ["schemas"]},
        "note": "an sdist has no top-level schemas/",
    },
    {
        "id": "no-readme-or-pyproject",
        "kind": "layout",
        "reason": "no (pyproject.toml|README) next to the tests",
        "when": {"absent_path": ["pyproject.toml"]},
        "note": "tests run from an installed copy",
    },
    # --- optional backend (never qualified when skipped) ------------------------------------------
    {
        "id": "openfhe-not-installed",
        "kind": "optional-backend",
        "reason": "could not import 'openfhe'",
        "when": {"missing": ["openfhe"]},
        "blocked_by": "openfhe",
        "note": "the OpenFHE backend is not installable on this runner; its equivalence tests do not run, so the backend is NOT QUALIFIED",
    },
    # --- optional dependencies ---------------------------------------------------------------------
    {
        "id": "tenseal-not-installed",
        "kind": "dependency",
        "reason": "(could not import 'tenseal'|no TenSEAL backend available)",
        "when": {"missing": ["tenseal"]},
        "blocked_by": "tenseal",
        "note": "TenSEAL ('fhe' extra) is not installed. Forbidden under REGAUDIT_REQUIRE_TENSEAL=1",
    },
    {
        "id": "fastapi-not-installed",
        "kind": "dependency",
        "reason": "(could not import 'fastapi'|the \\[server\\] extra \\(fastapi\\) is not installed)",
        "when": {"missing": ["fastapi"]},
        "blocked_by": "fastapi",
        "note": "the 'server' extra is not installed",
    },
    {
        "id": "httpx-not-installed",
        "kind": "dependency",
        "reason": "(could not import 'httpx'|httpx \\(dev extra\\) is not installed)",
        "when": {"missing": ["httpx"]},
        "blocked_by": "httpx",
        "note": "the 'dev' extra is not installed",
    },
    {
        "id": "uvicorn-not-installed",
        "kind": "dependency",
        "reason": "could not import 'uvicorn'",
        "when": {"missing": ["uvicorn"]},
        "blocked_by": "uvicorn",
        "note": "the 'server' extra is not installed",
    },
    {
        "id": "pyyaml-not-installed",
        "kind": "dependency",
        "reason": "could not import 'yaml'",
        "when": {"missing": ["yaml"]},
        "blocked_by": "yaml",
        "note": "the 'dev' extra is not installed",
    },
    # --- not installed as a package ----------------------------------------------------------------
    {
        "id": "package-not-installed",
        "kind": "layout",
        "reason": "(regaudit-fhe is not installed|regaudit-fhe console script is not installed)",
        "when": {"absent_executable": ["regaudit-fhe"]},
        "note": "the tests ran against src/ without 'pip install -e .'",
    },
]

# What counts as having exercised a backend. A backend is "executed" only if its modules ran, passed and skipped
# nothing; otherwise the ledger reports it as NOT QUALIFIED, whatever else passed.
BACKEND_QUALIFICATION: dict[str, dict[str, object]] = {
    "tenseal-ckks": {
        "module": "tenseal",
        "modules": [
            "tests/test_tenseal_backend.py",
            "tests/test_fhe_equivalence_matrix.py",
            "tests/test_precision_bounds.py",
            "tests/test_property_based.py",
        ],
        "not_qualified_because": "TenSEAL missing, or an equivalence module skipped or failed",
    },
    "openfhe-ckks": {
        "module": "openfhe",
        "modules": ["tests/test_openfhe_backend.py"],
        "not_qualified_because": (
            "the openfhe package is not installed here, so the OpenFHE equivalence tests did not run"
        ),
    },
}

# Printed in every ledger. Static: what no run of this suite can show, whatever the counts are.
UNTESTED_NOTES: list[str] = [
    "OpenFHE: tests/test_openfhe_backend.py runs only where the 'openfhe' package imports. The CI matrix does not "
    "install it, so no OpenFHE ciphertext path is executed in CI; the backend is not qualified.",
    "Only the TenSEAL/SEAL build installed on the runner is exercised; other TenSEAL or SEAL builds are not.",
    "Real-key-custody (HSM/KMS) providers: only the KeyProvider interface is tested, with in-process stand-ins.",
    "Windows: no CI entry runs on Windows; POSIX-only and ACL tests are not executed there at all.",
    "A passing ledger says the listed tests executed and passed. It is not an audit or a security certification.",
]
