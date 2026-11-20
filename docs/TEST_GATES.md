# Test gates

A green `pytest` run does not say which tests ran. A security test that skips, because a package is missing or a
skip marker was added, looks the same as one that passed. The test gate closes that gap. It does not change what
the tests check. It checks that the tests that must run did run.

This is engineering accounting for the maintainers. A passing gate is not an audit, a certification or a claim
of regulatory compliance.

## What the gate reports

Every test outcome lands in exactly one line of the ledger:

| Ledger line | Meaning | Fails the gate |
| --- | --- | --- |
| required, executed and passed | a mandatory test ran and passed | no |
| required, failed | a mandatory test failed, errored or was marked xfail | yes |
| required, unexpectedly skipped | a mandatory test skipped and the manifest does not declare that skip for this platform | yes |
| intentionally skipped | a skip the manifest declares for this platform, backend or checkout layout | no |
| blocked by unavailable dependency | an optional test skipped because an optional package is not installed, as declared | no |
| optional, skipped, not declared | an optional test skipped for a reason no rule covers | only with `REGAUDIT_GATE_STRICT_SKIPS=1` |
| optional, passed / failed | everything else | a failure fails pytest as usual |

A mandatory module that is missing from the run, or that collects fewer tests than its floor, also fails the gate.
Deleting or deselecting a security test cannot pass silently.

The ledger is written as `test-gate/test-gate-ledger.json` (machine readable) and `.txt` (the same summary the run
prints). It records the platform, Python version, which optional packages were importable, every skip with its
reason and the rule that declared it, the per-module floors, and the backend qualification below.

## Running it

```
pip install -e ".[dev,server,fhe]"
REGAUDIT_REQUIRE_TENSEAL=1 pytest tests/ --gate --gate-dir test-gate
```

`--gate` belongs on the full-suite run. A partial run cannot satisfy the per-module floors. Without `--gate`
nothing is enforced and nothing is written; the markers are still applied (`pytest -m security_gate`).

## Which tests are mandatory

The list is explicit, in `tests/_gate_manifest.py`, and the plugin (`tests/_gate_plugin.py`) applies the
`security_gate` marker to every test in each listed module. A test can also be made mandatory by decorating it with
`@pytest.mark.security_gate`.

A module is on the list when a regression in it could make the verifier accept something it must refuse, or
accept it more than once, or let another account change what it trusts:

- storage policy: a strict profile refuses a store another account can change
- trust store: enrolment, lifecycle, issuer binding, strict parsing
- replay protection: record-if-absent, expiry, policy floor, migration
- report and envelope verification: verdicts, strict parsing, signatures, tampered, forged and self-signed evidence
- revocation: file store, hostile sequences, public gate
- parser and input limits
- the CLI verdict and exit-code contract, run on real processes
- the HTTP verify and server trust paths

Release-workflow policy tests, documentation tests, packaging tests, benchmarks and the experimental revocation
prototype are not on the list. They may skip on a partial checkout, and the manifest declares when.

The floor for each module (`min_tests`) is the number of tests collected when the list was reviewed. Raise it when
tests are added. Lowering it needs a stated reason in the commit.

## Expected skips

`EXPECTED_SKIPS` in the same file declares, per environment, which skips are intentional. A rule names the skip
reason and the condition under which it is expected (platform, missing package, partial checkout, root user). A rule
that does not hold on the machine declares nothing: the macOS ACL tests are declared only for non-macOS, so a macOS
runner that skips them fails the gate. Only platform and environment rules can excuse a mandatory test.
A missing package never can.

## TenSEAL and OpenFHE

With `REGAUDIT_REQUIRE_TENSEAL=1`:

- pytest refuses to start if TenSEAL cannot be imported;
- every TenSEAL-dependent test is mandatory and a skip of any of them fails the gate.

CI sets it for the interpreters that have a TenSEAL wheel (see the comment in `.github/workflows/ci.yml`). Without
it, a missing TenSEAL is reported as "blocked by unavailable dependency".

A backend is reported as `executed` only if its test modules ran, passed and skipped nothing. OpenFHE is not
installed in CI, so the ledger reports it as `NOT QUALIFIED`. An unexecuted backend is never qualified, however many
other tests pass. The ledger also prints what no run of this suite can show (`UNTESTED_NOTES`).

## Changing the lists

Both lists are reviewed data. When you add a test file that guards a security property, add it to
`SECURITY_GATE_MODULES` in the same commit. When you add a `skip` that is legitimate on some platform, add a rule to
`EXPECTED_SKIPS` with a `note`. The gate's own tests are in `tests/test_gate_tooling.py`.
