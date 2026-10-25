#!/usr/bin/env python3
"""Exercise an INSTALLED regaudit-fhe from a directory that is not a source checkout.

Run it with the interpreter of the virtualenv the wheel was installed into, from outside the repository:

    cd "$(mktemp -d)" && /path/to/venv/bin/python /path/to/repo/scripts/smoke_installed_wheel.py \
        --version 0.1.0 --forbid-path /path/to/repo

It fails unless the package was imported from site-packages (not from ``--forbid-path`` or the working
directory), all runtime schemas load, a report.v1 and a report.v2 can be signed and verified, a tampered
report is refused and the console script works.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--forbid-path", action="append", default=[], type=Path)
    args = ap.parse_args()

    import numpy as np

    import regaudit_fhe as rf
    from regaudit_fhe import schemas

    here = Path(rf.__file__).resolve()
    cwd = Path.cwd().resolve()
    forbidden = [p.resolve() for p in args.forbid_path] + [cwd]
    for bad in forbidden:
        if bad == here or bad in here.parents:
            print(f"FAIL: regaudit_fhe was imported from {here}, inside {bad}", file=sys.stderr)
            return 1
    if "site-packages" not in here.parts:
        print(f"FAIL: regaudit_fhe is not in site-packages: {here}", file=sys.stderr)
        return 1
    if (cwd / "schemas").exists():
        print("FAIL: the working directory must not contain a schemas/ directory", file=sys.stderr)
        return 1
    if rf.__version__ != args.version:
        print(
            f"FAIL: installed version {rf.__version__} != expected {args.version}", file=sys.stderr
        )
        return 1

    names = schemas.list_schemas()
    if len(names) != 14:
        print(f"FAIL: expected 14 schema names, got {len(names)}", file=sys.stderr)
        return 1
    for name in names:
        schemas.load_schema(name)

    report = rf.audit_fairness(
        np.array([1.0, 0.0, 1.0, 0.0]),
        np.array([1.0, 0.0, 0.0, 0.0]),
        np.array([1.0, 1.0, 0.0, 0.0]),
        np.array([0.0, 0.0, 1.0, 1.0]),
    )
    signer = rf.Signer.generate(issuer="smoke", key_id="k1")
    v1 = rf.envelope("fairness", report, signer=signer)
    schemas.validate_envelope(v1.to_dict())
    if v1.algorithm_version != args.version:
        print("FAIL: envelope algorithm_version != package version", file=sys.stderr)
        return 1
    trusted = rf.verify_envelope(v1, trusted_keys={"k1": signer.public_key_pem()})
    if trusted.trust_status != "TRUSTED":
        print(f"FAIL: v1 trust_status {trusted.trust_status}", file=sys.stderr)
        return 1
    tampered = json.loads(json.dumps(v1.to_dict()))
    tampered["issuer"] = "someone-else"
    if (
        rf.verify_envelope(
            rf.parse_envelope(tampered), trusted_keys={"k1": signer.public_key_pem()}
        ).trust_status
        != "INVALID"
    ):
        print("FAIL: a tampered v1 report was not refused", file=sys.stderr)
        return 1

    v2 = rf.envelope_v2(
        "fairness",
        report,
        signer=signer,
        deployment_id="smoke-deployment",
        audit_run_id="3f2b1c4e-5a6d-4e7f-8091-a2b3c4d5e6f7",
        issued_at=datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc),
    )
    schemas.validate_envelope_v2(v2.to_dict())
    result = rf.verify_report(
        rf.parse_envelope(json.loads(json.dumps(v2.to_dict()))),
        rf.VerificationPolicy(allow_self_signed=True),
    )
    if not (
        result.integrity_valid
        and result.trust_status == "SELF_SIGNED_ONLY"
        and result.accepted is False
    ):
        print(
            f"FAIL: unexpected v2 result {result.trust_status} accepted={result.accepted}",
            file=sys.stderr,
        )
        return 1

    script = Path(sys.executable).parent / "regaudit-fhe"
    out = subprocess.run(  # noqa: S603 - fixed argv
        [str(script), "schema", "envelope.v2"], capture_output=True, text=True, check=False, cwd=cwd
    )
    if out.returncode != 0 or '"$schema"' not in out.stdout:
        print(
            f"FAIL: console script `schema envelope.v2` failed: {out.stderr[-300:]}",
            file=sys.stderr,
        )
        return 1

    print(f"smoke ok: regaudit-fhe {rf.__version__} from {here.parent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
