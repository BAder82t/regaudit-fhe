#!/usr/bin/env python3
"""Mutation-sensitivity check for the Phase 3A trust core.

Each mutant breaks one security-relevant line in an isolated copy of the
repository, then runs the trust test-suite against that copy. A mutant is
KILLED if any test fails. A SURVIVED mutant means the tests do not pin that
behaviour (or the mutation is equivalent, which must be argued in review).

    python scripts/mutation_check_phase3a.py [--jobs N] [--only SUBSTRING]

Nothing in the working tree is modified.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = "src/regaudit_fhe"
TESTS = [
    "tests/test_canonical_v2.py",
    "tests/test_report_v2.py",
    "tests/test_report_v2_vectors.py",
    "tests/test_schema_v2.py",
    "tests/test_trust_entries.py",
    "tests/test_trust_store.py",
    "tests/test_envelope_signatures.py",
    "tests/test_trust_hardening.py",
    "tests/test_replay_local.py",
    "tests/test_verification_engine.py",
    "tests/test_server_trust.py",
    "tests/test_server.py",
    "tests/test_cli_verify_exit_codes.py",
    "tests/test_public_api_v2.py",
    "tests/test_phase3a_contract.py",
]


@dataclass(frozen=True)
class Mutant:
    name: str
    file: str
    old: str
    new: str
    # Non-empty only for a mutant argued to be behaviourally equivalent because a
    # second, independent layer refuses the same inputs (defence in depth).
    equivalent: str = ""


V, S, C = f"{SRC}/verification.py", f"{SRC}/server.py", f"{SRC}/cli.py"
K, R2, TR = f"{SRC}/canonical.py", f"{SRC}/report_v2.py", f"{SRC}/trust.py"
RP, TM, KY = f"{SRC}/replay.py", f"{SRC}/_time.py", f"{SRC}/_keys.py"
RE = f"{SRC}/reports.py"

# Mutants argued to be behaviourally equivalent: a second, independent layer
# refuses the same inputs (defence in depth). Keyed by the mutant id prefix.
EQUIVALENT = {
    "V02": "issuer_trusted is implied whenever nothing blocks (it needs the entry, identity_ok and "
    "sig_ok, and each failing one already blocks); kept as defence in depth",
    "K04": "check_value() rejects the non-finite float json.loads would produce; the hook only "
    "gives a precise message",
    "K05": "json.loads refuses a leading U+FEFF itself; the explicit check only gives a precise message",
}

MUTANTS = [
    # --- verification engine -------------------------------------------------
    Mutant(
        "V01 accepted ignores blocking reasons",
        V,
        "accepted = not blocking and integrity_valid and issuer_trusted",
        "accepted = integrity_valid and issuer_trusted",
    ),
    Mutant(
        "V02 accepted ignores issuer_trusted",
        V,
        "accepted = not blocking and integrity_valid and issuer_trusted",
        "accepted = not blocking and integrity_valid",
    ),
    Mutant(
        "V03 signature checked against the embedded key",
        V,
        "verify_pem = registered_pem if store is not None else embedded_pem",
        "verify_pem = embedded_pem",
    ),
    Mutant(
        "V04 embedded PEM mismatch ignored",
        V,
        "if _norm_pem(entry.public_key_pem) != _norm_pem(embedded_pem):",
        "if False:",
    ),
    Mutant("V05 signed fingerprint ignored", V, "if not fingerprint_ok:", "if False:"),
    Mutant(
        "V06 signed issuer name ignored",
        V,
        "if entry.issuer is not None and env.issuer != entry.issuer:",
        "if False:",
    ),
    Mutant(
        "V07 deployment scope ignored",
        V,
        "if entry.deployments is not None and (",
        "if False and (",
    ),
    Mutant(
        "V08 primitive scope ignored",
        V,
        "if entry.primitives is not None and env.primitive not in entry.primitives:",
        "if False:",
    ),
    Mutant(
        "V09 parameter-set pin ignored",
        V,
        "            entry.parameter_set_pin is not None\n            and entry.parameter_set_pin != env.parameter_set_hash",
        "            False",
    ),
    Mutant("V10 legacy revoked key not blocking", V, 'block("KEY_REVOKED")', 'note("KEY_REVOKED")'),
    Mutant(
        "V11 unknown compromise boundary tolerated",
        V,
        "        # Unknown compromise boundary: nothing this key signed is trusted\n"
        "        # evidence, whatever time the signer or a token claims.\n"
        '        block("KEY_COMPROMISED_NO_CHRONOLOGY")',
        '        note("KEY_COMPROMISED_NO_CHRONOLOGY")',
    ),
    Mutant(
        "V12 compromise boundary made inclusive",
        V,
        "elif not (evidence.gen_time + evidence.accuracy < boundary):",
        "elif not (evidence.gen_time + evidence.accuracy <= boundary):",
    ),
    Mutant(
        "V13 timestamp accuracy ignored for compromise",
        V,
        "elif not (evidence.gen_time + evidence.accuracy < boundary):",
        "elif not (evidence.gen_time < boundary):",
    ),
    Mutant(
        "V14 retirement chronology ignored",
        V,
        "    elif evidence.gen_time + evidence.accuracy >= retired_at:",
        "    elif False:",
    ),
    Mutant(
        "V15 trust-history freshness ignored",
        V,
        'return policy.profile != "high-assurance" and _history_state(policy, now) == HISTORY_FRESH',
        "return True",
    ),
    Mutant(
        "V16 failed timestamp not blocking",
        V,
        'block("TIMESTAMP_FAILED")',
        'note("TIMESTAMP_FAILED")',
    ),
    Mutant(
        "V17 required timestamp policy ignored",
        V,
        "if policy.require_verified_timestamp and ts_status != TS_VERIFIED:",
        "if False:",
    ),
    Mutant(
        "V18 audience mismatch ignored", V, "if policy.verifier_id not in audience:", "if False:"
    ),
    Mutant("V19 maximum age ignored", V, "elif now - issued > max_age:", "elif False:"),
    Mutant(
        "V20 future-dated report ignored", V, "if issued > now + policy.clock_skew:", "if False:"
    ),
    Mutant(
        "V21 replay id never recorded",
        V,
        "if cache.record(key_id, env.audit_run_id, now=now, retain=retain):",
        "if True:",
    ),
    Mutant(
        "V22 replay check never detects",
        V,
        "if cache.seen(key_id, env.audit_run_id, now=now):",
        "if False:",
    ),
    Mutant(
        "V23 replay store failure fails open in production",
        V,
        '(note if policy.profile == "development" else block)("REPLAY_STATE_UNAVAILABLE")',
        'note("REPLAY_STATE_UNAVAILABLE")',
    ),
    Mutant(
        "V24 replay recorded before other checks pass",
        V,
        'if policy.replay_mode != "off" and not blocking:',
        'if policy.replay_mode != "off":',
    ),
    Mutant(
        "V25 legacy v1 always allowed",
        V,
        "if not v2 and not policy.legacy_v1_allowed:",
        "if False:",
    ),
    Mutant(
        "V26 self-signed path can be accepted",
        V,
        "            trust_status=status,\n            accepted=False,",
        "            trust_status=status,\n            accepted=integrity_valid,",
    ),
    Mutant(
        "V27 future-dated timestamp evidence accepted",
        V,
        "and evidence.gen_time <= now + policy.clock_skew",
        "and True",
    ),
    Mutant(
        "V28 chronology shown for unauthenticated issuer",
        V,
        "    if not issuer_trusted:\n        # Nothing about time",
        "    if False:\n        # Nothing about time",
    ),
    Mutant(
        "V29 dev flag allowed outside development",
        V,
        'if self.allow_self_signed and self.profile != "development":',
        "if False:",
    ),
    Mutant(
        "V30 signer-asserted time allowed outside development",
        V,
        'if self.historical_acceptance == "signer-asserted" and self.profile != "development":',
        "if False:",
    ),
    Mutant(
        "V31 non-persistent replay cache allowed in production",
        V,
        "if self.replay_cache.scope != SCOPE_LOCAL_PERSISTENT:",
        "if False:",
    ),
    Mutant(
        "V32 unparseable issued_at tolerated",
        V,
        'block("MALFORMED_ENVELOPE")  # an unreadable issue time',
        'note("MALFORMED_ENVELOPE")  # an unreadable issue time',
    ),
    Mutant(
        "V33 replay retention too short",
        V,
        "+ 2 * policy.clock_skew",
        "+ policy.clock_skew - policy.clock_skew",
    ),
    # --- server --------------------------------------------------------------
    Mutant(
        "S01 /v1/verify does not fail closed without a store",
        S,
        "            if not config.allow_self_signed:\n                raise HTTPException(",
        "            if False:\n                raise HTTPException(",
    ),
    Mutant(
        "S02 request-time profile re-check removed",
        S,
        '            if config.profile != "development":',
        "            if False:",
    ),
    Mutant("S03 request-time exposure check removed", S, "if refusal is not None:", "if False:"),
    Mutant(
        "S04 server socket loopback check removed",
        S,
        "    if not (isinstance(host, str) and _is_loopback_host(host)):",
        "    if False:",
    ),
    Mutant(
        "S05 forwarding headers tolerated without a proxy policy",
        S,
        '    if not nets:\n        return "forwarding',
        '    if False:\n        return "forwarding',
    ),
    Mutant(
        "S06 chunked body size limit removed",
        S,
        "if len(received) > config.max_body_bytes:",
        "if False:",
    ),
    Mutant(
        "S07 untrusted peer may vouch for a forwarded client",
        S,
        "    if not _in_networks(str(client[0]), nets):",
        "    if False:",
    ),
    Mutant(
        "S08 leftmost X-Forwarded-For entry trusted",
        S,
        'for hop in reversed([h.strip() for h in xff.split(",")]):',
        'for hop in [h.strip() for h in xff.split(",")]:',
    ),
    Mutant(
        "S09 non-loopback direct client tolerated",
        S,
        "        if not _is_loopback_host(str(client[0])):",
        "        if False:",
    ),
    Mutant(
        "S10 duplicate JSON keys tolerated in the request",
        S,
        "payload = loads_strict(bytes(received), max_bytes=config.max_body_bytes)",
        "payload = __import__('json').loads(bytes(received))",
    ),
    Mutant(
        "S11 verification runs on the event loop",
        S,
        "result = await run_in_threadpool(verify, env, policy)",
        "result = verify(env, policy)",
    ),
    Mutant(
        "S12 only the first X-Forwarded-For line considered",
        S,
        'xff = ",".join(_header_lines(headers, "x-forwarded-for"))',
        'xff = headers.get("x-forwarded-for") or ""',
    ),
    # --- CLI -----------------------------------------------------------------
    Mutant(
        "C01 self-signed report exits 0",
        C,
        "return 0 if result.accepted else 1",
        "return 0 if result.integrity_valid else 1",
    ),
    Mutant(
        "C02 unreadable trust store exits 2",
        C,
        '            sys.stderr.write(f"--trusted-keys: {exc}\\n")\n            return 3',
        '            sys.stderr.write(f"--trusted-keys: {exc}\\n")\n            return 2',
    ),
    Mutant(
        "C03 missing trust material not a usage error",
        C,
        "if trust_store is None and not args.allow_self_signed:",
        "if False:",
    ),
    Mutant(
        "C04 non-finite max age accepted",
        C,
        "if not math.isfinite(value) or value <= 0:",
        "if False:",
    ),
    Mutant("C05 report size limit removed", C, "if size > MAX_INPUT_BYTES:", "if False:"),
    # --- canonical / envelope / trust / replay ------------------------------
    Mutant("K01 duplicate keys tolerated", K, "        if key in out:", "        if False:"),
    Mutant("K02 non-finite numbers tolerated", K, "if not math.isfinite(value):", "if False:"),
    Mutant(
        "K03 non-string keys tolerated",
        K,
        "            if not isinstance(key, str):",
        "            if False:",
    ),
    Mutant(
        "K04 NaN/Infinity constants tolerated",
        K,
        "            parse_constant=_reject_constant,\n",
        "",
    ),
    Mutant(
        "K05 byte order mark tolerated", K, 'if raw.startswith(b"\\xef\\xbb\\xbf"):', "if False:"
    ),
    Mutant("K06 nesting depth unbounded", K, "if depth > MAX_DEPTH:", "if False:"),
    Mutant(
        "E01 no signing domain separation",
        R2,
        'SIGN_DOMAIN = b"regaudit-fhe/report/v2/sign\\x00"',
        'SIGN_DOMAIN = b""',
    ),
    Mutant(
        "E02 no sealed-digest domain separation",
        R2,
        'SEAL_DOMAIN = b"regaudit-fhe/sealed-envelope/v2\\x00"',
        'SEAL_DOMAIN = b""',
    ),
    Mutant(
        "E03 unknown top-level fields tolerated",
        R2,
        '        if unknown:\n            raise EnvelopeFormatError("UNKNOWN_FIELD", f"unknown field(s)',
        '        if False:\n            raise EnvelopeFormatError("UNKNOWN_FIELD", f"unknown field(s)',
    ),
    Mutant(
        "E04 non-canonical base64 tolerated",
        K,
        '    if base64.b64encode(raw).decode("ascii") != text:',
        "    if False:",
    ),
    Mutant(
        "E05 signature length unchecked",
        K,
        "    if length is not None and len(raw) != length:",
        "    if False:",
    ),
    Mutant(
        "E06 sealed digest omits the signature",
        R2,
        '"signature_b64": self.receipt.get("signature_b64"),',
        '"signature_b64": "",',
    ),
    Mutant(
        "E07 loose timestamps accepted",
        TM,
        "if not isinstance(value, str) or not _RFC3339.match(value):",
        "if not isinstance(value, str):",
    ),
    Mutant(
        "E08 free-form fields not canonically checked",
        R2,
        "                check_value(value)",
        "                pass",
    ),
    Mutant(
        "T01 one key may be registered under two ids",
        TR,
        "        if fp in seen:",
        "        if False:",
    ),
    Mutant(
        "T02 non-Ed25519 keys accepted",
        KY,
        "    if not isinstance(key, Ed25519PublicKey):",
        "    if False:",
    ),
    Mutant(
        "T03 retired key without retired_at accepted",
        TR,
        'if status == "retired" and retired_at is None:',
        "if False:",
    ),
    Mutant("T04 oversized trust store read", TR, "if size > MAX_TRUST_STORE_BYTES:", "if False:"),
    Mutant(
        "P01 replay cache has no lock",
        RP,
        "self._lock = threading.Lock()",
        "self._lock = __import__('contextlib').nullcontext()",
    ),
    Mutant(
        "P02 replay cache evicts when full",
        RP,
        "            if len(self._entries) >= self._capacity:",
        "            if False:",
    ),
    Mutant(
        "P03 replay retention ignored",
        RP,
        "self._entries[(key_id, run_id)] = expires",
        "self._entries[(key_id, run_id)] = now",
    ),
    Mutant(
        "P04 sqlite replay store not transactional",
        RP,
        'conn.execute("BEGIN IMMEDIATE")',
        'conn.execute("SELECT 1")',
    ),
    Mutant(
        "B01 retirement boundary made inclusive",
        V,
        "    elif evidence.gen_time + evidence.accuracy >= retired_at:",
        "    elif evidence.gen_time + evidence.accuracy > retired_at:",
    ),
    Mutant(
        "B02 signer-asserted retirement boundary made inclusive",
        V,
        "        elif issued >= retired_at:",
        "        elif issued > retired_at:",
    ),
    Mutant(
        "U01 Unix sockets allowed for the development option",
        S,
        "    if not server or len(server) < 2 or server[1] is None:",
        "    if not server:",
    ),
    Mutant(
        "U02 unknown peer tolerated for the development option",
        S,
        '    if not client or not client[0]:\n        return "peer address unknown"\n',
        "",
    ),
    Mutant(
        "D01 in-memory replay cache claims to be durable",
        RP,
        "    durable = False  # lost when the process exits",
        "    durable = True  # lost when the process exits",
    ),
    Mutant(
        "D02 sqlite replay cache claims not to be durable",
        RP,
        "    durable = True  # committed to the sqlite file before record() returns",
        "    durable = False  # committed to the sqlite file before record() returns",
    ),
    Mutant(
        "D03 replay durability not reported",
        V,
        '"replay_durable": self.replay_durable,',
        '"replay_durable": None,',
    ),
    Mutant(
        "X01 empty --trusted-keys treated as omitted",
        C,
        "    if args.trusted_keys is not None:",
        "    if args.trusted_keys:",
    ),
    Mutant(
        "Z01 direct TrustStore construction allows key aliases",
        TR,
        "        _require_unique_keys(self.keys)\n        for map_key, entry in self.entries.items():",
        "        for map_key, entry in self.entries.items():",
    ),
    Mutant(
        "Z02 v1 signature base64 decoded leniently",
        RE,
        "        signature = decode_canonical_b64(signature_b64, length=64)",
        "        signature = base64.b64decode(signature_b64)",
    ),
    Mutant(
        "Z03 v1 timestamp token base64 decoded leniently",
        RE,
        "        token = decode_canonical_b64(token_b64)",
        "        token = base64.b64decode(token_b64)",
    ),
    Mutant(
        "Z04 CLI turns an unavailable replay store into a policy refusal",
        C,
        '    if "REPLAY_STATE_UNAVAILABLE" in result.blocking_reasons:',
        "    if False:",
    ),
    Mutant(
        "Z05 HTTP turns an unavailable replay store into a verdict",
        S,
        '        if "REPLAY_STATE_UNAVAILABLE" in result.blocking_reasons:',
        "        if False:",
    ),
    Mutant(
        "Z06 trust-store entry key_id not checked against its map key",
        TR,
        "            if entry.key_id != map_key:",
        "            if False:",
    ),
    Mutant(
        "P05 naive times accepted by the replay store",
        RP,
        "    if moment.tzinfo is None or moment.utcoffset() is None:",
        "    if False:",
    ),
    Mutant(
        "L01 legacy API ignores entry scope",
        RE,
        "issuer_ok = _v1_entry_scope_ok(store.entry(key_id), env)",
        "issuer_ok = True",
    ),
    Mutant(
        "L02 legacy API ignores not_before",
        RE,
        "    if entry.not_before is not None:\n        try:",
        "    if False:\n        try:",
    ),
    Mutant(
        "L03 legacy API ignores the issuer name",
        RE,
        "    if entry.issuer is not None and env.issuer != entry.issuer:\n        return False\n",
        "",
    ),
    Mutant(
        "L04 legacy API ignores the primitive scope",
        RE,
        "    if entry.primitives is not None and env.primitive not in entry.primitives:\n        return False\n",
        "",
    ),
    Mutant(
        "L05 legacy API ignores the deployment scope",
        RE,
        "    if entry.deployments is not None:  # v1 carries no deployment_id, so it cannot match\n        return False\n",
        "",
    ),
    Mutant(
        "M01 trust store keeps a mutable view of keys",
        TR,
        'object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))',
        'object.__setattr__(self, "keys", self.keys)',
    ),
    Mutant(
        "M02 trust store skips the entries consistency check",
        TR,
        "        if self.entries:\n            # The legacy views feed",
        "        if False:\n            # The legacy views feed",
    ),
    Mutant(
        "M03 RFC 3339 fraction not normalised",
        TM,
        'text = _FRACTION.sub(lambda m: "." + m.group(1).ljust(6, "0"), text, count=1)',
        "pass",
    ),
]


def run_one(m: Mutant, workdir: Path) -> tuple[Mutant, str, str]:
    copy = workdir / m.name.split()[0]
    shutil.copytree(
        ROOT,
        copy,
        ignore=shutil.ignore_patterns(
            ".git",
            "__pycache__",
            ".venv",
            "*.egg-info",
            ".mypy_cache",
            ".ruff_cache",
            ".pytest_cache",
        ),
    )
    target = copy / m.file
    text = target.read_text(encoding="utf-8")
    if m.old not in text:
        return m, "ERROR", f"pattern not found in {m.file}"
    target.write_text(text.replace(m.old, m.new, 1), encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(copy / "src"), "CI": "1"}
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [
            sys.executable,
            "-m",
            "pytest",
            *TESTS,
            "-x",
            "-q",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:warnings",
        ],
        cwd=copy,
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    shutil.rmtree(copy, ignore_errors=True)
    if proc.returncode == 0:
        reason = m.equivalent or EQUIVALENT.get(m.name.split()[0], "")
        return (m, "EQUIVALENT", reason) if reason else (m, "SURVIVED", "")
    failed = [
        ln for ln in proc.stdout.splitlines() if ln.startswith("FAILED") or ln.startswith("ERROR")
    ]
    return m, "KILLED", (failed[0][:110] if failed else "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    chosen = [m for m in MUTANTS if args.only in m.name]
    with tempfile.TemporaryDirectory(prefix="mut3a-") as tmp:
        work = Path(tmp)
        with cf.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            results = list(pool.map(lambda m: run_one(m, work), chosen))
    survived = 0
    equivalent = 0
    for m, status, detail in results:
        print(f"{status:10s} {m.name} | {detail}")
        survived += status in ("SURVIVED", "ERROR")
        equivalent += status == "EQUIVALENT"
    killed = sum(status == "KILLED" for _, status, _ in results)
    print(
        f"\n{killed}/{len(results)} killed, {equivalent} equivalent (argued), {survived} survived"
    )
    return 1 if survived else 0


if __name__ == "__main__":
    raise SystemExit(main())
