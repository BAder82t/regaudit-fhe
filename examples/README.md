# Examples

Runnable flows that use synthetic data.

## Try it in one minute

[`examples/strict_verification_quickstart.py`](strict_verification_quickstart.py)
uses only the installed package and synthetic data. It signs a report, verifies it
against a trust store (`TRUSTED`), then shows what a valid-but-untrusted signature, a
forged report and a tampered report look like, and what the CLI exit codes are:

```bash
python examples/strict_verification_quickstart.py            # files go to a temp dir
python examples/strict_verification_quickstart.py --out demo # keep report.json + trust_store.json
regaudit-fhe verify -i demo/report.json --trusted-keys demo/trust_store.json --verifier-id regulator-a
```

## Examples

The folder folder ships these flows. They use synthetic data and
need only the installed package unless noted. Run them from a checkout (the folder is not
part of the wheel); `01` and `02` write their JSON output into the current directory.

| File | Flow |
| ---- | ---- |
| `strict_verification_quickstart.py` | **Start here.** Create, sign and strictly verify a `report.v2`; valid signature vs trusted signer; forged and tampered reports; CLI exit codes. |
| `04_cli_roundtrip.sh` | Pure CLI: input -> audit -> verify (`SELF_SIGNED_ONLY`, exit 1, as the CLI signs with an ephemeral key). |
| `01_client_local_audit.py` | Internal audit on synthetic data; archive JSON locally. |
| `02_client_to_regulator.py` | Build a regulator submission bundle. |
| `03_regulator_verify.py` | Verify every envelope inside a bundle against a `TrustStore` (`--bundle`, `--trust-store`); surfaces typed failure reasons. |
| `signed_envelope.py`, `regulator_verify_signature.py` | Signing, tamper detection and trusted-key pinning walk-throughs. |
| `server_client.py` | Drive the HTTP app in-process with a test client: auth scopes, three audits, one verification (needs `[server]`). |
| `openfhe_fairness_roundtrip.py`, `benchmark_reproduce.py` | Encrypted-backend demos (need `[fhe]`). |
