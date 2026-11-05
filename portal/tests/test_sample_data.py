"""The bundled demonstration files: made-up reports, a demonstration trust list, no key that could sign anything."""

from __future__ import annotations

import base64
import binascii
import contextlib
import importlib.util
import json
import re
from datetime import timedelta
from importlib import resources
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import regaudit_fhe.verification as engine_verification
from regaudit_fhe.report_v2 import parse_envelope_strict
from regaudit_fhe.trust import TrustStore
from regaudit_fhe.verification import VerificationPolicy

PORTAL = Path(__file__).parents[1]
PACKAGE = PORTAL / "regaudit_portal"
SAMPLES = PACKAGE / "samples"
SAMPLE_IDS = (
    "trusted",
    "untrusted-signer",
    "modified",
    "plaintext-backend",
    "declares-encrypted-backend",
)
EXPECTED = {
    "trusted": ("TRUSTED", []),
    "untrusted-signer": ("INVALID", ["ISSUER_UNKNOWN"]),
    "modified": ("INVALID", ["HASH_MISMATCH", "SIGNATURE_INVALID"]),
    "plaintext-backend": ("TRUSTED", []),
    "declares-encrypted-backend": ("TRUSTED", []),
}
DEMO_KEY_ID = "demo-only-synthetic-key"


def _bundled(*parts: str) -> bytes:
    return resources.files("regaudit_portal").joinpath("samples", *parts).read_bytes()


def engine_verdict(sample_id: str) -> dict:
    """What the engine says about a bundled file under the demonstration policy, built here from the bundled files."""
    store = TrustStore.from_dict(json.loads(_bundled("demo-trust-list.json")))
    policy = VerificationPolicy(
        profile="development",
        trust_store=store,
        verifier_id="demo-verifier",
        clock_skew=timedelta(days=36500),
        check_provenance=True,
    )
    env = parse_envelope_strict(json.loads(_bundled("reports", f"{sample_id}.json")))
    return engine_verification.verify(env, policy).to_dict()


def test_the_demonstration_issuer_is_unmistakable_everywhere():
    trust_list = json.loads(_bundled("demo-trust-list.json"))
    assert [entry["issuer"] for entry in trust_list["entries"].values()] == [
        "DEMO-ONLY synthetic issuer"
    ]
    assert list(trust_list["entries"]) == [DEMO_KEY_ID]
    manifest = json.loads(_bundled("index.json"))
    assert manifest["issuer"] == "DEMO-ONLY synthetic issuer"
    for sample_id in SAMPLE_IDS:
        report = json.loads(_bundled("reports", f"{sample_id}.json"))
        assert report["issuer"].startswith("DEMO-ONLY"), sample_id
        assert report["deployment_id"] in ("demonstration-only", "changed-after-signing")


# ----------------------------------------------------------------------------- no key that could sign anything


def _public_keys_in(folder: Path) -> set[bytes]:
    keys = set()
    for path in folder.rglob("*.json"):
        for pem in re.findall(
            r"-----BEGIN PUBLIC KEY-----.+?-----END PUBLIC KEY-----",
            path.read_text().replace("\\n", "\n"),
            re.S,
        ):
            loaded = serialization.load_pem_public_key(pem.encode())
            keys.add(
                loaded.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            )
    return keys


def private_key_material_in(folder: Path) -> list[str]:
    """What looks like a private key in any text file under ``folder``: a PEM block, or a seed that gives a bundled key."""
    publics = _public_keys_in(folder)
    found = []
    for path in sorted(p for p in folder.rglob("*") if p.is_file() and p.suffix not in (".pyc",)):
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        if re.search(r"-----BEGIN[ A-Z]*PRIVATE KEY-----", text):
            found.append(f"{path.name}: a private key block")
        for token in re.findall(r"[A-Za-z0-9+/_=-]{43,100}|[0-9a-fA-F]{64,128}", text):
            decoded = []
            if re.fullmatch(r"[0-9a-fA-F]+", token) and len(token) in (64, 128):
                decoded.append(bytes.fromhex(token))
            for decode in (base64.b64decode, base64.urlsafe_b64decode):
                with contextlib.suppress(binascii.Error, ValueError):
                    decoded.append(decode(token + "=" * (-len(token) % 4)))
            for raw in decoded:
                seeds = (
                    [raw[:32]] if len(raw) in (32, 64) else [raw[-32:]] if len(raw) == 48 else []
                )
                for seed in seeds:
                    derived = (
                        Ed25519PrivateKey.from_private_bytes(seed)
                        .public_key()
                        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    )
                    if derived in publics:
                        found.append(f"{path.name}: a seed that gives a bundled public key")
    return found


def test_no_private_key_or_seed_exists_anywhere_in_the_package():
    assert _public_keys_in(SAMPLES), "the scan has public keys to compare against"
    assert private_key_material_in(PACKAGE) == []


def test_the_scan_would_notice_a_planted_key(tmp_path):
    """A scan that finds nothing proves nothing unless it is shown to find something."""
    key = Ed25519PrivateKey.generate()
    public_pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    seed = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    (tmp_path / "list.json").write_text(json.dumps({"public_key_pem": public_pem}))
    assert private_key_material_in(tmp_path) == []
    for name, text in (
        (
            "pem.txt",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
        ),
        ("b64.txt", base64.b64encode(seed).decode()),
        ("urlsafe.txt", base64.urlsafe_b64encode(seed).decode().rstrip("=")),
        ("hex.txt", seed.hex()),
        (
            "der.txt",
            base64.b64encode(
                key.private_bytes(
                    serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            ).decode(),
        ),
    ):
        (tmp_path / name).write_text(text)
        assert private_key_material_in(tmp_path), name
        (tmp_path / name).unlink()


def test_the_bundled_files_belong_together():
    trust_list = json.loads(_bundled("demo-trust-list.json"))
    enrolled = trust_list["entries"][DEMO_KEY_ID]["public_key_pem"]
    trusted = json.loads(_bundled("reports", "trusted.json"))
    outsider = json.loads(_bundled("reports", "untrusted-signer.json"))
    modified = json.loads(_bundled("reports", "modified.json"))
    assert trusted["receipt"]["public_key_pem"] == enrolled
    assert outsider["receipt"]["public_key_pem"] != enrolled and outsider["key_id"] != DEMO_KEY_ID
    assert {k for k in trusted if trusted[k] != modified[k]} == {"deployment_id"}


def test_the_package_data_names_the_samples():
    text = (PORTAL / "pyproject.toml").read_text()
    assert '"samples/*"' in text and '"samples/reports/*"' in text
    for name in ("index.json", "demo-trust-list.json", *(f"reports/{i}.json" for i in SAMPLE_IDS)):
        assert (SAMPLES / name).is_file(), name


# ----------------------------------------------------------------------------- the script that makes them


def _script():
    spec = importlib.util.spec_from_file_location(
        "make_demo_samples", PORTAL / "tools" / "make_demo_samples.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_script_signs_with_a_throwaway_key_and_writes_nothing_that_can_sign(tmp_path):
    script = _script()
    first, second = tmp_path / "first", tmp_path / "second"
    script.make(first)
    script.make(second)
    assert private_key_material_in(first) == [] and private_key_material_in(second) == []
    assert (first / "demo-trust-list.json").read_text() != (
        second / "demo-trust-list.json"
    ).read_text(), "a new key each run"
    assert sorted(p.name for p in first.rglob("*") if p.is_file()) == sorted(
        ["index.json", "demo-trust-list.json", *(f"{i}.json" for i in SAMPLE_IDS)]
    )
    store = TrustStore.from_dict(json.loads((first / "demo-trust-list.json").read_text()))
    policy = VerificationPolicy(
        profile="development", trust_store=store, verifier_id="demo-verifier",
        clock_skew=timedelta(days=36500), check_provenance=True,
    )  # fmt: skip
    for sample_id, (status, _) in EXPECTED.items():
        env = parse_envelope_strict(
            json.loads((first / "reports" / f"{sample_id}.json").read_text())
        )
        assert engine_verification.verify(env, policy).trust_status == status, sample_id


def test_the_script_never_writes_a_key_by_name():
    source = (PORTAL / "tools" / "make_demo_samples.py").read_text()
    assert "private_bytes" not in source and "PRIVATE" not in source and "private_key" not in source
    assert "del issuer, unenrolled" in source
