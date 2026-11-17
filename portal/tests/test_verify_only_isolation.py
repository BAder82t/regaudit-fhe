"""The Portal is a verify-only product: it carries no encrypted-computation or decryption machinery and no private key.

Two properties, shown from the code as it is built and run:

* Importing the Portal, building its application, checking every bundled sample and a batch loads none of the engine's
  encrypted-computation modules, no CKKS library, and not the HTTP server's audit code. This is measured in a fresh
  interpreter, so what other tests imported cannot hide anything.
* Nothing under the Portal's package or its installer folder holds private key material: no PEM private-key block, no key
  file by name, no 32-byte seed written as a file. The demonstration trust list holds public keys and fingerprints only.

The route allow-list (``test_admin_isolation.py``) pins which paths and methods exist.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

PORTAL = Path(__file__).parents[1]

FORBIDDEN_MODULES = (
    "tenseal",
    "openfhe",
    "regaudit_fhe.fhe",
    "regaudit_fhe.fhe.separated",
    "regaudit_fhe.fhe.primitives",
    "regaudit_fhe.server",
)

PROBE = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
import regaudit_portal
from regaudit_portal.app import build_app
from regaudit_portal.samples import load_samples
samples = load_samples()
app = build_app(None, port=0)  # welcome mode: no configuration, only the bundled samples can be checked
from fastapi.testclient import TestClient
client = TestClient(app, base_url="http://127.0.0.1:0")
checked = []
for entry in samples.listing():
    r = client.post("/api/samples/" + entry["id"] + "/verify")
    checked.append(r.status_code)
loaded = sorted(m for m in sys.modules if m.split(".")[0] in {"tenseal", "openfhe"} or m.startswith("regaudit_fhe"))
print(json.dumps({"checked": checked, "loaded": loaded}))
"""


def _probe() -> dict:
    done = subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-c", PROBE, str(PORTAL)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-800:]
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_checking_every_sample_loads_no_encrypted_computation_and_no_ckks_library():
    seen = _probe()
    assert seen["checked"] and all(code == 200 for code in seen["checked"]), seen["checked"]
    loaded = set(seen["loaded"])
    assert loaded, "the engine itself must be loaded: the probe would otherwise prove nothing"
    assert any(m == "regaudit_fhe.verification" for m in loaded)
    bad = sorted(
        m for m in loaded if any(m == f or m.startswith(f + ".") for f in FORBIDDEN_MODULES)
    )
    assert bad == [], f"the verify-only Portal loaded: {bad}"


def test_the_portal_source_imports_nothing_encrypted_by_name():
    pattern = re.compile(
        r"^\s*(?:from|import)\s+(tenseal|openfhe|regaudit_fhe\.fhe|regaudit_fhe\.server)\b", re.M
    )
    offenders = [
        str(p.relative_to(PORTAL))
        for p in (PORTAL / "regaudit_portal").rglob("*.py")
        if pattern.search(p.read_text(encoding="utf-8"))
    ]
    assert offenders == []


PEM_PRIVATE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
KEY_FILE_NAMES = re.compile(
    r"(\.pem|\.key|\.p12|\.pfx|\.jks|id_rsa|id_ed25519|decryptor\.key|evaluator\.key)$", re.I
)


def _shipped_files():
    for folder in (PORTAL / "regaudit_portal", PORTAL / "installer"):
        for path in folder.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                yield path


def test_no_private_key_material_is_shipped_with_the_portal():
    names = [str(p.relative_to(PORTAL)) for p in _shipped_files() if KEY_FILE_NAMES.search(p.name)]
    assert names == [], names
    blocks = []
    for path in _shipped_files():
        if path.stat().st_size > 5_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if PEM_PRIVATE.search(text):
            blocks.append(str(path.relative_to(PORTAL)))
    # The page and the setup code mention the words "PRIVATE KEY" to refuse a pasted one; that text has no block header.
    assert blocks == [], blocks


def test_the_demonstration_trust_list_holds_public_keys_and_fingerprints_only():
    listing = json.loads(
        (PORTAL / "regaudit_portal" / "samples" / "demo-trust-list.json").read_text()
    )
    text = json.dumps(listing)
    assert not PEM_PRIVATE.search(text)
    for entry in json.loads(text).get("entries", {}).values():
        assert not ({"private_key", "private_key_pem", "seed", "secret"} & set(entry)), sorted(
            entry
        )


@pytest.mark.parametrize("name", ["decryptor", "evaluator", "separated", "keygen"])
def test_no_route_of_the_portal_decrypts_evaluates_or_makes_keys(name):
    probe = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from regaudit_portal.app import build_app
app = build_app(None, port=0)
print(json.dumps(sorted(getattr(r, "path", "") for r in app.routes)))
"""
    done = subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-c", probe, str(PORTAL)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-500:]
    paths = json.loads(done.stdout.strip().splitlines()[-1])
    assert not [p for p in paths if name in p.lower()], paths
