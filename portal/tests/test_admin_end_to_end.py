"""From the browser to a working portal: prepare a plan through the portal's own route, describe it, apply it to a fresh
account, start the real portal on the result, and check real signed reports against it.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from helpers import (
    JSON_HEADERS,
    PLAN_VERIFIER,
    client_for,
    fake_home,
    fingerprint_of,
    issuer_signer,
    plan_request,
    signed_report,
)
from regaudit_portal.paths import default_config_folder

import regaudit_fhe as rf

PORTAL = Path(__file__).resolve().parents[1]


def _command(home: Path, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-m", "regaudit_portal", *argv],
        env={**os.environ, "HOME": str(home), "PYTHONPATH": str(PORTAL)},
        cwd=PORTAL, capture_output=True, text=True, timeout=120, check=False, stdin=subprocess.DEVNULL,
    )  # fmt: skip


def _post(url: str, body: bytes) -> dict:
    request = urllib.request.Request(url, data=body, headers=JSON_HEADERS, method="POST")  # noqa: S310 - 127.0.0.1 only
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - 127.0.0.1 only
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, **json.loads(exc.read())}


@pytest.fixture
def account(tmp_path, monkeypatch):
    home = fake_home(tmp_path, monkeypatch)
    parent = default_config_folder().parent
    parent.mkdir(parents=True)
    for place in (home, *[p for p in parent.parents if home in p.parents], parent):
        os.chmod(place, 0o755)  # noqa: S103 - what a real home folder has
    return home


def test_prepare_describe_apply_then_the_portal_trusts_that_issuer_and_no_other_key(
    account, tmp_path
):
    issuer = issuer_signer("Northwind Ltd", "northwind-2026")

    # 1. The browser: the portal's own stateless route, in welcome mode, writes nothing.
    response = client_for(None).post(
        "/api/setup/plan", content=json.dumps(plan_request([issuer])).encode(), headers=JSON_HEADERS
    )
    assert response.status_code == 200
    plan = tmp_path / response.json()["file_name"]
    plan.write_text(response.json()["plan_text"])
    assert not default_config_folder().exists()

    # 2. Describe, as the application or Terminal would.
    described = _command(account, "admin-describe", "--json", str(plan))
    body = json.loads(described.stdout)
    assert described.returncode == 0 and body["ok"] is True
    assert body["issuers"] == [{"number": 1, "issuer": "Northwind Ltd", "key_id": "northwind-2026"}]

    # 3. Apply, with the fingerprint the issuer gave by another route.
    applied = _command(
        account, "admin-apply", "--expect-plan-sha256", body["plan_sha256"],
        "--expect-fingerprint", f"{issuer.key_id}={fingerprint_of(issuer)}", "--", str(plan),
    )  # fmt: skip
    assert applied.returncode == 0, applied.stderr
    assert "Restart it to use this configuration" in applied.stdout

    # 4. Start the real portal on the standard folder, as the application does.
    portal = subprocess.Popen(
        [sys.executable, "-m", "regaudit_portal", "serve", "--port", "0"],
        env={**os.environ, "HOME": str(account), "PYTHONPATH": str(PORTAL)},
        cwd=PORTAL, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )  # fmt: skip
    try:
        line = ""
        while not line.startswith("portal-listening"):
            line = portal.stdout.readline()
            assert line or portal.poll() is None, "the portal did not start"
        assert line.strip().endswith("mode=ready"), line
        url = line.split("url=")[1].split()[0]

        # 5. A real signed report from that issuer is trusted.
        good = _post(url + "api/verify", signed_report(issuer, audience=(PLAN_VERIFIER,)))
        assert good["verification"]["trust_status"] == "TRUSTED", good
        assert good["verification"]["issuer"] == "Northwind Ltd"

        # 6. A report from a different key is refused, also under the same issuer name and key id.
        impostor = rf.Signer.generate(issuer="Northwind Ltd", key_id="northwind-2026")
        stranger = rf.Signer.generate(issuer="Northwind Ltd", key_id="someone-else")
        for signer in (impostor, stranger):
            refused = _post(url + "api/verify", signed_report(signer, audience=(PLAN_VERIFIER,)))
            assert refused["verification"]["trust_status"] == "INVALID", refused
            assert refused["verification"]["accepted"] is False

        # 7. The setup page agrees that trust is configured, and is not a demonstration.
        with urllib.request.urlopen(url + "api/setup", timeout=30) as answer:  # noqa: S310 - 127.0.0.1 only
            setup = json.loads(answer.read())
        assert setup["trust_configured"] is True and setup["demonstration_trust_list"] is False
    finally:
        portal.send_signal(signal.SIGTERM)
        out = portal.communicate(timeout=30)[0]
    assert "the portal has stopped." in out
