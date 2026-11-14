"""A setup plan is checked strictly, refuses key material it must never hold, and says exactly what would be written.

Everything here goes through the same code as the prepare route and the apply command: ``regaudit_portal.plan``.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from helpers import crafted_plan, fingerprint_of, issuer_signer, plan_request, prepare_plan
from regaudit_portal import plan as plan_module
from regaudit_portal.config import read_settings, read_trust_store
from regaudit_portal.plan import PlanProblem, notices, prepared, read_plan, shown, summary_lines

import regaudit_fhe as rf
from regaudit_fhe import cli as engine_cli

SAMPLES = Path(__file__).parents[1] / "regaudit_portal" / "samples"


def _send(request) -> tuple[int, dict]:
    raw = request if isinstance(request, bytes) else json.dumps(request).encode()
    return prepared(raw)


def _with(request: dict, **changes) -> dict:
    """The request with the first issuer's members changed."""
    copy = json.loads(json.dumps(request))
    copy["issuers"][0].update(changes)
    return copy


@pytest.fixture(scope="module")
def signer():
    return issuer_signer()


@pytest.fixture
def request_body(signer):
    return plan_request([signer])


# ----------------------------------------------------------------------------- a good plan


def test_a_good_request_gives_the_plan_and_exactly_what_would_be_written(signer, request_body):
    status, body = _send(request_body)
    assert status == 200 and body["ok"] is True
    assert body["issuers"] == [
        {
            "number": 1,
            "issuer": signer.issuer,
            "key_id": signer.key_id,
            "matches": True,
        }
    ]
    assert fingerprint_of(signer) not in json.dumps(body)
    plan = read_plan(body["plan_text"].encode())
    assert body["plan_sha256"] == plan.content_sha256 and body["file_name"].endswith(".json")
    assert [w["file"] for w in body["writes"]] == ["portal-config.json", "trust-store.json"]
    assert body["writes"][0]["text"] == plan.configuration_text()
    assert body["writes"][1]["text"] == plan.trust_list_text()
    assert all(w["mode"] == "0600" for w in body["writes"])


def test_the_plan_file_holds_no_fingerprint_no_place_and_no_private_material(signer, request_body):
    text = _send(request_body)[1]["plan_text"]
    assert fingerprint_of(signer) not in text and "fingerprint" not in text
    for word in ("path", "folder", "store", "config_folder", "PRIVATE", "SECRET"):
        assert word not in text, word
    assert text.isascii()


def test_upper_case_and_surrounding_spaces_in_a_fingerprint_are_accepted_as_trust_add_accepts_them(
    signer, request_body
):
    for typed in (
        fingerprint_of(signer).upper(),
        f"  {fingerprint_of(signer)}\n",
        f"\t{fingerprint_of(signer)} ",
    ):
        assert _send(_with(request_body, fingerprint=typed))[0] == 200


def test_the_summary_shows_no_fingerprint(signer, request_body):
    _, body = _send(request_body)
    lines = summary_lines(read_plan(body["plan_text"].encode()))
    assert lines == body["summary"]
    assert not any(re.search(r"[0-9a-f]{64}", line) for line in lines)
    assert any("No fingerprint is shown here, on purpose" in line for line in lines)


def test_the_add_issuers_plan_writes_no_configuration(signer):
    status, body = _send(plan_request([signer], mode="add-issuers"))
    assert status == 200 and len(body["writes"]) == 1
    assert "configuration" not in json.loads(body["plan_text"])
    assert "Nothing already in it is changed" in body["writes"][0]["note"]


# ----------------------------------------------------------------------------- private and secret key material


def _ed25519_private(signer, fmt, encryption=None):
    return signer.private_key.private_bytes(
        serialization.Encoding.PEM, fmt, encryption or serialization.NoEncryption()
    ).decode()


def _secret_forms(signer) -> dict[str, str]:
    pkcs8 = _ed25519_private(signer, serialization.PrivateFormat.PKCS8)
    der = signer.private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    raw = signer.private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public_raw = signer.public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    openssh = _ed25519_private(signer, serialization.PrivateFormat.OpenSSH)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return {
        "pkcs8 pem": pkcs8,
        "pkcs8 pem lower case header": pkcs8.replace("PRIVATE KEY", "private key"),
        "encrypted pkcs8 pem": _ed25519_private(
            signer, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw")
        ),
        "openssh": openssh,
        "openssh body without its header": "".join(openssh.strip().splitlines()[1:-1]),
        "ec private key": ec_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode(),
        "rsa private key": rsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode(),
        "pkcs8 der in base64 without a header": base64.b64encode(der).decode(),
        "pkcs8 der in base64 over several lines": "\n".join(
            re.findall(".{1,20}", base64.b64encode(der).decode())
        ),
        "raw seed in hex": raw.hex(),
        "raw seed in base64": base64.b64encode(raw).decode(),
        "raw seed in url-safe base64 without padding": base64.urlsafe_b64encode(raw)
        .decode()
        .rstrip("="),
        "seed and public half in hex": (raw + public_raw).hex(),
        "seed and public half in base64": base64.b64encode(raw + public_raw).decode(),
        "public key then private key": signer.public_key_pem() + pkcs8,
        "private key then public key": pkcs8 + signer.public_key_pem(),
        "putty key file": "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPrivate-Lines: 1\nAAAAIH0Kq\n",
        "age secret key": "AGE-SECRET-KEY-1QQPQZ3R3NNWRZ8E9SH8Y0HXKQZ6LJ3T4XMW6M2XLX4X3F8PQZ3RSQ6R7XYZ",
        "minisign secret key": "untrusted comment: minisign encrypted secret key\nRWRTY0IyAAAAAAAAAAAAAAAAAAAA",
        "pgp private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----",
        "json web key with its private member": json.dumps(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "d": base64.urlsafe_b64encode(raw).decode().rstrip("="),
                "x": "AAAA",
            }
        ),
    }


@pytest.fixture(scope="module")
def secrets(signer):
    return _secret_forms(signer)


def _distinctive(text: str) -> list[str]:
    """Pieces of the secret that must not come back in any answer."""
    pieces = [
        line.strip()
        for line in text.splitlines()
        if len(line.strip()) >= 12 and "-----" not in line
    ]
    compact = "".join(text.split())
    return [p[:24] for p in pieces] + ([compact[:24]] if len(compact) >= 24 else [compact])


def test_private_or_secret_key_material_in_the_public_key_box_is_refused_in_every_form(
    secrets, request_body
):
    for label, secret in secrets.items():
        status, body = _send(_with(request_body, public_key=secret))
        assert status == 422 and body["error"] == "secret_key_material", (label, body)
        assert body["where"] == "issuer 1, public key", label
        assert "private" in body["message"].lower() or "secret" in body["message"].lower(), label
        answer = json.dumps(body)
        for piece in _distinctive(secret):
            assert piece not in answer, (label, piece)


@pytest.mark.parametrize("member", ["issuer", "key_id", "fingerprint"])
def test_a_private_key_in_any_other_box_is_refused_too_and_not_shown_back(
    secrets, request_body, member
):
    for label in ("pkcs8 pem", "openssh", "pkcs8 der in base64 without a header", "putty key file"):
        status, body = _send(_with(request_body, **{member: secrets[label]}))
        assert status == 422 and body["error"] == "secret_key_material", (member, label, body)
        for piece in _distinctive(secrets[label]):
            assert piece not in json.dumps(body)


def test_a_private_key_in_the_verifier_id_an_unknown_member_or_a_member_name_is_refused(
    secrets, request_body
):
    secret = secrets["pkcs8 pem"]
    bad = json.loads(json.dumps(request_body))
    bad["configuration"]["verifier_id"] = secret
    assert _send(bad)[1]["error"] == "secret_key_material"
    bad = json.loads(json.dumps(request_body))
    bad["extra"] = secret
    assert _send(bad)[1]["error"] == "secret_key_material"
    bad = json.loads(json.dumps(request_body))
    bad["issuers"][0][secrets["pkcs8 der in base64 without a header"]] = "x"
    _, body = _send(bad)
    assert body["error"] == "secret_key_material" and secrets[
        "pkcs8 der in base64 without a header"
    ][:24] not in json.dumps(body)


def test_raw_key_bytes_or_a_cut_private_key_in_a_name_are_refused_and_not_shown_back(
    signer, request_body
):
    raw = signer.private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    der = signer.private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_raw = signer.public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    for value in (
        raw.hex(),
        raw.hex().upper(),
        (raw + public_raw).hex(),
        base64.b64encode(raw).decode(),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
        base64.b64encode(der).decode() + "x",
        base64.b64encode(der).decode()[:30],
    ):
        status, body = _send(_with(request_body, issuer=value))
        assert status == 422 and body["error"] == "secret_key_material", (value, body)
        assert value not in json.dumps(body)


def test_long_one_word_names_and_hexadecimal_key_ids_are_still_accepted(signer, request_body):
    """Only random-looking tokens of a raw key's size are refused in a name. A key id may be hexadecimal: issuers
    sometimes derive it from the key, and it cannot be told apart from a raw secret by its form."""
    for name in (
        "NorthwindAnalyticsLimitedOfTheUnitedKingdomX",
        "ACME",
        "a" * 44,
        "Northwind 2026 Ltd",
    ):
        assert _send(_with(request_body, issuer=name))[0] == 200, name
    assert _send(_with(request_body, key_id="ab" * 32))[0] == 200


def test_ordinary_names_that_mention_private_or_secret_are_not_mistaken_for_keys(signer):
    for name in (
        "Acme Private Bank AG",
        "Secret Garden Analytics",
        "Private Key Infrastructure Ltd",
    ):
        named = rf.Signer(name, "acme-1", signer.private_key, signer.public_key)
        assert _send(plan_request([named]))[0] == 200, name


def test_a_public_key_in_hex_is_refused_as_possibly_secret_with_a_message_saying_why(
    signer, request_body
):
    public_raw = signer.public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    _, body = _send(_with(request_body, public_key=public_raw.hex()))
    assert (
        body["error"] == "secret_key_material"
        and "fingerprint or a raw secret key" in body["message"]
    )
    _, body = _send(_with(request_body, public_key=fingerprint_of(signer)))
    assert body["error"] == "secret_key_material" and fingerprint_of(signer) not in json.dumps(body)


# ----------------------------------------------------------------------------- what is not one Ed25519 public key


@pytest.mark.parametrize(
    "label, text",
    [
        ("leading text", "hello\n{pem}"),
        ("trailing text", "{pem}bye\n"),
        ("two keys", "{pem}{pem}"),
        ("a header line", "{begin}\nProc-Type: 4,ENCRYPTED\n{body}\n{end}\n"),
        ("a blank line inside", "{begin}\n\n{body}\n{end}\n"),
        ("not base64 inside", "{begin}\n%%%%\n{end}\n"),
        ("only the base64", "{body}"),
        ("empty", ""),
        (
            "openssh public key",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x@y",
        ),
        ("a certificate", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"),
    ],
)
def test_anything_but_one_pem_public_key_is_refused(signer, request_body, label, text):
    lines = signer.public_key_pem().strip().splitlines()
    value = text.format(pem=signer.public_key_pem(), begin=lines[0], end=lines[-1], body=lines[1])
    status, body = _send(_with(request_body, public_key=value))
    assert status == 422 and body["where"] == "issuer 1, public key", (label, body)


def test_a_key_that_is_not_ed25519_is_refused(request_body):
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    pem = other.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    status, body = _send(_with(request_body, public_key=pem))
    assert status == 422 and "Only Ed25519 public keys are accepted" in body["message"]


def test_crlf_line_ends_and_indentation_are_tidied_into_the_engines_own_form(signer, request_body):
    messy = "  " + signer.public_key_pem().replace("\n", "\r\n    ")
    status, body = _send(_with(request_body, public_key=messy))
    assert status == 200
    assert (
        read_plan(body["plan_text"].encode()).issuers[0].public_key_pem == signer.public_key_pem()
    )


# ----------------------------------------------------------------------------- the demonstration keys


def test_the_bundled_demonstration_keys_are_refused_by_fingerprint_whatever_they_are_called(
    request_body,
):
    trust = json.loads((SAMPLES / "demo-trust-list.json").read_text())
    unenrolled = json.loads((SAMPLES / "reports" / "untrusted-signer.json").read_text())["receipt"][
        "public_key_pem"
    ]
    for pem in (trust["entries"]["demo-only-synthetic-key"]["public_key_pem"], unenrolled):
        from regaudit_fhe._keys import spki_fingerprint

        status, body = _send(_with(request_body, public_key=pem, fingerprint=spki_fingerprint(pem)))
        assert status == 422 and body["error"] == "demonstration_key", body
        assert "demonstration keys" in body["message"] and "never be enrolled" in body["message"]


@pytest.mark.parametrize(
    "member, value",
    [
        ("issuer", "DEMO-ONLY synthetic issuer"),
        ("issuer", "Example Synthetic Issuer"),
        ("issuer", "Demo Analytics Ltd"),
        ("key_id", "demo-only-synthetic-key"),
        ("key_id", "synthetic-issuer-key"),
    ],
)
def test_names_and_key_ids_that_contain_demo_or_synthetic_are_ordinary(request_body, member, value):
    """No name or key id makes an issuer a demonstration: only the bundled keys, by fingerprint, are refused."""
    status, body = _send(_with(request_body, **{member: value}))
    assert status == 200, body


def test_a_plan_cannot_ask_for_demonstration_trust(signer):
    content = json.loads(prepare_plan([signer]))
    content["configuration"]["trust_mode"] = "demonstration"
    with pytest.raises(PlanProblem):
        read_plan(crafted_plan(content))
    request = plan_request([signer])
    request["configuration"]["trust_mode"] = "demonstration"
    assert _send(request)[0] == 422
    request = plan_request([signer])
    request["trust_mode"] = "demonstration"
    assert _send(request)[0] == 422


# ----------------------------------------------------------------------------- fingerprints as typed


def _lookalike(fingerprint: str) -> dict[str, str]:
    return {
        "fullwidth digits and letters": fingerprint.translate(
            str.maketrans("0123456789abcdef", "０１２３４５６７８９ａｂｃｄｅｆ")
        ),
        "cyrillic a": fingerprint.replace("a", "а", 1)
        if "a" in fingerprint
        else "а" + fingerprint[1:],
        "greek omicron for zero": fingerprint.replace("0", "ο", 1)
        if "0" in fingerprint
        else "ο" + fingerprint[1:],
        "zero-width space inside": fingerprint[:10] + "​" + fingerprint[10:],
        "no-break spaces around": " " + fingerprint + " ",
        "arabic-indic digit": "٠" + fingerprint[1:],
    }


def test_fingerprint_near_misses_are_refused_with_a_reason_and_never_shown_back(
    signer, request_body
):
    fp = fingerprint_of(signer)
    near = {
        "colons": ":".join(re.findall("..", fp)),
        "colons upper case": ":".join(re.findall("..", fp.upper())),
        "spaces inside": " ".join(re.findall("....", fp)),
        "dashes inside": "-".join(re.findall("........", fp)),
        "one character short": fp[:-1],
        "one character long": fp + "0",
        "not hexadecimal": fp[:-1] + "g",
        **_lookalike(fp),
    }
    for label, typed in near.items():
        status, body = _send(_with(request_body, fingerprint=typed))
        assert status == 422 and body["error"] == "fingerprint_format", (label, body)
        assert body["where"] == "issuer 1, fingerprint"
        assert typed not in json.dumps(body, ensure_ascii=False), label


def test_a_fingerprint_that_differs_by_one_character_is_a_mismatch_and_no_plan_is_made(
    signer, request_body
):
    fp = fingerprint_of(signer)
    wrong = fp[:-1] + ("0" if fp[-1] != "0" else "1")
    status, body = _send(_with(request_body, fingerprint=wrong))
    assert status == 422 and body["error"] == "fingerprint_mismatch" and "plan_text" not in body
    assert (
        body["issuers"][0]["matches"] is False and "computed_fingerprint" not in body["issuers"][0]
    )
    assert wrong not in json.dumps(body) and fp not in json.dumps(body)


def test_an_empty_fingerprint_is_refused(request_body):
    assert _send(_with(request_body, fingerprint="  "))[1]["error"] == "fingerprint_missing"


# ----------------------------------------------------------------------------- names and key ids


@pytest.mark.parametrize(
    "name",
    [
        "\x1b[31mEvil Ltd",
        "\x1b]0;title\x07Acme",
        "Acme\x07Ltd",
        "Acme\nLtd",
        "Acme\rLtd",
        "Acme\tLtd",
        "Acme‮Ltd",
        "Acme​Ltd",
        "Acme Ltd",
        "Acme\x00Ltd",
        "Acme\x7fLtd",
        "Acme\x9bLtd",
        " Acme Ltd",
        "Acme Ltd ",
        "A" * 257,
        "",
    ],
)
def test_names_with_control_or_invisible_characters_or_stray_spaces_are_refused_and_not_shown_back(
    request_body, name
):
    status, body = _send(_with(request_body, issuer=name))
    assert status == 422 and body["where"] == "issuer 1, name", body
    if name.strip():
        assert name not in json.dumps(body, ensure_ascii=False)
        assert "\x1b" not in json.dumps(body, ensure_ascii=False)


@pytest.mark.parametrize(
    "key_id",
    [
        "../x",
        "a/b",
        "a\\b",
        ".hidden",
        "-x",
        "a..b",
        "with space",
        "ключ",
        "x" * 129,
        "",
        "~root",
        "a:b",
        "C:",
    ],
)
def test_path_like_or_unusual_key_ids_are_refused(request_body, key_id):
    status, body = _send(_with(request_body, key_id=key_id))
    assert status == 422 and body["where"] == "issuer 1, key id", body


def test_two_issuers_with_the_same_key_id_or_the_same_key_are_refused(signer):
    other = issuer_signer("Other Ltd", signer.key_id)
    assert _send(plan_request([signer, other]))[1]["message"].startswith(
        "Two issuers have the same key id"
    )
    same_key = rf.Signer("Other Ltd", "other-1", signer.private_key, signer.public_key)
    assert _send(plan_request([signer, same_key]))[1]["message"].startswith(
        "The same public key appears twice"
    )


# ----------------------------------------------------------------------------- the configuration


@pytest.mark.parametrize(
    "change",
    [
        {"profile": "custom"},
        {"profile": ""},
        {"profile": None},
        {"profile": 1},
        {"max_age_days": 0},
        {"max_age_days": 3651},
        {"max_age_days": 30.0},
        {"max_age_days": "30"},
        {"max_age_days": True},
        {"replay_mode": "off"},
        {"verifier_id": ""},
        {"verifier_id": "me\x1b[2J"},
        {"verifier_id": "x" * 201},
        {"allow_self_signed": True},
        {"trust_store": "../../elsewhere.json"},
        {"replay_db": "/tmp/replay.db"},  # noqa: S108 - a place a plan must never name
    ],
)
def test_a_configuration_outside_the_fixed_choices_is_refused(request_body, change):
    bad = json.loads(json.dumps(request_body))
    bad["configuration"].update(change)
    status, body = _send(bad)
    assert status == 422, (change, body)


@pytest.mark.parametrize("days", [1, 3650])
def test_the_ends_of_the_age_range_are_accepted(signer, days):
    assert _send(plan_request([signer], max_age_days=days))[0] == 200


def test_every_profile_and_replay_mode_offered_is_accepted(signer):
    for profile in ("confidential", "high-assurance", "development"):
        for mode in ("check", "record"):
            assert _send(plan_request([signer], profile=profile, replay_mode=mode))[0] == 200


def test_add_issuers_with_a_configuration_or_first_setup_without_one_is_refused(signer):
    first = plan_request([signer])
    first["mode"] = "add-issuers"
    assert _send(first)[0] == 422
    add = plan_request([signer], mode="add-issuers")
    add["mode"] = "first-setup"
    assert _send(add)[0] == 422


# ----------------------------------------------------------------------------- the shape of what is sent


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"\xef\xbb\xbf{}",
        b"\xff\xfe{}",
        b'{"mode": "first-setup", "mode": "add-issuers"}',
        b'{"mode": NaN}',
        b'{"mode": "first-setup"} trailing',
        b"[" * 5000 + b"]" * 5000,
        b'{"a":' * 3000 + b"1" + b"}" * 3000,
        b"[]",
        b'"first-setup"',
        b"null",
    ],
)
def test_anything_that_is_not_one_plain_json_object_of_the_right_shape_is_refused(raw):
    status, body = _send(raw)
    assert status == 422 and body.get("ok") is not True, body


def test_more_than_the_size_limit_is_refused_before_it_is_parsed(signer):
    big = plan_request([signer])
    big["configuration"]["verifier_id"] = "x" * (plan_module.MAX_PLAN_BYTES + 1)
    assert _send(big)[0] == 413


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(issuers=[]),
        lambda r: r.update(issuers={}),
        lambda r: r.update(issuers=[r["issuers"][0]] * 11),
        lambda r: r["issuers"].__setitem__(0, "not an object"),
        lambda r: r["issuers"][0].update(status="revoked"),
        lambda r: r["issuers"][0].update(replace="old-key"),
        lambda r: r["issuers"][0].pop("key_id"),
        lambda r: r.update(remove=["old-key"]),
        lambda r: r.update(destination="/etc"),
        lambda r: r.update(mode="remove-issuers"),
        lambda r: r.pop("mode"),
    ],
)
def test_wrong_types_unknown_members_and_unsupported_actions_are_refused(request_body, change):
    bad = json.loads(json.dumps(request_body))
    change(bad)
    assert _send(bad)[0] == 422


# ----------------------------------------------------------------------------- a plan file


def test_a_prepared_plan_reads_back_to_the_same_plan(signer):
    text = prepare_plan([signer, issuer_signer("Second Issuer", "second-1")])
    plan = read_plan(text.encode())
    assert plan.text() == text and len(plan.issuers) == 2


def _tampered(text: str):
    """Every way of changing one thing in a plan while keeping the checksum it came with."""
    original = json.loads(text)
    another = issuer_signer("Mallory Ltd", "mallory-1").public_key_pem()
    changes = {
        "profile": lambda p: p["configuration"].update(profile="development"),
        "verifier id": lambda p: p["configuration"].update(verifier_id="someone-else"),
        "maximum age": lambda p: p["configuration"].update(max_age_days=3650),
        "replay mode": lambda p: p["configuration"].update(replay_mode="record"),
        "issuer name": lambda p: p["issuers"][0].update(issuer="Mallory Ltd"),
        "key id": lambda p: p["issuers"][0].update(key_id="mallory-1"),
        "public key": lambda p: p["issuers"][0].update(public_key_pem=another),
        "issuer added": lambda p: p["issuers"].append(
            {"issuer": "Mallory Ltd", "key_id": "mallory-1", "public_key_pem": another}
        ),
        "issuer removed": lambda p: p["issuers"].pop(),
        "issuers reordered": lambda p: p["issuers"].reverse(),
        "checksum": lambda p: p.update(
            content_sha256=("0" if p["content_sha256"][0] != "0" else "1") + p["content_sha256"][1:]
        ),
    }
    for label, change in changes.items():
        copy = json.loads(json.dumps(original))
        change(copy)
        yield label, json.dumps(copy).encode()


def test_changing_any_field_of_a_plan_without_its_checksum_is_refused(signer):
    text = prepare_plan([signer, issuer_signer("Second Issuer", "second-1")])
    for label, data in _tampered(text):
        with pytest.raises(PlanProblem) as caught:
            read_plan(data)
        assert caught.value.code == "changed", (label, caught.value)


def test_a_checksum_is_not_a_signature_a_hostile_plan_with_a_matching_checksum_reads(signer):
    """Anyone can make a plan whose checksum matches. Reading it is not trusting it: the typed fingerprint is."""
    attacker = issuer_signer(signer.issuer, signer.key_id)
    content = json.loads(prepare_plan([signer]))
    content["issuers"][0]["public_key_pem"] = attacker.public_key_pem()
    plan = read_plan(crafted_plan(content))
    assert plan.issuers[0].fingerprint == fingerprint_of(attacker) != fingerprint_of(signer)


@pytest.mark.parametrize(
    "change",
    [
        lambda p, fp: p["issuers"][0].update(fingerprint=fp),
        lambda p, fp: p["issuers"][0].update(fingerprint_sha256=fp),
        lambda p, fp: p.update(fingerprints={"northwind-2026": fp}),
        lambda p, fp: p.update(destination="/etc"),
        lambda p, fp: p.update(config_folder="~/elsewhere"),
        lambda p, fp: p.update(trust_store="../x.json"),
        lambda p, fp: p.update(revoke=["old"]),
        lambda p, fp: p["issuers"][0].update(status="compromised"),
        lambda p, fp: p.update(format="something-else"),
        lambda p, fp: p.update(version=2),
        lambda p, fp: p.update(version=True),
        lambda p, fp: p.update(version=1.0),
        lambda p, fp: p.update(mode="add-issuers"),
        lambda p, fp: p.update(content_sha256=p["content_sha256"].upper()),
    ],
)
def test_a_plan_with_members_or_values_a_plan_never_has_is_refused_even_with_a_matching_checksum(
    signer, change
):
    content = json.loads(prepare_plan([signer]))
    change(content, fingerprint_of(signer))
    data = (
        crafted_plan(content)
        if content["content_sha256"].islower()
        else json.dumps(content).encode()
    )
    with pytest.raises(PlanProblem):
        read_plan(data)


def test_a_plan_whose_key_is_not_written_the_way_the_portal_writes_it_is_refused(signer):
    content = json.loads(prepare_plan([signer]))
    content["issuers"][0]["public_key_pem"] = content["issuers"][0]["public_key_pem"].replace(
        "\n", "\r\n"
    )
    with pytest.raises(PlanProblem) as caught:
        read_plan(crafted_plan(content))
    assert caught.value.code == "changed"


def test_a_crafted_plan_holding_a_demonstration_key_is_refused(signer):
    pem = json.loads((SAMPLES / "demo-trust-list.json").read_text())["entries"][
        "demo-only-synthetic-key"
    ]["public_key_pem"]
    content = json.loads(prepare_plan([signer]))
    content["issuers"][0]["public_key_pem"] = pem
    with pytest.raises(PlanProblem) as caught:
        read_plan(crafted_plan(content))
    assert caught.value.code == "demonstration_key"


def test_a_plan_file_over_the_size_limit_is_refused(signer):
    with pytest.raises(PlanProblem) as caught:
        read_plan(prepare_plan([signer]).encode() + b" " * plan_module.MAX_PLAN_BYTES)
    assert caught.value.code == "too_large"


# ----------------------------------------------------------------------------- the same bytes as trust add


def _trust_add(store: Path, key_dir: Path, signer: rf.Signer) -> None:
    key = key_dir / f"{signer.key_id}.pub"
    key.write_text(signer.public_key_pem())
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        code = engine_cli.main(
            ["trust", "add", "--store", str(store), "--key-id", signer.key_id, "--issuer", signer.issuer,
             "--public-key", str(key), "--fingerprint", fingerprint_of(signer)]
        )  # fmt: skip
    assert code == 0


def test_the_trust_list_shown_is_byte_for_byte_what_regaudit_fhe_trust_add_writes(tmp_path):
    signers = [
        issuer_signer("Northwind Ltd", "nw-1"),
        issuer_signer("Ünïcode Issuer GmbH", "u-2"),
        issuer_signer("Third", "t.3"),
    ]
    store = tmp_path / "store.json"
    for signer in signers:
        _trust_add(store, tmp_path, signer)
    plan = read_plan(prepare_plan(signers).encode())
    assert plan.trust_list_text().encode() == store.read_bytes()


def test_adding_to_an_existing_trust_list_gives_what_trust_add_gives_from_that_list(tmp_path):
    first, later = issuer_signer("Northwind Ltd", "nw-1"), issuer_signer("Later Ltd", "later-1")
    store = tmp_path / "store.json"
    store.write_text(json.dumps({"as_of": "2026-01-01T00:00:00Z", "entries": {}}))
    _trust_add(store, tmp_path, first)
    existing = json.loads(store.read_text())
    _trust_add(store, tmp_path, later)
    plan = read_plan(prepare_plan([later], mode="add-issuers").encode())
    assert plan.trust_list_text(existing).encode() == store.read_bytes()


def test_the_configuration_shown_is_one_the_portal_reads_as_the_plan_says(tmp_path, signer):
    plan = read_plan(
        prepare_plan(
            [signer], profile="high-assurance", max_age_days=7, replay_mode="record"
        ).encode()
    )
    folder = tmp_path / "c"
    folder.mkdir(mode=0o700)
    for name, text in (
        ("portal-config.json", plan.configuration_text()),
        ("trust-store.json", plan.trust_list_text()),
    ):
        (folder / name).write_text(text)
        os.chmod(folder / name, 0o600)
    settings = read_settings(folder / "portal-config.json")
    assert (settings.profile, settings.verifier_id, settings.max_age_days, settings.replay_mode) == (
        "high-assurance", "northwind-verifier", 7, "record"
    )  # fmt: skip
    assert settings.allow_self_signed is False and list(read_trust_store(settings).entries) == [
        signer.key_id
    ]
    assert (
        settings.trust_mode == "customer"
        and '"trust_mode": "customer"' in plan.configuration_text()
    )


# ----------------------------------------------------------------------------- showing text safely


def test_shown_makes_control_and_invisible_characters_visible_and_caps_the_length():
    assert shown("a\x1b[31mb‮c\x07") == "a\\u{001B}[31mb\\u{202E}c\\u{0007}"
    assert shown("x" * 10, 4) == "xxxx (shortened)"
    assert shown("Northwind Ltd") == "Northwind Ltd"


# ----------------------------------------------------------------------------- settings that weaken the checks are named first


def _plan(signer, **options):
    return read_plan(prepare_plan([signer], **options).encode())


def test_the_weak_settings_plan_says_so_first_in_plain_sentences(signer):
    """The real issuer's key with the development profile, 3650 days and replay mode check."""
    plan = _plan(signer, profile="development", max_age_days=3650, replay_mode="check")
    lines = summary_lines(plan)
    assert len(notices(plan)) == 3 and lines[:3] == notices(plan)
    assert lines[0].startswith("Notice: the profile is development. It is for trying things out.")
    assert "Do not rely on its results" in lines[0]
    assert (
        lines[1].startswith("Notice: the maximum report age is 3650 days.")
        and "longer than 30 days" in lines[1]
    )
    assert (
        lines[2].startswith("Notice: the replay mode is check.")
        and "not refused as a repeat" in lines[2]
    )
    assert lines[3].startswith(
        'Verifier id: "northwind-verifier". A report that names its recipients must name'
    )
    assert "your own organisation's id" in lines[3]
    assert lines.index(lines[3]) < next(
        i for i, line in enumerate(lines) if line.startswith("Issuers to enrol")
    )


def test_a_plan_without_weak_settings_has_no_notice_and_starts_with_the_verifier_id(signer):
    for profile in ("confidential", "high-assurance"):
        plan = _plan(signer, profile=profile, max_age_days=30, replay_mode="record")
        assert notices(plan) == [] and summary_lines(plan)[0].startswith("Verifier id:")


@pytest.mark.parametrize(
    "options, expected",
    [
        ({"profile": "development", "replay_mode": "record"}, ["development"]),
        ({"replay_mode": "check"}, ["replay mode is check"]),
        ({"max_age_days": 30, "replay_mode": "record"}, []),
        ({"max_age_days": 31, "replay_mode": "record"}, ["31 days"]),
        ({"max_age_days": 1, "replay_mode": "record"}, []),
    ],
)
def test_each_notice_appears_for_its_own_setting_and_the_age_notice_starts_above_30_days(
    signer, options, expected
):
    found = notices(_plan(signer, **options))
    assert len(found) == len(expected) and all(
        word in line for word, line in zip(expected, found, strict=True)
    )


def test_adding_issuers_changes_no_setting_so_it_has_no_notice_and_no_verifier_line(signer):
    plan = _plan(signer, mode="add-issuers")
    assert notices(plan) == [] and not any(
        line.startswith("Verifier id") for line in summary_lines(plan)
    )


def test_the_prepare_answer_shows_the_notices_first(signer):
    status, body = _send(
        plan_request([signer], profile="development", max_age_days=3650, replay_mode="check")
    )
    assert status == 200 and len(body["notices"]) == 3 and body["summary"][:3] == body["notices"]


# ----------------------------------------------------------------------------- a private seed in the wrong box


def _seed(signer) -> bytes:
    return signer.private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def test_the_private_seed_of_the_plans_own_key_is_refused_in_any_box_and_not_shown_back(
    signer, request_body
):
    seed = _seed(signer)
    public = signer.public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    forms = [seed.hex(), base64.urlsafe_b64encode(seed).decode().rstrip("="), (seed + public).hex()]
    for value in forms:
        for member in ("key_id", "fingerprint"):
            status, body = _send(_with(request_body, **{member: value}))
            assert status == 422 and body["error"] == "secret_key_material", (member, value, body)
            assert "private key of one of the public keys in this plan" in body["message"]
            assert value not in json.dumps(body)
        bad = json.loads(json.dumps(request_body))
        bad["configuration"]["verifier_id"] = value
        status, body = _send(bad)
        assert (
            body["error"] == "secret_key_material" and body["where"] == "configuration, verifier id"
        )


def test_a_plan_file_whose_key_id_is_its_own_private_seed_is_refused(signer):
    content = json.loads(prepare_plan([signer]))
    content["issuers"][0]["key_id"] = _seed(signer).hex()
    with pytest.raises(PlanProblem) as caught:
        read_plan(crafted_plan(content))
    assert caught.value.code == "secret_key_material"


def test_ids_that_only_look_like_secret_bytes_are_accepted(signer, request_body):
    """A key id derived from a key is hexadecimal or base64url, so its form alone cannot be refused."""
    import hashlib

    der = signer.public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    thumbprint = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip("=")
    if not thumbprint[0].isalnum():
        # A key id must start with a letter or a digit, whatever its form: one in 32 thumbprints starts with - or _.
        assert _send(_with(request_body, key_id=thumbprint))[0] == 422, thumbprint
        thumbprint = "k" + thumbprint[1:]
    for key_id in (
        fingerprint_of(signer),  # the SHA-256 fingerprint as the key id: 64 hexadecimal characters
        hashlib.sha512(der).hexdigest(),  # 128 hexadecimal characters
        thumbprint,  # a JWK thumbprint: 43
        _seed(issuer_signer()).hex(),  # random bytes that are not this plan's key
    ):
        assert _send(_with(request_body, key_id=key_id))[0] == 200, key_id
    ok = json.loads(json.dumps(request_body))
    ok["configuration"]["verifier_id"] = "ab" * 32
    assert _send(ok)[0] == 200


def test_a_name_or_key_id_typed_as_the_fingerprint_is_told_it_is_not_one(signer, request_body):
    """Not "take out the separators": a name or a key id often has spaces or dashes, and it is not a fingerprint."""
    for typed in (signer.key_id, signer.issuer, "Test Issuer One Ltd", "test-issuer-1"):
        status, body = _send(_with(request_body, fingerprint=typed))
        assert status == 422 and body["error"] == "fingerprint_format", typed
        assert body["message"] == plan_module.NOT_A_FINGERPRINT, typed
        assert "separators" not in body["message"] and typed not in json.dumps(body), typed
    # A real fingerprint written with separators still gets the advice to take them out.
    fp = fingerprint_of(signer)
    for typed in (":".join(re.findall("..", fp)), " ".join(re.findall("....", fp))):
        status, body = _send(_with(request_body, fingerprint=typed))
        assert status == 422 and "without separators" in body["message"]
