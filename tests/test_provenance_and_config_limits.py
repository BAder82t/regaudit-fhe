"""Provenance allocation bound and strict validation of numeric server settings (0.1.1).

* ``n_buckets`` made the provenance primitive allocate a dense (n_buckets, n_slots) float64 matrix: a ~100 byte
  request with ``n_buckets=8192`` took ~750 MB. It is now bounded (``max_provenance_buckets`` and
  ``max_provenance_cells``) before schema validation, thread dispatch and any allocation, on the HTTP route and on
  the shared dispatch used by the CLI and the library.
* ``REGAUDIT_FHE_MAX_BODY_BYTES``, ``..._RATE_LIMIT_PER_MIN``, ``..._REQUEST_TIMEOUT_S`` and the rest of the
  numeric settings refuse to start on a value that is zero, negative, NaN, infinite, malformed, padded, signed,
  non-ASCII or absurdly large.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import textwrap
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from regaudit_fhe import server
from regaudit_fhe._limits import InputLimitError, InputLimits, check_primitive_cost, use_limits
from regaudit_fhe.cli import _audit_dispatch, main
from regaudit_fhe.server import ServerConfig, build_app

H = {"Authorization": "Bearer t", "Content-Type": "application/json"}
INCONSISTENT = {"detail": "the audit input is inconsistent (see the input schema)"}


def _client(**kw: Any) -> TestClient:
    base: dict[str, Any] = dict(
        api_keys={"t": frozenset({"admin"})},
        dev_mode=False,
        max_body_bytes=8 << 20,
        rate_limit_per_min=10**6,
        request_timeout_s=60.0,
        cors_origins=(),
    )
    base.update(kw)
    return TestClient(build_app(config=ServerConfig(**base), logger=logging.getLogger("t")))


def _prov(n_buckets: Any, n_rows: int = 1, k: Any = 1) -> bytes:
    body = {
        "attributions": [0.1] * n_rows,
        "row_ids": list(range(n_rows)),
        "n_buckets": n_buckets,
        "k": k,
    }
    return json.dumps(body).encode()


def _refusal(limit: str, maximum: int, detail: str) -> dict[str, Any]:
    return {"detail": detail, "code": "INPUT_LIMIT_EXCEEDED", "limit": limit, "maximum": maximum}


BUCKETS = "provenance input has more buckets than the configured limit"
CELLS = "provenance input needs a larger bucket matrix than the configured limit"


def test_provenance_defaults_are_the_documented_ones() -> None:
    lim = InputLimits()
    assert (lim.max_provenance_buckets, lim.max_provenance_cells) == (1024, 8388608)


# ---- n_buckets boundary ---------------------------------------------------------------------------------


def test_the_cap_itself_is_served() -> None:
    r = _client().post("/v1/audit/provenance", content=_prov(1024), headers=H)
    assert r.status_code == 200
    assert len(r.json()["result"]["bucket_aggregates"]) == 1024


def test_cap_minus_one_passes_the_limit_and_fails_in_the_primitive_not_with_413() -> None:
    # 1023 is not a power of two: the limit lets it through and the primitive refuses it, fast and fixed-body.
    r = _client().post("/v1/audit/provenance", content=_prov(1023), headers=H)
    assert r.status_code == 422
    assert r.json() == INCONSISTENT


@pytest.mark.parametrize("value", [1025, 2048, 4096, 8192, 32768, 10**9, 10**30, 4096.0, 1e30])
def test_excessive_n_buckets_is_refused_before_any_allocation(value: Any) -> None:
    r = _client().post("/v1/audit/provenance", content=_prov(value), headers=H)
    assert r.status_code == 413
    assert r.json() == _refusal("max_provenance_buckets", 1024, BUCKETS)
    assert "n_buckets" not in r.text and str(value) not in r.text


@pytest.mark.parametrize("value", ["4096", 3.5, True, None, -1, 0, [], {}, "1e9"])
def test_invalid_n_buckets_types_are_a_schema_refusal(value: Any) -> None:
    r = _client().post("/v1/audit/provenance", content=_prov(value), headers=H)
    assert r.status_code == 422
    body = r.json()
    assert set(body) == {"detail"}
    assert isinstance(body["detail"], str)


def test_k_beyond_n_buckets_is_still_the_primitive_refusal() -> None:
    r = _client().post("/v1/audit/provenance", content=_prov(4, 4, k=5), headers=H)
    assert r.status_code == 422
    assert r.json() == INCONSISTENT


def test_the_bucket_matrix_size_is_bounded_not_just_the_bucket_count() -> None:
    c = _client(max_body_bytes=16 << 20)
    # 64 x 131072 = 2**23 cells: exactly the cap, served.
    r = c.post("/v1/audit/provenance", content=_prov(64, 131072), headers=H)
    assert r.status_code == 200
    # 128 x 131072 = 2**24 cells: refused although 128 buckets is far below the bucket cap.
    r = c.post("/v1/audit/provenance", content=_prov(128, 131072), headers=H)
    assert r.status_code == 413
    assert r.json() == _refusal("max_provenance_cells", 8388608, CELLS)
    # 65 x 131072 is just past the cap although 65 is not even close to the bucket cap
    r = c.post("/v1/audit/provenance", content=_prov(65, 131072), headers=H)
    assert r.status_code == 413
    assert r.json()["limit"] == "max_provenance_cells"


def test_operator_can_raise_the_limits_and_cannot_disable_them() -> None:
    lim = InputLimits(max_provenance_buckets=2048, max_provenance_cells=1 << 24)
    r = _client(input_limits=lim).post("/v1/audit/provenance", content=_prov(2048), headers=H)
    assert r.status_code == 200
    with pytest.raises(ValueError, match="positive integer"):
        InputLimits(max_provenance_buckets=0)
    with pytest.raises(ValueError, match="positive integer"):
        InputLimits(max_provenance_cells=-1)


# ---- the shared dispatch (CLI and library) ---------------------------------------------------------------


@pytest.mark.parametrize("value", [1025, 4096, 8192, 10**9, 10**30])
def test_dispatch_refuses_before_validation_or_allocation(value: int) -> None:
    payload = json.loads(_prov(value))
    with pytest.raises(InputLimitError) as info:
        _audit_dispatch("provenance", payload)
    assert info.value.limit == "max_provenance_buckets"
    assert str(info.value) == "max_provenance_buckets exceeded (maximum 1024)"


def test_dispatch_tolerates_wrong_types_and_leaves_them_to_the_schema() -> None:
    for bad in ("x", None, True, 1.5, -3, []):
        check_primitive_cost("provenance", {"n_buckets": bad}, InputLimits())
    check_primitive_cost("provenance", [1, 2], InputLimits())


def test_dispatch_uses_the_servers_configured_limits_inside_use_limits() -> None:
    payload = json.loads(_prov(2048))
    with pytest.raises(InputLimitError):
        _audit_dispatch("provenance", payload)
    with use_limits(InputLimits(max_provenance_buckets=2048, max_provenance_cells=1 << 24)):
        assert _audit_dispatch("provenance", payload).primitive == "provenance"


def test_cli_audit_refuses_with_exit_code_2(
    tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / "in.json"
    src.write_bytes(_prov(8192))
    assert main(["audit", "provenance", "-i", str(src)]) == 2
    assert (
        capsys.readouterr().err
        == "input rejected: max_provenance_buckets exceeded (maximum 1024)\n"
    )


# ---- peak memory ------------------------------------------------------------------------------------------

_CHILD = textwrap.dedent(
    """
    import json, resource, sys
    from regaudit_fhe.cli import _audit_dispatch
    nb, n = int(sys.argv[1]), int(sys.argv[2])
    payload = {"attributions": [0.1] * n, "row_ids": list(range(n)), "n_buckets": nb, "k": 1}
    unit = 1 if sys.platform == "linux" else 1024
    base = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    try:
        _audit_dispatch("provenance", payload); out = "ok"
    except ValueError as exc:
        out = type(exc).__name__
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(json.dumps({"out": out, "delta_mb": (peak - base) / unit / 1024}))
    """
)


def _child(nb: int, n: int) -> dict[str, Any]:
    done = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-c", _CHILD, str(nb), str(n)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_the_cap_bounds_peak_memory() -> None:
    refused = _child(8192, 1)  # was ~750 MB before the cap
    assert refused["out"] == "InputLimitError"
    assert refused["delta_mb"] < 20
    refused = _child(32768, 1)
    assert refused["out"] == "InputLimitError"
    assert refused["delta_mb"] < 20
    at_cap = _child(64, 131072)  # 2**23 cells = a 64 MiB matrix
    assert at_cap["out"] == "ok"
    assert (
        at_cap["delta_mb"] < 200
    )  # measured about 75 MB; the unbounded case was 750 MB and growing 4x


# ---- other size-like parameters of every primitive ---------------------------------------------------------


@pytest.mark.parametrize(
    ("primitive", "payload"),
    [
        (
            "fairness",
            {
                "y_true": [1, 0],
                "y_pred": [1, 0],
                "group_a": [1, 0],
                "group_b": [0, 1],
                "threshold": 1,
            },
        ),
        ("drift", {"p": [0.5, 0.5], "q": [0.5, 0.5], "drift_threshold": 1e308}),
        (
            "disagreement",
            {"model_polynomials": [[0.1] * 4] * 3, "test_input": [0.5], "threshold": 1e308},
        ),
        ("calibration", {"scores": [0.1, 0.2], "quantiles": [0.5, 0.5]}),
        ("concordance", {"risk": [0.1, 0.2], "time": [1.0, 2.0], "event": [1, 0]}),
        (
            "provenance",
            {"attributions": [0.1, 0.2], "row_ids": [10**18, 2], "n_buckets": 2, "k": 2},
        ),
        ("provenance", {"attributions": [0.1], "row_ids": [10**30], "n_buckets": 2, "k": 1}),
    ],
)
def test_extreme_scalar_parameters_do_not_allocate_or_crash(
    primitive: str, payload: dict[str, Any]
) -> None:
    r = _client().post(f"/v1/audit/{primitive}", content=json.dumps(payload).encode(), headers=H)
    assert r.status_code in (200, 422)
    assert set(r.json()) >= {"detail"} or r.json()["primitive"] == primitive


# ---- strict numeric settings --------------------------------------------------------------------------------

SETTINGS = [
    "REGAUDIT_FHE_MAX_BODY_BYTES",
    "REGAUDIT_FHE_RATE_LIMIT_PER_MIN",
    "REGAUDIT_FHE_REQUEST_TIMEOUT_S",
]
MALFORMED = [
    "abc",
    " 5",
    "5 ",
    "5\n",
    "1_0",
    "+5",
    "-5",
    "0x10",
    "٣",
    "１２",
    "nan",
    "NaN",
    "inf",
    "-inf",
    "1e",
    ".5",
    "5.",
]


@pytest.mark.parametrize("name", SETTINGS)
@pytest.mark.parametrize(
    "value", [*MALFORMED, "0", "0.0", "-1", "-0", "99999999999999999999", "1e400"]
)
def test_invalid_numeric_settings_refuse_to_start(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(server.PolicyError):
        server.load_config_from_env()


@pytest.mark.parametrize(
    ("name", "value", "attr", "expected"),
    [
        ("REGAUDIT_FHE_MAX_BODY_BYTES", "1", "max_body_bytes", 1),
        ("REGAUDIT_FHE_MAX_BODY_BYTES", "1073741824", "max_body_bytes", 1 << 30),
        ("REGAUDIT_FHE_RATE_LIMIT_PER_MIN", "1", "rate_limit_per_min", 1),
        ("REGAUDIT_FHE_RATE_LIMIT_PER_MIN", "1000000000", "rate_limit_per_min", 10**9),
        ("REGAUDIT_FHE_REQUEST_TIMEOUT_S", "0.5", "request_timeout_s", 0.5),
        ("REGAUDIT_FHE_REQUEST_TIMEOUT_S", "3600", "request_timeout_s", 3600.0),
        ("REGAUDIT_FHE_REQUEST_TIMEOUT_S", "45", "request_timeout_s", 45.0),
    ],
)
def test_valid_boundary_values_are_accepted(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str, attr: str, expected: Any
) -> None:
    monkeypatch.setenv(name, value)
    assert getattr(server.load_config_from_env(), attr) == expected


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("REGAUDIT_FHE_MAX_BODY_BYTES", "1073741825"),
        ("REGAUDIT_FHE_RATE_LIMIT_PER_MIN", "1000000001"),
        ("REGAUDIT_FHE_REQUEST_TIMEOUT_S", "3600.5"),
        ("REGAUDIT_FHE_QUEUE_WAIT_S", "3601"),
        ("REGAUDIT_FHE_MAX_CONCURRENT_AUDITS", "257"),
        ("REGAUDIT_FHE_MAX_ARRAY_ELEMENTS", "1000000001"),
        ("REGAUDIT_FHE_MAX_PROVENANCE_BUCKETS", "0"),
        ("REGAUDIT_FHE_MAX_PROVENANCE_CELLS", "-1"),
        ("REGAUDIT_FHE_MAX_PROVENANCE_CELLS", "2147483649"),
        ("REGAUDIT_FHE_MAX_PROVENANCE_BUCKETS", "1_0"),
        ("REGAUDIT_FHE_MAX_ARRAY_ELEMENTS", "+5"),
        ("REGAUDIT_FHE_MAX_ARRAY_ELEMENTS", "٣"),
        ("REGAUDIT_FHE_MAX_ARRAY_ELEMENTS", " 7"),
        ("REGAUDIT_FHE_MAX_AGE_S", "nan"),
        ("REGAUDIT_FHE_MAX_AGE_S", "-3"),
        ("REGAUDIT_FHE_MAX_AGE_S", "1_0"),
    ],
)
def test_other_settings_are_strict_and_bounded_too(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(server.PolicyError):
        server.load_config_from_env()


@pytest.mark.parametrize(
    "value", ["1e300", "1.5", "nan", "inf", "-1", "1e", " 0.001", "1_0", "٣", "0.0.1"]
)
def test_switch_interval_is_bounded_and_strict(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("REGAUDIT_FHE_SWITCH_INTERVAL_S", value)
    with pytest.raises(server.PolicyError):
        server.apply_switch_interval_from_env()


def test_switch_interval_zero_still_means_interpreter_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REGAUDIT_FHE_SWITCH_INTERVAL_S", "0")
    assert server.apply_switch_interval_from_env() is None


def test_unset_and_empty_settings_use_the_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (*SETTINGS, "REGAUDIT_FHE_QUEUE_WAIT_S", "REGAUDIT_FHE_MAX_AGE_S"):
        monkeypatch.delenv(name, raising=False)
    cfg = server.load_config_from_env()
    assert (cfg.max_body_bytes, cfg.rate_limit_per_min, cfg.request_timeout_s) == (
        1 << 20,
        60,
        30.0,
    )
    for name in SETTINGS:
        monkeypatch.setenv(name, "")
    cfg = server.load_config_from_env()
    assert (cfg.max_body_bytes, cfg.rate_limit_per_min, cfg.request_timeout_s) == (
        1 << 20,
        60,
        30.0,
    )


def test_zero_never_meant_disabled_for_these_settings() -> None:
    # 0.1.0 clamped a zero rate limit to one per minute and answered every request 504 for a zero timeout;
    # neither is documented as "off", so they are refused.
    for bad in (0, -1, True, 1.5, None):
        with pytest.raises(server.PolicyError):
            build_app(config=_cfg(rate_limit_per_min=bad))
    for bad in (0, -1, float("nan"), float("inf"), 3601, True, None):
        with pytest.raises(server.PolicyError):
            build_app(config=_cfg(request_timeout_s=bad))
    for bad in (0, -5, True, 1 << 31):
        with pytest.raises(server.PolicyError):
            build_app(config=_cfg(max_body_bytes=bad))


def _cfg(**kw: Any) -> ServerConfig:
    base: dict[str, Any] = dict(
        api_keys={},
        dev_mode=True,
        max_body_bytes=1 << 20,
        rate_limit_per_min=60,
        request_timeout_s=30.0,
        cors_origins=(),
    )
    base.update(kw)
    return ServerConfig(**base)


def test_healthz_stays_200_with_valid_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REGAUDIT_FHE_REQUEST_TIMEOUT_S", "0.5")
    monkeypatch.setenv("REGAUDIT_FHE_RATE_LIMIT_PER_MIN", "1")
    monkeypatch.setenv("REGAUDIT_FHE_DEV_MODE", "1")
    client = TestClient(build_app(config=server.load_config_from_env()))
    for _ in range(3):
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


# ---- serve reports every configuration refusal as exit code 2 ---------------------------------------------------


@pytest.mark.parametrize(
    "env",
    [
        {"REGAUDIT_FHE_REQUEST_TIMEOUT_S": "0"},
        {"REGAUDIT_FHE_RATE_LIMIT_PER_MIN": "-1"},
        {"REGAUDIT_FHE_MAX_BODY_BYTES": "nan"},
        {"REGAUDIT_FHE_SWITCH_INTERVAL_S": "1e300"},
        {"REGAUDIT_FHE_MAX_BODY_BYTES": "2000", "REGAUDIT_FHE_MAX_INFLIGHT_BODY_BYTES": "1000"},
    ],
)
def test_serve_refuses_to_start_with_one_line_and_exit_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], env: dict[str, str]
) -> None:
    monkeypatch.setenv("REGAUDIT_FHE_API_KEYS", "k:admin")
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert main(["serve", "--host", "127.0.0.1", "--port", "0"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("refusing to start: ")
    assert err.count("\n") == 1
    assert "Traceback" not in err
