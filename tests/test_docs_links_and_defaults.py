"""Documentation smoke tests: relative markdown links resolve; DEPLOYMENT.md defaults match the code."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if not (ROOT / "docs" / "DEPLOYMENT.md").is_file():
    pytest.skip("docs/ is not part of this checkout", allow_module_level=True)

LINK = re.compile(r"(?<!\!)\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^(```|~~~)")


def _markdown_files() -> list[Path]:
    files = [
        ROOT / "README.md",
        ROOT / "SECURITY.md",
        ROOT / "CHANGELOG.md",
        ROOT / "CONTRIBUTING.md",
    ]
    files += sorted((ROOT / "docs").rglob("*.md"))
    return [f for f in files if f.is_file()]


def _links(path: Path) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    in_fence = False
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if FENCE.match(line.strip()):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        line = re.sub(r"`[^`]*`", "", line)  # inline code is not a link
        out.extend((n, m.group(1)) for m in LINK.finditer(line))
    return out


def _relative_targets() -> list[tuple[Path, int, str]]:
    found = []
    for f in _markdown_files():
        for n, target in _links(f):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                continue
            found.append((f, n, target))
    return found


def test_there_are_links_to_check() -> None:
    assert len(_relative_targets()) > 20


def test_every_relative_markdown_link_resolves() -> None:
    broken = []
    for f, n, target in _relative_targets():
        rel = target.split("#", 1)[0].split("?", 1)[0]
        if rel and not (f.parent / rel).exists():
            broken.append(f"{f.relative_to(ROOT)}:{n} -> {target}")
    assert not broken, "broken relative links:\n" + "\n".join(broken)


# --- DEPLOYMENT.md defaults versus the code ---------------------------------------------------

ENV_ROW = re.compile(r"^\|\s*`(REGAUDIT_FHE_[A-Z_]+)`\s*\|\s*(.+?)\s*\|", re.M)

# env var -> accessor on the config built from an empty environment
ACCESSORS = {
    "REGAUDIT_FHE_DEV_MODE": lambda c: c.dev_mode,
    "REGAUDIT_FHE_MAX_BODY_BYTES": lambda c: c.max_body_bytes,
    "REGAUDIT_FHE_RATE_LIMIT_PER_MIN": lambda c: c.rate_limit_per_min,
    "REGAUDIT_FHE_REQUEST_TIMEOUT_S": lambda c: c.request_timeout_s,
    "REGAUDIT_FHE_ALLOW_SELF_SIGNED": lambda c: c.allow_self_signed,
    "REGAUDIT_FHE_PROFILE": lambda c: c.profile,
    "REGAUDIT_FHE_REPLAY_MODE": lambda c: c.replay_mode,
    "REGAUDIT_FHE_MAX_ARRAY_ELEMENTS": lambda c: c.input_limits.max_array_elements,
    "REGAUDIT_FHE_MAX_TOTAL_ELEMENTS": lambda c: c.input_limits.max_total_elements,
    "REGAUDIT_FHE_MAX_JSON_DEPTH": lambda c: c.input_limits.max_depth,
    "REGAUDIT_FHE_MAX_CONCURRENT_AUDITS": lambda c: c.max_concurrent_audits,
    "REGAUDIT_FHE_MAX_QUEUED_AUDITS": lambda c: c.max_queued_audits,
    "REGAUDIT_FHE_QUEUE_WAIT_S": lambda c: c.queue_wait_s,
    "REGAUDIT_FHE_MAX_CONCURRENT_VERIFIES": lambda c: c.max_concurrent_verifies,
}


def _doc_defaults() -> dict[str, str]:
    text = (ROOT / "docs" / "DEPLOYMENT.md").read_text(encoding="utf-8")
    out: dict[str, str] = {}
    for name, default in ENV_ROW.findall(text):
        out.setdefault(name, default.strip("`").strip())
    return out


def test_deployment_md_documents_every_checked_variable() -> None:
    docs = _doc_defaults()
    missing = sorted(set(ACCESSORS) - set(docs))
    assert not missing, f"DEPLOYMENT.md no longer lists: {missing}"


def test_deployment_md_defaults_match_server_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    import os

    from regaudit_fhe.server import load_config_from_env

    for key in [k for k in os.environ if k.startswith("REGAUDIT_FHE_")]:
        monkeypatch.delenv(key)
    config = load_config_from_env()
    docs = _doc_defaults()
    wrong = []
    for name, accessor in ACCESSORS.items():
        actual = accessor(config)
        documented = docs[name]
        if isinstance(actual, bool):
            ok = documented == ("1" if actual else "0")
        elif isinstance(actual, (int, float)):
            try:
                ok = float(documented) == float(actual)
            except ValueError:
                ok = False
        else:
            ok = documented == str(actual)
        if not ok:
            wrong.append(f"{name}: documented {documented!r}, code {actual!r}")
    assert not wrong, "DEPLOYMENT.md defaults differ from the code:\n" + "\n".join(wrong)
