"""Checking several signed reports in one request, within fixed limits.

A batch is only a way of sending several individual JSON report files at once. Each file is then checked exactly as a
single upload is (``app`` runs the same function for both), so each has the same size limit, parsing, engine check,
rate-limit accounting and trust context. There is no archive handling: a file is one report's bytes, nothing is
unpacked, and no name is ever used as a path.

The request is JSON, not a multipart form. Multipart parsing is what makes a web framework spool uploads to temporary
files, and a base64 string carries the file's exact bytes, so the report's own checksum and every parsing rule are the
same as for a single upload.

This module holds the limits and the parts that need no engine: reading the request, and the shape of the answer.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import Any

from regaudit_fhe.canonical import CanonicalError, loads_strict

from .explain import DEMONSTRATION_LABEL, FHE_NOTICE, NOT_A_CLAIM, printable

# The limits. Each is derived from the existing single-report limits and from what was measured (see the design note):
# one report is at most 1 MB and 120 checks are allowed a minute, so a batch of 20 uses a sixth of a minute's budget and
# the reports of a batch together are capped at 8 MB (below 20 x 1 MB, because no real report is near its limit).
MAX_FILES = 20
MAX_REPORT_BYTES = 1 << 20  # the single-report limit, unchanged
MAX_REPORT_BASE64 = 4 * ((MAX_REPORT_BYTES + 2) // 3)
MAX_TOTAL_REPORT_BYTES = 8 * (1 << 20)  # all the reports of a batch together
# The whole request: that much as base64 inside JSON, plus room for the names and the JSON around them.
MAX_BODY_BYTES = (MAX_TOTAL_REPORT_BYTES * 4 + 2) // 3 + (1 << 16)
MAX_CONCURRENT_BATCHES = 2  # batches in progress at once; each checks its files one at a time
MAX_NAME_SHOWN = 120

SCHEMA = "regaudit-portal-batch/1"

TOO_MANY_FILES = f"A batch can hold at most {MAX_FILES} files. Nothing was verified. Send the files in smaller groups."
NOT_A_BATCH = (
    "This request is not a list of report files this portal can read. Nothing was verified, so treat it as not "
    "accepted. Choose the report files again."
)
BATCH_TOO_LARGE = (
    f"This batch is over the {MAX_TOTAL_REPORT_BYTES // (1 << 20)} MB limit for all the files together. Nothing was verified. "
    "Send the files in smaller groups."
)
NOT_RUN_ENGINE = (
    "This file was not checked: the check stopped because the verification engine could not be validated. Nothing "
    "was verified for it."
)
NOT_RUN_CLOSED = "This file was not checked: the connection was closed before the batch finished."
BUSY = "The portal is already checking other batches. Nothing was verified. Try again in a few seconds."
BAD_TYPE = "A batch is sent as JSON from the portal's own page."


class BatchFormatError(Exception):
    """The request as a whole is not a list of files. The code goes in the refusal."""

    def __init__(self, code: str, message: str, status: int = 422) -> None:
        super().__init__(code)
        self.code, self.message, self.status = code, message, status


@dataclass(frozen=True)
class Item:
    index: int
    name: str
    name_shortened: bool
    content_b64: str | None


def display_name(value: Any) -> tuple[str, bool]:
    """A file name is untrusted text. It is shown, neutralised and shortened, and used for nothing else."""
    if not isinstance(value, str) or not value:
        return "(no name)", False
    return printable(value, MAX_NAME_SHOWN), len(value) > MAX_NAME_SHOWN


def read_items(raw: bytes) -> list[Item]:
    """The files of a batch, in the order sent, or a refusal of the whole request.

    The request is ``{"files": [{"name": "<text>", "content_b64": "<base64 of the file's bytes>"}, ...]}``, with those
    members and no others. Duplicate keys, invalid UTF-8, a non-object and anything nested too deep are refused.
    """
    try:
        body = loads_strict(raw, max_bytes=MAX_BODY_BYTES)
    except (CanonicalError, RecursionError, ValueError, TypeError) as exc:
        raise BatchFormatError("not_a_batch", NOT_A_BATCH) from exc
    if not isinstance(body, dict) or set(body) != {"files"} or not isinstance(body["files"], list):
        raise BatchFormatError("not_a_batch", NOT_A_BATCH)
    files = body["files"]
    if not files:
        raise BatchFormatError("not_a_batch", NOT_A_BATCH)
    if len(files) > MAX_FILES:
        raise BatchFormatError("too_many_files", TOO_MANY_FILES, 413)
    items = []
    for index, entry in enumerate(files):
        if (
            not isinstance(entry, dict)
            or set(entry) - {"name", "content_b64"}
            or "content_b64" not in entry
        ):
            raise BatchFormatError("not_a_batch", NOT_A_BATCH)
        name, shortened = display_name(entry.get("name"))
        content = entry["content_b64"]
        items.append(Item(index, name, shortened, content if isinstance(content, str) else None))
    return items


class FileUnreadable(Exception):
    """One file cannot be decoded or is too large. Only that file is refused; ``code`` and ``status`` say how."""

    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code, self.status = code, status


def decode(item: Item) -> bytes:
    if item.content_b64 is None:
        raise FileUnreadable("not_a_report", 422)
    if len(item.content_b64) > MAX_REPORT_BASE64:
        raise FileUnreadable("too_large", 413)  # refused before any of it is decoded
    try:
        data = base64.b64decode(item.content_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FileUnreadable("not_a_report", 422) from exc
    if len(data) > MAX_REPORT_BYTES:
        raise FileUnreadable("too_large", 413)
    return data


def file_entry(item: Item, raw: bytes | None) -> dict[str, Any]:
    """What identifies a file in the answer. ``id`` and ``index`` are the portal's, in request order."""
    return {
        "id": f"file-{item.index + 1}",
        "index": item.index,
        "name": item.name,
        "name_shortened": item.name_shortened,
        "size_bytes": len(raw) if raw is not None else None,
        "report_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
    }


def summarise(files: list[dict[str, Any]]) -> dict[str, Any]:
    trusted = invalid = refused = not_run = 0
    recorded: list[str] = []
    for entry in files:
        if entry["ok"]:
            if entry["result"]["verification"]["trust_status"] == "TRUSTED":
                trusted += 1
            else:
                invalid += 1
            statuses = entry["result"].get("statuses")
            if statuses is not None and statuses["replay"]["state"] == "recorded":
                recorded.append(entry["id"])
        elif entry["error"]["error"] == "not_run":
            not_run += 1
        else:
            refused += 1
    return {
        "total": len(files),
        "trusted": trusted,
        "not_accepted": invalid,
        "refused": refused,
        "not_run": not_run,
        "recorded_in_replay_file": recorded,
    }


def limits() -> dict[str, int]:
    return {
        "max_files": MAX_FILES,
        "max_file_bytes": MAX_REPORT_BYTES,
        "max_total_bytes": MAX_TOTAL_REPORT_BYTES,
        "max_request_bytes": MAX_BODY_BYTES,
        "max_concurrent_batches": MAX_CONCURRENT_BATCHES,
    }


def answer(
    files: list[dict[str, Any]],
    *,
    batch_id: str,
    trust_mode: str,
    demonstration: bool,
    replay_mode: str,
    rate: dict[str, int],
    complete: bool,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": SCHEMA,
        "batch_id": batch_id,
        "complete": complete,
        "trust_mode": trust_mode,
        "replay_mode": replay_mode,
        "limits": limits(),
        "rate": rate,
        "summary": summarise(files),
        "files": files,
        "not_a_claim": NOT_A_CLAIM,
        "fhe_notice": FHE_NOTICE,
    }
    if demonstration:
        body["demonstration_label"] = DEMONSTRATION_LABEL
    return body
