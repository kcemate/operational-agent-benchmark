from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

_SCHEMA = "oab.trace-event/v1"
_EVENT_KEYS = {
    "schema",
    "seq",
    "event_type",
    "monotonic_ns",
    "stream",
    "payload_b64",
    "payload_bytes",
    "payload_sha256",
    "previous_event_sha256",
    "details",
    "event_sha256",
}


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _event_hash(event_without_hash: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(event_without_hash)).hexdigest()


@dataclass(frozen=True)
class TraceValidation:
    valid: bool
    errors: tuple[str, ...]
    event_count: int
    terminal_hash: str | None


class CanonicalTrace:
    def __init__(
        self,
        path: Path,
        *,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._handle = path.open("xb")
        self._clock = monotonic_ns
        self._sequence = 0
        self._previous_hash: str | None = None
        self._closed = False

    def append(
        self,
        event_type: str,
        stream: str,
        *,
        payload: bytes = b"",
        details: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        if self._closed:
            raise RuntimeError("trace is closed")
        if not event_type or not stream:
            raise ValueError("event_type and stream are required")
        self._sequence += 1
        event: dict[str, object] = {
            "schema": _SCHEMA,
            "seq": self._sequence,
            "event_type": event_type,
            "monotonic_ns": self._clock(),
            "stream": stream,
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "payload_bytes": len(payload),
            "payload_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "previous_event_sha256": self._previous_hash,
            "details": dict(details or {}),
        }
        digest = _event_hash(event)
        event["event_sha256"] = digest
        self._handle.write(_canonical_bytes(event) + b"\n")
        self._handle.flush()
        self._previous_hash = digest
        return dict(event)

    def close(self) -> None:
        if self._closed:
            return
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._handle.close()
        self._closed = True

    def __enter__(self) -> "CanonicalTrace":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def validate_trace(path: Path) -> TraceValidation:
    errors: list[str] = []
    previous_hash: str | None = None
    event_count = 0
    try:
        raw_lines = path.read_bytes().splitlines(keepends=True)
    except OSError:
        return TraceValidation(False, ("trace_unreadable",), 0, None)
    for line_number, raw_line in enumerate(raw_lines, start=1):
        if not raw_line.endswith(b"\n"):
            errors.append(f"line_missing_newline:{line_number}")
        try:
            event = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            errors.append(f"noncanonical_or_invalid_json:{line_number}")
            continue
        if not isinstance(event, dict):
            errors.append(f"noncanonical_or_invalid_json:{line_number}")
            continue
        try:
            canonical_line = _canonical_bytes(event) + b"\n"
        except (TypeError, ValueError, RecursionError):
            errors.append(f"noncanonical_or_invalid_json:{line_number}")
            continue
        if canonical_line != raw_line:
            errors.append(f"noncanonical_or_invalid_json:{line_number}")
        if set(event) != _EVENT_KEYS:
            errors.append(f"event_shape_invalid:{line_number}")
            continue
        event_count += 1
        if event.get("schema") != _SCHEMA:
            errors.append(f"schema_invalid:{line_number}")
        if event.get("seq") != event_count:
            errors.append(f"sequence_invalid:{line_number}")
        if not isinstance(event.get("event_type"), str) or not event.get("event_type"):
            errors.append(f"event_type_invalid:{line_number}")
        if not isinstance(event.get("stream"), str) or not event.get("stream"):
            errors.append(f"stream_invalid:{line_number}")
        if not isinstance(event.get("monotonic_ns"), int) or event.get("monotonic_ns", -1) < 0:
            errors.append(f"monotonic_time_invalid:{line_number}")
        if event.get("previous_event_sha256") != previous_hash:
            errors.append(f"previous_hash_mismatch:{line_number}")

        payload_b64 = event.get("payload_b64")
        try:
            payload = base64.b64decode(payload_b64, validate=True) if isinstance(payload_b64, str) else b""
        except ValueError:
            payload = b""
            errors.append(f"payload_base64_invalid:{line_number}")
        if event.get("payload_bytes") != len(payload):
            errors.append(f"payload_length_mismatch:{line_number}")
        expected_payload_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
        if event.get("payload_sha256") != expected_payload_hash:
            errors.append(f"payload_hash_mismatch:{line_number}")
        if not isinstance(event.get("details"), dict):
            errors.append(f"details_invalid:{line_number}")

        claimed_hash = event.get("event_sha256")
        without_hash = dict(event)
        without_hash.pop("event_sha256", None)
        expected_hash = _event_hash(without_hash)
        if claimed_hash != expected_hash:
            errors.append(f"event_hash_mismatch:{line_number}")
        previous_hash = claimed_hash if isinstance(claimed_hash, str) else None
    if not raw_lines:
        errors.append("trace_empty")
    return TraceValidation(
        valid=not errors,
        errors=tuple(errors),
        event_count=event_count,
        terminal_hash=previous_hash,
    )
