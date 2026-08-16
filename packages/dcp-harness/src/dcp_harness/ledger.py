"""Append-only, hash-chained phase ledger."""

from __future__ import annotations

from collections.abc import Mapping
import fcntl
import json
import os
from pathlib import Path
from typing import Any

from dcp_harness.util import HarnessError, hash_json, utc_now


class EventLedger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not event_type or any(char.isspace() for char in event_type):
            raise HarnessError("event_type must be a nonempty token")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.parent.is_symlink():
            raise HarnessError("event ledger directory cannot be a symbolic link")
        if self.path.is_symlink() or (
            self.path.exists() and not self.path.is_file()
        ):
            raise HarnessError("event ledger must be a regular file")
        with self.path.open("a+", encoding="utf-8", newline="\n") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.seek(0)
            lines = [line for line in handle.read().splitlines() if line]
            previous = "genesis"
            index = 0
            if lines:
                try:
                    last = json.loads(lines[-1])
                except json.JSONDecodeError as exc:
                    raise HarnessError("event ledger tail is malformed") from exc
                previous = str(last.get("event_hash", ""))
                index = int(last.get("event_index", -1)) + 1
            sealed: dict[str, Any] = {
                "event_index": index,
                "event_type": event_type,
                "recorded_at": utc_now(),
                "previous_event_hash": previous,
                "payload": dict(payload),
            }
            sealed["event_hash"] = hash_json(sealed)
            handle.seek(0, os.SEEK_END)
            handle.write(
                json.dumps(sealed, ensure_ascii=False, sort_keys=True) + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return sealed

    def events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        if not self.path.is_file() or self.path.is_symlink():
            raise HarnessError("event ledger is not a regular file")
        events: list[dict[str, Any]] = []
        for line_number, line in enumerate(
            self.path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise HarnessError(
                    f"event ledger line {line_number} is malformed"
                ) from exc
            if not isinstance(value, dict):
                raise HarnessError(f"event ledger line {line_number} is not an object")
            events.append(value)
        return events

    def verify(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        previous = "genesis"
        for index, item in enumerate(self.events()):
            claimed = item.get("event_hash")
            body = dict(item)
            body.pop("event_hash", None)
            if body.get("event_index") != index:
                errors.append(f"event {index} has the wrong index")
            if body.get("previous_event_hash") != previous:
                errors.append(f"event {index} has the wrong previous hash")
            if claimed != hash_json(body):
                errors.append(f"event {index} has a content hash mismatch")
            previous = str(claimed)
        return not errors, errors

    @property
    def head(self) -> str:
        events = self.events()
        return str(events[-1]["event_hash"]) if events else "genesis"
