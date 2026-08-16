"""Strict JSON, hashing, and safe file helpers used by the harness."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any


class HarnessError(RuntimeError):
    """A fail-closed harness error with a user-facing message."""


def canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HarnessError(f"value is not strict JSON: {exc}") from exc


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def hash_json(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def hash_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise HarnessError(f"expected a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: object) -> None:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8") + b"\n"
    atomic_write(path, raw)


def atomic_write(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise HarnessError(f"refusing to write through a symlink: {path.parent}")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".partial"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def load_json(path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise HarnessError(f"missing regular JSON file: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"invalid JSON in {path}: {exc}") from exc


def load_json_object(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict):
        raise HarnessError(f"expected a JSON object in {path}")
    return value


def require_keys(
    value: Mapping[str, Any],
    *,
    allowed: set[str],
    required: set[str] = frozenset(),
    label: str,
) -> None:
    unknown = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unknown:
        raise HarnessError(f"{label} has unknown keys: {', '.join(unknown)}")
    if missing:
        raise HarnessError(f"{label} is missing keys: {', '.join(missing)}")


def explicit_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HarnessError(f"{label} must be a nonempty string")
    if value != value.strip() or any(ord(char) < 32 for char in value):
        raise HarnessError(f"{label} must be canonical text")
    return value


def positive_int(value: object, label: str, *, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise HarnessError(f"{label} must be an integer >= {minimum}")
    return value


def finite_float(value: object, label: str, *, minimum: float = 0.0) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise HarnessError(f"{label} must be a finite number")
    result = float(value)
    if not (result >= minimum and result < float("inf")):
        raise HarnessError(f"{label} must be finite and >= {minimum}")
    return result


def safe_child(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise HarnessError("relative path must be nonempty")
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts or "" in candidate.parts:
        raise HarnessError(f"unsafe relative path: {relative!r}")
    root = root.resolve()
    target = root.joinpath(candidate)
    resolved_parent = target.parent.resolve()
    if resolved_parent != root and root not in resolved_parent.parents:
        raise HarnessError(f"path escapes its root: {relative!r}")
    return target


def redact_environment_value(name: str, value: str | None) -> dict[str, object]:
    """Bind presence without recording a secret value."""

    return {
        "name": name,
        "present": bool(value),
        "value_hash": sha256_bytes(value.encode("utf-8")) if value else None,
    }

