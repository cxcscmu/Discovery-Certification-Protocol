#!/usr/bin/env python3
"""Reject accidental private or repository-wide files in dcp-harness builds."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
import sys
import tarfile
import zipfile


BANNED_PARTS = {
    ".env",
    "artifacts",
    "examples",
    "paper",
    "reference_harness",
    "web_snapshot",
}
BANNED_NAMES = {
    "claude_stream.jsonl",
    "claude_stderr.log",
    "events.jsonl",
    "private_oracle.json",
}
SDIST_TOP_LEVEL = {
    "LICENSE",
    "MANIFEST.in",
    "PKG-INFO",
    "README.md",
    "pyproject.toml",
    "setup.cfg",
    "src",
    "tests",
}


def _members(path: Path) -> tuple[str, list[str]]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return "wheel", [item.filename for item in archive.infolist()]
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            return "sdist", [item.name for item in archive.getmembers()]
    raise ValueError(f"unsupported distribution archive: {path}")


def _check(path: Path) -> list[str]:
    kind, names = _members(path)
    errors: list[str] = []
    for name in names:
        item = PurePosixPath(name)
        lowered_parts = {part.lower() for part in item.parts}
        if lowered_parts & BANNED_PARTS or item.name.lower() in BANNED_NAMES:
            errors.append(f"{path}: forbidden member {name}")
        if any(part.startswith(".env") for part in item.parts):
            errors.append(f"{path}: environment file {name}")
        if kind == "wheel" and item.parts:
            top = item.parts[0]
            if top != "dcp_harness" and not top.startswith("dcp_harness-"):
                errors.append(f"{path}: unexpected wheel member {name}")
        if kind == "sdist" and len(item.parts) >= 2:
            top = item.parts[1]
            if top not in SDIST_TOP_LEVEL:
                errors.append(f"{path}: unexpected sdist member {name}")
    return errors


def main(arguments: list[str]) -> int:
    if not arguments:
        print("usage: check_harness_distribution.py ARCHIVE...", file=sys.stderr)
        return 2
    errors: list[str] = []
    for argument in arguments:
        errors.extend(_check(Path(argument)))
    if errors:
        print("\n".join(dict.fromkeys(errors)), file=sys.stderr)
        return 1
    print(f"checked {len(arguments)} dcp-harness distribution archive(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
