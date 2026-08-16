"""Fail when a DCP release archive crosses the small-verifier boundary."""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path, PurePosixPath
import zipfile


SDIST_ALLOWED_TOP_LEVEL = {
    "LICENSE",
    "MANIFEST.in",
        "PKG-INFO",
    "README_PYPI.md",
    "dcp",
    "dcp_audit.egg-info",
    "pyproject.toml",
    "setup.cfg",
}
FORBIDDEN_PARTS = {
    ".env",
    ".github",
    "agent_core",
    "artifacts",
    "artifacts_registry",
    "discovery_certification",
    "docs",
    "examples",
    "multi_agent_graph_operator",
    "multi_agent_graph_primitive",
    "paper",
    "reference_harness",
    "scripts",
    "tests",
}


def _wheel_members(path: Path) -> list[PurePosixPath]:
    with zipfile.ZipFile(path) as archive:
        return [PurePosixPath(name) for name in archive.namelist()]


def _sdist_members(path: Path) -> list[PurePosixPath]:
    with tarfile.open(path, "r:gz") as archive:
        members = [
            PurePosixPath(member.name)
            for member in archive.getmembers()
            if member.isfile()
        ]
    roots = {member.parts[0] for member in members if member.parts}
    if len(roots) != 1:
        raise SystemExit(f"{path}: sdist must have exactly one root directory")
    return [PurePosixPath(*member.parts[1:]) for member in members]


def check(path: Path) -> None:
    if path.suffix == ".whl":
        members = _wheel_members(path)
        invalid = [
            str(member)
            for member in members
            if not (
                member.parts
                and (
                    member.parts[0] == "dcp"
                    or member.parts[0].endswith(".dist-info")
                )
            )
        ]
    elif path.name.endswith(".tar.gz"):
        members = _sdist_members(path)
        top_level = {member.parts[0] for member in members if member.parts}
        invalid = sorted(top_level - SDIST_ALLOWED_TOP_LEVEL)
    else:
        raise SystemExit(f"{path}: unsupported release archive")

    forbidden = sorted(
        str(member)
        for member in members
        if set(member.parts) & FORBIDDEN_PARTS
        or "__pycache__" in member.parts
        or member.suffix in {".pyc", ".pyo"}
    )
    if invalid or forbidden:
        details = invalid + forbidden
        raise SystemExit(f"{path}: release boundary violation: {details}")
    print(f"{path}: release boundary verified ({len(members)} files)")


def main(argv: list[str] | None = None) -> int:
    paths = [Path(value) for value in (sys.argv[1:] if argv is None else argv)]
    if not paths:
        raise SystemExit("provide at least one wheel or sdist")
    for path in paths:
        check(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
