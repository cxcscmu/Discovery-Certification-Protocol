"""Safe workspace cloning and content manifests."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
from typing import Any

from dcp_harness.util import HarnessError, hash_file, hash_json


DEFAULT_EXCLUDES = frozenset({".git", "__pycache__", ".pytest_cache"})


def _walk(root: Path, *, excludes: frozenset[str]) -> list[Path]:
    root = root.resolve()
    if not root.is_dir():
        raise HarnessError(f"workspace is not a directory: {root}")
    files: list[Path] = []
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        kept_directories: list[str] = []
        for name in sorted(directory_names):
            candidate = current_path / name
            if name in excludes:
                continue
            if candidate.is_symlink():
                raise HarnessError(f"workspace contains a directory symlink: {candidate}")
            kept_directories.append(name)
        directory_names[:] = kept_directories
        for name in sorted(file_names):
            candidate = current_path / name
            if name in excludes:
                continue
            if candidate.is_symlink():
                raise HarnessError(f"workspace contains a file symlink: {candidate}")
            mode = candidate.stat().st_mode
            if not stat.S_ISREG(mode):
                raise HarnessError(f"workspace contains a non-regular file: {candidate}")
            files.append(candidate)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def manifest(
    root: Path, *, excludes: frozenset[str] = DEFAULT_EXCLUDES
) -> dict[str, Any]:
    root = root.resolve()
    rows: list[dict[str, Any]] = []
    for path in _walk(root, excludes=excludes):
        mode = path.stat().st_mode
        rows.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": hash_file(path),
                "executable": bool(mode & stat.S_IXUSR),
            }
        )
    body = {"schema": "dcp_workspace_manifest_v1", "files": rows}
    body["manifest_hash"] = hash_json(body)
    return body


def clone_workspace(source: Path, destination: Path) -> dict[str, Any]:
    source = source.resolve()
    if destination.exists():
        raise HarnessError(f"workspace destination already exists: {destination}")
    source_manifest = manifest(source)
    destination.mkdir(parents=True)
    for item in source_manifest["files"]:
        relative = Path(item["path"])
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, target)
        target.chmod(0o700 if item["executable"] else 0o600)
    copied_manifest = manifest(destination)
    if copied_manifest["manifest_hash"] != source_manifest["manifest_hash"]:
        raise HarnessError("workspace clone does not match the frozen source")
    return copied_manifest


def diff_manifests(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    left = {row["path"]: row for row in before.get("files", [])}
    right = {row["path"]: row for row in after.get("files", [])}
    added = sorted(set(right) - set(left))
    removed = sorted(set(left) - set(right))
    modified = sorted(
        path
        for path in set(left) & set(right)
        if left[path] != right[path]
    )
    result = {
        "schema": "dcp_workspace_diff_v1",
        "before_manifest_hash": before.get("manifest_hash"),
        "after_manifest_hash": after.get("manifest_hash"),
        "added": added,
        "modified": modified,
        "removed": removed,
    }
    result["diff_hash"] = hash_json(result)
    return result


def checkpoint(source: Path, destination: Path) -> dict[str, Any]:
    """Create an immutable-by-convention checkpoint with no symbolic links."""

    frozen = clone_workspace(source, destination)
    for item in frozen["files"]:
        path = destination / item["path"]
        path.chmod(0o500 if item["executable"] else 0o400)
    return frozen
