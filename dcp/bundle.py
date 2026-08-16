"""Portable, content-addressed evidence bundles for the DCP kernel.

Two immutable interchange profiles are supported.  The legacy Core profile
contains the four inputs needed to replay Gates 1/2.  ``full_audit_v1`` adds
the complete Gate-3 input for feedback-effect, sham, and neutral-recovery
replay.  Each manifest hashes every payload and has a deterministic content
id; the formats never auto-upgrade one another on write.

This layer proves two local facts only:

* the payload bytes still match the manifest; and
* the saved certificate is exactly reproducible by the current kernel.

It does not authenticate who produced the evidence, reserve an audit slot, or
counter-sign a certificate.  Reports therefore always use
``provenance_scope=local_content_addressed_only`` and
``formal_certificate_issued=false``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, fields, is_dataclass
from enum import Enum
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from dcp.evaluate import evaluate
from dcp.registration import Registration
from dcp.types import (
    AdequacyEvidence,
    ArtifactScores,
    BranchOutcome,
    ControlAttempt,
    FeedbackPair,
    Gate1Evidence,
    Gate2Evidence,
    Gate3Evidence,
    IntegrityEvidence,
    RawAttemptOutcome,
    ShamCalibration,
    ShamPair,
    Validity,
)


BUNDLE_FORMAT = "dcp-core-evidence-bundle"
BUNDLE_FORMAT_VERSION = "1.0"
FULL_AUDIT_BUNDLE_FORMAT = "dcp-audit-bundle"
FULL_AUDIT_BUNDLE_FORMAT_VERSION = "1.0"
FULL_AUDIT_PROFILE = "full_audit_v1"
PROVENANCE_SCOPE = "local_content_addressed_only"
MANIFEST_NAME = "manifest.json"

_PAYLOAD_LAYOUT = {
    "registration": (
        "payload/registration.json",
        "dcp.core.registration.v1",
    ),
    "integrity": (
        "payload/integrity.json",
        "dcp.core.integrity-evidence.v1",
    ),
    "gate1": ("payload/gate1.json", "dcp.core.gate1-evidence.v1"),
    "gate2": ("payload/gate2.json", "dcp.core.gate2-evidence.v1"),
    "certificate": (
        "payload/certificate.json",
        "dcp.core.kernel-decision-record.v1",
    ),
}

_FULL_AUDIT_PAYLOAD_LAYOUT = {
    "registration": (
        "payload/registration.json",
        "dcp.full-audit.registration.v1",
    ),
    "integrity": (
        "payload/integrity.json",
        "dcp.full-audit.integrity-evidence.v1",
    ),
    "gate1": ("payload/gate1.json", "dcp.full-audit.gate1-evidence.v1"),
    "gate2": ("payload/gate2.json", "dcp.full-audit.gate2-evidence.v1"),
    "gate3": ("payload/gate3.json", "dcp.full-audit.gate3-evidence.v1"),
    "certificate": (
        "payload/certificate.json",
        "dcp.full-audit.kernel-decision-record.v1",
    ),
}


class BundleError(ValueError):
    """Raised when a bundle cannot be encoded or decoded safely."""


def write_core_bundle(
    directory: str | Path,
    reg: Registration,
    integrity: IntegrityEvidence,
    g1: Gate1Evidence,
    g2: Gate2Evidence,
    certificate: Any,
) -> dict[str, Any]:
    """Write a deterministic DCP Core bundle and return its manifest.

    ``certificate`` may be a kernel ``Certificate`` (anything exposing
    ``to_dict()``) or its already materialized mapping.  Gate 3 is deliberately
    absent from this first, Core-only interchange format.
    """

    if not isinstance(reg, Registration):
        raise BundleError("reg must be a Registration")
    if not isinstance(integrity, IntegrityEvidence):
        raise BundleError("integrity must be an IntegrityEvidence")
    if not isinstance(g1, Gate1Evidence):
        raise BundleError("g1 must be a Gate1Evidence")
    if not isinstance(g2, Gate2Evidence):
        raise BundleError("g2 must be a Gate2Evidence")

    certificate_payload = _certificate_mapping(certificate)
    _require_nonformal_certificate(certificate_payload)
    payload_values = {
        "registration": reg,
        "integrity": integrity,
        "gate1": g1,
        "gate2": g2,
        "certificate": certificate_payload,
    }

    root = Path(directory)
    payload_root = root / "payload"
    root.mkdir(parents=True, exist_ok=True)
    if payload_root.is_symlink():
        raise BundleError("payload directory cannot be a symbolic link")
    payload_root.mkdir(parents=True, exist_ok=True)
    expected_payload_paths = {
        Path(relative).relative_to("payload")
        for relative, _schema in _PAYLOAD_LAYOUT.values()
    }
    existing_paths = list(payload_root.rglob("*"))
    symbolic_links = sorted(
        str(path.relative_to(payload_root))
        for path in existing_paths
        if path.is_symlink()
    )
    if symbolic_links:
        raise BundleError(
            "symbolic links are not allowed in payload/: "
            + ", ".join(symbolic_links)
        )
    unexpected = sorted(
        str(path.relative_to(payload_root))
        for path in existing_paths
        if path.is_file() and path.relative_to(payload_root) not in expected_payload_paths
    )
    if unexpected:
        raise BundleError(
            "payload directory contains unregistered files: " + ", ".join(unexpected)
        )

    entries: dict[str, dict[str, Any]] = {}
    for name, value in payload_values.items():
        relative_path, schema = _PAYLOAD_LAYOUT[name]
        encoded = _canonical_json_bytes(_jsonable(value))
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(encoded)
        entries[name] = {
            "path": relative_path,
            "schema": schema,
            "media_type": "application/json",
            "content_digest": _digest(encoded),
            "size_bytes": len(encoded),
        }

    identity = {
        "format": BUNDLE_FORMAT,
        "format_version": BUNDLE_FORMAT_VERSION,
        "hash_algorithm": "sha256",
        "provenance_scope": PROVENANCE_SCOPE,
        "formal_certificate_issued": False,
        "payloads": entries,
    }
    manifest = dict(identity)
    manifest["bundle_id"] = _digest(_canonical_json_bytes(identity))
    (root / MANIFEST_NAME).write_bytes(_canonical_json_bytes(manifest))
    return manifest


def write_full_audit_bundle(
    directory: str | Path,
    reg: Registration,
    integrity: IntegrityEvidence,
    g1: Gate1Evidence,
    g2: Gate2Evidence,
    g3: Gate3Evidence,
    certificate: Any,
) -> dict[str, Any]:
    """Write a deterministic ``full_audit_v1`` bundle.

    Unlike the legacy Core interchange format, this profile carries the full
    Gate-3 input needed to reproduce feedback-effect, sham-adequacy, and
    neutral-recovery decisions.  It remains a local content-addressed record;
    a registry must still validate and countersign issuance separately.
    """

    for value, expected, label in (
        (reg, Registration, "reg"),
        (integrity, IntegrityEvidence, "integrity"),
        (g1, Gate1Evidence, "g1"),
        (g2, Gate2Evidence, "g2"),
        (g3, Gate3Evidence, "g3"),
    ):
        if not isinstance(value, expected):
            raise BundleError(f"{label} must be a {expected.__name__}")

    certificate_payload = _certificate_mapping(certificate)
    _require_nonformal_certificate(certificate_payload)
    payload_values = {
        "registration": reg,
        "integrity": integrity,
        "gate1": g1,
        "gate2": g2,
        "gate3": g3,
        "certificate": certificate_payload,
    }

    root = Path(directory)
    _prepare_full_audit_output(root)
    entries: dict[str, dict[str, Any]] = {}
    for name, value in payload_values.items():
        relative_path, schema = _FULL_AUDIT_PAYLOAD_LAYOUT[name]
        encoded = _canonical_json_bytes(_jsonable(value))
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(encoded)
        entries[name] = {
            "path": relative_path,
            "schema": schema,
            "media_type": "application/json",
            "content_digest": _digest(encoded),
            "size_bytes": len(encoded),
        }

    identity = {
        "format": FULL_AUDIT_BUNDLE_FORMAT,
        "format_version": FULL_AUDIT_BUNDLE_FORMAT_VERSION,
        "profile": FULL_AUDIT_PROFILE,
        "hash_algorithm": "sha256",
        "provenance_scope": PROVENANCE_SCOPE,
        "formal_certificate_issued": False,
        "payloads": entries,
    }
    manifest = dict(identity)
    manifest["bundle_id"] = _digest(_canonical_json_bytes(identity))
    (root / MANIFEST_NAME).write_bytes(_canonical_json_bytes(manifest))
    return manifest


def verify_core_bundle(directory: str | Path) -> dict[str, Any]:
    """Validate hashes, replay the kernel, and compare the saved certificate.

    Malformed or modified bundles produce a structured failing report rather
    than a partial verdict.  Payloads are not deserialized until every content
    digest has passed.
    """

    root = Path(directory)
    report: dict[str, Any] = {
        "bundle_format": BUNDLE_FORMAT,
        "format_version": BUNDLE_FORMAT_VERSION,
        "bundle_id": None,
        "ok": False,
        "manifest_valid": False,
        "payload_hashes_valid": False,
        "kernel_replay_matches": False,
        "provenance_scope": PROVENANCE_SCOPE,
        "formal_certificate_issued": False,
        "payloads": {},
        "saved_verdict": None,
        "replayed_verdict": None,
        "errors": [],
    }
    errors: list[str] = report["errors"]

    try:
        manifest = _load_json(root / MANIFEST_NAME)
        _validate_manifest(manifest, root)
        report["bundle_id"] = manifest["bundle_id"]
        report["manifest_valid"] = True
    except (OSError, BundleError, TypeError, ValueError, KeyError) as exc:
        errors.append(f"manifest validation failed: {exc}")
        return report

    all_hashes_valid = True
    for name, (expected_path, _schema) in _PAYLOAD_LAYOUT.items():
        entry = manifest["payloads"][name]
        path = root / expected_path
        try:
            raw = path.read_bytes()
            actual_digest = _digest(raw)
            actual_size = len(raw)
            valid = (
                actual_digest == entry["content_digest"]
                and actual_size == entry["size_bytes"]
            )
        except OSError as exc:
            actual_digest = None
            actual_size = None
            valid = False
            errors.append(f"cannot read payload {name}: {exc}")
        report["payloads"][name] = {
            "path": expected_path,
            "schema": entry["schema"],
            "expected_digest": entry["content_digest"],
            "actual_digest": actual_digest,
            "expected_size_bytes": entry["size_bytes"],
            "actual_size_bytes": actual_size,
            "valid": valid,
        }
        if not valid:
            all_hashes_valid = False
            if actual_digest is not None:
                errors.append(f"payload digest or size mismatch: {name}")

    report["payload_hashes_valid"] = all_hashes_valid
    if not all_hashes_valid:
        return report

    try:
        reg = _registration_from_dict(_load_json(root / _PAYLOAD_LAYOUT["registration"][0]))
        integrity = _integrity_from_dict(
            _load_json(root / _PAYLOAD_LAYOUT["integrity"][0])
        )
        gate1 = _gate1_from_dict(_load_json(root / _PAYLOAD_LAYOUT["gate1"][0]))
        gate2 = _gate2_from_dict(_load_json(root / _PAYLOAD_LAYOUT["gate2"][0]))
        saved_certificate = _require_object(
            _load_json(root / _PAYLOAD_LAYOUT["certificate"][0]),
            "certificate",
        )
        _require_nonformal_certificate(saved_certificate)
        replayed_certificate = evaluate(
            reg,
            gate1,
            gate2,
            integrity=integrity,
        ).to_dict()
    except (OSError, BundleError, TypeError, ValueError, KeyError) as exc:
        errors.append(f"payload decode or kernel replay failed: {exc}")
        return report

    report["saved_verdict"] = saved_certificate.get("verdict")
    report["replayed_verdict"] = replayed_certificate.get("verdict")
    report["kernel_replay_matches"] = replayed_certificate == saved_certificate
    if not report["kernel_replay_matches"]:
        errors.append("saved certificate does not match a fresh kernel replay")
    report["ok"] = bool(
        report["manifest_valid"]
        and report["payload_hashes_valid"]
        and report["kernel_replay_matches"]
    )
    return report


def verify_full_audit_bundle(directory: str | Path) -> dict[str, Any]:
    """Verify and replay a ``full_audit_v1`` bundle entirely offline."""

    root = Path(directory)
    report: dict[str, Any] = {
        "bundle_format": FULL_AUDIT_BUNDLE_FORMAT,
        "format_version": FULL_AUDIT_BUNDLE_FORMAT_VERSION,
        "bundle_profile": FULL_AUDIT_PROFILE,
        "bundle_id": None,
        "ok": False,
        "manifest_valid": False,
        "payload_hashes_valid": False,
        "kernel_replay_matches": False,
        "provenance_scope": PROVENANCE_SCOPE,
        "formal_certificate_issued": False,
        "payloads": {},
        "saved_verdict": None,
        "replayed_verdict": None,
        "errors": [],
    }
    errors: list[str] = report["errors"]

    try:
        manifest = _load_json(root / MANIFEST_NAME)
        _validate_full_audit_manifest(manifest, root)
        report["bundle_id"] = manifest["bundle_id"]
        report["manifest_valid"] = True
    except (OSError, BundleError, TypeError, ValueError, KeyError) as exc:
        errors.append(f"manifest validation failed: {exc}")
        return report

    all_hashes_valid = True
    for name, (expected_path, _schema) in _FULL_AUDIT_PAYLOAD_LAYOUT.items():
        entry = manifest["payloads"][name]
        path = root / expected_path
        try:
            raw = path.read_bytes()
            actual_digest = _digest(raw)
            actual_size = len(raw)
            valid = (
                actual_digest == entry["content_digest"]
                and actual_size == entry["size_bytes"]
            )
        except OSError as exc:
            actual_digest = None
            actual_size = None
            valid = False
            errors.append(f"cannot read payload {name}: {exc}")
        report["payloads"][name] = {
            "path": expected_path,
            "schema": entry["schema"],
            "expected_digest": entry["content_digest"],
            "actual_digest": actual_digest,
            "expected_size_bytes": entry["size_bytes"],
            "actual_size_bytes": actual_size,
            "valid": valid,
        }
        if not valid:
            all_hashes_valid = False
            if actual_digest is not None:
                errors.append(f"payload digest or size mismatch: {name}")

    report["payload_hashes_valid"] = all_hashes_valid
    if not all_hashes_valid:
        return report

    try:
        reg = _registration_from_dict(
            _load_json(root / _FULL_AUDIT_PAYLOAD_LAYOUT["registration"][0])
        )
        integrity = _integrity_from_dict(
            _load_json(root / _FULL_AUDIT_PAYLOAD_LAYOUT["integrity"][0])
        )
        gate1 = _gate1_from_dict(
            _load_json(root / _FULL_AUDIT_PAYLOAD_LAYOUT["gate1"][0])
        )
        gate2 = _gate2_from_dict(
            _load_json(root / _FULL_AUDIT_PAYLOAD_LAYOUT["gate2"][0])
        )
        gate3 = _gate3_from_dict(
            _load_json(root / _FULL_AUDIT_PAYLOAD_LAYOUT["gate3"][0])
        )
        saved_certificate = _require_object(
            _load_json(root / _FULL_AUDIT_PAYLOAD_LAYOUT["certificate"][0]),
            "certificate",
        )
        _require_nonformal_certificate(saved_certificate)
        replayed_certificate = evaluate(
            reg,
            gate1,
            gate2,
            gate3,
            integrity=integrity,
        ).to_dict()
    except (OSError, BundleError, TypeError, ValueError, KeyError) as exc:
        errors.append(f"payload decode or kernel replay failed: {exc}")
        return report

    report["saved_verdict"] = saved_certificate.get("verdict")
    report["replayed_verdict"] = replayed_certificate.get("verdict")
    report["kernel_replay_matches"] = replayed_certificate == saved_certificate
    if not report["kernel_replay_matches"]:
        errors.append("saved certificate does not match a fresh kernel replay")
    report["ok"] = bool(
        report["manifest_valid"]
        and report["payload_hashes_valid"]
        and report["kernel_replay_matches"]
    )
    return report


def verify_bundle(directory: str | Path) -> dict[str, Any]:
    """Auto-detect and verify either supported bundle profile."""

    root = Path(directory)
    try:
        manifest = _require_object(_load_json(root / MANIFEST_NAME), "manifest")
    except (OSError, BundleError, TypeError, ValueError) as exc:
        return _unsupported_bundle_report(
            None, None, None, f"manifest detection failed: {exc}"
        )

    bundle_format = manifest.get("format")
    version = manifest.get("format_version")
    profile = manifest.get("profile")
    if bundle_format == BUNDLE_FORMAT:
        return verify_core_bundle(root)
    if bundle_format == FULL_AUDIT_BUNDLE_FORMAT:
        return verify_full_audit_bundle(root)
    return _unsupported_bundle_report(
        bundle_format,
        version,
        profile,
        f"unsupported bundle format: {bundle_format!r}",
    )


def _certificate_mapping(certificate: Any) -> dict[str, Any]:
    if hasattr(certificate, "to_dict") and callable(certificate.to_dict):
        certificate = certificate.to_dict()
    return _require_object(_jsonable(certificate), "certificate")


def _require_nonformal_certificate(certificate: Mapping[str, Any]) -> None:
    protocol = certificate.get("protocol")
    if not isinstance(protocol, Mapping):
        raise BundleError("certificate.protocol must be an object")
    if protocol.get("formal_certificate_issued") is not False:
        raise BundleError(
            "a local Core bundle cannot claim formal_certificate_issued=true"
        )


def _prepare_full_audit_output(root: Path) -> None:
    """Create a strict full-audit root without silently changing profiles."""

    if root.is_symlink():
        raise BundleError("bundle directory cannot be a symbolic link")
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / MANIFEST_NAME
    if manifest_path.exists():
        existing = _require_object(_load_json(manifest_path), "manifest")
        if (
            existing.get("format") != FULL_AUDIT_BUNDLE_FORMAT
            or existing.get("format_version") != FULL_AUDIT_BUNDLE_FORMAT_VERSION
            or existing.get("profile") != FULL_AUDIT_PROFILE
        ):
            raise BundleError(
                "refusing to overwrite a bundle with a different format/profile"
            )

    expected_files = {Path(MANIFEST_NAME)} | {
        Path(relative) for relative, _schema in _FULL_AUDIT_PAYLOAD_LAYOUT.values()
    }
    actual_files: set[Path] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise BundleError(
                f"symbolic links are not allowed in a full audit bundle: "
                f"{path.relative_to(root)}"
            )
        if path.is_file():
            actual_files.add(path.relative_to(root))
    unexpected = sorted(str(path) for path in actual_files - expected_files)
    if unexpected:
        raise BundleError(
            "full audit bundle contains unregistered files: "
            + ", ".join(unexpected)
        )
    (root / "payload").mkdir(parents=True, exist_ok=True)


def _validate_full_audit_manifest(manifest_value: Any, root: Path) -> None:
    manifest = _require_object(manifest_value, "manifest")
    expected_top_level = {
        "format",
        "format_version",
        "profile",
        "hash_algorithm",
        "provenance_scope",
        "formal_certificate_issued",
        "payloads",
        "bundle_id",
    }
    _reject_unknown_fields(manifest, expected_top_level, "manifest")
    if set(manifest) != expected_top_level:
        missing = sorted(expected_top_level - set(manifest))
        raise BundleError(f"manifest missing fields: {missing}")
    if manifest["format"] != FULL_AUDIT_BUNDLE_FORMAT:
        raise BundleError(f"unsupported bundle format: {manifest['format']!r}")
    if manifest["format_version"] != FULL_AUDIT_BUNDLE_FORMAT_VERSION:
        raise BundleError(
            "unsupported full-audit format version: "
            f"{manifest['format_version']!r}"
        )
    if manifest["profile"] != FULL_AUDIT_PROFILE:
        raise BundleError(f"unsupported audit profile: {manifest['profile']!r}")
    if manifest["hash_algorithm"] != "sha256":
        raise BundleError("manifest hash_algorithm must be sha256")
    if manifest["provenance_scope"] != PROVENANCE_SCOPE:
        raise BundleError(
            f"manifest provenance_scope must be {PROVENANCE_SCOPE}"
        )
    if manifest["formal_certificate_issued"] is not False:
        raise BundleError("local bundle cannot claim formal certificate issuance")

    payloads = _require_object(manifest["payloads"], "manifest.payloads")
    if set(payloads) != set(_FULL_AUDIT_PAYLOAD_LAYOUT):
        raise BundleError(
            "manifest payload names must be exactly: "
            + ", ".join(sorted(_FULL_AUDIT_PAYLOAD_LAYOUT))
        )
    expected_entry_fields = {
        "path",
        "schema",
        "media_type",
        "content_digest",
        "size_bytes",
    }
    for name, (expected_path, expected_schema) in (
        _FULL_AUDIT_PAYLOAD_LAYOUT.items()
    ):
        entry = _require_object(payloads[name], f"manifest.payloads.{name}")
        _reject_unknown_fields(
            entry, expected_entry_fields, f"manifest.payloads.{name}"
        )
        if set(entry) != expected_entry_fields:
            missing = sorted(expected_entry_fields - set(entry))
            raise BundleError(f"manifest payload {name} missing fields: {missing}")
        if entry["path"] != expected_path:
            raise BundleError(f"manifest payload {name} has a non-canonical path")
        if entry["schema"] != expected_schema:
            raise BundleError(f"manifest payload {name} has an unknown schema")
        if entry["media_type"] != "application/json":
            raise BundleError(f"manifest payload {name} must be application/json")
        _validate_digest(entry["content_digest"], f"payload {name} digest")
        if (
            not isinstance(entry["size_bytes"], int)
            or isinstance(entry["size_bytes"], bool)
            or entry["size_bytes"] < 0
        ):
            raise BundleError(f"manifest payload {name} has invalid size_bytes")

    if root.is_symlink():
        raise BundleError("bundle directory cannot be a symbolic link")
    expected_files = {Path(MANIFEST_NAME)} | {
        Path(path) for path, _schema in _FULL_AUDIT_PAYLOAD_LAYOUT.values()
    }
    actual_files: set[Path] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise BundleError(
                f"symbolic links are not allowed in a full audit bundle: "
                f"{path.relative_to(root)}"
            )
        if path.is_file():
            actual_files.add(path.relative_to(root))
    if actual_files != expected_files:
        missing = sorted(str(item) for item in expected_files - actual_files)
        extra = sorted(str(item) for item in actual_files - expected_files)
        raise BundleError(f"bundle file set mismatch; missing={missing}, extra={extra}")

    identity = {key: manifest[key] for key in expected_top_level - {"bundle_id"}}
    expected_bundle_id = _digest(_canonical_json_bytes(identity))
    _validate_digest(manifest["bundle_id"], "bundle_id")
    if manifest["bundle_id"] != expected_bundle_id:
        raise BundleError("bundle_id does not match the manifest payload table")


def _unsupported_bundle_report(
    bundle_format: Any,
    version: Any,
    profile: Any,
    error: str,
) -> dict[str, Any]:
    return {
        "bundle_format": bundle_format,
        "format_version": version,
        "bundle_profile": profile,
        "bundle_id": None,
        "ok": False,
        "manifest_valid": False,
        "payload_hashes_valid": False,
        "kernel_replay_matches": False,
        "provenance_scope": PROVENANCE_SCOPE,
        "formal_certificate_issued": False,
        "payloads": {},
        "saved_verdict": None,
        "replayed_verdict": None,
        "errors": [error],
    }


def _validate_manifest(manifest_value: Any, root: Path) -> None:
    manifest = _require_object(manifest_value, "manifest")
    expected_top_level = {
        "format",
        "format_version",
        "hash_algorithm",
        "provenance_scope",
        "formal_certificate_issued",
        "payloads",
        "bundle_id",
    }
    _reject_unknown_fields(manifest, expected_top_level, "manifest")
    if manifest.get("format") != BUNDLE_FORMAT:
        raise BundleError(f"unsupported bundle format: {manifest.get('format')!r}")
    if manifest.get("format_version") != BUNDLE_FORMAT_VERSION:
        raise BundleError(
            f"unsupported bundle format version: {manifest.get('format_version')!r}"
        )
    if manifest.get("hash_algorithm") != "sha256":
        raise BundleError("manifest hash_algorithm must be sha256")
    if manifest.get("provenance_scope") != PROVENANCE_SCOPE:
        raise BundleError(
            f"manifest provenance_scope must be {PROVENANCE_SCOPE}"
        )
    if manifest.get("formal_certificate_issued") is not False:
        raise BundleError("local bundle cannot claim formal certificate issuance")

    payloads = _require_object(manifest.get("payloads"), "manifest.payloads")
    if set(payloads) != set(_PAYLOAD_LAYOUT):
        raise BundleError(
            "manifest payload names must be exactly: "
            + ", ".join(sorted(_PAYLOAD_LAYOUT))
        )
    for name, (expected_path, expected_schema) in _PAYLOAD_LAYOUT.items():
        entry = _require_object(payloads[name], f"manifest.payloads.{name}")
        expected_entry_fields = {
            "path",
            "schema",
            "media_type",
            "content_digest",
            "size_bytes",
        }
        _reject_unknown_fields(
            entry, expected_entry_fields, f"manifest.payloads.{name}"
        )
        if set(entry) != expected_entry_fields:
            missing = sorted(expected_entry_fields - set(entry))
            raise BundleError(f"manifest payload {name} missing fields: {missing}")
        if entry["path"] != expected_path:
            raise BundleError(f"manifest payload {name} has a non-canonical path")
        if entry["schema"] != expected_schema:
            raise BundleError(f"manifest payload {name} has an unknown schema")
        if entry["media_type"] != "application/json":
            raise BundleError(f"manifest payload {name} must be application/json")
        _validate_digest(entry["content_digest"], f"payload {name} digest")
        if (
            not isinstance(entry["size_bytes"], int)
            or isinstance(entry["size_bytes"], bool)
            or entry["size_bytes"] < 0
        ):
            raise BundleError(f"manifest payload {name} has invalid size_bytes")

    expected_files = {
        Path(path).relative_to("payload")
        for path, _schema in _PAYLOAD_LAYOUT.values()
    }
    payload_root = root / "payload"
    if not payload_root.is_dir():
        raise BundleError("payload directory is missing")
    actual_files: set[Path] = set()
    for path in payload_root.rglob("*"):
        if path.is_symlink():
            raise BundleError(f"symbolic links are not allowed in payload/: {path.name}")
        if path.is_file():
            actual_files.add(path.relative_to(payload_root))
    if actual_files != expected_files:
        missing = sorted(str(item) for item in expected_files - actual_files)
        extra = sorted(str(item) for item in actual_files - expected_files)
        raise BundleError(f"payload file set mismatch; missing={missing}, extra={extra}")

    identity = {key: manifest[key] for key in expected_top_level - {"bundle_id"}}
    expected_bundle_id = _digest(_canonical_json_bytes(identity))
    _validate_digest(manifest.get("bundle_id"), "bundle_id")
    if manifest["bundle_id"] != expected_bundle_id:
        raise BundleError("bundle_id does not match the manifest payload table")


def _registration_from_dict(value: Any) -> Registration:
    return _construct(Registration, value, "registration")


def _integrity_from_dict(value: Any) -> IntegrityEvidence:
    return _construct(IntegrityEvidence, value, "integrity")


def _gate1_from_dict(value: Any) -> Gate1Evidence:
    data = _checked_dataclass_dict(Gate1Evidence, value, "gate1")
    return Gate1Evidence(
        astar=_artifact_from_dict(data["astar"], "gate1.astar"),
        baseline=_artifact_from_dict(data["baseline"], "gate1.baseline"),
    )


def _artifact_from_dict(value: Any, label: str) -> ArtifactScores:
    data = _checked_dataclass_dict(ArtifactScores, value, label)
    try:
        data["validity"] = Validity(data.get("validity", Validity.UNRESOLVED.value))
    except ValueError as exc:
        raise BundleError(f"{label}.validity is invalid") from exc
    if "per_unit" in data:
        data["per_unit"] = tuple(_require_array(data["per_unit"], f"{label}.per_unit"))
    if "unit_ids" in data:
        data["unit_ids"] = tuple(_require_array(data["unit_ids"], f"{label}.unit_ids"))
    return ArtifactScores(**data)


def _gate2_from_dict(value: Any) -> Gate2Evidence:
    data = _checked_dataclass_dict(Gate2Evidence, value, "gate2")
    controls_raw = _require_array(data.get("controls", []), "gate2.controls")
    adequacy_raw = data.get("adequacy", {})
    return Gate2Evidence(
        controls=tuple(
            _control_from_dict(item, f"gate2.controls[{index}]")
            for index, item in enumerate(controls_raw)
        ),
        adequacy=_construct(AdequacyEvidence, adequacy_raw, "gate2.adequacy"),
    )


def _control_from_dict(value: Any, label: str) -> ControlAttempt:
    data = _checked_dataclass_dict(ControlAttempt, value, label)
    try:
        data["outcome"] = RawAttemptOutcome(
            data.get("outcome", RawAttemptOutcome.UNRESOLVED.value)
        )
        data["validity"] = Validity(data.get("validity", Validity.UNRESOLVED.value))
    except ValueError as exc:
        raise BundleError(f"{label} contains an invalid enum value") from exc
    if data.get("per_unit") is not None:
        data["per_unit"] = tuple(_require_array(data["per_unit"], f"{label}.per_unit"))
    if "unit_ids" in data:
        data["unit_ids"] = tuple(_require_array(data["unit_ids"], f"{label}.unit_ids"))
    return ControlAttempt(**data)


def _gate3_from_dict(value: Any) -> Gate3Evidence:
    data = _checked_dataclass_dict(Gate3Evidence, value, "gate3")
    pairs_raw = _require_array(data.get("pairs"), "gate3.pairs")
    if "sham" not in data:
        raise BundleError("gate3.sham is required")
    data["pairs"] = tuple(
        _feedback_pair_from_dict(item, f"gate3.pairs[{index}]")
        for index, item in enumerate(pairs_raw)
    )
    data["sham"] = _sham_calibration_from_dict(data["sham"], "gate3.sham")
    if data.get("neutral_adequacy") is not None:
        data["neutral_adequacy"] = _construct(
            AdequacyEvidence,
            data["neutral_adequacy"],
            "gate3.neutral_adequacy",
        )
    try:
        return Gate3Evidence(**data)
    except TypeError as exc:
        raise BundleError(f"gate3 does not satisfy Gate3Evidence: {exc}") from exc


def _feedback_pair_from_dict(value: Any, label: str) -> FeedbackPair:
    data = _checked_dataclass_dict(FeedbackPair, value, label)
    if "truthful" not in data or "neutral" not in data:
        raise BundleError(f"{label} requires truthful and neutral branches")
    data["truthful"] = _branch_from_dict(data["truthful"], f"{label}.truthful")
    data["neutral"] = _branch_from_dict(data["neutral"], f"{label}.neutral")
    try:
        return FeedbackPair(**data)
    except TypeError as exc:
        raise BundleError(f"{label} does not satisfy FeedbackPair: {exc}") from exc


def _sham_calibration_from_dict(value: Any, label: str) -> ShamCalibration:
    data = _checked_dataclass_dict(ShamCalibration, value, label)
    pairs_raw = _require_array(data.get("pairs"), f"{label}.pairs")
    data["pairs"] = tuple(
        _sham_pair_from_dict(item, f"{label}.pairs[{index}]")
        for index, item in enumerate(pairs_raw)
    )
    try:
        return ShamCalibration(**data)
    except TypeError as exc:
        raise BundleError(f"{label} does not satisfy ShamCalibration: {exc}") from exc


def _sham_pair_from_dict(value: Any, label: str) -> ShamPair:
    data = _checked_dataclass_dict(ShamPair, value, label)
    if "reference_null" not in data or "proposed_sham" not in data:
        raise BundleError(
            f"{label} requires reference_null and proposed_sham branches"
        )
    data["reference_null"] = _branch_from_dict(
        data["reference_null"], f"{label}.reference_null"
    )
    data["proposed_sham"] = _branch_from_dict(
        data["proposed_sham"], f"{label}.proposed_sham"
    )
    try:
        return ShamPair(**data)
    except TypeError as exc:
        raise BundleError(f"{label} does not satisfy ShamPair: {exc}") from exc


def _branch_from_dict(value: Any, label: str) -> BranchOutcome:
    data = _checked_dataclass_dict(BranchOutcome, value, label)
    try:
        data["outcome"] = RawAttemptOutcome(
            data.get("outcome", RawAttemptOutcome.UNRESOLVED.value)
        )
        data["validity"] = Validity(
            data.get("validity", Validity.UNRESOLVED.value)
        )
    except ValueError as exc:
        raise BundleError(f"{label} contains an invalid enum value") from exc
    if data.get("per_unit") is not None:
        data["per_unit"] = tuple(
            _require_array(data["per_unit"], f"{label}.per_unit")
        )
    if "unit_ids" in data:
        data["unit_ids"] = tuple(
            _require_array(data["unit_ids"], f"{label}.unit_ids")
        )
    try:
        return BranchOutcome(**data)
    except TypeError as exc:
        raise BundleError(f"{label} does not satisfy BranchOutcome: {exc}") from exc


def _construct(cls: type[Any], value: Any, label: str) -> Any:
    data = _checked_dataclass_dict(cls, value, label)
    try:
        return cls(**data)
    except TypeError as exc:
        raise BundleError(f"{label} does not satisfy {cls.__name__}: {exc}") from exc


def _checked_dataclass_dict(
    cls: type[Any], value: Any, label: str
) -> dict[str, Any]:
    data = _require_object(value, label)
    allowed = {item.name for item in fields(cls)}
    _reject_unknown_fields(data, allowed, label)
    # The dataclass constructor below enforces genuinely required fields.  A
    # mutable copy is needed for enum and nested-record decoding.
    return dict(data)


def _reject_unknown_fields(
    value: Mapping[str, Any], allowed: set[str], label: str
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise BundleError(f"{label} has unknown fields: {unknown}")


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BundleError(f"{label} must be a JSON object")
    return value


def _require_array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise BundleError(f"{label} must be a JSON array")
    return value


def _jsonable(value: Any) -> Any:
    if isinstance(value, Gate3Evidence):
        value = asdict(value)
        if value.get("neutral_contract_audit_pass") is None:
            # ``None`` is an in-memory compatibility sentinel, not a legacy
            # wire field.  Omitting it keeps old full_audit_v1 payload bytes
            # and content ids stable.
            value.pop("neutral_contract_audit_pass", None)
    elif is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    if isinstance(value, Enum):
        return value.value
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise BundleError("NaN and Infinity are not valid bundle values")
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise BundleError("bundle JSON object keys must be strings")
            result[key] = _jsonable(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    raise BundleError(f"value is not representable as strict JSON: {type(value).__name__}")


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise BundleError(f"cannot encode strict JSON: {exc}") from exc
    return (text + "\n").encode("utf-8")


def _load_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise BundleError(f"{path.name} is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise BundleError(f"{path.name} is not strict JSON: {exc}") from exc


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise BundleError(f"non-finite JSON number is forbidden: {value}")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_digest(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise BundleError(f"{label} must use sha256:<hex>")
    hex_part = value.removeprefix("sha256:")
    if len(hex_part) != 64 or any(char not in "0123456789abcdef" for char in hex_part):
        raise BundleError(f"{label} is not a canonical SHA-256 digest")


__all__ = [
    "BUNDLE_FORMAT",
    "BUNDLE_FORMAT_VERSION",
    "BundleError",
    "FULL_AUDIT_BUNDLE_FORMAT",
    "FULL_AUDIT_BUNDLE_FORMAT_VERSION",
    "FULL_AUDIT_PROFILE",
    "PROVENANCE_SCOPE",
    "verify_bundle",
    "verify_core_bundle",
    "verify_full_audit_bundle",
    "write_core_bundle",
    "write_full_audit_bundle",
]
