"""Small public command-line wrapper around the offline DCP verifier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from dcp import __version__
from dcp.bundle import verify_bundle


def _human_report(report: Mapping[str, Any]) -> str:
    bundle_id = report.get("bundle_id") or "unavailable"
    lines = [
        f"Replay: {'VERIFIED' if report.get('ok') else 'FAILED'}",
        f"Bundle: {bundle_id}",
    ]
    if not report.get("ok"):
        lines.append("Decision: unavailable")
        errors = report.get("errors")
        if isinstance(errors, list) and errors:
            lines.append("Errors:")
            lines.extend(f"  - {error}" for error in errors)
        return "\n".join(lines)

    verdict = report.get("replayed_verdict")
    if not isinstance(verdict, Mapping):
        verdict = {}
    profile = report.get("bundle_profile") or report.get("bundle_format")
    lines.extend(
        (
            f"Profile: {profile or 'unavailable'}",
            f"Core: {verdict.get('core', 'not_tested')}",
            f"Evidence: {verdict.get('evidence', 'not_tested')}",
            f"Provenance: {report.get('provenance_scope', 'unavailable')}",
            "Formal issuance: "
            + ("yes" if report.get("formal_certificate_issued") else "no"),
        )
    )
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dcp",
        description="Verify a DCP Audit Bundle entirely offline.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser(
        "verify",
        help="check hashes and replay the deterministic DCP decision",
    )
    verify_parser.add_argument("bundle", type=Path, help="Audit Bundle directory")
    verify_parser.add_argument(
        "--json",
        action="store_true",
        help="print the complete machine-readable verification report",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "verify":
        report = verify_bundle(args.bundle)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
        else:
            print(_human_report(report))
        return 0 if report["ok"] else 1
    return 2


__all__ = ["main"]

