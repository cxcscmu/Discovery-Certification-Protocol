"""Command-line entry point for offline DCP bundle verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from dcp.bundle import verify_bundle


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m dcp",
        description="Offline tools for the DCP evaluation core",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser(
        "verify",
        help="verify hashes and replay a supported DCP Audit Bundle",
    )
    verify_parser.add_argument("bundle", type=Path, help="bundle directory")
    args = parser.parse_args(argv)

    if args.command == "verify":
        report = verify_bundle(args.bundle)
        print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
        return 0 if report["ok"] else 1
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
