"""Command-line interface for COOKIEAUDIT."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import audit_dump, render_table, render_json, render_html


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Audit Set-Cookie security flags from an HTTP response dump.",
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    sub = parser.add_subparsers(dest="command")

    audit = sub.add_parser(
        "audit", help="Audit cookies from a response dump file (or - for stdin)."
    )
    audit.add_argument(
        "input", nargs="?", default="-",
        help="Path to response dump, or '-' for stdin (default).",
    )
    audit.add_argument(
        "--format", choices=["table", "json", "html"], default="table",
        help="Output format (default: table). 'html' writes a shareable report.",
    )
    audit.add_argument(
        "-o", "--output", default=None,
        help="Write report to this file instead of stdout.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "audit":
        parser.print_help()
        return 2

    try:
        text = _read_input(args.input)
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2

    report = audit_dump(text)

    if args.format == "json":
        out = render_json(report)
    elif args.format == "html":
        out = render_html(report)
    else:
        out = render_table(report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out)
        except OSError as exc:
            print(f"error: cannot write output: {exc}", file=sys.stderr)
            return 2
        print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(out)

    # Non-zero exit when medium+ findings exist, so this works in CI/pipelines.
    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
