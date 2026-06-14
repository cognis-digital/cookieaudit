"""Command-line interface for COOKIEAUDIT."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .core import TOOL_NAME, TOOL_VERSION, audit_dump, render_html, render_json, render_table


def _read_input(path: str) -> str:
    """Read text from *path* or stdin when path is '-'.

    Raises ``OSError`` on I/O failure and ``ValueError`` when *path* is not a
    non-empty string.
    """
    if not isinstance(path, str) or not path:
        raise ValueError(f"input path must be a non-empty string, got {path!r}")
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
        "input",
        nargs="?",
        default="-",
        help="Path to response dump, or '-' for stdin (default).",
    )
    audit.add_argument(
        "--format",
        choices=["table", "json", "html"],
        default="table",
        help="Output format (default: table). 'html' writes a shareable report.",
    )
    audit.add_argument(
        "-o",
        "--output",
        default=None,
        help="Write report to this file instead of stdout.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point.  Returns 0 (clean), 1 (findings), or 2 (usage/I-O error)."""
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 2


def _main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return 2

    if args.command != "audit":
        print(f"error: unknown command {args.command!r}", file=sys.stderr)
        parser.print_help(sys.stderr)
        return 2

    try:
        text = _read_input(args.input)
    except (OSError, ValueError) as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2

    try:
        report = audit_dump(text)
    except (TypeError, ValueError) as exc:
        print(f"error: failed to parse input: {exc}", file=sys.stderr)
        return 2

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
