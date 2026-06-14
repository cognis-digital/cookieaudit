#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request


def _validate_url(url: str) -> None:
    """Raise ValueError if *url* is not an http/https URL."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("--url must be a non-empty string")
    scheme = url.split("://", 1)[0].lower()
    if scheme not in ("http", "https"):
        raise ValueError(
            f"--url must use http or https scheme, got {scheme!r}"
        )


def main() -> int:
    ap = argparse.ArgumentParser(
        description="POST cookieaudit JSON findings to a webhook URL.",
    )
    ap.add_argument("--url", required=True, help="Destination URL (http/https).")
    ap.add_argument(
        "--header",
        action="append",
        default=[],
        help="Extra header in 'Key: Value' form (repeatable).",
    )
    args = ap.parse_args()

    try:
        _validate_url(args.url)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    payload = sys.stdin.buffer.read()
    if not payload:
        print("error: no input received on stdin", file=sys.stderr)
        return 2

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as exc:
        print(f"webhook error: HTTP {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"webhook error: {exc.reason}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"webhook error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
