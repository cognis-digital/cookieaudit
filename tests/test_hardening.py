"""Hardening tests for COOKIEAUDIT.

Covers error paths, edge cases, and input-validation behaviour introduced
during the production-hardening pass.  No network required.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from cookieaudit.cli import main
from cookieaudit.core import (
    TOOL_NAME,
    TOOL_VERSION,
    audit_dump,
    parse_dump,
    parse_set_cookie,
)


# ---------------------------------------------------------------------------
# core.py — TOOL_NAME / TOOL_VERSION are now defined in core
# ---------------------------------------------------------------------------


def test_tool_identity_from_core():
    assert TOOL_NAME == "cookieaudit"
    assert TOOL_VERSION.count(".") == 2


# ---------------------------------------------------------------------------
# core.py — audit_dump guards
# ---------------------------------------------------------------------------


def test_audit_dump_none_raises():
    with pytest.raises((TypeError, ValueError)):
        audit_dump(None)  # type: ignore[arg-type]


def test_audit_dump_wrong_type_raises():
    with pytest.raises((TypeError, ValueError)):
        audit_dump(123)  # type: ignore[arg-type]


def test_audit_dump_empty_string_returns_empty_report():
    report = audit_dump("")
    assert report.cookies == []
    assert report.findings == []
    assert report.failed is False
    assert report.worst_severity is None


def test_audit_dump_whitespace_only_returns_empty_report():
    report = audit_dump("   \n\t\n  ")
    assert report.cookies == []
    assert report.findings == []


# ---------------------------------------------------------------------------
# core.py — parse edge cases
# ---------------------------------------------------------------------------


def test_parse_set_cookie_none_value():
    # cookie with '=' but empty value is valid
    c = parse_set_cookie("empty=")
    assert c is not None
    assert c.name == "empty"
    assert c.value == ""


def test_parse_set_cookie_malformed_max_age_is_ignored():
    c = parse_set_cookie("x=1; Max-Age=notanumber")
    assert c is not None
    # max_age stays None on parse failure — cookie is treated as session cookie
    assert c.max_age is None
    assert c.is_session is True


def test_parse_dump_empty_string():
    assert parse_dump("") == []


def test_parse_dump_no_set_cookie_lines():
    dump = "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 0\n"
    # No Set-Cookie headers → no cookies parsed
    assert parse_dump(dump) == []


def test_parse_dump_only_blank_lines():
    assert parse_dump("\n\n\n") == []


def test_parse_set_cookie_set_cookie_prefix_only():
    # "Set-Cookie: " with nothing after it → None
    assert parse_set_cookie("Set-Cookie: ") is None


def test_parse_set_cookie_no_equals_in_name_value():
    assert parse_set_cookie("justabareword") is None


# ---------------------------------------------------------------------------
# cli.py — missing file returns exit code 2 with message on stderr
# ---------------------------------------------------------------------------


def test_cli_missing_file_exits_2(capsys):
    code = main(["audit", "/nonexistent/path/to/file.txt"])
    assert code == 2
    captured = capsys.readouterr()
    assert "error" in captured.err.lower()


def test_cli_no_subcommand_exits_2(capsys):
    code = main([])
    assert code == 2


def test_cli_empty_input_exits_0(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("", encoding="utf-8")
    code = main(["audit", str(empty)])
    assert code == 0


def test_cli_output_file_written(tmp_path):
    dump = tmp_path / "dump.txt"
    dump.write_text("Set-Cookie: theme=dark; Secure; HttpOnly; SameSite=Lax\n", encoding="utf-8")
    out = tmp_path / "report.json"
    code = main(["audit", str(dump), "--format", "json", "-o", str(out)])
    assert code == 0
    content = out.read_text(encoding="utf-8")
    assert '"cookieaudit"' in content


def test_cli_bad_output_dir_exits_2(tmp_path):
    dump = tmp_path / "dump.txt"
    dump.write_text("Set-Cookie: x=1\n", encoding="utf-8")
    code = main(["audit", str(dump), "-o", "/nonexistent/dir/out.html"])
    assert code == 2


# ---------------------------------------------------------------------------
# mcp_server.py — module compiles and imports without the optional mcp dep
# ---------------------------------------------------------------------------


def test_mcp_server_imports_cleanly():
    import importlib
    # Must not raise ImportError (scan/to_json no longer referenced)
    mod = importlib.import_module("cookieaudit.mcp_server")
    assert callable(mod.serve)


def test_mcp_server_serve_is_callable():
    from cookieaudit.mcp_server import serve

    # serve() must exist and be callable; the module must import without error
    # now that the old broken scan/to_json imports have been corrected.
    assert callable(serve)


# ---------------------------------------------------------------------------
# webhook.py — URL validation
# ---------------------------------------------------------------------------


def test_webhook_url_validation_rejects_non_http():
    from integrations.webhook import _validate_url

    with pytest.raises(ValueError, match="http"):
        _validate_url("ftp://example.com/hook")


def test_webhook_url_validation_rejects_empty():
    from integrations.webhook import _validate_url

    with pytest.raises(ValueError):
        _validate_url("")


def test_webhook_url_validation_accepts_https():
    from integrations.webhook import _validate_url

    _validate_url("https://example.com/hook")  # must not raise
