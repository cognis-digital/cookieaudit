"""Smoke tests for COOKIEAUDIT. No network. Run with: python -m pytest -q

Also runnable directly: python tests/test_smoke.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cookieaudit import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    parse_set_cookie,
    parse_dump,
    audit_cookie,
    audit_dump,
)
from cookieaudit.cli import main  # noqa: E402
from cookieaudit.core import render_html, render_json, render_table  # noqa: E402


def test_metadata():
    assert TOOL_NAME == "cookieaudit"
    assert TOOL_VERSION.count(".") == 2


def test_parse_basic():
    c = parse_set_cookie("Set-Cookie: sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert c is not None
    assert c.name == "sid"
    assert c.value == "abc"
    assert c.secure and c.http_only
    assert c.same_site == "Lax"
    assert c.path == "/"


def test_parse_value_only_and_attrs():
    c = parse_set_cookie("foo=bar; Domain=.example.com; Max-Age=120")
    assert c.name == "foo"
    assert c.domain == ".example.com"
    assert c.max_age == 120
    assert c.is_session is False


def test_parse_invalid_returns_none():
    assert parse_set_cookie("") is None
    assert parse_set_cookie("Secure") is None  # no name=value


def test_clean_cookie_has_no_findings():
    c = parse_set_cookie("theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert audit_cookie(c) == []


def test_missing_flags_flagged():
    c = parse_set_cookie("sessionid=xyz")  # sensitive, bare
    codes = {f.code for f in audit_cookie(c)}
    assert "missing-secure" in codes
    assert "missing-httponly" in codes
    assert "missing-samesite" in codes


def test_samesite_none_without_secure_is_high():
    c = parse_set_cookie("x=1; SameSite=None")
    findings = audit_cookie(c)
    high = [f for f in findings if f.code == "samesite-none-insecure"]
    assert high and high[0].severity == "high"


def test_host_prefix_violation():
    c = parse_set_cookie("__Host-id=1; Path=/; HttpOnly")  # missing Secure
    codes = {f.code for f in audit_cookie(c)}
    assert "host-prefix-violation" in codes


def test_parse_dump_counts():
    dump = (
        "HTTP/1.1 200 OK\n"
        "Set-Cookie: a=1; Secure; HttpOnly; SameSite=Lax\n"
        "Set-Cookie: b=2\n"
        "Content-Length: 0\n"
    )
    cookies = parse_dump(dump)
    assert len(cookies) == 2
    assert {c.name for c in cookies} == {"a", "b"}


def test_report_failed_and_renderers():
    report = audit_dump("Set-Cookie: sid=1; SameSite=None\n")
    assert report.failed is True
    assert "cookieaudit" in render_json(report)
    assert "COOKIEAUDIT" in render_html(report)
    assert "Findings" in render_table(report)


def test_clean_report_not_failed():
    report = audit_dump("Set-Cookie: theme=dark; Secure; HttpOnly; SameSite=Lax\n")
    assert report.failed is False
    assert report.findings == []


def test_cli_exit_codes(tmp_path=None):
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        bad = os.path.join(d, "bad.txt")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("Set-Cookie: sid=1; SameSite=None\n")
        assert main(["audit", bad, "--format", "json"]) == 1

        good = os.path.join(d, "good.txt")
        with open(good, "w", encoding="utf-8") as fh:
            fh.write("Set-Cookie: theme=dark; Secure; HttpOnly; SameSite=Lax\n")
        assert main(["audit", good, "--format", "json"]) == 0

        out = os.path.join(d, "r.html")
        assert main(["audit", bad, "--format", "html", "-o", out]) == 1
        with open(out, encoding="utf-8") as fh:
            assert "<!DOCTYPE html>" in fh.read()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
