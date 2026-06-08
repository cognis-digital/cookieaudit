"""COOKIEAUDIT - audit Set-Cookie security flags from an HTTP response dump.

Defensive analysis tool: parses Set-Cookie headers you already own (from a saved
response dump) and flags missing hardening attributes (Secure, HttpOnly,
SameSite, scoping, lifetime). No network access, standard library only.
"""
from .core import (
    Cookie,
    Finding,
    AuditReport,
    parse_dump,
    parse_set_cookie,
    audit_cookie,
    audit_dump,
    SEVERITY_ORDER,
)

TOOL_NAME = "cookieaudit"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Cookie",
    "Finding",
    "AuditReport",
    "parse_dump",
    "parse_set_cookie",
    "audit_cookie",
    "audit_dump",
    "SEVERITY_ORDER",
    "TOOL_NAME",
    "TOOL_VERSION",
]
