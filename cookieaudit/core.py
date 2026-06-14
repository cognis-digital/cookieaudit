"""Core engine for COOKIEAUDIT.

Parses Set-Cookie header lines out of a raw HTTP response dump and evaluates
each cookie against a set of hardening rules. Pure standard library.
"""
from __future__ import annotations

import html as _html
import re
from dataclasses import dataclass, field
from typing import List, Optional

TOOL_NAME = "cookieaudit"
TOOL_VERSION = "0.6.5"

# Severity ranking (higher index = worse) used for sorting and exit codes.
SEVERITY_ORDER = ["info", "low", "medium", "high"]

# Names that conventionally carry a session/auth token. Used to escalate
# severity when such a cookie is missing protections.
_SENSITIVE_HINTS = re.compile(
    r"(sess|sid|auth|token|jwt|csrf|xsrf|login|account|remember|secret)",
    re.IGNORECASE,
)

# RFC 6265 cookie-prefix rules.
_PREFIX_HOST = "__Host-"
_PREFIX_SECURE = "__Secure-"


@dataclass
class Cookie:
    """A parsed Set-Cookie value."""

    name: str
    value: str
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None  # 'Strict' | 'Lax' | 'None' | None
    domain: Optional[str] = None
    path: Optional[str] = None
    max_age: Optional[int] = None
    expires: Optional[str] = None
    raw: str = ""
    line_no: int = 0

    @property
    def is_sensitive(self) -> bool:
        return bool(_SENSITIVE_HINTS.search(self.name))

    @property
    def is_session(self) -> bool:
        """True when the cookie has no explicit lifetime (session cookie)."""
        return self.max_age is None and self.expires is None


@dataclass
class Finding:
    cookie: str
    severity: str
    code: str
    message: str
    recommendation: str
    line_no: int = 0


@dataclass
class AuditReport:
    findings: List[Finding] = field(default_factory=list)
    cookies: List[Cookie] = field(default_factory=list)

    @property
    def worst_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_ORDER.index(f.severity)).severity

    def counts(self) -> dict:
        c = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] += 1
        return c

    @property
    def failed(self) -> bool:
        """A run 'fails' if any finding is medium severity or worse."""
        worst = self.worst_severity
        if worst is None:
            return False
        return SEVERITY_ORDER.index(worst) >= SEVERITY_ORDER.index("medium")


def parse_set_cookie(value: str, line_no: int = 0) -> Optional[Cookie]:
    """Parse a single Set-Cookie header value into a Cookie.

    Accepts either the full header line ('Set-Cookie: foo=bar; ...') or just
    the value ('foo=bar; ...'). Returns None if no name=value pair is found.
    """
    text = value.strip()
    if not text:
        return None
    # Strip an optional 'Set-Cookie:' prefix (case-insensitive).
    m = re.match(r"^set-cookie\s*:\s*", text, re.IGNORECASE)
    if m:
        text = text[m.end():]
    if not text:
        return None

    parts = [p.strip() for p in text.split(";")]
    nv = parts[0]
    if "=" not in nv:
        # A bare attribute with no name=value is not a valid cookie.
        return None
    name, _, val = nv.partition("=")
    name = name.strip()
    if not name:
        return None

    cookie = Cookie(name=name, value=val.strip(), raw=value.strip(), line_no=line_no)

    for attr in parts[1:]:
        if not attr:
            continue
        key, _, aval = attr.partition("=")
        key_l = key.strip().lower()
        aval = aval.strip()
        if key_l == "secure":
            cookie.secure = True
        elif key_l == "httponly":
            cookie.http_only = True
        elif key_l == "samesite":
            norm = aval.lower()
            cookie.same_site = {
                "strict": "Strict",
                "lax": "Lax",
                "none": "None",
            }.get(norm, aval or None)
        elif key_l == "domain":
            cookie.domain = aval or None
        elif key_l == "path":
            cookie.path = aval or None
        elif key_l == "max-age":
            try:
                cookie.max_age = int(aval)
            except ValueError:
                cookie.max_age = None
        elif key_l == "expires":
            cookie.expires = aval or None
    return cookie


def parse_dump(text: str) -> List[Cookie]:
    """Extract all Set-Cookie cookies from a raw response dump.

    Recognizes lines beginning with 'Set-Cookie:' (case-insensitive). Also
    tolerates a plain list of cookie values (one per line) when no header
    prefix is present anywhere in the input.
    """
    lines = text.splitlines()
    has_header = any(re.match(r"^\s*set-cookie\s*:", ln, re.IGNORECASE) for ln in lines)
    cookies: List[Cookie] = []
    for i, line in enumerate(lines, start=1):
        if has_header:
            if not re.match(r"^\s*set-cookie\s*:", line, re.IGNORECASE):
                continue
            c = parse_set_cookie(line, line_no=i)
        else:
            if not line.strip():
                continue
            c = parse_set_cookie(line, line_no=i)
        if c is not None:
            cookies.append(c)
    return cookies


def _bump(severity: str, sensitive: bool) -> str:
    """Escalate a base severity one notch for sensitive cookies."""
    if not sensitive:
        return severity
    idx = min(SEVERITY_ORDER.index(severity) + 1, len(SEVERITY_ORDER) - 1)
    return SEVERITY_ORDER[idx]


def audit_cookie(cookie: Cookie) -> List[Finding]:
    """Evaluate one cookie against hardening rules."""
    out: List[Finding] = []
    sensitive = cookie.is_sensitive

    def add(severity, code, msg, rec):
        out.append(
            Finding(
                cookie=cookie.name,
                severity=severity,
                code=code,
                message=msg,
                recommendation=rec,
                line_no=cookie.line_no,
            )
        )

    # Secure flag.
    if not cookie.secure:
        add(
            _bump("medium", sensitive),
            "missing-secure",
            "Cookie is not marked Secure; it can be sent over plaintext HTTP.",
            "Add the Secure attribute so the cookie is only sent over HTTPS.",
        )

    # HttpOnly flag.
    if not cookie.http_only:
        sev = _bump("medium", sensitive) if sensitive else "low"
        add(
            sev,
            "missing-httponly",
            "Cookie is not marked HttpOnly; it is readable by client-side JavaScript.",
            "Add HttpOnly to block script access and reduce XSS token theft risk.",
        )

    # SameSite.
    if cookie.same_site is None:
        add(
            _bump("low", sensitive),
            "missing-samesite",
            "Cookie has no SameSite attribute; browsers default to Lax but this is implicit.",
            "Set SameSite explicitly (Lax or Strict) to document CSRF intent.",
        )
    elif cookie.same_site == "None" and not cookie.secure:
        add(
            "high",
            "samesite-none-insecure",
            "SameSite=None requires the Secure attribute; this cookie will be rejected by modern browsers.",
            "Either add Secure, or use SameSite=Lax/Strict.",
        )

    # Overly broad Path scoping.
    if cookie.path is not None and cookie.path == "/" and sensitive:
        add(
            "low",
            "broad-path",
            "Sensitive cookie is scoped to Path=/ (entire origin).",
            "Scope sensitive cookies to the narrowest path that needs them.",
        )

    # Leading-dot / broad Domain.
    if cookie.domain is not None and cookie.domain.startswith("."):
        add(
            "low",
            "broad-domain",
            "Cookie uses a leading-dot Domain, sharing it with all subdomains.",
            "Drop the leading dot or omit Domain to keep the cookie host-only.",
        )

    # Cookie prefixes (RFC 6265bis).
    if cookie.name.startswith(_PREFIX_HOST):
        if not cookie.secure:
            add("high", "host-prefix-violation",
                "__Host- prefix requires Secure.",
                "Add Secure to honor the __Host- prefix contract.")
        if cookie.domain is not None:
            add("high", "host-prefix-violation",
                "__Host- prefix forbids a Domain attribute.",
                "Remove the Domain attribute for __Host- cookies.")
        if cookie.path != "/":
            add("medium", "host-prefix-violation",
                "__Host- prefix requires Path=/.",
                "Set Path=/ for __Host- cookies.")
    elif cookie.name.startswith(_PREFIX_SECURE) and not cookie.secure:
        add("high", "secure-prefix-violation",
            "__Secure- prefix requires Secure.",
            "Add Secure to honor the __Secure- prefix contract.")

    # Excessive lifetime for sensitive session-like cookies.
    if sensitive and cookie.max_age is not None and cookie.max_age > 60 * 60 * 24 * 30:
        add(
            "low",
            "long-lived",
            "Sensitive cookie has a lifetime longer than 30 days.",
            "Shorten Max-Age for auth/session cookies to limit replay windows.",
        )

    return out


def audit_dump(text: str) -> AuditReport:
    if text is None:
        raise ValueError("audit_dump: text must be a str, got None")
    if not isinstance(text, str):
        raise TypeError(f"audit_dump: text must be a str, got {type(text).__name__}")
    cookies = parse_dump(text)
    findings: List[Finding] = []
    for c in cookies:
        findings.extend(audit_cookie(c))
    findings.sort(
        key=lambda f: (
            -SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 0,
            f.cookie,
            f.code,
        )
    )
    return AuditReport(findings=findings, cookies=cookies)


# ----------------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------------

_SEV_HEX = {
    "high": "#c0392b",
    "medium": "#e67e22",
    "low": "#f1c40f",
    "info": "#3498db",
}


def render_table(report: AuditReport) -> str:
    lines: List[str] = []
    lines.append(f"Parsed {len(report.cookies)} cookie(s).")
    if report.cookies:
        lines.append("")
        lines.append(f"{'COOKIE':<24} {'SEC':<4}{'HTTP':<5}{'SAMESITE':<10}")
        lines.append("-" * 47)
        for c in report.cookies:
            lines.append(
                f"{c.name[:23]:<24} "
                f"{('Y' if c.secure else '-'):<4}"
                f"{('Y' if c.http_only else '-'):<5}"
                f"{(c.same_site or '-'):<10}"
            )
    lines.append("")
    if not report.findings:
        lines.append("No findings. All cookies pass the hardening checks.")
        return "\n".join(lines)

    counts = report.counts()
    summary = "  ".join(
        f"{s}={counts[s]}" for s in reversed(SEVERITY_ORDER) if counts[s]
    )
    lines.append(f"Findings ({len(report.findings)}): {summary}")
    lines.append("")
    for f in report.findings:
        loc = f" [line {f.line_no}]" if f.line_no else ""
        lines.append(f"[{f.severity.upper():<6}] {f.cookie} :: {f.code}{loc}")
        lines.append(f"         {f.message}")
        lines.append(f"         -> {f.recommendation}")
    return "\n".join(lines)


def render_json(report: AuditReport) -> str:
    import json

    payload = {
        "tool": "cookieaudit",
        "summary": {
            "cookies": len(report.cookies),
            "findings": len(report.findings),
            "worst_severity": report.worst_severity,
            "failed": report.failed,
            "counts": report.counts(),
        },
        "cookies": [
            {
                "name": c.name,
                "secure": c.secure,
                "http_only": c.http_only,
                "same_site": c.same_site,
                "domain": c.domain,
                "path": c.path,
                "max_age": c.max_age,
                "expires": c.expires,
                "is_sensitive": c.is_sensitive,
                "is_session": c.is_session,
                "line_no": c.line_no,
            }
            for c in report.cookies
        ],
        "findings": [
            {
                "cookie": f.cookie,
                "severity": f.severity,
                "code": f.code,
                "message": f.message,
                "recommendation": f.recommendation,
                "line_no": f.line_no,
            }
            for f in report.findings
        ],
    }
    return json.dumps(payload, indent=2)


def render_html(report: AuditReport) -> str:
    e = _html.escape
    counts = report.counts()
    worst = report.worst_severity or "none"
    badge_color = _SEV_HEX.get(report.worst_severity, "#2ecc71")

    rows = []
    for f in report.findings:
        color = _SEV_HEX.get(f.severity, "#7f8c8d")
        rows.append(
            "<tr>"
            f"<td><span class='sev' style='background:{color}'>{e(f.severity.upper())}</span></td>"
            f"<td class='mono'>{e(f.cookie)}</td>"
            f"<td class='mono'>{e(f.code)}</td>"
            f"<td>{e(f.message)}<div class='rec'>&rarr; {e(f.recommendation)}</div></td>"
            f"<td class='mono'>{f.line_no or ''}</td>"
            "</tr>"
        )
    findings_html = "\n".join(rows) if rows else (
        "<tr><td colspan='5' class='ok'>No findings &mdash; all cookies pass the hardening checks.</td></tr>"
    )

    cookie_rows = []
    for c in report.cookies:
        def yn(v):
            return "<span class='yes'>yes</span>" if v else "<span class='no'>no</span>"
        cookie_rows.append(
            "<tr>"
            f"<td class='mono'>{e(c.name)}</td>"
            f"<td>{yn(c.secure)}</td>"
            f"<td>{yn(c.http_only)}</td>"
            f"<td class='mono'>{e(c.same_site or '-')}</td>"
            f"<td class='mono'>{e(c.domain or '-')}</td>"
            f"<td class='mono'>{e(c.path or '-')}</td>"
            "</tr>"
        )
    cookie_html = "\n".join(cookie_rows) if cookie_rows else (
        "<tr><td colspan='6'>No cookies parsed.</td></tr>"
    )

    chips = " ".join(
        f"<span class='chip' style='border-color:{_SEV_HEX[s]}'>"
        f"<b style='color:{_SEV_HEX[s]}'>{counts[s]}</b> {s}</span>"
        for s in reversed(SEVERITY_ORDER)
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>COOKIEAUDIT report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin: 0; padding: 2rem; background:#f5f6f8; color:#1c1e21; }}
  h1 {{ margin:0 0 .25rem; font-size:1.5rem; }}
  .sub {{ color:#65676b; margin-bottom:1.25rem; font-size:.9rem; }}
  .card {{ background:#fff; border:1px solid #e0e0e0; border-radius:10px;
          padding:1.25rem; margin-bottom:1.25rem; box-shadow:0 1px 2px rgba(0,0,0,.05); }}
  .verdict {{ display:inline-block; padding:.4rem .9rem; border-radius:6px;
             color:#fff; font-weight:700; background:{badge_color}; }}
  .chip {{ display:inline-block; border:2px solid #ccc; border-radius:20px;
          padding:.15rem .7rem; margin:.2rem .3rem .2rem 0; font-size:.85rem; }}
  table {{ width:100%; border-collapse:collapse; font-size:.9rem; }}
  th,td {{ text-align:left; padding:.55rem .6rem; border-bottom:1px solid #eee; vertical-align:top; }}
  th {{ color:#65676b; font-weight:600; font-size:.78rem; text-transform:uppercase; letter-spacing:.03em; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:.85em; }}
  .sev {{ color:#fff; padding:.1rem .5rem; border-radius:4px; font-size:.72rem; font-weight:700; }}
  .rec {{ color:#65676b; font-size:.82rem; margin-top:.2rem; }}
  .yes {{ color:#1e7e34; font-weight:600; }}
  .no {{ color:#c0392b; font-weight:600; }}
  .ok {{ color:#1e7e34; text-align:center; padding:1rem; }}
</style></head>
<body>
  <h1>COOKIEAUDIT</h1>
  <div class="sub">Set-Cookie hardening report &mdash; defensive analysis of a response dump.</div>
  <div class="card">
    <div class="verdict">{'FINDINGS: ' + worst.upper() if report.findings else 'CLEAN'}</div>
    <div style="margin-top:.9rem">{chips}</div>
    <div class="sub" style="margin-top:.6rem;margin-bottom:0">
      {len(report.cookies)} cookie(s) parsed &middot; {len(report.findings)} finding(s)
    </div>
  </div>
  <div class="card">
    <h3 style="margin-top:0">Cookies</h3>
    <table>
      <thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Domain</th><th>Path</th></tr></thead>
      <tbody>
{cookie_html}
      </tbody>
    </table>
  </div>
  <div class="card">
    <h3 style="margin-top:0">Findings</h3>
    <table>
      <thead><tr><th>Severity</th><th>Cookie</th><th>Code</th><th>Detail</th><th>Line</th></tr></thead>
      <tbody>
{findings_html}
      </tbody>
    </table>
  </div>
</body></html>"""
