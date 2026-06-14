"""COOKIEAUDIT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

from cookieaudit.core import audit_dump, render_json


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-cookieaudit[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "Install the MCP extra: pip install 'cognis-cookieaudit[mcp]'",
            flush=True,
        )
        return 1
    app = FastMCP("cookieaudit")

    @app.tool()
    def cookieaudit_scan(target: str) -> str:
        """Audit Set-Cookie flags (Secure/HttpOnly/SameSite) from a response dump.

        Returns JSON findings.
        """
        if not isinstance(target, str):
            return '{"error": "target must be a string"}'
        return render_json(audit_dump(target))

    app.run()
    return 0
