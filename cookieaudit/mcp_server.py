"""COOKIEAUDIT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from cookieaudit.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-cookieaudit[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-cookieaudit[mcp]'")
        return 1
    app = FastMCP("cookieaudit")

    @app.tool()
    def cookieaudit_scan(target: str) -> str:
        """Audit Set-Cookie flags (Secure/HttpOnly/SameSite) from a response dump. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
