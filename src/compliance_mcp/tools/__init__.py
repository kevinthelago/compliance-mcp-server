"""MCP tool implementations — loaded into the server at startup.

``load_tools(mcp)`` is the single integration seam: it imports every tool module
so the real implementations replace the ``NotImplementedError`` stubs the server
registers in :mod:`compliance_mcp.server`.  ``policy`` and ``framework`` register
via ``@mcp.tool()`` at import time; ``scan`` and ``gate`` expose explicit
``register(mcp)`` hooks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastmcp import FastMCP


def load_tools(mcp: FastMCP) -> None:
    """Wire every real tool implementation onto *mcp*, overriding the stubs."""
    # Import side effect: @mcp.tool() decorators register query_policy /
    # list_policies / control_coverage / explain_control over the stubs.
    from compliance_mcp.tools import framework, gate, policy, scan  # noqa: F401

    scan.register(mcp)
    gate.register(mcp)
