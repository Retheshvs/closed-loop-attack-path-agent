"""Model Context Protocol (MCP) Server for Closed-Loop Attack-Path Agent.

Exposes the 7 graph analysis, simulation, and remediation tools via FastMCP / MCPServer
so external MCP clients (Claude Desktop, Claude Code, Cursor) can autonomously inspect
and remediate the lab graph.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict

# Compatible with both MCP 1.x (FastMCP) and MCP 2.x (MCPServer)
try:
    from mcp.server.mcpserver import MCPServer as FastMCP
except (ImportError, ModuleNotFoundError):
    from mcp.server.fastmcp import FastMCP

from app.tools import (
    apply_fix as tool_apply_fix,
    explain_path as tool_explain_path,
    find_attack_paths as tool_find_attack_paths,
    find_choke_points as tool_find_choke_points,
    rescan_and_verify as tool_rescan_and_verify,
    scan_lab as tool_scan_lab,
    simulate_fix as tool_simulate_fix,
)

mcp = FastMCP("ClosedLoopAttackPathAgent")


@mcp.tool()
def scan_lab() -> str:
    """Scans the Docker lab, maps network memberships, and populates the FalkorDB graph."""
    res = tool_scan_lab()
    return json.dumps(res, indent=2)


@mcp.tool()
def find_attack_paths() -> str:
    """Finds all multi-hop attack paths through EXPLOITABLE_FROM edges to crown jewel databases."""
    res = tool_find_attack_paths()
    return json.dumps(res, indent=2)


@mcp.tool()
def find_choke_points() -> str:
    """Ranks services by path intersection frequency and FalkorDB centrality (PageRank / Betweenness)."""
    res = tool_find_choke_points()
    return json.dumps(res, indent=2)


@mcp.tool()
def simulate_fix(service: str, fix: str) -> str:
    """Safely simulates a remediation action in a copied graph ('lab_sim') without altering 'lab'.

    Args:
        service: Target service name ('web', 'api', 'admin', 'db', 'fileshare')
        fix: Remediation action ('patch_service', 'rotate_credential', 'disconnect_network')
    """
    res = tool_simulate_fix(service=service, fix=fix)
    return json.dumps(res, indent=2)


@mcp.tool()
def apply_fix(service: str, fix: str) -> str:
    """Applies a whitelisted remediation action to the live lab container/configuration.

    Args:
        service: Target service name ('web', 'api', 'admin', 'db', 'fileshare')
        fix: Whitelisted action ('patch_service', 'rotate_credential', 'disconnect_network')
    """
    res = tool_apply_fix(service=service, fix=fix)
    return json.dumps(res, indent=2)


@mcp.tool()
def rescan_and_verify() -> str:
    """Re-scans the live lab and verifies if all attack paths have been successfully eliminated."""
    res = tool_rescan_and_verify()
    return json.dumps(res, indent=2)


@mcp.tool()
def explain_path(path_id: int = 0) -> str:
    """Provides a hop-by-hop breakdown of vulnerability and network reasons for a chosen path.

    Args:
        path_id: 0-based index of the attack path to inspect (default 0)
    """
    res = tool_explain_path(path_id=path_id)
    return json.dumps(res, indent=2)


if __name__ == "__main__":
    # Run the MCP server over stdio
    mcp.run()
