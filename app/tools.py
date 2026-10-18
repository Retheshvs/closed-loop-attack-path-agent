"""Tools Module for Closed-Loop Attack-Path Agent.

Implements the 7 core tools with Anthropic-compatible JSON schemas.
All tools return a consistent format:
    { "result": ..., "evidence": [...], "summary": "..." }
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from app.fixes import apply_fix as execute_fix
from app.graph import AttackPathGraph
from app.scanner import scan_lab as execute_scan

# Shared graph instance for tools (lazy initialized to real FalkorDB)
_shared_graph: Optional[AttackPathGraph] = None


def get_graph() -> AttackPathGraph:
    """Returns the shared graph instance, initializing connection to real FalkorDB on first call."""
    global _shared_graph
    if _shared_graph is None:
        _shared_graph = AttackPathGraph()
    return _shared_graph


def set_graph(graph: Any) -> None:
    """Sets the shared graph instance (used for test isolation)."""
    global _shared_graph
    _shared_graph = graph


# ============================================================================
# Tool Implementations
# ============================================================================


def scan_lab() -> Dict[str, Any]:
    """Scans the Docker lab, maps network memberships, and populates the FalkorDB graph."""
    graph = get_graph()
    scan_summary = execute_scan(graph)
    attack_paths = graph.attack_paths("lab")
    source_str = scan_summary.get("lab_source", "lab source: config files, no containers")

    return {
        "result": scan_summary,
        "evidence": attack_paths,
        "summary": (
            f"Scanned {scan_summary['services_scanned']} services ({source_str}), discovering "
            f"{scan_summary['reachability_edges']} network edges and {len(attack_paths)} active attack paths."
        ),
    }


def find_attack_paths() -> Dict[str, Any]:
    """Finds all multi-hop attack paths through EXPLOITABLE_FROM edges to crown jewels."""
    graph = get_graph()
    paths = graph.attack_paths("lab")

    return {
        "result": {
            "path_count": len(paths),
            "paths": paths,
        },
        "evidence": paths,
        "summary": f"Identified {len(paths)} distinct attack paths leading to crown jewels.",
    }


def find_choke_points() -> Dict[str, Any]:
    """Ranks lab services by path frequency and graph centrality (PageRank / Betweenness)."""
    graph = get_graph()
    choke_data = graph.choke_points("lab")
    top = choke_data.get("top_choke_point")
    ranking = choke_data.get("ranking", [])

    top_share = ranking[0]["path_share"] * 100 if ranking else 0

    return {
        "result": choke_data,
        "evidence": [[item["service"], str(item["path_count"])] for item in ranking],
        "summary": (
            f"Service '{top}' is the primary choke point, intersecting {top_share:.0f}% of attack paths."
            if top
            else "No choke points identified."
        ),
    }


def simulate_fix(service: str, fix: str) -> Dict[str, Any]:
    """Safely simulates a remediation action in a copied FalkorDB graph ('lab_sim')."""
    graph = get_graph()
    sim_result = graph.simulate_fix(service, fix)

    return {
        "result": sim_result,
        "evidence": sim_result.get("eliminated_paths", []),
        "summary": (
            f"Simulating '{fix}' on '{service}' reduces attack paths from {sim_result['paths_before']} "
            f"to {sim_result['paths_remaining']} (eliminates {sim_result['reduction']} paths)."
        ),
    }


def apply_fix(service: str, fix: str) -> Dict[str, Any]:
    """Applies a whitelisted remediation action (patch_service, rotate_credential, disconnect_network)."""
    fix_result = execute_fix(service, fix)

    return {
        "result": fix_result,
        "evidence": [[service, fix]],
        "summary": f"Successfully applied '{fix}' to service '{service}': {fix_result['details']}",
    }


def rescan_and_verify() -> Dict[str, Any]:
    """Re-scans the live lab, updates FalkorDB, and verifies if attack paths have been eliminated."""
    graph = get_graph()
    paths_before = graph.attack_paths("lab")

    # Perform live scan
    execute_scan(graph)

    paths_after = graph.attack_paths("lab")
    removed = [p for p in paths_before if p not in paths_after]

    verified = len(paths_after) == 0

    return {
        "result": {
            "paths_before": paths_before,
            "paths_after": paths_after,
            "removed_paths": removed,
            "count_before": len(paths_before),
            "count_after": len(paths_after),
            "verified_clean": verified,
        },
        "evidence": paths_after,
        "summary": (
            f"Verification complete: Attack paths dropped from {len(paths_before)} to {len(paths_after)}. "
            f"{'All attack paths eliminated.' if verified else 'Some attack paths remain.'}"
        ),
    }


def explain_path(path_id: int = 0) -> Dict[str, Any]:
    """Provides a hop-by-hop breakdown of why a specific attack path succeeds."""
    graph = get_graph()
    paths = graph.attack_paths("lab")

    if not paths:
        return {
            "result": {"error": "No attack paths found in current graph."},
            "evidence": [],
            "summary": "Graph is completely secured; zero attack paths exist.",
        }

    idx = max(0, min(path_id, len(paths) - 1))
    target_path = paths[idx]
    explanation = graph.explain_path(target_path)

    return {
        "result": explanation,
        "evidence": [target_path],
        "summary": explanation.get("summary", "Hop-by-hop path breakdown generated."),
    }


# ============================================================================
# Tool Registry & JSON Schemas for Anthropic / MCP
# ============================================================================

TOOL_DEFINITIONS = [
    {
        "name": "scan_lab",
        "description": "Scans the lab Docker containers, maps network memberships, and populates the FalkorDB graph.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "find_attack_paths",
        "description": "Discovers all paths from Attacker through EXPLOITABLE_FROM edges to crown jewel services.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "find_choke_points",
        "description": "Ranks services by attack path intersection count and graph centrality (PageRank/Betweenness).",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "simulate_fix",
        "description": "Simulates a fix on a copied graph ('lab_sim') in FalkorDB without modifying the real graph.",
        "input_schema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Target service name (e.g. 'web', 'api', 'admin', 'db', 'fileshare').",
                },
                "fix": {
                    "type": "string",
                    "enum": ["patch_service", "rotate_credential", "disconnect_network"],
                    "description": "The remediation action to simulate.",
                },
            },
            "required": ["service", "fix"],
        },
    },
    {
        "name": "apply_fix",
        "description": "Applies a whitelisted remediation action to a container in the lab.",
        "input_schema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Target service name (e.g. 'web', 'api', 'admin', 'db', 'fileshare').",
                },
                "fix": {
                    "type": "string",
                    "enum": ["patch_service", "rotate_credential", "disconnect_network"],
                    "description": "The remediation action to apply.",
                },
            },
            "required": ["service", "fix"],
        },
    },
    {
        "name": "rescan_and_verify",
        "description": "Re-scans the lab, updates the graph, and verifies whether attack paths have been eliminated.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "explain_path",
        "description": "Returns a detailed hop-by-hop breakdown of reasons (CVEs, creds) for an attack path.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path_id": {
                    "type": "integer",
                    "description": "0-based index of the attack path to inspect.",
                    "default": 0,
                },
            },
            "required": [],
        },
    },
]

TOOL_FUNCTION_MAP = {
    "scan_lab": scan_lab,
    "find_attack_paths": find_attack_paths,
    "find_choke_points": find_choke_points,
    "simulate_fix": simulate_fix,
    "apply_fix": apply_fix,
    "rescan_and_verify": rescan_and_verify,
    "explain_path": explain_path,
}
