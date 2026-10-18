"""Integration tests against a real FalkorDB server.

Skipped only if FALKORDB_HOST is not set or server is unreachable.
Validates:
1. Baseline: exactly 3 attack paths to crown jewels.
2. Choke point: 'api' is top choke point.
3. Safe simulation: simulate_fix proves reduction to 0 while leaving real graph untouched.
4. Live remediation: patching 'api' gives 0 paths upon re-scan.
"""

import os
import pytest
from dotenv import load_dotenv

load_dotenv()

from app.fixes import apply_fix, reset_lab
from app.graph import AttackPathGraph
from app.scanner import scan_lab


def get_real_graph():
    host = os.environ.get("FALKORDB_HOST")
    if not host:
        pytest.skip("FALKORDB_HOST not set. Skipping real FalkorDB integration tests.")

    port = int(os.environ.get("FALKORDB_PORT", 6379))
    username = os.environ.get("FALKORDB_USERNAME") or None
    password = os.environ.get("FALKORDB_PASSWORD") or None
    ssl_env = os.environ.get("FALKORDB_SSL", "false").strip().lower()
    ssl = ssl_env in ("true", "1", "yes")

    try:
        graph = AttackPathGraph(host=host, port=port, username=username, password=password, ssl=ssl)
        return graph
    except Exception as e:
        pytest.skip(f"Could not connect to real FalkorDB server at {host}:{port}: {e}")


def test_real_falkordb_end_to_end():
    graph = get_real_graph()

    # Step 1: Reset lab and scan into real FalkorDB
    reset_lab()
    scan_lab(graph)

    # Step 2: Verify exactly 3 attack paths
    paths = graph.attack_paths("lab")
    assert len(paths) == 3, f"Expected 3 attack paths, found {len(paths)}: {paths}"

    # Step 3: Verify top choke point is 'api'
    choke_data = graph.choke_points("lab")
    assert choke_data.get("top_choke_point") == "api", f"Expected top choke point 'api', got {choke_data.get('top_choke_point')}"

    # Step 4: Verify simulate_fix leaves real graph untouched
    paths_before = graph.attack_paths("lab")
    sim_res = graph.simulate_fix(service="api", fix="patch_service")
    assert sim_res["paths_before"] == 3
    assert sim_res["paths_remaining"] == 0
    assert sim_res["reduction"] == 3
    assert sim_res["simulated_clean"] is True

    # Real graph MUST remain completely unchanged
    paths_after_sim = graph.attack_paths("lab")
    assert len(paths_after_sim) == 3
    assert paths_after_sim == paths_before

    # Step 5: Apply live fix to 'api' and verify re-scan produces 0 attack paths
    apply_fix(service="api", fix="patch_service")
    scan_lab(graph)
    paths_after_fix = graph.attack_paths("lab")
    assert len(paths_after_fix) == 0, f"Expected 0 attack paths after fix, got {len(paths_after_fix)}: {paths_after_fix}"

    # Cleanup: restore baseline
    reset_lab()
    scan_lab(graph)
    assert len(graph.attack_paths("lab")) == 3
