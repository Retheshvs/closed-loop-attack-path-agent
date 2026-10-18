"""Acceptance Tests for Closed-Loop Attack-Path Agent.

Validates all 6 mandatory hackathon acceptance criteria:
1. Fresh reset + scan = 3 attack paths, top choke point = 'api'.
2. simulate_fix never changes the real graph.
3. Fixes outside the whitelist or on unknown services are strictly rejected.
4. Full agent run ends with paths_after = 0 and a report with path evidence.
5. /reset returns the lab to 3 paths for complete demo repeatability.
"""

import asyncio
import pytest

from app.agent import AgentRunner
from app.fixes import apply_fix, reset_lab
from app.graph import AttackPathGraph
from app.scanner import scan_lab
from app.tools import get_graph


@pytest.fixture(autouse=True)
def ensure_baseline():
    """Ensures lab and graph are reset to baseline state before each test."""
    reset_lab()
    graph = get_graph()
    scan_lab(graph)
    yield
    reset_lab()
    scan_lab(graph)


def test_baseline_paths_and_choke_point():
    """Criteria 1: Fresh reset + scan = 3 attack paths, top choke point = 'api'."""
    reset_lab()
    graph = get_graph()
    scan_lab(graph)

    paths = graph.attack_paths("lab")
    assert len(paths) == 3, f"Expected exactly 3 attack paths, found {len(paths)}: {paths}"

    # Verify that all 3 paths reach crown jewels (db or fileshare)
    assert any("db" in p for p in paths), "Expected path targeting db"
    assert any("fileshare" in p for p in paths), "Expected path targeting fileshare"

    # Verify choke points
    choke_data = graph.choke_points("lab")
    top_choke = choke_data.get("top_choke_point")
    assert top_choke == "api", f"Expected top choke point to be 'api', got '{top_choke}'"

    # Verify api appears in all 3 paths
    api_entry = next((item for item in choke_data["ranking"] if item["service"] == "api"), None)
    assert api_entry is not None, "api must be in ranking"
    assert api_entry["path_count"] == 3, f"api should be on 3 paths, got {api_entry['path_count']}"


def test_simulate_fix_preserves_real_graph():
    """Criteria 2: simulate_fix never changes the real graph."""
    graph = get_graph()
    paths_before = graph.attack_paths("lab")
    assert len(paths_before) == 3

    # Run simulation on 'api' with 'patch_service'
    sim_res = graph.simulate_fix(service="api", fix="patch_service")

    # Simulation should report reduction to 0 paths
    assert sim_res["paths_before"] == 3
    assert sim_res["paths_remaining"] == 0
    assert sim_res["reduction"] == 3
    assert sim_res["simulated_clean"] is True

    # CRITICAL: Verify the real 'lab' graph was completely untouched
    paths_after_sim = graph.attack_paths("lab")
    assert len(paths_after_sim) == 3, "Real graph 'lab' was mutated by simulate_fix!"
    assert paths_after_sim == paths_before, "Attack paths in real graph changed!"


def test_whitelist_security_validation():
    """Criteria 3: Fixes outside whitelist or unknown services are strictly rejected."""
    # Invalid action
    with pytest.raises(ValueError, match="not a whitelisted remediation"):
        apply_fix(service="api", fix="shell_exec")

    with pytest.raises(ValueError, match="not a whitelisted remediation"):
        apply_fix(service="web", fix="delete_container")

    # Invalid service
    with pytest.raises(ValueError, match="not in the approved lab inventory"):
        apply_fix(service="rogue_server", fix="patch_service")

    with pytest.raises(ValueError, match="not in the approved lab inventory"):
        apply_fix(service="external_attacker", fix="rotate_credential")


def test_full_agent_run_eliminates_paths():
    """Criteria 4: Full agent run ends with paths_after = 0 and an evidence report."""
    runner = AgentRunner(run_id="test_run_1")
    asyncio.run(runner.run())

    # Collect events
    events = []
    while not runner.event_queue.empty():
        evt = runner.event_queue.get_nowait()
        events.append(evt)

    # Check for final report event
    report_event = next((e for e in events if e.get("type") == "final_report"), None)
    assert report_event is not None, "Agent must emit a final_report event"

    report_text = report_event["data"]["report"]
    assert "0 Attack Paths Remaining" in report_text or "paths dropped from 3 to 0" in report_text or "VERIFIED CLEAN" in report_text

    # Verify that graph now has 0 attack paths
    graph = get_graph()
    paths_final = graph.attack_paths("lab")
    assert len(paths_final) == 0, f"Expected 0 attack paths after full agent run, found {len(paths_final)}"


def test_lab_reset_repeatability():
    """Criteria 5: /reset returns the lab to 3 paths, ensuring repeatable demos."""
    # First apply fix to eliminate paths
    apply_fix("api", "patch_service")
    graph = get_graph()
    scan_lab(graph)
    assert len(graph.attack_paths("lab")) == 0, "Paths should be 0 after patching api"

    # Now reset the lab
    reset_res = reset_lab()
    assert reset_res["success"] is True

    # Re-scan
    scan_lab(graph)
    restored_paths = graph.attack_paths("lab")
    assert len(restored_paths) == 3, f"Expected 3 paths restored after reset, got {len(restored_paths)}"

    choke_data = graph.choke_points("lab")
    assert choke_data["top_choke_point"] == "api"
