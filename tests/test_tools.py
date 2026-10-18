"""Unit tests for the 7 tools in tools.py."""

import pytest
from app.fixes import reset_lab
from app.scanner import scan_lab
from app.tools import (
    apply_fix,
    explain_path,
    find_attack_paths,
    find_choke_points,
    get_graph,
    rescan_and_verify,
    scan_lab as tool_scan_lab,
    simulate_fix,
)


@pytest.fixture(autouse=True)
def setup_teardown():
    reset_lab()
    graph = get_graph()
    scan_lab(graph)
    yield
    reset_lab()
    scan_lab(graph)


def test_all_tools_standard_output_format():
    """Verifies that all 7 tools return {result, evidence, summary}."""
    tools_to_test = [
        (tool_scan_lab, {}),
        (find_attack_paths, {}),
        (find_choke_points, {}),
        (simulate_fix, {"service": "api", "fix": "patch_service"}),
        (explain_path, {"path_id": 0}),
    ]

    for tool_fn, kwargs in tools_to_test:
        out = tool_fn(**kwargs)
        assert isinstance(out, dict), f"{tool_fn.__name__} should return a dict"
        assert "result" in out, f"{tool_fn.__name__} missing 'result'"
        assert "evidence" in out, f"{tool_fn.__name__} missing 'evidence'"
        assert "summary" in out, f"{tool_fn.__name__} missing 'summary'"
        assert isinstance(out["summary"], str), f"{tool_fn.__name__} summary should be a string"
        assert len(out["summary"]) > 0, f"{tool_fn.__name__} summary should not be empty"


def test_explain_path_details():
    """Verifies explain_path returns structured hop-by-hop breakdown."""
    out = explain_path(path_id=0)
    assert out["result"] is not None
    hops = out["result"].get("hops", [])
    assert len(hops) >= 2, "Path should contain at least 2 hops"

    first_hop = hops[0]
    assert first_hop["from_node"] == "Attacker"
    assert "exploitable_reasons" in first_hop
    assert len(first_hop["exploitable_reasons"]) > 0


def test_apply_and_verify_cycle():
    """Verifies apply_fix and rescan_and_verify end-to-end."""
    # Apply fix
    apply_out = apply_fix(service="api", fix="patch_service")
    assert apply_out["result"]["success"] is True

    # Rescan and verify
    verify_out = rescan_and_verify()
    res = verify_out["result"]
    assert res["count_before"] == 3
    assert res["count_after"] == 0
    assert res["verified_clean"] is True
    assert len(res["removed_paths"]) == 3
