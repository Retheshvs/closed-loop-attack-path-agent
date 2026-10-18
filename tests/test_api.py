"""API tests for FastAPI endpoints."""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_baseline():
    """Ensures lab baseline is loaded before each API test."""
    client.post("/reset")
    yield
    client.post("/reset")


def test_health_endpoint():
    """Tests GET /health."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "falkordb_connected" in data


def test_graph_endpoint():
    """Tests GET /graph."""
    response = client.get("/graph")
    assert response.status_code == 200
    data = response.json()
    assert "elements" in data
    assert "attack_paths" in data
    assert data["attack_paths_count"] == 3
    assert data["top_choke_point"] == "api"


def test_reset_endpoint():
    """Tests POST /reset."""
    response = client.post("/reset")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["attack_paths_count"] == 3


def test_run_endpoint():
    """Tests POST /run."""
    response = client.post("/run")
    assert response.status_code == 200
    data = response.json()
    assert "run_id" in data
    assert data["status"] == "started"
