"""Pytest configuration and test isolation fixtures."""

import os
import pytest
from app.tools import set_graph
from tests.fake_falkordb import FakeAttackPathGraph


@pytest.fixture(autouse=True)
def configure_test_graph(request):
    """If real FalkorDB is not connected or running unit tests, inject FakeAttackPathGraph.

    The integration test file 'test_real_falkordb.py' handles its own real connection.
    """
    if "test_real_falkordb" in request.node.nodeid:
        yield
        return

    # Check if a real FalkorDB is reachable
    host = os.environ.get("FALKORDB_HOST")
    use_fake = True
    if host:
        try:
            from app.graph import AttackPathGraph
            real_g = AttackPathGraph()
            set_graph(real_g)
            use_fake = False
        except Exception:
            use_fake = True

    if use_fake:
        fake_g = FakeAttackPathGraph()
        set_graph(fake_g)

    yield
