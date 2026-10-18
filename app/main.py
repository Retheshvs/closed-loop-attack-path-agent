"""FastAPI Application for Closed-Loop Attack-Path Agent.

Provides HTTP and Server-Sent Events (SSE) endpoints for controlling the agent,
inspecting the FalkorDB attack graph, resetting lab posture, and serving the UI.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Any, Dict

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

from app.agent import AgentRunner, stream_agent_events
from app.fixes import reset_lab as execute_reset_lab
from app.graph import AttackPathGraph
from app.scanner import scan_lab as execute_scan
from app.tools import get_graph

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes graph baseline upon app startup. Fails loudly if FalkorDB is unreachable."""
    graph = get_graph()
    execute_scan(graph)
    logger.info(
        "FalkorDB connected (version %s). Initial lab scan completed. Attack paths: %d",
        graph.server_version,
        len(graph.attack_paths("lab")),
    )
    yield


app = FastAPI(
    title="Closed-Loop Attack-Path Agent",
    description="Autonomous defensive agent using FalkorDB to discover, simulate, and eliminate Docker attack paths.",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for browser access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR, exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# In-memory store for active agent runs
active_runners: Dict[str, AgentRunner] = {}


@app.get("/")
async def root():
    """Serves the single-page Cytoscape UI."""
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Closed-Loop Attack-Path Agent API. Static UI not yet created."}


@app.get("/health")
async def health():
    """Returns system and database health status with engine and real server version."""
    graph = get_graph()
    return {
        "status": "ok",
        "engine": "falkordb-server",
        "falkordb_connected": graph.is_connected,
        "falkordb_version": graph.server_version,
        "falkordb_host": graph.host,
        "falkordb_port": graph.port,
        "falkordb_username": graph.username,
        "falkordb_ssl": graph.ssl,
        "attack_paths_count": len(graph.attack_paths("lab")),
    }


@app.get("/graph")
async def get_graph_data():
    """Returns current FalkorDB graph state formatted for Cytoscape.js."""
    graph = get_graph()
    paths = graph.attack_paths("lab")
    choke_data = graph.choke_points("lab")
    elements = graph.to_cytoscape_elements()

    return {
        "elements": elements,
        "attack_paths": paths,
        "attack_paths_count": len(paths),
        "choke_points": choke_data,
        "top_choke_point": choke_data.get("top_choke_point"),
    }


@app.post("/run")
async def start_run(background_tasks: BackgroundTasks):
    """Starts an autonomous agent remediation run."""
    run_id = str(uuid.uuid4())[:8]
    runner = AgentRunner(run_id=run_id)
    active_runners[run_id] = runner

    # Launch agent loop asynchronously
    background_tasks.add_task(runner.run)

    return {
        "run_id": run_id,
        "status": "started",
        "events_url": f"/events/{run_id}",
    }


@app.get("/events/{run_id}")
async def get_events(run_id: str):
    """Streams agent execution steps and graph updates over Server-Sent Events (SSE)."""
    runner = active_runners.get(run_id)
    if not runner:
        raise HTTPException(status_code=404, detail=f"Run ID '{run_id}' not found.")

    return EventSourceResponse(stream_agent_events(runner))


@app.post("/reset")
async def reset_lab():
    """Restores the lab and FalkorDB graph to its vulnerable starting state."""
    reset_res = execute_reset_lab()
    graph = get_graph()
    scan_res = execute_scan(graph)
    paths = graph.attack_paths("lab")

    return {
        "success": True,
        "message": "Lab successfully reset to baseline vulnerable state.",
        "attack_paths_count": len(paths),
        "attack_paths": paths,
        "reset_details": reset_res,
        "scan_details": scan_res,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
