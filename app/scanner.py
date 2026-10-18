"""Lab Scanner Module for Closed-Loop Attack-Path Agent.

Discovers Docker lab topology, queries service /info endpoints, builds reachability
maps based on network segmentation, and populates FalkorDB.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
import requests

from app.graph import AttackPathGraph

logger = logging.getLogger("scanner")
logger.setLevel(logging.INFO)

LAB_SERVICES = ["web", "api", "admin", "db", "fileshare"]
CONFIG_DIR = os.environ.get(
    "LAB_CONFIG_DIR",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "lab", "config"),
)

# Standard network mapping for the lab
SERVICE_NETWORKS = {
    "web": ["internet_net", "dmz_net"],
    "api": ["dmz_net", "internal_net"],
    "admin": ["internal_net"],
    "db": ["internal_net"],
    "fileshare": ["internal_net"],
}

# Container port mappings to localhost when querying from host
HOST_PORT_MAP = {
    "web": 8080,
    "api": 8081,
    "admin": 8082,
    "db": 8083,
    "fileshare": 8084,
}


def load_service_config(service_name: str) -> Dict[str, Any]:
    """Loads a service config JSON file from disk."""
    config_path = os.path.join(CONFIG_DIR, f"{service_name}.json")
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "name": service_name,
        "zone": "internal",
        "version": "1.0.0",
        "vulns": [],
        "creds_weak": False,
        "ports": [5000],
        "holds": None,
    }


def query_service_info(service_name: str) -> Dict[str, Any]:
    """Queries /info endpoint from live container or falls back to mounted config."""
    if os.environ.get("PROBE_HTTP", "0") == "1":
        port = HOST_PORT_MAP.get(service_name)
        if port:
            try:
                resp = requests.get(f"http://127.0.0.1:{port}/info", timeout=0.1)
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                pass

    # Read from mounted/local config JSON
    return load_service_config(service_name)


def get_docker_network_topology() -> Tuple[Dict[str, List[str]], str]:
    """Gets container network memberships via Docker SDK or fallback topology."""
    try:
        import docker

        client = docker.from_env()
        containers = client.containers.list()
        topology: Dict[str, List[str]] = {}

        for c in containers:
            c_name = c.name.replace("lab_", "")
            if c_name in LAB_SERVICES:
                networks = list(c.attrs.get("NetworkSettings", {}).get("Networks", {}).keys())
                normalized = []
                for n in networks:
                    for standard_net in ["internet_net", "dmz_net", "internal_net"]:
                        if standard_net in n:
                            normalized.append(standard_net)
                            break
                    else:
                        normalized.append(n)
                topology[c_name] = normalized

        if len(topology) >= len(LAB_SERVICES):
            return topology, "docker containers"
    except Exception as e:
        logger.debug("Docker SDK topology lookup notice: %s. Using defined topology.", e)

    return dict(SERVICE_NETWORKS), "lab source: config files, no containers"


def build_reachability_map(
    services: List[Dict[str, Any]], topology: Dict[str, List[str]]
) -> List[Tuple[str, str, str]]:
    """Builds reachability map: A can reach B if they share a network and B exposes a port.

    Applies role constraints:
    - Crown jewel storage endpoints (db, fileshare) do not initiate outbound connections.
    - Admin panel only manages the database.
    - Web proxy communicates with API gateway.
    - API gateway dispatches to backend services (admin, db, fileshare).
    """
    reachability: List[Tuple[str, str, str]] = []

    # Client-side initiating services
    allowed_clients = {
        "web": {"api"},
        "api": {"admin", "db", "fileshare"},
        "admin": {"db"},
    }

    for svc_a in services:
        name_a = svc_a["name"]
        nets_a = set(topology.get(name_a, []))
        allowed_targets = allowed_clients.get(name_a, set())

        for svc_b in services:
            name_b = svc_b["name"]
            if name_a == name_b or name_b not in allowed_targets:
                continue

            nets_b = set(topology.get(name_b, []))
            common_nets = nets_a.intersection(nets_b)

            # B must expose at least one port
            ports_b = svc_b.get("ports", [])
            if common_nets and len(ports_b) > 0:
                for net in sorted(common_nets):
                    reachability.append((name_a, name_b, net))

    return reachability


def scan_lab(graph: Optional[AttackPathGraph] = None) -> Dict[str, Any]:
    """Scans the Docker lab, rebuilds FalkorDB graph, and returns scan summary.

    1. Gathers service configurations & network memberships.
    2. Builds reachability map.
    3. Rebuilds FalkorDB graph 'lab'.
    4. Returns summary of services, edges, and vulnerabilities found.
    """
    if graph is None:
        graph = AttackPathGraph()

    topology, lab_source = get_docker_network_topology()

    services: List[Dict[str, Any]] = []
    total_vulns = 0
    crown_jewels = []

    for s_name in LAB_SERVICES:
        cfg = query_service_info(s_name)
        services.append(cfg)
        vulns = cfg.get("vulns", [])
        total_vulns += len(vulns)
        if cfg.get("holds"):
            crown_jewels.append({"service": s_name, "crown_jewel": cfg.get("holds")})

    reachability = build_reachability_map(services, topology)

    # Rebuild FalkorDB graph
    graph.wipe_and_rebuild(services, reachability)

    attack_paths = graph.attack_paths("lab")

    return {
        "lab_source": lab_source,
        "services_scanned": len(services),
        "reachability_edges": len(reachability),
        "vulnerabilities_found": total_vulns,
        "crown_jewels": crown_jewels,
        "attack_paths_detected": len(attack_paths),
        "services": [
            {
                "name": s["name"],
                "zone": s.get("zone"),
                "version": s.get("version"),
                "vulns_count": len(s.get("vulns", [])),
                "creds_weak": s.get("creds_weak", False),
                "holds": s.get("holds"),
            }
            for s in services
        ],
    }
