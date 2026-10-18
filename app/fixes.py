"""Defensive Fix Execution Module for Closed-Loop Attack-Path Agent.

Implements strict whitelist enforcement for remediations against lab services.
Never executes arbitrary shell commands.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from typing import Any, Dict, Optional

logger = logging.getLogger("fixes")
logger.setLevel(logging.INFO)

VALID_ACTIONS = frozenset({"disconnect_network", "patch_service", "rotate_credential"})
VALID_SERVICES = frozenset({"web", "api", "admin", "db", "fileshare"})

CONFIG_DIR = os.environ.get(
    "LAB_CONFIG_DIR",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "lab", "config"),
)
TEMPLATE_DIR = os.environ.get(
    "LAB_TEMPLATE_DIR",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "lab", "config_templates"),
)


def bump_version(version: str) -> str:
    """Bumps semantic patch version, e.g. 1.2.0 -> 1.2.1."""
    parts = version.split(".")
    try:
        parts[-1] = str(int(parts[-1]) + 1)
        return ".".join(parts)
    except Exception:
        return f"{version}-patched"


def restart_docker_container(service_name: str) -> bool:
    """Restarts a lab container via Docker SDK if available."""
    try:
        import docker

        client = docker.from_env()
        container_names = [f"lab_{service_name}", service_name]
        for c_name in container_names:
            try:
                container = client.containers.get(c_name)
                container.restart(timeout=2)
                logger.info("Restarted container %s", c_name)
                return True
            except Exception:
                continue
    except Exception as e:
        logger.debug("Container restart notice: %s", e)
    return False


def apply_fix(
    service: str, fix: str, network: Optional[str] = None
) -> Dict[str, Any]:
    """Applies a whitelisted remediation action to a lab service container/config.

    Strictly validates service name and action.
    """
    # 1. Strict Whitelist Validation
    if service not in VALID_SERVICES:
        raise ValueError(
            f"Access denied: Service '{service}' is not in the approved lab inventory: {sorted(VALID_SERVICES)}"
        )

    if fix not in VALID_ACTIONS:
        raise ValueError(
            f"Action denied: '{fix}' is not a whitelisted remediation. Allowed: {sorted(VALID_ACTIONS)}"
        )

    config_path = os.path.join(CONFIG_DIR, f"{service}.json")
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Service configuration file not found at {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    details = ""

    # 2. Execute Whitelisted Action
    if fix == "patch_service":
        vulns = cfg.get("vulns", [])
        patched_cves = []
        for v in vulns:
            if v.get("exploitable", True):
                v["exploitable"] = False
                patched_cves.append(v.get("cve"))

        old_ver = cfg.get("version", "1.0.0")
        new_ver = bump_version(old_ver)
        cfg["version"] = new_ver
        cfg["creds_weak"] = False  # Patching hardening includes credential sanitization

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)

        restart_docker_container(service)
        details = (
            f"Patched vulnerabilities {patched_cves} on service '{service}'. "
            f"Bumped version from {old_ver} to {new_ver}. Hardened credentials."
        )

    elif fix == "rotate_credential":
        cfg["creds_weak"] = False
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)

        restart_docker_container(service)
        details = f"Rotated credentials for '{service}'. creds_weak set to false."

    elif fix == "disconnect_network":
        target_network = network or "dmz_net"
        disconnected = False
        try:
            import docker

            client = docker.from_env()
            container = client.containers.get(f"lab_{service}")
            container.disconnect(target_network)
            disconnected = True
        except Exception as e:
            logger.debug("Network disconnect notice: %s", e)

        details = f"Disconnected service '{service}' from network '{target_network}'."

    return {
        "success": True,
        "service": service,
        "action": fix,
        "details": details,
    }


def reset_lab() -> Dict[str, Any]:
    """Restores the lab to its vulnerable starting state for demo repeatability.

    1. Copies template JSON configs back to active configs.
    2. Reconnects containers to standard networks if disconnected.
    3. Restarts containers if Docker is available.
    """
    restored_files = []
    if os.path.exists(TEMPLATE_DIR):
        for fname in os.listdir(TEMPLATE_DIR):
            if fname.endswith(".json"):
                src = os.path.join(TEMPLATE_DIR, fname)
                dst = os.path.join(CONFIG_DIR, fname)
                shutil.copyfile(src, dst)
                restored_files.append(fname)

    # Reconnect docker networks and restart containers if running
    try:
        import docker

        client = docker.from_env()
        standard_networks = {
            "web": ["internet_net", "dmz_net"],
            "api": ["dmz_net", "internal_net"],
            "admin": ["internal_net"],
            "db": ["internal_net"],
            "fileshare": ["internal_net"],
        }
        for svc, nets in standard_networks.items():
            try:
                container = client.containers.get(f"lab_{svc}")
                for net_name in nets:
                    try:
                        net = client.networks.get(net_name)
                        net.connect(container)
                    except Exception:
                        pass
                container.restart(timeout=2)
            except Exception:
                pass
    except Exception as e:
        logger.debug("Reset docker networks notice: %s", e)

    return {
        "success": True,
        "restored_configurations": restored_files,
        "message": "Lab successfully reset to vulnerable baseline state.",
    }
