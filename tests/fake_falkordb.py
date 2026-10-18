"""In-memory FalkorDB emulator for offline unit testing only.

This module is NEVER imported or used by the production application.
It serves as an offline mock for unit tests when a real FalkorDB server is unavailable.
"""

from __future__ import annotations

import copy
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("fake_falkordb")


class FakeAttackPathGraph:
    """Offline emulator mimicking FalkorDB graph state and Cypher traversals."""

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None):
        self.host = host or "localhost"
        self.port = int(port or 6379)
        self.ssl = False
        self._connected = True
        self.server_version = "4.0.0"
        self._mem_nodes: Dict[str, Dict[str, Any]] = {}
        self._mem_edges: List[Dict[str, Any]] = []
        self._mem_graphs: Dict[str, Dict[str, Any]] = {}

    @property
    def is_connected(self) -> bool:
        return True

    def wipe_and_rebuild(
        self,
        services: List[Dict[str, Any]],
        reachability: List[Tuple[str, str, str]],
        identities: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self._mem_nodes.clear()
        self._mem_edges.clear()

        self._mem_nodes["Attacker"] = {
            "name": "Attacker",
            "type": "Attacker",
            "zone": "internet",
        }

        for svc in services:
            s_name = svc["name"]
            self._mem_nodes[s_name] = {
                "name": s_name,
                "type": "Service",
                "zone": svc.get("zone", "internal"),
                "version": svc.get("version", "1.0.0"),
                "creds_weak": svc.get("creds_weak", False),
                "ports": svc.get("ports", []),
                "holds": svc.get("holds"),
            }

            if svc.get("holds"):
                cj_name = svc["holds"]
                cj_id = f"cj_{cj_name}"
                self._mem_nodes[cj_id] = {
                    "name": cj_name,
                    "type": "CrownJewel",
                    "held_by": s_name,
                }
                self._mem_edges.append({
                    "src": s_name,
                    "dst": cj_id,
                    "type": "HOLDS",
                    "props": {},
                })

            for v in svc.get("vulns", []):
                v_id = f"vuln_{v['cve']}"
                self._mem_nodes[v_id] = {
                    "name": v["cve"],
                    "cve": v["cve"],
                    "type": "Vuln",
                    "vuln_name": v.get("name", ""),
                    "severity": v.get("severity", "HIGH"),
                    "exploitable": v.get("exploitable", True),
                }
                self._mem_edges.append({
                    "src": s_name,
                    "dst": v_id,
                    "type": "HAS_VULN",
                    "props": {},
                })

        for ident in identities or []:
            i_name = ident.get("name", "admin_user")
            self._mem_nodes[i_name] = {
                "name": i_name,
                "type": "Identity",
                "role": ident.get("role", "admin"),
            }
            if "service" in ident:
                self._mem_edges.append({
                    "src": i_name,
                    "dst": ident["service"],
                    "type": "HAS_ACCESS_TO",
                    "props": {},
                })

        for s_name, s_data in self._mem_nodes.items():
            if s_data.get("type") == "Service" and s_data.get("zone") == "internet":
                self._mem_edges.append({
                    "src": "Attacker",
                    "dst": s_name,
                    "type": "CAN_REACH",
                    "props": {"via": "internet"},
                })
                svc_vulns = [
                    self._mem_nodes[e["dst"]]
                    for e in self._mem_edges
                    if e["src"] == s_name and e["type"] == "HAS_VULN"
                ]
                has_exploitable = any(v.get("exploitable") for v in svc_vulns) or s_data.get("creds_weak")
                if has_exploitable:
                    self._mem_edges.append({
                        "src": "Attacker",
                        "dst": s_name,
                        "type": "EXPLOITABLE_FROM",
                        "props": {"entry": True},
                    })

        for src, dst, via in reachability:
            if src not in self._mem_nodes or dst not in self._mem_nodes:
                continue
            self._mem_edges.append({
                "src": src,
                "dst": dst,
                "type": "CAN_REACH",
                "props": {"via": via},
            })

            dst_node = self._mem_nodes[dst]
            dst_vulns = [
                self._mem_nodes[e["dst"]]
                for e in self._mem_edges
                if e["src"] == dst and e["type"] == "HAS_VULN"
            ]
            dst_exploitable = any(v.get("exploitable") for v in dst_vulns) or dst_node.get("creds_weak")
            if dst_exploitable:
                self._mem_edges.append({
                    "src": src,
                    "dst": dst,
                    "type": "EXPLOITABLE_FROM",
                    "props": {"via": via},
                })

    def attack_paths(self, graph_name: str = "lab") -> List[List[str]]:
        nodes = self._mem_graphs.get(graph_name, {}).get("nodes", self._mem_nodes)
        edges = self._mem_graphs.get(graph_name, {}).get("edges", self._mem_edges)

        targets = set()
        for e in edges:
            if e["type"] == "HOLDS":
                targets.add(e["src"])

        paths: List[List[str]] = []

        def dfs(current: str, path: List[str], depth: int):
            if depth > 5:
                return
            if current in targets and current != "Attacker":
                paths.append(list(path))
                return
            for edge in edges:
                if edge["src"] == current and edge["type"] == "EXPLOITABLE_FROM":
                    nxt = edge["dst"]
                    if nxt not in path:
                        path.append(nxt)
                        dfs(nxt, path, depth + 1)
                        path.pop()

        dfs("Attacker", ["Attacker"], 0)
        unique_paths = []
        for p in paths:
            if p not in unique_paths:
                unique_paths.append(p)
        return unique_paths

    def choke_points(self, graph_name: str = "lab") -> Dict[str, Any]:
        paths = self.attack_paths(graph_name)
        total_paths = len(paths)

        counts: Dict[str, int] = {}
        for path in paths:
            services_in_path = set(n for n in path if n != "Attacker")
            for svc in services_in_path:
                counts[svc] = counts.get(svc, 0) + 1

        def choke_sort_key(item):
            svc, count = item
            is_entry = (self._mem_nodes.get(svc, {}).get("zone") == "internet")
            return (count, not is_entry)

        ranking = []
        for svc, count in sorted(counts.items(), key=choke_sort_key, reverse=True):
            share = round(count / total_paths, 2) if total_paths > 0 else 0.0
            ranking.append({
                "service": svc,
                "path_count": count,
                "path_share": share,
            })

        top_choke_point = ranking[0]["service"] if ranking else None
        return {
            "total_attack_paths": total_paths,
            "ranking": ranking,
            "top_choke_point": top_choke_point,
            "centrality": {"betweenness": {"api": 1.0}, "pagerank": {"api": 0.4}},
        }

    def copy_graph(self, src: str, dst: str) -> None:
        src_nodes = self._mem_graphs.get(src, {}).get("nodes", self._mem_nodes)
        src_edges = self._mem_graphs.get(src, {}).get("edges", self._mem_edges)
        self._mem_graphs[dst] = {
            "nodes": copy.deepcopy(src_nodes),
            "edges": copy.deepcopy(src_edges),
        }

    def delete_graph(self, graph_name: str) -> None:
        if graph_name in self._mem_graphs:
            del self._mem_graphs[graph_name]

    def simulate_fix(self, service: str, fix: str) -> Dict[str, Any]:
        paths_before = self.attack_paths("lab")
        count_before = len(paths_before)

        self.copy_graph("lab", "lab_sim")
        sim = self._mem_graphs.get("lab_sim")
        if sim:
            sim_nodes = sim["nodes"]
            sim_edges = sim["edges"]

            if fix == "patch_service":
                for edge in list(sim_edges):
                    if edge["src"] == service and edge["type"] == "HAS_VULN":
                        vuln_id = edge["dst"]
                        if vuln_id in sim_nodes:
                            sim_nodes[vuln_id]["exploitable"] = False
                if service in sim_nodes:
                    sim_nodes[service]["creds_weak"] = False
                sim["edges"] = [
                    e for e in sim_edges
                    if not (e["dst"] == service and e["type"] == "EXPLOITABLE_FROM")
                ]
            elif fix == "rotate_credential":
                if service in sim_nodes:
                    sim_nodes[service]["creds_weak"] = False
                has_active_vuln = any(
                    sim_nodes.get(e["dst"], {}).get("exploitable")
                    for e in sim_edges
                    if e["src"] == service and e["type"] == "HAS_VULN"
                )
                if not has_active_vuln:
                    sim["edges"] = [
                        e for e in sim_edges
                        if not (e["dst"] == service and e["type"] == "EXPLOITABLE_FROM")
                    ]
            elif fix == "disconnect_network":
                sim["edges"] = [
                    e for e in sim_edges
                    if not ((e["src"] == service or e["dst"] == service) and e["type"] in ("CAN_REACH", "EXPLOITABLE_FROM"))
                ]

        paths_remaining = self.attack_paths("lab_sim")
        count_remaining = len(paths_remaining)
        self.delete_graph("lab_sim")

        eliminated = [p for p in paths_before if p not in paths_remaining]
        return {
            "service": service,
            "fix": fix,
            "paths_before": count_before,
            "paths_remaining": count_remaining,
            "reduction": count_before - count_remaining,
            "eliminated_paths": eliminated,
            "simulated_clean": count_remaining == 0,
        }

    def explain_path(self, path: List[str]) -> Dict[str, Any]:
        hops = []
        for i in range(len(path) - 1):
            src = path[i]
            dst = path[i + 1]
            hops.append({
                "hop_number": i + 1,
                "from_node": src,
                "to_node": dst,
                "network_via": "network",
                "destination_zone": "dmz" if dst == "api" else "internal",
                "exploitable_reasons": ["Vulnerability exploitable"],
                "cves": [{"cve": "CVE-2023-22515", "name": "Gateway RCE", "severity": "CRITICAL"}],
                "weak_credentials": False,
            })
        return {
            "path": path,
            "hop_count": len(hops),
            "hops": hops,
            "crown_jewels_at_risk": ["customer_data"],
            "summary": f"Path from {path[0]} traverses {len(hops)} hops to compromise {path[-1]}",
        }

    def to_cytoscape_elements(self) -> List[Dict[str, Any]]:
        elements = []
        for nid, data in self._mem_nodes.items():
            ntype = data.get("type", "Service")
            if ntype in ("Vuln", "Identity"):
                continue
            elements.append({
                "data": {
                    "id": nid,
                    "label": data.get("name", nid),
                    "type": ntype,
                    "zone": data.get("zone", ""),
                    "is_chokepoint": nid == "api",
                },
                "classes": ntype.lower(),
            })
        for i, e in enumerate(self._mem_edges):
            if e["dst"].startswith("vuln_") or e["src"].startswith("admin_"):
                continue
            elements.append({
                "data": {
                    "id": f"e{i}",
                    "source": e["src"],
                    "target": e["dst"],
                    "label": e["type"],
                    "is_attack_path": e["type"] == "EXPLOITABLE_FROM",
                },
                "classes": "attack_edge" if e["type"] == "EXPLOITABLE_FROM" else "normal",
            })
        return elements
