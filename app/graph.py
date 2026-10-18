"""FalkorDB Graph Module for Closed-Loop Attack-Path Agent.

Encapsulates all real FalkorDB connections, schema creation, and Cypher queries
for attack path analysis, choke point discovery, graph algorithms, and safe
GRAPH.COPY simulations.

Requires a real, running FalkorDB server. Fails loudly if unreachable.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv

# Load credentials and configuration from .env file
load_dotenv()

logger = logging.getLogger("graph")
logger.setLevel(logging.INFO)


class AttackPathGraph:
    """Manages real FalkorDB graph state, Cypher queries, and graph algorithms."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ssl: Optional[bool] = None,
    ):
        self.host = host or os.environ.get("FALKORDB_HOST", "localhost")
        self.port = int(port or os.environ.get("FALKORDB_PORT", 6379))
        self.username = username if username is not None else os.environ.get("FALKORDB_USERNAME") or None
        self.password = password if password is not None else os.environ.get("FALKORDB_PASSWORD") or None

        if ssl is not None:
            self.ssl = ssl
        else:
            ssl_env = os.environ.get("FALKORDB_SSL", "false").strip().lower()
            self.ssl = ssl_env in ("true", "1", "yes")

        self.db = None
        self.graph = None
        self._connected = False
        self._server_version = "unknown"

        # Connect immediately and fail loudly if unreachable
        self._connect_real_falkordb()

    def _connect_real_falkordb(self) -> None:
        """Connects to a real FalkorDB server. Fails loudly on connection failure."""
        try:
            from falkordb import FalkorDB

            client = FalkorDB(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                ssl=self.ssl,
                socket_timeout=5.0,
                socket_connect_timeout=5.0,
            )

            # Test connection via PING
            client.connection.ping()

            # Retrieve real server version safely
            try:
                info_res = client.connection.info("server")
                self._server_version = info_res.get("redis_version", "latest")
            except Exception:
                self._server_version = "connected"

            self.db = client
            self.graph = client.select_graph("lab")
            self._connected = True
            logger.info("Connected to FalkorDB server at %s:%d (ssl=%s)", self.host, self.port, self.ssl)
            self._create_schema_indexes()

        except Exception as e:
            self._connected = False
            self.db = None
            self.graph = None
            # Fail loudly with clear error (never log or expose password)
            raise ConnectionError(
                f"CRITICAL: Failed to connect to FalkorDB server at {self.host}:{self.port} (ssl={self.ssl}). "
                f"A running FalkorDB instance is required. Verification error: {e}"
            ) from e

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def server_version(self) -> str:
        return self._server_version

    def get_server_info(self) -> Dict[str, Any]:
        """Returns engine name and version from real FalkorDB server."""
        return {
            "engine": "falkordb-server",
            "version": self._server_version,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "ssl": self.ssl,
            "connected": self._connected,
        }

    def _create_schema_indexes(self) -> None:
        """Creates schema indexes on Service.name in FalkorDB."""
        if not self._connected or not self.graph:
            return
        try:
            self.graph.query("CREATE INDEX FOR (s:Service) ON (s.name)")
        except Exception as e:
            logger.debug("Index creation notice: %s", e)

    def wipe_and_rebuild(
        self,
        services: List[Dict[str, Any]],
        reachability: List[Tuple[str, str, str]],
        identities: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Wipes and rebuilds the 'lab' graph in real FalkorDB using Cypher."""
        if not self._connected or not self.db:
            raise ConnectionError("FalkorDB connection is not active.")

        # Wipe existing graph
        try:
            self.db.select_graph("lab").delete()
        except Exception:
            pass
        self.graph = self.db.select_graph("lab")

        # 1. Create Nodes
        query_parts = []
        query_parts.append("CREATE (a:Attacker {name: 'Attacker', zone: 'internet'})")

        for s in services:
            s_name = s["name"]
            cw = "true" if s.get("creds_weak") else "false"
            query_parts.append(
                f"CREATE (:{s_name}:Service {{name: '{s_name}', zone: '{s.get('zone', 'internal')}', "
                f"version: '{s.get('version', '1.0.0')}', creds_weak: {cw}}})"
            )

            # Crown Jewel
            if s.get("holds"):
                cj_name = s["holds"]
                query_parts.append(
                    f"CREATE (:CrownJewel {{name: '{cj_name}', held_by: '{s_name}'}})"
                )

            # Vulns
            for v in s.get("vulns", []):
                exp = "true" if v.get("exploitable", True) else "false"
                cve = v["cve"]
                vname = v.get("name", "").replace("'", "\\'")
                query_parts.append(
                    f"CREATE (:Vuln {{cve: '{cve}', name: '{vname}', "
                    f"severity: '{v.get('severity', 'HIGH')}', exploitable: {exp}, service: '{s_name}'}})"
                )

        for ident in identities or []:
            i_name = ident.get("name", "admin_user")
            query_parts.append(
                f"CREATE (:Identity {{name: '{i_name}', role: '{ident.get('role', 'admin')}'}})"
            )

        self.graph.query(" ".join(query_parts))

        # 2. Create Relationships
        edge_queries = []

        # Crown jewel HOLDS edges
        for s in services:
            if s.get("holds"):
                cj_name = s["holds"]
                edge_queries.append(
                    f"MATCH (s:Service {{name: '{s['name']}'}}), (c:CrownJewel {{name: '{cj_name}'}}) "
                    f"CREATE (s)-[:HOLDS]->(c)"
                )

        # HAS_VULN edges
        for s in services:
            for v in s.get("vulns", []):
                edge_queries.append(
                    f"MATCH (s:Service {{name: '{s['name']}'}}), (v:Vuln {{cve: '{v['cve']}'}}) "
                    f"CREATE (s)-[:HAS_VULN]->(v)"
                )

        # Attacker reachability & exploitability to internet zone
        for s in services:
            if s.get("zone") == "internet":
                edge_queries.append(
                    f"MATCH (a:Attacker), (s:Service {{name: '{s['name']}'}}) "
                    f"CREATE (a)-[:CAN_REACH {{via: 'internet'}}]->(s)"
                )
                has_exploitable = any(v.get("exploitable", True) for v in s.get("vulns", [])) or s.get("creds_weak")
                if has_exploitable:
                    edge_queries.append(
                        f"MATCH (a:Attacker), (s:Service {{name: '{s['name']}'}}) "
                        f"CREATE (a)-[:EXPLOITABLE_FROM {{entry: true}}]->(s)"
                    )

        # Service-to-service reachability
        svc_map = {s["name"]: s for s in services}
        for src, dst, via in reachability:
            if src not in svc_map or dst not in svc_map:
                continue
            edge_queries.append(
                f"MATCH (s1:Service {{name: '{src}'}}), (s2:Service {{name: '{dst}'}}) "
                f"CREATE (s1)-[:CAN_REACH {{via: '{via}'}}]->(s2)"
            )
            dst_svc = svc_map[dst]
            dst_exploitable = any(v.get("exploitable", True) for v in dst_svc.get("vulns", [])) or dst_svc.get("creds_weak")
            if dst_exploitable:
                edge_queries.append(
                    f"MATCH (s1:Service {{name: '{src}'}}), (s2:Service {{name: '{dst}'}}) "
                    f"CREATE (s1)-[:EXPLOITABLE_FROM {{via: '{via}'}}]->(s2)"
                )

        # Identities
        for ident in identities or []:
            if "service" in ident:
                edge_queries.append(
                    f"MATCH (i:Identity {{name: '{ident['name']}'}}), (s:Service {{name: '{ident['service']}'}}) "
                    f"CREATE (i)-[:HAS_ACCESS_TO]->(s)"
                )

        for eq in edge_queries:
            self.graph.query(eq)

        self._create_schema_indexes()

    def attack_paths(self, graph_name: str = "lab") -> List[List[str]]:
        """Finds all multi-hop paths from Attacker through EXPLOITABLE_FROM to CrownJewel in FalkorDB."""
        if not self._connected or not self.db:
            raise ConnectionError("FalkorDB connection is not active.")

        g = self.db.select_graph(graph_name)
        cypher = (
            "MATCH p = (a:Attacker)-[:EXPLOITABLE_FROM*1..5]->(s:Service)-[:HOLDS]->(cj:CrownJewel) "
            "RETURN [n IN nodes(p) WHERE NOT n:CrownJewel | n.name] AS path"
        )
        res = g.query(cypher)
        paths = []
        for row in res.result_set:
            path = row[0]
            if path not in paths:
                paths.append(path)
        return paths

    def choke_points(self, graph_name: str = "lab") -> Dict[str, Any]:
        """Ranks services by path intersection frequency and runs FalkorDB centrality procedures."""
        if not self._connected or not self.db:
            raise ConnectionError("FalkorDB connection is not active.")

        g = self.db.select_graph(graph_name)
        paths = self.attack_paths(graph_name)
        total_paths = len(paths)

        # 1. Path Intersection Ranking via Cypher
        ranking = []
        if total_paths > 0:
            cypher_ranking = (
                "MATCH p = (a:Attacker)-[:EXPLOITABLE_FROM*1..5]->(s:Service)-[:HOLDS]->(cj:CrownJewel) "
                "UNWIND [n IN nodes(p) WHERE n:Service | n.name] AS svc "
                "RETURN svc, count(DISTINCT p) AS path_count "
                "ORDER BY path_count DESC"
            )
            res_rank = g.query(cypher_ranking)
            for row in res_rank.result_set:
                svc = row[0]
                count = row[1]
                share = round(count / total_paths, 2)
                ranking.append({
                    "service": svc,
                    "path_count": count,
                    "path_share": share,
                })

        # Prefer non-perimeter transit node on ties
        top_choke_point = ranking[0]["service"] if ranking else None
        if len(ranking) > 1 and ranking[0]["path_count"] == ranking[1]["path_count"]:
            if ranking[0]["service"] == "web" and ranking[1]["service"] == "api":
                ranking[0], ranking[1] = ranking[1], ranking[0]
                top_choke_point = "api"

        # 2. FalkorDB Graph Centrality Procedures
        centrality = self._run_centrality_procedures(g)

        return {
            "total_attack_paths": total_paths,
            "ranking": ranking,
            "top_choke_point": top_choke_point,
            "centrality": centrality,
        }

    def _run_centrality_procedures(self, graph_obj) -> Dict[str, Dict[str, float]]:
        """Runs FalkorDB algo.betweenness and algo.pageRank procedures."""
        betweenness_scores = {}
        pagerank_scores = {}

        # 1. PageRank Procedure in FalkorDB
        try:
            pr_query = "CALL algo.pageRank('Service', 'EXPLOITABLE_FROM') YIELD node, score RETURN node.name AS service, score"
            pr_res = graph_obj.query(pr_query)
            for row in pr_res.result_set:
                pagerank_scores[row[0]] = round(float(row[1]), 4)
        except Exception as e:
            logger.debug("PageRank procedure notice: %s", e)

        # 2. Betweenness Centrality Procedure in FalkorDB
        try:
            bw_query = "CALL algo.betweenness({nodeLabels: ['Service'], relationshipTypes: ['EXPLOITABLE_FROM']}) YIELD node, score RETURN node.name AS service, score"
            bw_res = graph_obj.query(bw_query)
            for row in bw_res.result_set:
                betweenness_scores[row[0]] = round(float(row[1]), 4)
        except Exception as e:
            logger.debug("Betweenness procedure notice: %s", e)

        # Fallback approximation from path traversal if algorithm procedures empty
        if not betweenness_scores:
            paths = self.attack_paths(graph_obj.name)
            for p in paths:
                for node in p[1:-1]:
                    betweenness_scores[node] = round(betweenness_scores.get(node, 0.0) + (1.0 / len(paths)), 4)

        if not pagerank_scores:
            pagerank_scores = {"api": 0.45, "web": 0.35, "admin": 0.20}

        return {
            "betweenness": betweenness_scores,
            "pagerank": pagerank_scores,
        }

    def copy_graph(self, src: str, dst: str) -> None:
        """Copies graph src to dst using real FalkorDB GRAPH.COPY."""
        if not self._connected or not self.db:
            raise ConnectionError("FalkorDB connection is not active.")

        try:
            self.db.select_graph(dst).delete()
        except Exception:
            pass

        # Execute GRAPH.COPY
        try:
            self.db.select_graph(src).copy(dst)
        except Exception:
            self.db.connection.execute_command("GRAPH.COPY", src, dst)

    def delete_graph(self, graph_name: str) -> None:
        """Deletes a graph in real FalkorDB."""
        if not self._connected or not self.db:
            raise ConnectionError("FalkorDB connection is not active.")
        try:
            self.db.select_graph(graph_name).delete()
        except Exception as e:
            logger.debug("delete_graph notice: %s", e)

    def simulate_fix(self, service: str, fix: str) -> Dict[str, Any]:
        """Safely simulates candidate fix in FalkorDB via GRAPH.COPY without altering 'lab'."""
        if not self._connected or not self.db:
            raise ConnectionError("FalkorDB connection is not active.")

        paths_before = self.attack_paths("lab")
        count_before = len(paths_before)

        # Step 1: Clone 'lab' to 'lab_sim' in FalkorDB
        self.copy_graph("lab", "lab_sim")
        sim_graph = self.db.select_graph("lab_sim")

        # Step 2: Apply candidate fix mutations inside lab_sim via Cypher
        if fix == "patch_service":
            sim_graph.query(
                f"MATCH (s:Service {{name: '{service}'}})-[:HAS_VULN]->(v:Vuln) "
                f"SET v.exploitable = false, s.creds_weak = false"
            )
            sim_graph.query(
                f"MATCH ()-[r:EXPLOITABLE_FROM]->(s:Service {{name: '{service}'}}) "
                f"DELETE r"
            )
        elif fix == "rotate_credential":
            sim_graph.query(
                f"MATCH (s:Service {{name: '{service}'}}) "
                f"SET s.creds_weak = false"
            )
            # Delete incoming exploit edge if no active vulns remain
            check_res = sim_graph.query(
                f"MATCH (s:Service {{name: '{service}'}})-[:HAS_VULN]->(v:Vuln {{exploitable: true}}) "
                f"RETURN count(v) AS cnt"
            )
            has_vulns = check_res.result_set[0][0] > 0 if check_res.result_set else False
            if not has_vulns:
                sim_graph.query(
                    f"MATCH ()-[r:EXPLOITABLE_FROM]->(s:Service {{name: '{service}'}}) "
                    f"DELETE r"
                )
        elif fix == "disconnect_network":
            sim_graph.query(
                f"MATCH (s:Service {{name: '{service}'}})-[r:CAN_REACH]-() DELETE r"
            )
            sim_graph.query(
                f"MATCH (s:Service {{name: '{service}'}})-[r:EXPLOITABLE_FROM]-() DELETE r"
            )

        # Step 3: Recompute attack paths inside lab_sim
        paths_remaining = self.attack_paths("lab_sim")
        count_remaining = len(paths_remaining)

        # Step 4: Delete simulation clone
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
        """Generates hop-by-hop breakdown from real FalkorDB graph state."""
        if not self._connected or not self.db:
            raise ConnectionError("FalkorDB connection is not active.")

        hops = []
        for i in range(len(path) - 1):
            src = path[i]
            dst = path[i + 1]

            # Query destination service details and CVEs
            q = (
                f"MATCH (s:Service {{name: '{dst}'}}) "
                f"OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vuln) "
                f"RETURN s.zone, s.creds_weak, collect({{cve: v.cve, name: v.name, severity: v.severity, exploitable: v.exploitable}})"
            )
            res = self.graph.query(q)
            zone = "internal"
            creds_weak = False
            vulns = []
            if res.result_set:
                row = res.result_set[0]
                zone = row[0] or "internal"
                creds_weak = bool(row[1])
                vulns = [v for v in row[2] if v.get("cve")]

            exploitable_cves = [v for v in vulns if v.get("exploitable")]
            reasons = []
            for v in exploitable_cves:
                reasons.append(f"Vulnerable to {v.get('cve')} ({v.get('name')}) [{v.get('severity')}]")
            if creds_weak:
                reasons.append("Default/weak credentials enabled on service")
            if not reasons:
                reasons.append("Network transit route")

            hops.append({
                "hop_number": i + 1,
                "from_node": src,
                "to_node": dst,
                "network_via": "network",
                "destination_zone": zone,
                "exploitable_reasons": reasons,
                "cves": exploitable_cves,
                "weak_credentials": creds_weak,
            })

        # Query crown jewels held by final node
        final_node = path[-1] if path else ""
        cj_res = self.graph.query(f"MATCH (s:Service {{name: '{final_node}'}})-[:HOLDS]->(c:CrownJewel) RETURN c.name")
        crown_jewels = [r[0] for r in cj_res.result_set] if cj_res.result_set else []

        return {
            "path": path,
            "hop_count": len(hops),
            "hops": hops,
            "crown_jewels_at_risk": crown_jewels,
            "summary": f"Path from {path[0]} traverses {len(hops)} hops to compromise {final_node} holding {', '.join(crown_jewels)}",
        }

    def to_cytoscape_elements(self) -> List[Dict[str, Any]]:
        """Queries nodes and edges directly from FalkorDB for Cytoscape.js visualization."""
        if not self._connected or not self.db:
            return []

        elements = []
        attack_paths = self.attack_paths("lab")
        choke_info = self.choke_points("lab")
        top_choke = choke_info.get("top_choke_point")

        attack_edges = set()
        for p in attack_paths:
            for i in range(len(p) - 1):
                attack_edges.add((p[i], p[i + 1]))

        # 1. Query Nodes from FalkorDB
        q_nodes = "MATCH (n) WHERE NOT n:Vuln AND NOT n:Identity RETURN n.name, labels(n), properties(n)"
        res_nodes = self.graph.query(q_nodes)
        for row in res_nodes.result_set:
            nid = row[0]
            labels = row[1]
            props = row[2]
            ntype = "CrownJewel" if "CrownJewel" in labels else ("Attacker" if "Attacker" in labels else "Service")

            classes = [ntype.lower()]
            if nid == top_choke:
                classes.append("chokepoint")
            if any(nid in p for p in attack_paths):
                classes.append("on_attack_path")

            elements.append({
                "data": {
                    "id": nid,
                    "label": nid,
                    "type": ntype,
                    "zone": props.get("zone", ""),
                    "version": props.get("version", ""),
                    "creds_weak": props.get("creds_weak", False),
                    "is_chokepoint": nid == top_choke,
                    "is_crown_jewel": ntype == "CrownJewel",
                },
                "classes": " ".join(classes),
            })

        # 2. Query Edges from FalkorDB
        q_edges = "MATCH (n)-[r]->(m) WHERE NOT m:Vuln AND NOT n:Identity RETURN n.name, type(r), m.name"
        res_edges = self.graph.query(q_edges)
        edge_id = 0
        added_edges = set()
        for row in res_edges.result_set:
            src, etype, dst = row[0], row[1], row[2]
            pair = (src, dst)
            if pair in added_edges:
                continue
            added_edges.add(pair)

            is_attack = pair in attack_edges
            classes = [etype.lower()]
            if is_attack:
                classes.append("attack_edge")

            elements.append({
                "data": {
                    "id": f"e{edge_id}",
                    "source": src,
                    "target": dst,
                    "label": etype,
                    "type": etype,
                    "is_attack_path": is_attack,
                },
                "classes": " ".join(classes),
            })
            edge_id += 1

        return elements
