"""
Graph analysis engine for dependency vulnerability assessment.
Uses SQLite for data storage and NetworkX for in-memory graph analysis.
"""

import logging
import math
import sqlite3

import networkx as nx

from config import Config

logger = logging.getLogger(__name__)


class GraphAnalyzer:
    """Performs graph analysis on dependency data using SQLite + NetworkX."""

    def __init__(self, db_path: str = None):
        self._db_path = db_path or Config.DATABASE_PATH
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def _build_graph(self, project_id: str) -> nx.DiGraph:
        """
        Build a NetworkX DiGraph from SQLite data for the given project.

        Queries packages and dependencies, returns a DiGraph with package UIDs
        as nodes and package metadata (name, version) as node attributes.
        """
        G = nx.DiGraph()
        cur = self._conn.cursor()

        # Add all package nodes with metadata
        cur.execute(
            "SELECT uid, name, version FROM packages WHERE project_id = ?",
            (project_id,),
        )
        for row in cur.fetchall():
            G.add_node(row["uid"], name=row["name"], version=row["version"])

        # Add dependency edges
        cur.execute(
            "SELECT d.source_uid, d.target_uid "
            "FROM dependencies d "
            "JOIN packages p1 ON d.source_uid = p1.uid "
            "JOIN packages p2 ON d.target_uid = p2.uid "
            "WHERE p1.project_id = ? AND p2.project_id = ?",
            (project_id, project_id),
        )
        for row in cur.fetchall():
            G.add_edge(row["source_uid"], row["target_uid"])

        return G

    def _get_affected_packages(self, project_id: str, cve_id: str) -> list[str]:
        """Return list of package UIDs affected by a given CVE in this project."""
        cur = self._conn.cursor()
        cur.execute(
            "SELECT a.package_uid FROM affects a "
            "JOIN packages p ON a.package_uid = p.uid "
            "WHERE a.vuln_id = ? AND p.project_id = ?",
            (cve_id, project_id),
        )
        return [row["package_uid"] for row in cur.fetchall()]

    def _node_to_dict(self, G: nx.DiGraph, uid: str) -> dict:
        """Convert a graph node to the standard output dict."""
        data = G.nodes[uid]
        return {"name": data["name"], "version": data["version"], "uid": uid}

    def find_shortest_attack_paths(
        self, project_id: str, cve_id: str
    ) -> list[list[dict]]:
        """
        Find the shortest path from any root dependency to the package
        affected by a given CVE.

        A root dependency is a package that no other package depends on
        within this project.
        """
        G = self._build_graph(project_id)
        target_uids = self._get_affected_packages(project_id, cve_id)

        if not target_uids:
            return []

        root_uids = [n for n in G.nodes() if G.in_degree(n) == 0]

        paths = []
        for root_uid in root_uids:
            for target_uid in target_uids:
                if not G.has_node(target_uid):
                    continue
                try:
                    sp = nx.shortest_path(G, root_uid, target_uid)
                    path_nodes = [self._node_to_dict(G, uid) for uid in sp]
                    paths.append(path_nodes)
                except nx.NetworkXNoPath:
                    continue

        # Sort by path length ascending
        paths.sort(key=lambda p: len(p))
        return paths

    def find_all_attack_paths(
        self, project_id: str, cve_id: str, depth_limit: int = 10
    ) -> list[list[dict]]:
        """
        Find all paths from root dependencies to the vulnerable package,
        with a configurable depth limit (default 10).
        """
        G = self._build_graph(project_id)
        target_uids = self._get_affected_packages(project_id, cve_id)

        if not target_uids:
            return []

        root_uids = [n for n in G.nodes() if G.in_degree(n) == 0]

        paths = []
        for root_uid in root_uids:
            for target_uid in target_uids:
                if not G.has_node(target_uid):
                    continue
                for path in nx.all_simple_paths(
                    G, root_uid, target_uid, cutoff=depth_limit
                ):
                    path_nodes = [self._node_to_dict(G, uid) for uid in path]
                    paths.append(path_nodes)
                    if len(paths) >= 200:
                        break
                if len(paths) >= 200:
                    break
            if len(paths) >= 200:
                break

        # Sort by path length ascending
        paths.sort(key=lambda p: len(p))
        return paths

    def calculate_risk_scores(self, project_id: str) -> list[dict]:
        """
        Calculate a risk score for each package based on:
        1. Number of vulnerabilities reachable through it
        2. Severity of those vulnerabilities
        3. How many dependency paths go through it (betweenness-like centrality)

        Returns a list of packages sorted by risk score descending.
        """
        severity_weights = {
            "CRITICAL": 10.0,
            "HIGH": 7.0,
            "MEDIUM": 4.0,
            "LOW": 1.0,
            "UNKNOWN": 2.0,
        }

        G = self._build_graph(project_id)
        cur = self._conn.cursor()

        # Get all vulnerabilities affecting packages in this project
        cur.execute(
            "SELECT a.package_uid, v.vuln_id, v.severity "
            "FROM affects a "
            "JOIN vulnerabilities v ON a.vuln_id = v.vuln_id "
            "JOIN packages p ON a.package_uid = p.uid "
            "WHERE p.project_id = ?",
            (project_id,),
        )
        # Map: package_uid -> list of {id, severity}
        pkg_vuln_map: dict[str, list[dict]] = {}
        vuln_pkg_uids: set[str] = set()
        for row in cur.fetchall():
            pkg_uid = row["package_uid"]
            vuln_pkg_uids.add(pkg_uid)
            pkg_vuln_map.setdefault(pkg_uid, []).append(
                {"id": row["vuln_id"], "severity": row["severity"]}
            )

        # Step 1: For each package, find all vulnerabilities reachable
        # downstream (packages it transitively depends on, including itself)
        package_vulns: dict[str, dict] = {}
        for node in G.nodes():
            data = G.nodes[node]
            # Find all descendants (transitive dependencies) + self
            descendants = nx.descendants(G, node) | {node}
            reachable_vulns = []
            seen_vuln_ids = set()
            for desc in descendants:
                for v in pkg_vuln_map.get(desc, []):
                    if v["id"] not in seen_vuln_ids:
                        seen_vuln_ids.add(v["id"])
                        reachable_vulns.append(v)
            package_vulns[node] = {
                "name": data["name"],
                "version": data["version"],
                "vulns": reachable_vulns,
            }

        # Step 2: Calculate betweenness-like centrality:
        # count how many (root -> vulnerable_package) paths go through each node
        root_uids = [n for n in G.nodes() if G.in_degree(n) == 0]
        centrality: dict[str, int] = {}

        for root_uid in root_uids:
            for vuln_uid in vuln_pkg_uids:
                if not G.has_node(vuln_uid):
                    continue
                for path in nx.all_simple_paths(
                    G, root_uid, vuln_uid, cutoff=10
                ):
                    for intermediate in path:
                        centrality[intermediate] = centrality.get(intermediate, 0) + 1

        # Step 3: Compute composite risk score
        scores: list[dict] = []
        for uid, info in package_vulns.items():
            vuln_score = sum(
                severity_weights.get(v.get("severity", "UNKNOWN"), 2.0)
                for v in info["vulns"]
            )
            path_through_count = centrality.get(uid, 0)
            # Composite: vulnerability severity sum * log-scaled centrality
            # Add 1 to avoid multiplying by zero
            centrality_factor = math.log2(path_through_count + 1) + 1
            risk_score = round(vuln_score * centrality_factor, 2)

            scores.append({
                "uid": uid,
                "name": info["name"],
                "version": info["version"],
                "risk_score": risk_score,
                "reachable_vulnerabilities": len(info["vulns"]),
                "vulnerability_severity_score": round(vuln_score, 2),
                "path_centrality": path_through_count,
            })

        scores.sort(key=lambda x: x["risk_score"], reverse=True)
        return scores

    def get_most_critical_packages(
        self, project_id: str, limit: int = 10
    ) -> list[dict]:
        """
        Find packages that are gateways to the most vulnerabilities.
        These are packages that, if compromised, would expose the most
        downstream vulnerabilities.
        """
        G = self._build_graph(project_id)
        cur = self._conn.cursor()

        # Get all vulnerabilities affecting packages in this project
        cur.execute(
            "SELECT a.package_uid, v.vuln_id, v.severity "
            "FROM affects a "
            "JOIN vulnerabilities v ON a.vuln_id = v.vuln_id "
            "JOIN packages p ON a.package_uid = p.uid "
            "WHERE p.project_id = ?",
            (project_id,),
        )
        pkg_vuln_map: dict[str, list[dict]] = {}
        for row in cur.fetchall():
            pkg_uid = row["package_uid"]
            pkg_vuln_map.setdefault(pkg_uid, []).append(
                {"id": row["vuln_id"], "severity": row["severity"]}
            )

        critical = []
        for node in G.nodes():
            data = G.nodes[node]

            # Count how many other packages depend on this one (dependents)
            # Predecessors in the DiGraph are packages that depend on this one
            # We need transitive dependents (all ancestors)
            dependents = nx.ancestors(G, node)
            dependent_count = len(dependents)

            # Count vulnerabilities reachable downstream (descendants + self)
            descendants = nx.descendants(G, node) | {node}
            seen_vuln_ids = set()
            severities = set()
            for desc in descendants:
                for v in pkg_vuln_map.get(desc, []):
                    if v["id"] not in seen_vuln_ids:
                        seen_vuln_ids.add(v["id"])
                        if v["severity"]:
                            severities.add(v["severity"])

            downstream_vuln_count = len(seen_vuln_ids)

            if downstream_vuln_count > 0:
                critical.append({
                    "uid": node,
                    "name": data["name"],
                    "version": data["version"],
                    "dependent_count": dependent_count,
                    "downstream_vulnerability_count": downstream_vuln_count,
                    "severities": sorted(severities),
                })

        # Sort by downstream_vuln_count * (dependent_count + 1) descending
        critical.sort(
            key=lambda x: x["downstream_vulnerability_count"] * (x["dependent_count"] + 1),
            reverse=True,
        )
        return critical[:limit]

    def get_vulnerability_summary(self, project_id: str) -> dict:
        """
        Aggregate vulnerability statistics for a project:
        - Total vulnerabilities by severity
        - Most affected packages
        - Overall risk assessment
        """
        cur = self._conn.cursor()

        # Severity breakdown
        cur.execute(
            "SELECT COALESCE(v.severity, 'UNKNOWN') AS severity, "
            "  COUNT(DISTINCT v.vuln_id) AS cnt "
            "FROM vulnerabilities v "
            "JOIN affects a ON v.vuln_id = a.vuln_id "
            "JOIN packages p ON a.package_uid = p.uid "
            "WHERE p.project_id = ? "
            "GROUP BY COALESCE(v.severity, 'UNKNOWN') "
            "ORDER BY CASE COALESCE(v.severity, 'UNKNOWN') "
            "  WHEN 'CRITICAL' THEN 0 "
            "  WHEN 'HIGH' THEN 1 "
            "  WHEN 'MEDIUM' THEN 2 "
            "  WHEN 'LOW' THEN 3 "
            "  ELSE 4 "
            "END",
            (project_id,),
        )
        severity_counts: dict[str, int] = {}
        total_vulns = 0
        for row in cur.fetchall():
            sev = row["severity"]
            count = row["cnt"]
            severity_counts[sev] = count
            total_vulns += count

        # Most affected packages (by number of direct vulnerabilities)
        cur.execute(
            "SELECT p.name, p.version, "
            "  COUNT(DISTINCT a.vuln_id) AS vuln_count "
            "FROM packages p "
            "JOIN affects a ON a.package_uid = p.uid "
            "JOIN vulnerabilities v ON a.vuln_id = v.vuln_id "
            "WHERE p.project_id = ? "
            "GROUP BY p.uid "
            "ORDER BY vuln_count DESC "
            "LIMIT 10",
            (project_id,),
        )
        most_affected = []
        for row in cur.fetchall():
            pkg_name = row["name"]
            pkg_version = row["version"]

            # Get severities for this package
            cur2 = self._conn.cursor()
            cur2.execute(
                "SELECT DISTINCT v.severity "
                "FROM vulnerabilities v "
                "JOIN affects a ON v.vuln_id = a.vuln_id "
                "JOIN packages p ON a.package_uid = p.uid "
                "WHERE p.project_id = ? AND p.name = ? AND p.version = ?",
                (project_id, pkg_name, pkg_version),
            )
            severities = [r["severity"] for r in cur2.fetchall() if r["severity"]]

            most_affected.append({
                "name": pkg_name,
                "version": pkg_version,
                "vulnerability_count": row["vuln_count"],
                "severities": severities,
            })

        # Total package count
        cur.execute(
            "SELECT COUNT(*) AS cnt FROM packages WHERE project_id = ?",
            (project_id,),
        )
        total_packages = cur.fetchone()["cnt"]

        # Packages with at least one vulnerability
        cur.execute(
            "SELECT COUNT(DISTINCT p.uid) AS cnt "
            "FROM packages p "
            "JOIN affects a ON a.package_uid = p.uid "
            "WHERE p.project_id = ?",
            (project_id,),
        )
        vulnerable_packages = cur.fetchone()["cnt"]

        # Compute overall risk level
        risk_level = "NONE"
        if severity_counts.get("CRITICAL", 0) > 0:
            risk_level = "CRITICAL"
        elif severity_counts.get("HIGH", 0) > 0:
            risk_level = "HIGH"
        elif severity_counts.get("MEDIUM", 0) > 0:
            risk_level = "MEDIUM"
        elif severity_counts.get("LOW", 0) > 0:
            risk_level = "LOW"
        elif total_vulns > 0:
            risk_level = "UNKNOWN"

        return {
            "project_id": project_id,
            "total_vulnerabilities": total_vulns,
            "severity_breakdown": severity_counts,
            "total_packages": total_packages,
            "vulnerable_packages": vulnerable_packages,
            "vulnerability_rate": round(
                vulnerable_packages / total_packages * 100, 1
            ) if total_packages > 0 else 0,
            "most_affected_packages": most_affected,
            "overall_risk_level": risk_level,
        }

    def close(self) -> None:
        """Close the SQLite connection."""
        self._conn.close()
