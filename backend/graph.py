"""
SQLite + NetworkX graph operations for storing and querying dependency data.
"""

import json
import sqlite3
from datetime import datetime, timezone

import networkx as nx

from config import Config


class GraphManager:
    """Manages all graph operations for the dependency graph."""

    def __init__(self, uri: str = None, user: str = None, password: str = None, db_path: str = None):
        db_path = db_path or Config.DATABASE_PATH
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.row_factory = sqlite3.Row
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        """Create tables if they don't exist."""
        cur = self._conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS projects(
                project_id TEXT PRIMARY KEY,
                ecosystem TEXT,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS packages(
                uid TEXT PRIMARY KEY,
                name TEXT,
                version TEXT,
                ecosystem TEXT,
                project_id TEXT,
                FOREIGN KEY(project_id) REFERENCES projects(project_id)
            );

            CREATE TABLE IF NOT EXISTS dependencies(
                source_uid TEXT,
                target_uid TEXT,
                PRIMARY KEY(source_uid, target_uid)
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities(
                vuln_id TEXT PRIMARY KEY,
                summary TEXT,
                severity TEXT,
                aliases TEXT,
                refs TEXT
            );

            CREATE TABLE IF NOT EXISTS affects(
                vuln_id TEXT,
                package_uid TEXT,
                PRIMARY KEY(vuln_id, package_uid)
            );
        """)
        self._conn.commit()

    def clear_project(self, project_id: str) -> dict:
        """
        Remove all data associated with a project: its Package nodes,
        Vulnerability nodes (if orphaned), and all relationships.
        """
        cur = self._conn.cursor()

        # Get all package uids for this project
        cur.execute(
            "SELECT uid FROM packages WHERE project_id = ?", (project_id,)
        )
        pkg_uids = [row["uid"] for row in cur.fetchall()]

        if pkg_uids:
            placeholders = ",".join("?" for _ in pkg_uids)

            # Delete affects rows for these packages
            cur.execute(
                f"DELETE FROM affects WHERE package_uid IN ({placeholders})",
                pkg_uids,
            )

            # Delete dependency edges involving these packages
            cur.execute(
                f"DELETE FROM dependencies WHERE source_uid IN ({placeholders}) "
                f"OR target_uid IN ({placeholders})",
                pkg_uids + pkg_uids,
            )

            # Delete the packages themselves
            cur.execute(
                f"DELETE FROM packages WHERE uid IN ({placeholders})",
                pkg_uids,
            )

        # Delete orphaned vulnerabilities (not connected to any remaining package)
        cur.execute(
            "DELETE FROM vulnerabilities WHERE vuln_id NOT IN "
            "(SELECT DISTINCT vuln_id FROM affects)"
        )

        # Delete the project
        cur.execute("DELETE FROM projects WHERE project_id = ?", (project_id,))

        self._conn.commit()
        return {"status": "cleared", "project_id": project_id}

    def ingest_dependencies(self, project_id: str, parsed_data: dict) -> dict:
        """
        Create Package nodes and DEPENDS_ON edges from parsed lockfile data.

        parsed_data format:
        {
            "ecosystem": "npm",
            "packages": [
                {"name": "...", "version": "...", "dependencies": ["name@version", ...]}
            ]
        }
        """
        ecosystem = parsed_data["ecosystem"]
        packages = parsed_data["packages"]

        cur = self._conn.cursor()

        # Create or update the project
        now = datetime.now(timezone.utc).isoformat()
        cur.execute(
            "INSERT OR REPLACE INTO projects(project_id, ecosystem, updated_at) "
            "VALUES (?, ?, ?)",
            (project_id, ecosystem, now),
        )

        node_count = 0
        edge_count = 0

        # Create all Package nodes first
        for pkg in packages:
            name = pkg["name"]
            version = pkg["version"]
            uid = f"{project_id}:{name}@{version}"

            cur.execute(
                "INSERT OR REPLACE INTO packages(uid, name, version, ecosystem, project_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (uid, name, version, ecosystem, project_id),
            )
            node_count += 1

        # Create DEPENDS_ON relationships
        for pkg in packages:
            name = pkg["name"]
            version = pkg["version"]
            source_uid = f"{project_id}:{name}@{version}"

            for dep_ref in pkg.get("dependencies", []):
                # dep_ref format: "name@version"
                if "@" in dep_ref:
                    dep_name, dep_version = dep_ref.rsplit("@", 1)
                else:
                    dep_name = dep_ref
                    dep_version = "unknown"

                target_uid = f"{project_id}:{dep_name}@{dep_version}"

                cur.execute(
                    "INSERT OR REPLACE INTO dependencies(source_uid, target_uid) "
                    "VALUES (?, ?)",
                    (source_uid, target_uid),
                )
                edge_count += 1

        self._conn.commit()

        return {
            "project_id": project_id,
            "nodes_created": node_count,
            "edges_created": edge_count,
        }

    def attach_vulnerabilities(self, project_id: str, vuln_data: list[dict]) -> dict:
        """
        Create Vulnerability nodes and AFFECTS edges.

        vuln_data format:
        [
            {
                "package_name": "...",
                "package_version": "...",
                "vulnerabilities": [
                    {
                        "id": "CVE-...",
                        "summary": "...",
                        "severity": "HIGH",
                        "aliases": [...],
                        "references": [...]
                    }
                ]
            }
        ]
        """
        cur = self._conn.cursor()
        vuln_count = 0
        affects_count = 0

        for entry in vuln_data:
            pkg_name = entry["package_name"]
            pkg_version = entry["package_version"]
            pkg_uid = f"{project_id}:{pkg_name}@{pkg_version}"

            for vuln in entry.get("vulnerabilities", []):
                vuln_id = vuln["id"]
                summary = vuln.get("summary", "")
                severity = vuln.get("severity", "UNKNOWN")
                aliases = json.dumps(vuln.get("aliases", []))
                references = json.dumps(vuln.get("references", []))

                cur.execute(
                    "INSERT OR REPLACE INTO vulnerabilities"
                    "(vuln_id, summary, severity, aliases, refs) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (vuln_id, summary, severity, aliases, references),
                )
                vuln_count += 1

                cur.execute(
                    "INSERT OR REPLACE INTO affects(vuln_id, package_uid) "
                    "VALUES (?, ?)",
                    (vuln_id, pkg_uid),
                )
                affects_count += 1

        self._conn.commit()

        return {
            "vulnerabilities_created": vuln_count,
            "affects_edges_created": affects_count,
        }

    def get_full_graph(self, project_id: str) -> dict:
        """
        Return all nodes and edges for a project, formatted for visualization.

        Returns:
        {
            "nodes": [{"data": {"id": ..., "label": ..., "type": ..., ...}}],
            "edges": [{"data": {"source": ..., "target": ..., "type": ...}}]
        }
        """
        cur = self._conn.cursor()

        # Get package nodes with vuln counts per severity
        cur.execute(
            "SELECT p.uid, p.name, p.version, p.ecosystem, "
            "  COUNT(DISTINCT a.vuln_id) AS vuln_count, "
            "  MAX(CASE v.severity "
            "    WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
            "    WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END) AS max_sev, "
            "  SUM(CASE WHEN v.severity='CRITICAL' THEN 1 ELSE 0 END) AS crit, "
            "  SUM(CASE WHEN v.severity='HIGH' THEN 1 ELSE 0 END) AS high, "
            "  SUM(CASE WHEN v.severity='MEDIUM' THEN 1 ELSE 0 END) AS med, "
            "  SUM(CASE WHEN v.severity='LOW' THEN 1 ELSE 0 END) AS low "
            "FROM packages p "
            "LEFT JOIN affects a ON a.package_uid = p.uid "
            "LEFT JOIN vulnerabilities v ON v.vuln_id = a.vuln_id "
            "WHERE p.project_id = ? "
            "GROUP BY p.uid",
            (project_id,),
        )
        sev_map = {4: 'CRITICAL', 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW', 0: None}
        nodes = []
        for row in cur.fetchall():
            vc = row["vuln_count"]
            ms = sev_map.get(row["max_sev"] or 0)
            label = f"{row['name']}@{row['version']}"
            if vc > 0:
                label += f"\n({vc} vuln{'s' if vc != 1 else ''})"
            nodes.append({
                "data": {
                    "id": row["uid"],
                    "label": label,
                    "type": "package",
                    "name": row["name"],
                    "version": row["version"],
                    "ecosystem": row["ecosystem"],
                    "vuln_count": vc,
                    "max_severity": ms,
                    "sev_critical": row["crit"] or 0,
                    "sev_high": row["high"] or 0,
                    "sev_medium": row["med"] or 0,
                    "sev_low": row["low"] or 0,
                }
            })

        # Get vulnerability nodes connected to this project's packages
        cur.execute(
            "SELECT DISTINCT v.vuln_id, v.summary, v.severity "
            "FROM vulnerabilities v "
            "JOIN affects a ON v.vuln_id = a.vuln_id "
            "JOIN packages p ON a.package_uid = p.uid "
            "WHERE p.project_id = ?",
            (project_id,),
        )
        for row in cur.fetchall():
            nodes.append({
                "data": {
                    "id": row["vuln_id"],
                    "label": row["vuln_id"],
                    "type": "vulnerability",
                    "summary": row["summary"],
                    "severity": row["severity"],
                }
            })

        # Get DEPENDS_ON edges
        cur.execute(
            "SELECT d.source_uid, d.target_uid "
            "FROM dependencies d "
            "JOIN packages p1 ON d.source_uid = p1.uid "
            "JOIN packages p2 ON d.target_uid = p2.uid "
            "WHERE p1.project_id = ? AND p2.project_id = ?",
            (project_id, project_id),
        )
        edges = []
        for row in cur.fetchall():
            edges.append({
                "data": {
                    "source": row["source_uid"],
                    "target": row["target_uid"],
                    "type": "DEPENDS_ON",
                }
            })

        # Get AFFECTS edges
        cur.execute(
            "SELECT a.vuln_id, a.package_uid "
            "FROM affects a "
            "JOIN packages p ON a.package_uid = p.uid "
            "WHERE p.project_id = ?",
            (project_id,),
        )
        for row in cur.fetchall():
            edges.append({
                "data": {
                    "source": row["vuln_id"],
                    "target": row["package_uid"],
                    "type": "AFFECTS",
                }
            })

        return {"nodes": nodes, "edges": edges}

    def get_vulnerable_paths(self, project_id: str, cve_id: str) -> list[list[dict]]:
        """
        Find all paths from root packages (packages that nothing depends on)
        to a package affected by a specific CVE.

        Returns a list of paths, where each path is a list of node dicts.
        """
        cur = self._conn.cursor()

        # Build a NetworkX DiGraph from all dependencies in this project
        G = nx.DiGraph()

        # Add all package nodes
        cur.execute(
            "SELECT uid, name, version FROM packages WHERE project_id = ?",
            (project_id,),
        )
        pkg_info = {}
        for row in cur.fetchall():
            uid = row["uid"]
            pkg_info[uid] = {"name": row["name"], "version": row["version"], "uid": uid}
            G.add_node(uid)

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

        # Find target packages affected by this CVE
        cur.execute(
            "SELECT a.package_uid FROM affects a "
            "JOIN packages p ON a.package_uid = p.uid "
            "WHERE a.vuln_id = ? AND p.project_id = ?",
            (cve_id, project_id),
        )
        target_uids = [row["package_uid"] for row in cur.fetchall()]

        if not target_uids:
            return []

        # Find root packages (no incoming DEPENDS_ON edges within this project)
        root_uids = [n for n in G.nodes() if G.in_degree(n) == 0]

        paths = []
        for root_uid in root_uids:
            for target_uid in target_uids:
                if not G.has_node(root_uid) or not G.has_node(target_uid):
                    continue
                for path in nx.all_simple_paths(G, root_uid, target_uid, cutoff=10):
                    path_nodes = [pkg_info[uid] for uid in path if uid in pkg_info]
                    if path_nodes:
                        paths.append(path_nodes)
                    if len(paths) >= 100:
                        break
                if len(paths) >= 100:
                    break
            if len(paths) >= 100:
                break

        return paths

    def get_stats(self, project_id: str) -> dict:
        """Return counts and summary for a project."""
        cur = self._conn.cursor()

        cur.execute(
            "SELECT ecosystem FROM projects WHERE project_id = ?",
            (project_id,),
        )
        row = cur.fetchone()
        if not row:
            return {
                "project_id": project_id,
                "ecosystem": None,
                "package_count": 0,
                "vulnerability_count": 0,
                "dependency_edge_count": 0,
            }

        ecosystem = row["ecosystem"]

        cur.execute(
            "SELECT COUNT(*) AS cnt FROM packages WHERE project_id = ?",
            (project_id,),
        )
        package_count = cur.fetchone()["cnt"]

        cur.execute(
            "SELECT COUNT(DISTINCT v.vuln_id) AS cnt "
            "FROM vulnerabilities v "
            "JOIN affects a ON v.vuln_id = a.vuln_id "
            "JOIN packages p ON a.package_uid = p.uid "
            "WHERE p.project_id = ?",
            (project_id,),
        )
        vulnerability_count = cur.fetchone()["cnt"]

        cur.execute(
            "SELECT COUNT(*) AS cnt "
            "FROM dependencies d "
            "JOIN packages p1 ON d.source_uid = p1.uid "
            "JOIN packages p2 ON d.target_uid = p2.uid "
            "WHERE p1.project_id = ? AND p2.project_id = ?",
            (project_id, project_id),
        )
        dependency_edge_count = cur.fetchone()["cnt"]

        return {
            "project_id": project_id,
            "ecosystem": ecosystem,
            "package_count": package_count,
            "vulnerability_count": vulnerability_count,
            "dependency_edge_count": dependency_edge_count,
        }

    def get_all_projects(self) -> list[dict]:
        """Return all scanned projects."""
        cur = self._conn.cursor()

        cur.execute(
            "SELECT p.project_id, p.ecosystem, p.updated_at, "
            "  (SELECT COUNT(*) FROM packages pkg WHERE pkg.project_id = p.project_id) AS package_count, "
            "  (SELECT COUNT(DISTINCT a.vuln_id) FROM affects a "
            "     JOIN packages pkg2 ON a.package_uid = pkg2.uid "
            "     WHERE pkg2.project_id = p.project_id) AS vulnerability_count "
            "FROM projects p "
            "ORDER BY p.updated_at DESC"
        )

        projects = []
        for row in cur.fetchall():
            projects.append({
                "project_id": row["project_id"],
                "ecosystem": row["ecosystem"],
                "updated_at": row["updated_at"] if row["updated_at"] else None,
                "package_count": row["package_count"],
                "vulnerability_count": row["vulnerability_count"],
            })

        return projects

    def get_all_vulnerabilities(self, project_id: str) -> list[dict]:
        """Return all vulnerabilities found for a project with affected packages."""
        cur = self._conn.cursor()

        cur.execute(
            "SELECT v.vuln_id, v.summary, v.severity, v.aliases, v.refs "
            "FROM vulnerabilities v "
            "WHERE v.vuln_id IN ("
            "  SELECT DISTINCT a.vuln_id FROM affects a "
            "  JOIN packages p ON a.package_uid = p.uid "
            "  WHERE p.project_id = ?"
            ") "
            "ORDER BY CASE v.severity "
            "  WHEN 'CRITICAL' THEN 0 "
            "  WHEN 'HIGH' THEN 1 "
            "  WHEN 'MEDIUM' THEN 2 "
            "  WHEN 'LOW' THEN 3 "
            "  ELSE 4 "
            "END",
            (project_id,),
        )

        vulns = []
        for row in cur.fetchall():
            vuln_id = row["vuln_id"]

            # Get affected packages for this vulnerability in this project
            cur2 = self._conn.cursor()
            cur2.execute(
                "SELECT pkg.name, pkg.version "
                "FROM affects a "
                "JOIN packages pkg ON a.package_uid = pkg.uid "
                "WHERE a.vuln_id = ? AND pkg.project_id = ?",
                (vuln_id, project_id),
            )
            affected_packages = [
                {"name": r["name"], "version": r["version"]}
                for r in cur2.fetchall()
            ]

            aliases_raw = row["aliases"]
            refs_raw = row["refs"]

            vulns.append({
                "id": vuln_id,
                "summary": row["summary"],
                "severity": row["severity"],
                "aliases": json.loads(aliases_raw) if aliases_raw else [],
                "references": json.loads(refs_raw) if refs_raw else [],
                "affected_packages": affected_packages,
            })

        return vulns

    def close(self) -> None:
        """Close the SQLite connection."""
        self._conn.close()
