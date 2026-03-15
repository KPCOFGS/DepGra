"""Tests for GraphManager (SQLite + NetworkX graph operations)."""

import tempfile
import os

import pytest

from graph import GraphManager


def _make_gm():
    """Create a GraphManager backed by an in-memory SQLite database."""
    return GraphManager(db_path=":memory:")


def _sample_parsed(n_packages=5):
    """Build a small parsed-data dict with a linear dependency chain."""
    packages = []
    for i in range(n_packages):
        deps = []
        if i < n_packages - 1:
            deps.append(f"pkg-{i + 1}@1.0.{i + 1}")
        packages.append({
            "name": f"pkg-{i}",
            "version": f"1.0.{i}",
            "dependencies": deps,
        })
    return {"ecosystem": "npm", "packages": packages}


# ------------------------------------------------------------------

def test_ingest_and_stats():
    gm = _make_gm()
    parsed = _sample_parsed(5)
    result = gm.ingest_dependencies("proj-1", parsed)

    assert result["project_id"] == "proj-1"
    assert result["nodes_created"] == 5
    assert result["edges_created"] == 4  # linear chain

    stats = gm.get_stats("proj-1")
    assert stats["package_count"] == 5
    assert stats["ecosystem"] == "npm"
    assert stats["dependency_edge_count"] == 4
    assert stats["vulnerability_count"] == 0
    gm.close()


def test_attach_vulnerabilities():
    gm = _make_gm()
    parsed = _sample_parsed(3)
    gm.ingest_dependencies("proj-v", parsed)

    vuln_data = [
        {
            "package_name": "pkg-2",
            "package_version": "1.0.2",
            "vulnerabilities": [
                {"id": "CVE-2099-0001", "summary": "Bad bug", "severity": "HIGH"},
                {"id": "CVE-2099-0002", "summary": "Another bug", "severity": "MEDIUM"},
            ],
        }
    ]
    vr = gm.attach_vulnerabilities("proj-v", vuln_data)
    assert vr["vulnerabilities_created"] == 2
    assert vr["affects_edges_created"] == 2

    stats = gm.get_stats("proj-v")
    assert stats["vulnerability_count"] == 2
    gm.close()


def test_get_full_graph():
    gm = _make_gm()
    parsed = _sample_parsed(3)
    gm.ingest_dependencies("proj-g", parsed)

    vuln_data = [
        {
            "package_name": "pkg-1",
            "package_version": "1.0.1",
            "vulnerabilities": [
                {"id": "CVE-2099-0010", "summary": "xss", "severity": "HIGH"},
            ],
        },
    ]
    gm.attach_vulnerabilities("proj-g", vuln_data)

    graph = gm.get_full_graph("proj-g")
    nodes = graph["nodes"]
    edges = graph["edges"]

    # 3 package nodes + 1 vuln node
    pkg_nodes = [n for n in nodes if n["data"]["type"] == "package"]
    vuln_nodes = [n for n in nodes if n["data"]["type"] == "vulnerability"]
    assert len(pkg_nodes) == 3
    assert len(vuln_nodes) == 1

    # vuln_count on the affected package node
    pkg1 = next(n for n in pkg_nodes if n["data"]["name"] == "pkg-1")
    assert pkg1["data"]["vuln_count"] == 1

    # Edge types
    dep_edges = [e for e in edges if e["data"]["type"] == "DEPENDS_ON"]
    aff_edges = [e for e in edges if e["data"]["type"] == "AFFECTS"]
    assert len(dep_edges) == 2
    assert len(aff_edges) == 1
    gm.close()


def test_vulnerable_paths():
    gm = _make_gm()
    # A -> B -> C chain
    parsed = {
        "ecosystem": "npm",
        "packages": [
            {"name": "A", "version": "1.0", "dependencies": ["B@1.0"]},
            {"name": "B", "version": "1.0", "dependencies": ["C@1.0"]},
            {"name": "C", "version": "1.0", "dependencies": []},
        ],
    }
    gm.ingest_dependencies("proj-p", parsed)
    gm.attach_vulnerabilities("proj-p", [
        {
            "package_name": "C",
            "package_version": "1.0",
            "vulnerabilities": [
                {"id": "CVE-PATH-1", "summary": "path vuln", "severity": "CRITICAL"},
            ],
        },
    ])

    paths = gm.get_vulnerable_paths("proj-p", "CVE-PATH-1")
    assert len(paths) >= 1
    # The path should be A -> B -> C
    first_path = paths[0]
    path_names = [n["name"] for n in first_path]
    assert path_names == ["A", "B", "C"]
    gm.close()


def test_clear_project():
    gm = _make_gm()
    parsed = _sample_parsed(3)
    gm.ingest_dependencies("proj-c", parsed)

    stats = gm.get_stats("proj-c")
    assert stats["package_count"] == 3

    gm.clear_project("proj-c")
    stats = gm.get_stats("proj-c")
    assert stats["package_count"] == 0
    assert stats["ecosystem"] is None
    gm.close()


def test_multiple_projects():
    gm = _make_gm()
    parsed_a = {
        "ecosystem": "npm",
        "packages": [
            {"name": "alpha", "version": "1.0", "dependencies": []},
            {"name": "beta", "version": "2.0", "dependencies": []},
        ],
    }
    parsed_b = {
        "ecosystem": "PyPI",
        "packages": [
            {"name": "gamma", "version": "3.0", "dependencies": []},
        ],
    }
    gm.ingest_dependencies("proj-A", parsed_a)
    gm.ingest_dependencies("proj-B", parsed_b)

    stats_a = gm.get_stats("proj-A")
    stats_b = gm.get_stats("proj-B")
    assert stats_a["package_count"] == 2
    assert stats_a["ecosystem"] == "npm"
    assert stats_b["package_count"] == 1
    assert stats_b["ecosystem"] == "PyPI"

    # Clearing one doesn't affect the other
    gm.clear_project("proj-A")
    assert gm.get_stats("proj-A")["package_count"] == 0
    assert gm.get_stats("proj-B")["package_count"] == 1
    gm.close()
