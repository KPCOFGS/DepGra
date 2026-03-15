"""Tests for GraphAnalyzer (risk scoring, attack paths, summaries)."""

import pytest

from graph import GraphManager
from analysis import GraphAnalyzer


PROJECT = "analysis-test"


def _seed_db(db_path: str):
    """
    Create a small graph in a shared db:

        A -> B -> C (vuln HIGH)
        A -> D (vuln CRITICAL)
        B -> D
    """
    gm = GraphManager(db_path=db_path)
    parsed = {
        "ecosystem": "npm",
        "packages": [
            {"name": "A", "version": "1.0", "dependencies": ["B@1.0", "D@1.0"]},
            {"name": "B", "version": "1.0", "dependencies": ["C@1.0", "D@1.0"]},
            {"name": "C", "version": "1.0", "dependencies": []},
            {"name": "D", "version": "1.0", "dependencies": []},
        ],
    }
    gm.ingest_dependencies(PROJECT, parsed)
    gm.attach_vulnerabilities(PROJECT, [
        {
            "package_name": "C",
            "package_version": "1.0",
            "vulnerabilities": [
                {"id": "CVE-C-1", "summary": "C is bad", "severity": "HIGH"},
            ],
        },
        {
            "package_name": "D",
            "package_version": "1.0",
            "vulnerabilities": [
                {"id": "CVE-D-1", "summary": "D is worse", "severity": "CRITICAL"},
            ],
        },
    ])
    gm.close()


@pytest.fixture(scope="module")
def db_path(tmp_path_factory):
    """Create a temp SQLite file shared across all tests in this module."""
    p = str(tmp_path_factory.mktemp("analysis") / "test.db")
    _seed_db(p)
    return p


@pytest.fixture
def analyzer(db_path):
    a = GraphAnalyzer(db_path=db_path)
    yield a
    a.close()


# ------------------------------------------------------------------


def test_shortest_paths(analyzer):
    paths = analyzer.find_shortest_attack_paths(PROJECT, "CVE-C-1")
    assert len(paths) >= 1
    # shortest path to C is A -> B -> C
    shortest = paths[0]
    names = [n["name"] for n in shortest]
    assert names == ["A", "B", "C"]


def test_risk_scores(analyzer):
    scores = analyzer.calculate_risk_scores(PROJECT)
    assert isinstance(scores, list)
    assert len(scores) > 0
    # Scores should be sorted descending
    for i in range(len(scores) - 1):
        assert scores[i]["risk_score"] >= scores[i + 1]["risk_score"]
    # Every entry has required fields
    for s in scores:
        assert "name" in s
        assert "risk_score" in s
        assert "reachable_vulnerabilities" in s


def test_critical_packages(analyzer):
    critical = analyzer.get_most_critical_packages(PROJECT)
    assert isinstance(critical, list)
    assert len(critical) > 0
    # Each entry has downstream_vulnerability_count > 0
    for c in critical:
        assert c["downstream_vulnerability_count"] > 0
        assert "name" in c
        assert "severities" in c


def test_vulnerability_summary(analyzer):
    summary = analyzer.get_vulnerability_summary(PROJECT)
    assert summary["project_id"] == PROJECT
    assert summary["total_vulnerabilities"] == 2

    breakdown = summary["severity_breakdown"]
    assert isinstance(breakdown, dict)
    assert breakdown.get("HIGH", 0) >= 1
    assert breakdown.get("CRITICAL", 0) >= 1

    assert summary["overall_risk_level"] == "CRITICAL"
    assert summary["total_packages"] == 4
    assert summary["vulnerable_packages"] == 2
