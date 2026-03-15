"""Tests for CVEFetcher (OSV.dev integration)."""

import pytest

from cve import CVEFetcher


# Mark all network tests so they can be skipped with:  pytest -m "not network"
pytestmark = pytest.mark.network


@pytest.fixture
def fetcher():
    f = CVEFetcher()
    yield f
    f.close()


def test_fetch_known_vulnerable(fetcher):
    """express@4.17.1 has known CVEs reported in OSV."""
    vulns = fetcher.fetch_vulnerabilities("npm", "express", "4.17.1")
    assert isinstance(vulns, list)
    assert len(vulns) >= 1

    v = vulns[0]
    assert "id" in v
    assert "severity" in v
    assert "summary" in v
    assert isinstance(v["id"], str)
    assert len(v["id"]) > 0


def test_fetch_clean_package(fetcher):
    """A made-up package name should return no vulns."""
    vulns = fetcher.fetch_vulnerabilities(
        "npm", "zzzz-nonexistent-pkg-12345", "0.0.1"
    )
    assert vulns == []


def test_batch_fetch(fetcher):
    """Batch-query two packages, one known-vulnerable."""
    packages = [
        {"name": "express", "version": "4.17.1", "ecosystem": "npm"},
        {"name": "zzzz-nonexistent-pkg-12345", "version": "0.0.1", "ecosystem": "npm"},
    ]
    results = fetcher.batch_fetch(packages)
    assert isinstance(results, list)
    # At least express should produce results; clean one is filtered out
    vuln_names = {r["package_name"] for r in results}
    assert "express" in vuln_names


def test_normalize_vuln():
    """Test the static _normalize_vuln helper with synthetic data."""
    raw = {
        "id": "GHSA-1234-5678",
        "summary": "A test vulnerability",
        "aliases": ["CVE-2099-9999"],
        "references": [
            {"url": "https://example.com/advisory/1"},
            {"url": "https://example.com/advisory/2"},
        ],
        "database_specific": {"severity": "HIGH"},
    }
    result = CVEFetcher._normalize_vuln(raw)
    assert result["id"] == "GHSA-1234-5678"
    assert result["severity"] == "HIGH"
    assert result["summary"] == "A test vulnerability"
    assert "CVE-2099-9999" in result["aliases"]
    assert "https://example.com/advisory/1" in result["references"]
