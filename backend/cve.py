"""
CVE fetcher that queries the OSV.dev API for vulnerability data.
"""

import time
import logging
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

from config import Config

logger = logging.getLogger(__name__)


# Mapping from OSV ecosystem names to the names we use internally
_ECOSYSTEM_MAP = {
    "npm": "npm",
    "PyPI": "PyPI",
    "crates.io": "crates.io",
    "Go": "Go",
}


class CVEFetcher:
    """
    Fetches vulnerability data from the OSV.dev API with caching,
    batching, and exponential backoff for rate limiting.
    """

    def __init__(self):
        self._cache: dict[str, list[dict]] = {}
        self._client = httpx.Client(timeout=30.0)
        self._max_retries = Config.OSV_MAX_RETRIES
        self._batch_size = Config.OSV_BATCH_SIZE

    def fetch_vulnerabilities(
        self, ecosystem: str, package_name: str, version: str
    ) -> list[dict]:
        """
        Query OSV.dev for vulnerabilities affecting a single package.

        Returns a list of standardized vulnerability dicts.
        """
        cache_key = f"{ecosystem}:{package_name}@{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        osv_ecosystem = _ECOSYSTEM_MAP.get(ecosystem, ecosystem)

        payload = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": osv_ecosystem,
            },
        }

        data = self._request_with_backoff(Config.OSV_QUERY_URL, payload)

        vulns = []
        for raw_vuln in data.get("vulns", []):
            vulns.append(self._normalize_vuln(raw_vuln))

        self._cache[cache_key] = vulns
        return vulns

    def batch_fetch(self, packages_list: list[dict]) -> list[dict]:
        """
        Efficiently fetch CVEs for all packages using the OSV batch endpoint.

        packages_list: [{"name": "...", "version": "...", "ecosystem": "..."}]

        Returns a list of dicts:
        [
            {
                "package_name": "...",
                "package_version": "...",
                "vulnerabilities": [...]
            }
        ]
        """
        results: list[dict] = []
        uncached_packages: list[dict] = []
        uncached_indices: list[int] = []

        # Check cache first
        for i, pkg in enumerate(packages_list):
            cache_key = f"{pkg['ecosystem']}:{pkg['name']}@{pkg['version']}"
            if cache_key in self._cache:
                results.append({
                    "package_name": pkg["name"],
                    "package_version": pkg["version"],
                    "vulnerabilities": self._cache[cache_key],
                })
            else:
                uncached_packages.append(pkg)
                uncached_indices.append(i)
                # Placeholder
                results.append({
                    "package_name": pkg["name"],
                    "package_version": pkg["version"],
                    "vulnerabilities": [],
                })

        # Batch query uncached packages
        if uncached_packages:
            self._batch_query_uncached(uncached_packages, uncached_indices, results)

        # Filter out entries with no vulnerabilities
        return [r for r in results if r["vulnerabilities"]]

    def _batch_query_uncached(
        self,
        uncached_packages: list[dict],
        uncached_indices: list[int],
        results: list[dict],
    ) -> None:
        """Send batch queries to OSV in chunks."""
        for chunk_start in range(0, len(uncached_packages), self._batch_size):
            chunk_end = min(chunk_start + self._batch_size, len(uncached_packages))
            chunk = uncached_packages[chunk_start:chunk_end]

            queries = []
            for pkg in chunk:
                osv_ecosystem = _ECOSYSTEM_MAP.get(pkg["ecosystem"], pkg["ecosystem"])
                queries.append({
                    "version": pkg["version"],
                    "package": {
                        "name": pkg["name"],
                        "ecosystem": osv_ecosystem,
                    },
                })

            payload = {"queries": queries}

            try:
                data = self._request_with_backoff(Config.OSV_BATCH_URL, payload)
            except Exception as e:
                logger.error("Batch query failed: %s. Falling back to individual queries.", e)
                self._fallback_individual_queries(chunk, chunk_start, uncached_indices, results)
                continue

            batch_results = data.get("results", [])

            # Collect all vuln IDs that need full detail fetching
            all_vuln_ids: set[str] = set()
            for batch_result in batch_results:
                for raw_vuln in batch_result.get("vulns", []):
                    vid = raw_vuln.get("id", "")
                    if vid:
                        all_vuln_ids.add(vid)

            # Fetch all vuln details concurrently
            vuln_detail_cache: dict[str, dict] = {}
            if all_vuln_ids:
                with ThreadPoolExecutor(max_workers=20) as pool:
                    futures = {
                        pool.submit(self._fetch_vuln_details, vid): vid
                        for vid in all_vuln_ids
                    }
                    for fut in as_completed(futures):
                        vid = futures[fut]
                        detail = fut.result()
                        if detail:
                            vuln_detail_cache[vid] = detail

            for j, batch_result in enumerate(batch_results):
                pkg = chunk[j]
                original_idx = uncached_indices[chunk_start + j]

                vulns = []
                for raw_vuln in batch_result.get("vulns", []):
                    vid = raw_vuln.get("id", "")
                    full_vuln = vuln_detail_cache.get(vid)
                    if full_vuln:
                        vulns.append(self._normalize_vuln(full_vuln))
                    else:
                        vulns.append(self._normalize_vuln(raw_vuln))

                cache_key = f"{pkg['ecosystem']}:{pkg['name']}@{pkg['version']}"
                self._cache[cache_key] = vulns

                results[original_idx]["vulnerabilities"] = vulns

    def _fetch_vuln_details(self, vuln_id: str) -> dict | None:
        """Fetch full vulnerability details from OSV.dev by ID."""
        if not vuln_id:
            return None
        try:
            url = f"{Config.OSV_API_URL}/vulns/{vuln_id}"
            response = self._client.get(url)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.warning("Failed to fetch details for %s: %s", vuln_id, e)
        return None

    def _fallback_individual_queries(
        self,
        chunk: list[dict],
        chunk_start: int,
        uncached_indices: list[int],
        results: list[dict],
    ) -> None:
        """If batch query fails, fall back to individual queries."""
        for j, pkg in enumerate(chunk):
            original_idx = uncached_indices[chunk_start + j]
            try:
                vulns = self.fetch_vulnerabilities(
                    pkg["ecosystem"], pkg["name"], pkg["version"]
                )
                results[original_idx]["vulnerabilities"] = vulns
            except Exception as e:
                logger.error(
                    "Individual query failed for %s@%s: %s",
                    pkg["name"], pkg["version"], e,
                )

    def _request_with_backoff(self, url: str, payload: dict) -> dict:
        """
        Make a POST request with exponential backoff on rate limiting
        and transient errors.
        """
        last_exception = None

        for attempt in range(self._max_retries):
            try:
                response = self._client.post(url, json=payload)

                if response.status_code == 200:
                    return response.json()

                if response.status_code == 429 or response.status_code >= 500:
                    # Rate limited or server error -- back off and retry
                    wait_time = min(2 ** attempt * 0.5, 30.0)
                    logger.warning(
                        "OSV API returned %d. Retrying in %.1fs (attempt %d/%d)",
                        response.status_code, wait_time, attempt + 1, self._max_retries,
                    )
                    time.sleep(wait_time)
                    continue

                # Client error (4xx other than 429) -- don't retry
                logger.error(
                    "OSV API returned %d: %s",
                    response.status_code, response.text[:500],
                )
                return {}

            except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as e:
                last_exception = e
                wait_time = min(2 ** attempt * 0.5, 30.0)
                logger.warning(
                    "OSV API request failed: %s. Retrying in %.1fs (attempt %d/%d)",
                    e, wait_time, attempt + 1, self._max_retries,
                )
                time.sleep(wait_time)

        if last_exception:
            raise last_exception
        return {}

    @staticmethod
    def _normalize_vuln(raw: dict) -> dict:
        """
        Convert an OSV vulnerability response into our standardized format.
        """
        vuln_id = raw.get("id", "UNKNOWN")
        summary = raw.get("summary", raw.get("details", "No description available."))

        # Extract severity from database_specific, severity array, or ecosystem_specific
        severity = _extract_severity(raw)

        # Collect aliases (CVE IDs, GHSAs, etc.)
        aliases = raw.get("aliases", [])

        # Collect reference URLs
        references = []
        for ref in raw.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)

        return {
            "id": vuln_id,
            "summary": summary[:500] if summary else "",
            "severity": severity,
            "aliases": aliases,
            "references": references[:10],  # Limit to 10 references
        }

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()


def _extract_severity(vuln: dict) -> str:
    """
    Extract a severity level from an OSV vulnerability entry.
    Checks multiple locations where severity information can live.
    """
    # Check the severity array (CVSS-based)
    severity_list = vuln.get("severity", [])
    if severity_list:
        for sev in severity_list:
            score_str = sev.get("score", "")
            sev_type = sev.get("type", "")

            if sev_type == "CVSS_V3" and score_str:
                # Parse CVSS vector to extract severity
                cvss_severity = _cvss_vector_to_severity(score_str)
                if cvss_severity:
                    return cvss_severity

    # Check database_specific for severity
    db_specific = vuln.get("database_specific", {})
    if isinstance(db_specific, dict):
        sev = db_specific.get("severity", "")
        if isinstance(sev, str) and sev.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return sev.upper()

    # Check ecosystem_specific
    eco_specific = vuln.get("ecosystem_specific", {})
    if isinstance(eco_specific, dict):
        sev = eco_specific.get("severity", "")
        if isinstance(sev, str) and sev.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return sev.upper()

    # Check affected[].ecosystem_specific and database_specific
    for affected in vuln.get("affected", []):
        if isinstance(affected, dict):
            for key in ("ecosystem_specific", "database_specific"):
                specific = affected.get(key, {})
                if isinstance(specific, dict):
                    sev = specific.get("severity", "")
                    if isinstance(sev, str) and sev.upper() in (
                        "CRITICAL", "HIGH", "MEDIUM", "LOW"
                    ):
                        return sev.upper()

    return "UNKNOWN"


def _cvss_vector_to_severity(vector: str) -> str | None:
    """
    Extract severity from a CVSS v3 vector string.
    The vector doesn't directly contain severity, but we can extract
    the base score if present, or infer from attack complexity.

    Common CVSS v3.1 vector format:
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    We compute a rough score from impact metrics.
    """
    if not vector or not vector.startswith("CVSS:"):
        return None

    metrics: dict[str, str] = {}
    parts = vector.split("/")
    for part in parts:
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key] = val

    # Simple heuristic based on confidentiality, integrity, availability impact
    impact_values = {"N": 0, "L": 1, "H": 3}
    score = 0
    for metric_key in ("C", "I", "A"):
        score += impact_values.get(metrics.get(metric_key, "N"), 0)

    # Adjust for attack vector and privileges
    if metrics.get("AV") == "N":  # Network
        score += 2
    if metrics.get("PR") == "N":  # No privileges required
        score += 1
    if metrics.get("AC") == "L":  # Low complexity
        score += 1

    if score >= 10:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"
    return "UNKNOWN"
