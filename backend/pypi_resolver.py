"""
Resolve transitive dependencies for PyPI packages by querying the PyPI JSON API.
Uses concurrent requests for speed.
"""

import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

logger = logging.getLogger(__name__)

_MAX_WORKERS = 20


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _extract_dep_name(req_str: str) -> str | None:
    """Extract package name from a PEP 508 requirement string."""
    m = re.match(r"^([A-Za-z0-9_.-]+)", req_str.strip())
    if m:
        return _normalize_name(m.group(1))
    return None


def _parse_requires_dist(requires: list[str]) -> list[str]:
    """Extract non-extra dependency names from requires_dist."""
    dep_names = []
    for req in requires:
        if "extra ==" in req or "extra==" in req:
            continue
        dep = _extract_dep_name(req)
        if dep:
            dep_names.append(dep)
    return dep_names


def _fetch_package_info(client: httpx.Client, name: str, version: str) -> tuple[str, list[str]]:
    """Fetch deps for a specific version. Returns (normalized_name, [dep_names])."""
    try:
        resp = client.get(f"https://pypi.org/pypi/{name}/{version}/json")
        if resp.status_code != 200:
            return (_normalize_name(name), [])
        data = resp.json()
        requires = data.get("info", {}).get("requires_dist") or []
        return (_normalize_name(name), _parse_requires_dist(requires))
    except Exception as e:
        logger.warning("Failed to fetch PyPI info for %s@%s: %s", name, version, e)
        return (_normalize_name(name), [])


def _fetch_latest_version(client: httpx.Client, name: str) -> str:
    """Fetch the latest version of a package from PyPI."""
    try:
        resp = client.get(f"https://pypi.org/pypi/{name}/json")
        if resp.status_code != 200:
            return "unknown"
        return resp.json().get("info", {}).get("version", "unknown")
    except Exception:
        return "unknown"


def resolve_pypi_deps(packages: list[dict], max_depth: int = 3) -> list[dict]:
    """
    Resolve transitive dependencies concurrently via PyPI JSON API.
    BFS by depth level, each level fetched in parallel.
    """
    known: dict[str, dict] = {}
    for pkg in packages:
        known[_normalize_name(pkg["name"])] = pkg

    queue = list(known.keys())
    visited: set[str] = set()

    client = httpx.Client(timeout=10.0, limits=httpx.Limits(max_connections=_MAX_WORKERS))

    try:
        for depth in range(max_depth):
            if not queue:
                break

            # Filter to unvisited
            to_resolve = [n for n in queue if n not in visited]
            if not to_resolve:
                break

            visited.update(to_resolve)

            # Fetch all deps for this level concurrently
            dep_results: dict[str, list[str]] = {}
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = {}
                for pkg_name in to_resolve:
                    pkg = known.get(pkg_name)
                    if not pkg or pkg["version"] == "unknown":
                        continue
                    fut = pool.submit(_fetch_package_info, client, pkg["name"], pkg["version"])
                    futures[fut] = pkg_name

                for fut in as_completed(futures):
                    norm_name, deps = fut.result()
                    dep_results[norm_name] = deps

            # Collect new packages we need to discover versions for
            new_names: set[str] = set()
            for pkg_name, deps in dep_results.items():
                for dep in deps:
                    norm = _normalize_name(dep)
                    if norm not in known and norm != pkg_name:
                        new_names.add(norm)

            # Fetch versions for all new packages concurrently
            if new_names:
                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    version_futures = {
                        pool.submit(_fetch_latest_version, client, name): name
                        for name in new_names
                    }
                    for fut in as_completed(version_futures):
                        name = version_futures[fut]
                        version = fut.result()
                        known[name] = {
                            "name": name,
                            "version": version,
                            "dependencies": [],
                        }

            # Now wire up dependency refs
            next_queue = []
            for pkg_name, deps in dep_results.items():
                dep_refs = []
                for dep in deps:
                    norm = _normalize_name(dep)
                    if norm == pkg_name or norm not in known:
                        continue
                    dep_refs.append(f"{norm}@{known[norm]['version']}")
                    if norm not in visited:
                        next_queue.append(norm)
                known[pkg_name]["dependencies"] = dep_refs

            queue = next_queue

    finally:
        client.close()

    return list(known.values())
