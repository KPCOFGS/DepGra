"""
Parser for npm package-lock.json (lockfileVersion 1, 2, and 3).
"""

import json
from typing import Any


def _parse_v2_v3_packages(data: dict) -> list[dict]:
    """
    Parse the 'packages' field used in lockfileVersion 2 and 3.
    Keys are paths like '' (root), 'node_modules/express',
    'node_modules/express/node_modules/debug', etc.
    """
    packages_section = data.get("packages", {})
    result: list[dict] = []

    # Build a lookup: package_path -> (name, version)
    path_info: dict[str, tuple[str, str]] = {}
    for path, info in packages_section.items():
        if path == "":
            # Root project entry; skip it as a dependency but note its deps
            continue
        # Extract name: last segment after node_modules/
        parts = path.split("node_modules/")
        name = parts[-1] if parts else path
        version = info.get("version", "unknown")
        path_info[path] = (name, version)

    # Now build each package entry with its dependencies
    for path, info in packages_section.items():
        if path == "":
            continue

        name, version = path_info[path]

        # Collect all dependency references
        dep_names: list[str] = []
        all_deps: dict[str, str] = {}
        for dep_key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = info.get(dep_key, {})
            if isinstance(deps, dict):
                all_deps.update(deps)

        # Resolve each dependency name to an actual installed version
        for dep_name in all_deps:
            resolved_version = _resolve_dep_version(
                packages_section, path, dep_name
            )
            dep_names.append(f"{dep_name}@{resolved_version}")

        result.append({
            "name": name,
            "version": version,
            "dependencies": dep_names,
        })

    return result


def _resolve_dep_version(
    packages_section: dict, parent_path: str, dep_name: str
) -> str:
    """
    Resolve the installed version of a dependency by walking up the
    node_modules tree (npm's nested resolution algorithm).
    """
    # Start from the deepest scope and walk up
    # parent_path example: 'node_modules/express'
    # Look for: 'node_modules/express/node_modules/dep_name'
    # Then: 'node_modules/dep_name'

    segments = parent_path.split("node_modules/")
    # Rebuild possible resolution paths from deepest to shallowest
    for i in range(len(segments) - 1, -1, -1):
        prefix = "node_modules/".join(segments[: i + 1])
        if prefix and not prefix.endswith("/"):
            candidate = f"{prefix}/node_modules/{dep_name}"
        else:
            candidate = f"node_modules/{dep_name}"

        if candidate in packages_section:
            return packages_section[candidate].get("version", "unknown")

    # Fallback: try the top-level
    top_level = f"node_modules/{dep_name}"
    if top_level in packages_section:
        return packages_section[top_level].get("version", "unknown")

    return "unknown"


def _parse_v1_dependencies(data: dict) -> list[dict]:
    """
    Parse the 'dependencies' field used in lockfileVersion 1.
    This is a nested structure where each dependency can itself
    contain a 'dependencies' field for nested versions.
    """
    result: list[dict] = []
    dependencies = data.get("dependencies", {})
    _walk_v1_deps(dependencies, result)
    return result


def _walk_v1_deps(deps: dict, result: list[dict], prefix: str = "") -> None:
    """Recursively walk v1 dependency tree."""
    for name, info in deps.items():
        version = info.get("version", "unknown")

        # Collect requires as dependency references
        dep_refs: list[str] = []
        requires = info.get("requires", {})
        if isinstance(requires, dict):
            for req_name, req_version_range in requires.items():
                # In v1, 'requires' has semver ranges, not exact versions.
                # We resolve from the nested or top-level deps.
                dep_refs.append(f"{req_name}@{req_version_range}")

        result.append({
            "name": name,
            "version": version,
            "dependencies": dep_refs,
        })

        # Recurse into nested dependencies
        nested = info.get("dependencies", {})
        if nested:
            _walk_v1_deps(nested, result)


def parse_package_lock(content: str) -> list[dict]:
    """
    Parse a package-lock.json file content string.
    Supports lockfileVersion 1, 2, and 3.

    Returns a list of package dicts:
    [{"name": "...", "version": "...", "dependencies": ["name@version", ...]}]
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in package-lock.json: {e}") from e

    lockfile_version = data.get("lockfileVersion", 1)

    if lockfile_version in (2, 3):
        # v2 and v3 both use the 'packages' field
        if "packages" in data:
            return _parse_v2_v3_packages(data)
        # v2 may also have 'dependencies' as fallback
        if "dependencies" in data:
            return _parse_v1_dependencies(data)
        return []
    elif lockfile_version == 1:
        return _parse_v1_dependencies(data)
    else:
        # Unknown version, try both approaches
        if "packages" in data:
            return _parse_v2_v3_packages(data)
        if "dependencies" in data:
            return _parse_v1_dependencies(data)
        return []
