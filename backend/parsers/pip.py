"""
Parser for Python dependency files:
- requirements.txt (pinned versions, comments, -r includes)
- poetry.lock (TOML format with full dependency tree)
"""

import os
import re
from typing import Any

import toml


def parse_requirements_txt(content: str) -> list[dict]:
    """
    Parse a requirements.txt file.

    Handles:
    - Pinned versions: package==1.0.0
    - Minimum versions: package>=1.0.0
    - Compatible release: package~=1.0.0
    - Comments (# ...)
    - Blank lines
    - Inline comments
    - -r / --requirement includes (noted but not followed since we only have content)
    - -e / --editable installs
    - Extras: package[extra]==1.0.0
    - Environment markers: package==1.0.0 ; python_version >= '3.8'

    Since requirements.txt does not encode transitive dependencies,
    all packages are marked as direct-only with empty dependency lists.
    """
    packages: list[dict] = []
    seen: set[str] = set()

    for raw_line in content.splitlines():
        line = raw_line.strip()

        # Skip empty lines
        if not line:
            continue

        # Skip pure comment lines
        if line.startswith("#"):
            continue

        # Skip options/flags like -r, --requirement, -i, --index-url, etc.
        if line.startswith("-"):
            continue

        # Remove inline comments
        if " #" in line:
            line = line[: line.index(" #")].strip()

        # Remove environment markers (after ;)
        if ";" in line:
            line = line[: line.index(";")].strip()

        # Remove extras notation for name extraction but keep for reference
        # e.g., requests[security]==2.28.0
        name, version = _extract_name_version(line)

        if not name:
            continue

        # Normalize name (PEP 503)
        normalized = _normalize_name(name)

        if normalized in seen:
            continue
        seen.add(normalized)

        packages.append({
            "name": normalized,
            "version": version,
            "dependencies": [],  # requirements.txt has no transitive dep info
        })

    return packages


def _extract_name_version(spec: str) -> tuple[str, str]:
    """
    Extract package name and version from a pip requirement specifier.
    Returns (name, version). Version may be 'unknown' if not pinned.
    """
    # Strip extras like [security]
    base = re.sub(r"\[.*?\]", "", spec).strip()

    # Try various version specifiers
    for op in ("===", "==", "~=", "!=", ">=", "<=", ">", "<"):
        if op in base:
            parts = base.split(op, 1)
            name = parts[0].strip()
            version_part = parts[1].strip()
            # Remove additional constraints like >=1.0,<2.0 — take only the first version
            if "," in version_part:
                version_part = version_part.split(",")[0].strip()
            return name, version_part
    # No version specifier
    return base.strip(), "unknown"


def _normalize_name(name: str) -> str:
    """Normalize package name per PEP 503: lowercase, replace [-_.] with -."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_poetry_lock(content: str) -> list[dict]:
    """
    Parse a poetry.lock file (TOML format).

    Each [[package]] entry contains:
    - name
    - version
    - [package.dependencies] with dependency names and version constraints

    Returns a list of package dicts with resolved dependency references.
    """
    try:
        data = toml.loads(content)
    except toml.TomlDecodeError as e:
        raise ValueError(f"Invalid TOML in poetry.lock: {e}") from e

    raw_packages = data.get("package", [])

    # Build a lookup for name -> version (use the first/only version found)
    version_lookup: dict[str, str] = {}
    for pkg in raw_packages:
        name = _normalize_name(pkg.get("name", ""))
        version = pkg.get("version", "unknown")
        if name:
            version_lookup[name] = version

    packages: list[dict] = []

    for pkg in raw_packages:
        name = _normalize_name(pkg.get("name", ""))
        version = pkg.get("version", "unknown")

        if not name:
            continue

        # Extract dependencies
        dep_refs: list[str] = []
        deps = pkg.get("dependencies", {})

        if isinstance(deps, dict):
            for dep_name, dep_constraint in deps.items():
                norm_dep = _normalize_name(dep_name)

                # Skip python version constraints
                if norm_dep == "python":
                    continue

                # Resolve to installed version from the lockfile
                dep_version = version_lookup.get(norm_dep, "unknown")
                dep_refs.append(f"{norm_dep}@{dep_version}")

        packages.append({
            "name": name,
            "version": version,
            "dependencies": dep_refs,
        })

    return packages
