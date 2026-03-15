"""
Parser for Rust Cargo.lock (TOML format).
"""

import toml


def parse_cargo_lock(content: str) -> list[dict]:
    """
    Parse a Cargo.lock file.

    Each [[package]] entry has:
    - name
    - version
    - source (optional)
    - checksum (optional)
    - dependencies (optional list of strings like "name version (source)")

    Returns a list of package dicts with dependency references.
    """
    try:
        data = toml.loads(content)
    except toml.TomlDecodeError as e:
        raise ValueError(f"Invalid TOML in Cargo.lock: {e}") from e

    raw_packages = data.get("package", [])

    # Build lookup: name -> list of versions (a crate can appear multiple times)
    version_lookup: dict[str, list[str]] = {}
    for pkg in raw_packages:
        name = pkg.get("name", "")
        version = pkg.get("version", "unknown")
        if name:
            version_lookup.setdefault(name, []).append(version)

    packages: list[dict] = []

    for pkg in raw_packages:
        name = pkg.get("name", "")
        version = pkg.get("version", "unknown")

        if not name:
            continue

        dep_refs: list[str] = []
        deps = pkg.get("dependencies", [])

        if isinstance(deps, list):
            for dep_entry in deps:
                dep_name, dep_version = _parse_cargo_dep_string(dep_entry)
                if dep_name:
                    # If no version was in the string, try to resolve from lockfile
                    if dep_version == "unknown":
                        versions = version_lookup.get(dep_name, [])
                        dep_version = versions[0] if len(versions) == 1 else "unknown"
                    dep_refs.append(f"{dep_name}@{dep_version}")

        packages.append({
            "name": name,
            "version": version,
            "dependencies": dep_refs,
        })

    return packages


def _parse_cargo_dep_string(dep_str: str) -> tuple[str, str]:
    """
    Parse a Cargo.lock dependency string.

    Formats:
    - "name version"
    - "name version (source)"
    - "name" (no version)

    Returns (name, version).
    """
    if not isinstance(dep_str, str):
        return ("", "unknown")

    dep_str = dep_str.strip()
    if not dep_str:
        return ("", "unknown")

    # Remove source in parentheses: "serde 1.0.0 (registry+...)"
    paren_idx = dep_str.find(" (")
    if paren_idx != -1:
        dep_str = dep_str[:paren_idx]

    parts = dep_str.split(" ", 1)
    name = parts[0]
    version = parts[1] if len(parts) > 1 else "unknown"

    return name, version
