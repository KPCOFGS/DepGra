"""
Parsers for Go module files: go.mod and go.sum.
"""

import re


def parse_go_mod(content: str) -> list[dict]:
    """
    Parse a go.mod file.

    Handles:
    - module directive
    - require blocks (both single-line and parenthesized blocks)
    - replace directives (adjusts the resolved module path/version)
    - exclude directives (ignored for dependency tracking)
    - retract directives (ignored)
    - // comments

    Returns a list of package dicts. Go modules don't encode the full
    transitive dependency tree in go.mod (only direct + indirect markers),
    so dependencies lists will be empty.
    """
    # Preserve raw lines so we can detect // indirect markers before stripping
    raw_lines = [raw_line.strip() for raw_line in content.splitlines()]
    lines = []
    for line in raw_lines:
        comment_idx = line.find("//")
        if comment_idx != -1:
            line = line[:comment_idx].strip()
        lines.append(line)

    # Parse replace directives first to build a replacement map
    replace_map: dict[str, tuple[str, str]] = {}
    _parse_replace_directives(lines, replace_map)

    # Parse require directives (pass raw_lines for indirect detection)
    required: list[tuple[str, str, bool]] = []
    _parse_require_directives(lines, raw_lines, required)

    packages: list[dict] = []
    seen: set[str] = set()

    for module_path, version, is_indirect in required:
        # Apply replacements
        replaced_path = module_path
        replaced_version = version

        # Check for exact module@version replacement
        key_exact = f"{module_path}@{version}"
        key_module = module_path

        if key_exact in replace_map:
            replaced_path, replaced_version = replace_map[key_exact]
        elif key_module in replace_map:
            replaced_path, replaced_version = replace_map[key_module]

        # Deduplicate
        pkg_key = f"{replaced_path}@{replaced_version}"
        if pkg_key in seen:
            continue
        seen.add(pkg_key)

        packages.append({
            "name": replaced_path,
            "version": replaced_version,
            "direct": not is_indirect,
            "dependencies": [],  # go.mod doesn't encode dep-of-dep relationships
        })

    return packages


def _parse_require_directives(
    lines: list[str], raw_lines: list[str], required: list[tuple[str, str, bool]]
) -> None:
    """Extract all require directives from pre-processed lines."""
    in_block = False

    for i, line in enumerate(lines):
        raw = raw_lines[i] if i < len(raw_lines) else line
        if not line:
            continue

        # Start of require block
        if line.startswith("require") and "(" in line:
            in_block = True
            after_paren = line.split("(", 1)[1].strip()
            if after_paren and after_paren != ")":
                _parse_require_line(after_paren, required, raw)
            continue

        # End of block
        if in_block and line.startswith(")"):
            in_block = False
            continue

        # Inside require block
        if in_block:
            _parse_require_line(line, required, raw)
            continue

        # Single-line require
        if line.startswith("require ") and "(" not in line:
            remainder = line[len("require "):].strip()
            _parse_require_line(remainder, required, raw)


def _parse_require_line(line: str, required: list[tuple[str, str, bool]], raw_line: str = "") -> None:
    """Parse a single require line like 'github.com/foo/bar v1.2.3 // indirect'."""
    line = line.strip()
    if not line or line.startswith(")"):
        return

    # Check for indirect marker from the raw line (before comment stripping)
    is_indirect = "// indirect" in raw_line.lower() if raw_line else False

    parts = line.split()
    if len(parts) >= 2:
        module_path = parts[0]
        version = parts[1]
        # Clean version: remove +incompatible suffix for our purposes
        version = version.split("+")[0] if "+" in version else version
        required.append((module_path, version, is_indirect))


def _parse_replace_directives(
    lines: list[str], replace_map: dict[str, tuple[str, str]]
) -> None:
    """Extract replace directives and build a replacement map."""
    in_block = False

    for line in lines:
        if not line:
            continue

        if line.startswith("replace") and "(" in line:
            in_block = True
            after_paren = line.split("(", 1)[1].strip()
            if after_paren and after_paren != ")":
                _parse_replace_line(after_paren, replace_map)
            continue

        if in_block and line.startswith(")"):
            in_block = False
            continue

        if in_block:
            _parse_replace_line(line, replace_map)
            continue

        if line.startswith("replace ") and "(" not in line:
            remainder = line[len("replace "):].strip()
            _parse_replace_line(remainder, replace_map)


def _parse_replace_line(
    line: str, replace_map: dict[str, tuple[str, str]]
) -> None:
    """
    Parse a single replace line:
    - module/path v1.0.0 => other/path v2.0.0
    - module/path => ../local/path
    """
    line = line.strip()
    if "=>" not in line:
        return

    left, right = line.split("=>", 1)
    left_parts = left.strip().split()
    right_parts = right.strip().split()

    if not left_parts or not right_parts:
        return

    old_module = left_parts[0]
    old_version = left_parts[1] if len(left_parts) > 1 else None

    new_module = right_parts[0]
    new_version = right_parts[1] if len(right_parts) > 1 else "local"

    # Store with version-specific key if version was given
    if old_version:
        replace_map[f"{old_module}@{old_version}"] = (new_module, new_version)
    replace_map[old_module] = (new_module, new_version)


def parse_go_sum(content: str) -> list[dict]:
    """
    Parse a go.sum file for version verification.

    Each line format: module/path version hash
    Lines with /go.mod suffix are module metadata, not the source itself.

    Returns deduplicated list of package dicts. go.sum doesn't encode
    dependency relationships, so dependencies lists will be empty.
    """
    packages: list[dict] = []
    seen: set[str] = set()

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        module_path = parts[0]
        version = parts[1]

        # Skip /go.mod entries (duplicates of the source entry)
        if version.endswith("/go.mod"):
            continue

        # Clean version
        version = version.split("+")[0] if "+" in version else version

        pkg_key = f"{module_path}@{version}"
        if pkg_key in seen:
            continue
        seen.add(pkg_key)

        packages.append({
            "name": module_path,
            "version": version,
            "dependencies": [],
        })

    return packages
