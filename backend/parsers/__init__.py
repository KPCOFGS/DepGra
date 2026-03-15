"""
Parser registry that auto-detects lockfile type from filename and dispatches
to the appropriate ecosystem parser.
"""

import os
from typing import Any

from parsers.npm import parse_package_lock
from parsers.pip import parse_requirements_txt, parse_poetry_lock
from parsers.cargo import parse_cargo_lock
from parsers.gomod import parse_go_mod, parse_go_sum

# Maps filename -> (parser_function, ecosystem)
_REGISTRY: dict[str, tuple[Any, str]] = {
    "package-lock.json": (parse_package_lock, "npm"),
    "requirements.txt": (parse_requirements_txt, "PyPI"),
    "poetry.lock": (parse_poetry_lock, "PyPI"),
    "Cargo.lock": (parse_cargo_lock, "crates.io"),
    "go.mod": (parse_go_mod, "Go"),
    "go.sum": (parse_go_sum, "Go"),
}

SUPPORTED_FILES = list(_REGISTRY.keys())


class UnsupportedLockfileError(Exception):
    """Raised when a lockfile type is not recognized."""
    pass


def detect_lockfile_type(filepath: str) -> str:
    """Return the basename if it matches a known lockfile, else raise."""
    basename = os.path.basename(filepath)
    if basename not in _REGISTRY:
        raise UnsupportedLockfileError(
            f"Unsupported lockfile: {basename}. "
            f"Supported types: {', '.join(SUPPORTED_FILES)}"
        )
    return basename


def parse_lockfile(filepath: str) -> dict:
    """
    Auto-detect lockfile type from filename, parse it, and return a
    standardized structure:

    {
        "ecosystem": "npm",
        "packages": [
            {
                "name": "express",
                "version": "4.18.2",
                "dependencies": ["accepts@1.3.8", "body-parser@1.20.1"]
            }
        ]
    }
    """
    basename = detect_lockfile_type(filepath)
    parser_fn, ecosystem = _REGISTRY[basename]

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    packages = parser_fn(content)

    return {
        "ecosystem": ecosystem,
        "packages": packages,
    }
