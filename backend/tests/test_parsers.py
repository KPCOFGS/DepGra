"""Tests for all lockfile parsers dispatched through parsers.parse_lockfile."""

import json
import os
import tempfile

import pytest

from parsers import parse_lockfile, UnsupportedLockfileError


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

def _write_tmp(filename: str, content: str) -> str:
    """Write *content* to a temp file whose basename is *filename*."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, filename)
    with open(path, "w") as f:
        f.write(content)
    return path


PACKAGE_LOCK_V3 = json.dumps({
    "name": "my-app",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "my-app", "version": "1.0.0",
             "dependencies": {"express": "^4.18.0"}},
        "node_modules/express": {
            "version": "4.18.2",
            "dependencies": {"accepts": "~1.3.8", "body-parser": "1.20.1"},
        },
        "node_modules/accepts": {"version": "1.3.8"},
        "node_modules/body-parser": {"version": "1.20.1"},
        "node_modules/express/node_modules/debug": {
            "version": "2.6.9",
        },
    },
})


def test_npm_v3():
    path = _write_tmp("package-lock.json", PACKAGE_LOCK_V3)
    result = parse_lockfile(path)

    assert result["ecosystem"] == "npm"
    pkgs = result["packages"]
    names = {p["name"] for p in pkgs}
    assert "express" in names
    assert "accepts" in names
    assert "body-parser" in names
    assert "debug" in names

    express = next(p for p in pkgs if p["name"] == "express")
    assert express["version"] == "4.18.2"
    # express depends on accepts and body-parser
    dep_names = [d.split("@")[0] for d in express["dependencies"]]
    assert "accepts" in dep_names
    assert "body-parser" in dep_names


PACKAGE_LOCK_V1 = json.dumps({
    "name": "legacy-app",
    "version": "0.1.0",
    "lockfileVersion": 1,
    "dependencies": {
        "lodash": {
            "version": "4.17.21",
            "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        },
        "express": {
            "version": "4.17.1",
            "requires": {"accepts": "~1.3.7"},
            "dependencies": {
                "accepts": {
                    "version": "1.3.7",
                },
            },
        },
    },
})


def test_npm_v1():
    path = _write_tmp("package-lock.json", PACKAGE_LOCK_V1)
    result = parse_lockfile(path)

    assert result["ecosystem"] == "npm"
    pkgs = result["packages"]
    names = [p["name"] for p in pkgs]
    assert "lodash" in names
    assert "express" in names
    # nested accepts should also appear
    assert "accepts" in names

    express = next(p for p in pkgs if p["name"] == "express")
    assert express["version"] == "4.17.1"
    dep_names = [d.split("@")[0] for d in express["dependencies"]]
    assert "accepts" in dep_names


# ---------------------------------------------------------------------------
# Cargo
# ---------------------------------------------------------------------------

CARGO_LOCK = """\
[[package]]
name = "my-crate"
version = "0.1.0"
dependencies = [
    "serde 1.0.193",
    "tokio 1.35.0 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.35.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
    "pin-project-lite 0.2.13",
]

[[package]]
name = "pin-project-lite"
version = "0.2.13"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""


def test_cargo():
    path = _write_tmp("Cargo.lock", CARGO_LOCK)
    result = parse_lockfile(path)

    assert result["ecosystem"] == "crates.io"
    pkgs = result["packages"]
    names = {p["name"] for p in pkgs}
    assert {"my-crate", "serde", "tokio", "pin-project-lite"} == names

    my_crate = next(p for p in pkgs if p["name"] == "my-crate")
    dep_names = [d.split("@")[0] for d in my_crate["dependencies"]]
    assert "serde" in dep_names
    assert "tokio" in dep_names

    tokio = next(p for p in pkgs if p["name"] == "tokio")
    dep_names_tokio = [d.split("@")[0] for d in tokio["dependencies"]]
    assert "pin-project-lite" in dep_names_tokio


# ---------------------------------------------------------------------------
# pip / requirements.txt
# ---------------------------------------------------------------------------

REQUIREMENTS_TXT = """\
# This is a comment
flask==2.3.3
requests[security]>=2.28.0,<3.0
numpy==1.24.0  # inline comment
-r base.txt
pytest~=7.4.0
pandas ; python_version >= '3.8'
"""


def test_pip_requirements():
    path = _write_tmp("requirements.txt", REQUIREMENTS_TXT)
    result = parse_lockfile(path)

    assert result["ecosystem"] == "PyPI"
    pkgs = result["packages"]
    names = {p["name"] for p in pkgs}
    assert "flask" in names
    assert "requests" in names
    assert "numpy" in names
    assert "pytest" in names
    assert "pandas" in names

    flask = next(p for p in pkgs if p["name"] == "flask")
    assert flask["version"] == "2.3.3"

    requests_pkg = next(p for p in pkgs if p["name"] == "requests")
    assert requests_pkg["version"] == "2.28.0"

    # requirements.txt has no transitive dep info
    assert all(p["dependencies"] == [] for p in pkgs)


# ---------------------------------------------------------------------------
# pip / poetry.lock
# ---------------------------------------------------------------------------

POETRY_LOCK = """\
[[package]]
name = "Flask"
version = "2.3.3"

[package.dependencies]
Werkzeug = ">=2.3.7"
Jinja2 = ">=3.1.2"

[[package]]
name = "Werkzeug"
version = "3.0.1"

[[package]]
name = "Jinja2"
version = "3.1.2"

[package.dependencies]
MarkupSafe = ">=2.0"

[[package]]
name = "MarkupSafe"
version = "2.1.3"
"""


def test_pip_poetry():
    path = _write_tmp("poetry.lock", POETRY_LOCK)
    result = parse_lockfile(path)

    assert result["ecosystem"] == "PyPI"
    pkgs = result["packages"]
    names = {p["name"] for p in pkgs}
    assert "flask" in names
    assert "werkzeug" in names
    assert "jinja2" in names
    assert "markupsafe" in names

    flask = next(p for p in pkgs if p["name"] == "flask")
    assert flask["version"] == "2.3.3"
    dep_names = [d.split("@")[0] for d in flask["dependencies"]]
    assert "werkzeug" in dep_names
    assert "jinja2" in dep_names

    jinja2 = next(p for p in pkgs if p["name"] == "jinja2")
    dep_names_j = [d.split("@")[0] for d in jinja2["dependencies"]]
    assert "markupsafe" in dep_names_j


# ---------------------------------------------------------------------------
# Go mod
# ---------------------------------------------------------------------------

GO_MOD = """\
module github.com/myorg/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/lib/pq v1.10.9 // indirect
    golang.org/x/text v0.14.0
)

require github.com/stretchr/testify v1.8.4

replace golang.org/x/text v0.14.0 => golang.org/x/text v0.15.0
"""


def test_gomod():
    path = _write_tmp("go.mod", GO_MOD)
    result = parse_lockfile(path)

    assert result["ecosystem"] == "Go"
    pkgs = result["packages"]
    names = {p["name"] for p in pkgs}
    assert "github.com/gin-gonic/gin" in names
    assert "github.com/lib/pq" in names
    assert "github.com/stretchr/testify" in names

    # replace directive should rewrite golang.org/x/text to v0.15.0
    text_pkg = next(p for p in pkgs if p["name"] == "golang.org/x/text")
    assert text_pkg["version"] == "v0.15.0"


def test_gomod_indirect():
    path = _write_tmp("go.mod", GO_MOD)
    result = parse_lockfile(path)
    pkgs = result["packages"]

    pq = next(p for p in pkgs if p["name"] == "github.com/lib/pq")
    assert pq["direct"] is False

    gin = next(p for p in pkgs if p["name"] == "github.com/gin-gonic/gin")
    assert gin["direct"] is True

    testify = next(p for p in pkgs if p["name"] == "github.com/stretchr/testify")
    assert testify["direct"] is True


# ---------------------------------------------------------------------------
# Unsupported file
# ---------------------------------------------------------------------------

def test_unsupported_file():
    path = _write_tmp("unknown.lock", "whatever")
    with pytest.raises(UnsupportedLockfileError):
        parse_lockfile(path)
