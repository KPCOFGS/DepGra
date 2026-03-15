# DepGra

Dependency vulnerability tracker that visualizes your software supply chain as an interactive graph.

![DepGra Screenshot](docs/screenshot.png)

## Features

- **4 ecosystem support** — npm, PyPI, Cargo (crates.io), and Go
- **Transitive dependency resolution** — recursively resolves the full dependency tree
- **CVE scanning** — queries OSV.dev for known vulnerabilities across all packages
- **DAG visualization** — interactive dependency graph rendered with Cytoscape.js
- **Risk scoring** — ranks packages by graph centrality and vulnerability exposure

## Quick Start

```bash
# Install
cd backend && uv venv .venv && source .venv/bin/activate && uv pip install -r requirements.txt && cd ..
cd frontend && npm install && npm run build && cd ..

# Run
python run.py
# Open http://127.0.0.1:5000
```

## CLI Usage

```bash
# Scan a lockfile
python run.py scan path/to/package-lock.json

# Fail CI if HIGH or above severity found
python run.py scan requirements.txt --fail-on HIGH

# Export results
python run.py scan Cargo.lock --export json --output results.json
```

## Supported Lockfiles

- `package-lock.json` (npm)
- `Cargo.lock` (crates.io)
- `poetry.lock` (PyPI)
- `requirements.txt` (PyPI)
- `go.mod` (Go)

## Architecture

DepGra is split into a Python backend and a Svelte frontend:

- **Backend** — Flask REST API backed by SQLite for persistence and NetworkX for in-memory graph analysis. Parses lockfiles, resolves transitive dependencies, queries the OSV.dev API for CVE data, and computes risk scores.
- **Frontend** — Svelte single-page application that renders the dependency graph as an interactive DAG using Cytoscape.js. Communicates with the backend via REST endpoints.
- **Data flow** — A lockfile is uploaded (or scanned via CLI), parsed into a package list, ingested into SQLite, enriched with CVE data from OSV.dev, and then served to the frontend for visualization and analysis.

## License

MIT
