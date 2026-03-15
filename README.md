# DepGra

Dependency vulnerability tracker that visualizes your software supply chain as an interactive graph.

<table>
  <tr>
    <td><img src="docs/1.png" width="300"/></td>
    <td><img src="docs/2.png" width="300"/></td>
    <td><img src="docs/3.png" width="300"/></td>
  </tr>
  <tr>
    <td><img src="docs/4.png" width="300"/></td>
    <td><img src="docs/5.png" width="300"/></td>
    <td><img src="docs/6.png" width="300"/></td>
  </tr>
</table>

## Why DepGra?

Software supply chain attacks are one of the fastest-growing security threats. Log4Shell, XZ Utils, and event-stream proved that a single vulnerable dependency buried deep in your tree can compromise everything. Existing tools like `npm audit` or `pip audit` output flat lists — they tell you *what* is vulnerable but not *how* it reaches your project or *which* packages are the riskiest chokepoints.

DepGra exists to fill that gap:

- **Visualize the full dependency tree** as a top-down graph so you can see the path from your code to a vulnerability
- **Surface the packages that matter most** — the ones that sit on the most dependency paths and gateway the most vulnerabilities
- **Work across ecosystems** — one tool for npm, PyPI, Cargo, and Go instead of four separate audit commands
- **Run anywhere** — no Docker, no external database, no cloud account. A single `python run.py` and you're scanning
- **Integrate into CI/CD** — the CLI mode exits non-zero when vulnerabilities exceed a severity threshold, so you can gate merges on supply chain safety

## How DepGra Compares

| Capability | `npm audit` / `pip audit` / `cargo audit` | Snyk (free tier) | DepGra |
|---|---|---|---|
| Multi-ecosystem scanning | One tool per ecosystem | Multiple ecosystems | npm, PyPI, Cargo, Go in one tool |
| Visual dependency graph | No — text output only | Snyk Web UI (SaaS) | Interactive DAG, runs locally in browser |
| Risk ranking by graph position | Sorted by severity only | Priority scoring | Centrality-based — ranks chokepoint packages higher |
| Attack path visualization | No | Dependency paths in web UI | Full path from root to vulnerable package |
| Transitive dependency resolution | Built-in for that ecosystem | Yes | Yes, including PyPI `requirements.txt` |
| CI/CD gating | `npm audit --audit-level`, `pip audit --fail-on`, `cargo audit` | Yes | `--fail-on SEVERITY` for all ecosystems |
| Runs locally | Yes (but queries remote advisory DBs) | CLI runs locally, results on snyk.io | Fully local — UI, data, and analysis |
| Cost | Free and open source | Free (limited scans) + paid plans | Free and open source |

> **Note:** Each tool has strengths. `npm audit` offers `npm audit fix` for auto-remediation. Snyk provides fix PRs, container scanning, and license compliance. DepGra's focus is graph-based risk analysis and cross-ecosystem visualization — it complements rather than replaces ecosystem-specific tools.

## Features

- **4 ecosystem support** — npm, PyPI, Cargo (crates.io), and Go
- **Transitive dependency resolution** — recursively resolves the full dependency tree (including flat `requirements.txt`)
- **CVE scanning** — queries [OSV.dev](https://osv.dev) for known vulnerabilities across all packages
- **DAG visualization** — interactive top-down dependency graph with color-coded vulnerability status per package
- **Risk scoring** — ranks packages by graph centrality and reachable vulnerability severity
- **Severity breakdown** — hover any package to see per-severity counts; click for full CVE details with references
- **Analysis dashboard** — summary statistics, severity charts, risk scores, and full vulnerability details with links

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

# Export results as JSON
python run.py scan Cargo.lock --export json --output results.json

# Export results as CSV
python run.py scan go.mod --export csv --output results.csv
```

## Supported Lockfiles

| File | Ecosystem | Transitive deps |
|---|---|---|
| `package-lock.json` | npm | Yes (from lockfile) |
| `Cargo.lock` | crates.io | Yes (from lockfile) |
| `poetry.lock` | PyPI | Yes (from lockfile) |
| `requirements.txt` | PyPI | Yes (resolved via PyPI API) |
| `go.mod` | Go | Direct + indirect markers |

## Architecture

DepGra is split into a Python backend and a Svelte frontend:

- **Backend** — Flask REST API backed by SQLite for persistence and NetworkX for in-memory graph analysis. Parses lockfiles, resolves transitive dependencies, queries the [OSV.dev](https://osv.dev) API for CVE data, and computes risk scores.
- **Frontend** — Svelte single-page application that renders the dependency graph as an interactive DAG using Cytoscape.js. Communicates with the backend via REST endpoints.
- **Data flow** — A lockfile is uploaded (or scanned via CLI), parsed into a package list, ingested into SQLite, enriched with CVE data from OSV.dev, and then served to the frontend for visualization and analysis.

## Running Tests

```bash
cd backend && source .venv/bin/activate
python -m pytest tests/ -v

# Skip network-dependent tests (OSV.dev API)
python -m pytest tests/ -v -m "not network"
```

## Support

If you find DepGra useful, consider supporting its development:

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-pink?logo=github&logoColor=white)](https://github.com/sponsors/KPCOFGS)

## License

MIT
