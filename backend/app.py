"""
Flask REST API for the Dependency Graph Vulnerability Tracker.
"""

import os
import uuid
import logging
import tempfile
from functools import wraps
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from config import Config
from parsers import parse_lockfile, UnsupportedLockfileError, SUPPORTED_FILES
from graph import GraphManager
from cve import CVEFetcher
from analysis import GraphAnalyzer
from pypi_resolver import resolve_pypi_deps

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Serve frontend static files from ../frontend/dist
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend" / "dist"

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH
CORS(app)

# Lazy-initialized singletons
_graph_manager: GraphManager | None = None
_cve_fetcher: CVEFetcher | None = None
_analyzer: GraphAnalyzer | None = None


def get_graph_manager() -> GraphManager:
    global _graph_manager
    if _graph_manager is None:
        _graph_manager = GraphManager()
    return _graph_manager


def get_cve_fetcher() -> CVEFetcher:
    global _cve_fetcher
    if _cve_fetcher is None:
        _cve_fetcher = CVEFetcher()
    return _cve_fetcher


def get_analyzer() -> GraphAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = GraphAnalyzer()
    return _analyzer


def handle_errors(f):
    """Decorator for consistent error handling on all endpoints."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except UnsupportedLockfileError as e:
            return jsonify({"error": str(e)}), 400
        except ValueError as e:
            return jsonify({"error": f"Invalid input: {e}"}), 400
        except FileNotFoundError as e:
            return jsonify({"error": f"File not found: {e}"}), 404
        except Exception as e:
            logger.exception("Unhandled error in %s", f.__name__)
            return jsonify({"error": f"Internal server error: {type(e).__name__}: {e}"}), 500
    return wrapper


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.route("/api/scan", methods=["POST"])
@handle_errors
def scan_lockfile():
    """
    Upload a lockfile (multipart form), parse it, ingest into Neo4j,
    fetch CVEs, and return scan results with project_id.

    Form fields:
    - file: the lockfile (required)
    - project_id: optional custom project ID (auto-generated if not provided)
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Use 'file' form field."}), 400

    uploaded = request.files["file"]
    if not uploaded.filename:
        return jsonify({"error": "Empty filename."}), 400

    project_id = request.form.get("project_id", "").strip()
    if not project_id:
        project_id = str(uuid.uuid4())

    # Save uploaded file to a temp location
    original_name = uploaded.filename
    tmp_dir = Config.UPLOAD_FOLDER
    os.makedirs(tmp_dir, exist_ok=True)

    # Preserve the original filename so the parser can detect the type
    tmp_path = os.path.join(tmp_dir, original_name)
    uploaded.save(tmp_path)

    try:
        # 1. Parse the lockfile
        logger.info("Parsing lockfile: %s", original_name)
        parsed = parse_lockfile(tmp_path)

        # 1b. Resolve transitive deps for PyPI packages (requirements.txt)
        if parsed["ecosystem"] == "PyPI" and all(
            len(pkg.get("dependencies", [])) == 0 for pkg in parsed["packages"]
        ):
            logger.info("Resolving transitive PyPI dependencies...")
            parsed["packages"] = resolve_pypi_deps(parsed["packages"], max_depth=2)
            logger.info("Resolved to %d total packages", len(parsed["packages"]))

        # 2. Clear any existing data for this project
        gm = get_graph_manager()
        gm.clear_project(project_id)

        # 3. Ingest dependencies into Neo4j
        logger.info(
            "Ingesting %d packages for project %s",
            len(parsed["packages"]), project_id,
        )
        ingest_stats = gm.ingest_dependencies(project_id, parsed)

        # 4. Fetch CVEs from OSV.dev
        logger.info("Fetching CVE data from OSV.dev...")
        fetcher = get_cve_fetcher()
        packages_for_query = [
            {
                "name": pkg["name"],
                "version": pkg["version"],
                "ecosystem": parsed["ecosystem"],
            }
            for pkg in parsed["packages"]
            if pkg["version"] != "unknown"
        ]

        vuln_results = fetcher.batch_fetch(packages_for_query)

        # 5. Attach vulnerabilities to the graph
        vuln_stats = gm.attach_vulnerabilities(project_id, vuln_results)

        # 6. Get summary stats
        stats = gm.get_stats(project_id)

        return jsonify({
            "project_id": project_id,
            "filename": original_name,
            "ecosystem": parsed["ecosystem"],
            "packages_parsed": len(parsed["packages"]),
            "ingest_stats": ingest_stats,
            "vulnerability_stats": vuln_stats,
            "summary": stats,
        }), 201

    finally:
        # Clean up temp file
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.route("/api/projects", methods=["GET"])
@handle_errors
def list_projects():
    """List all scanned projects."""
    gm = get_graph_manager()
    projects = gm.get_all_projects()
    return jsonify({"projects": projects})


@app.route("/api/graph/<project_id>", methods=["GET"])
@handle_errors
def get_graph(project_id: str):
    """
    Return full graph data (nodes + edges) formatted for Cytoscape.js.
    """
    gm = get_graph_manager()
    graph = gm.get_full_graph(project_id)

    if not graph["nodes"]:
        return jsonify({"error": f"No data found for project: {project_id}"}), 404

    return jsonify(graph)


@app.route("/api/paths/<project_id>/<cve_id>", methods=["GET"])
@handle_errors
def get_attack_paths(project_id: str, cve_id: str):
    """Return all attack paths to a specific CVE."""
    analyzer = get_analyzer()
    shortest = analyzer.find_shortest_attack_paths(project_id, cve_id)
    all_paths = analyzer.find_all_attack_paths(project_id, cve_id)

    return jsonify({
        "project_id": project_id,
        "cve_id": cve_id,
        "shortest_paths": shortest,
        "all_paths": all_paths,
        "total_paths": len(all_paths),
    })


@app.route("/api/vulnerabilities/<project_id>", methods=["GET"])
@handle_errors
def get_vulnerabilities(project_id: str):
    """List all vulnerabilities found, with severity and affected packages."""
    gm = get_graph_manager()
    vulns = gm.get_all_vulnerabilities(project_id)

    return jsonify({
        "project_id": project_id,
        "vulnerabilities": vulns,
        "total": len(vulns),
    })


@app.route("/api/analysis/<project_id>", methods=["GET"])
@handle_errors
def get_analysis(project_id: str):
    """Risk scores, critical packages, and summary stats."""
    analyzer = get_analyzer()

    risk_scores = analyzer.calculate_risk_scores(project_id)
    critical_packages = analyzer.get_most_critical_packages(project_id)
    summary = analyzer.get_vulnerability_summary(project_id)

    return jsonify({
        "project_id": project_id,
        "risk_scores": risk_scores[:50],  # Top 50
        "critical_packages": critical_packages,
        "summary": summary,
    })


@app.route("/api/projects/<project_id>", methods=["DELETE"])
@handle_errors
def delete_project(project_id: str):
    """Remove a project and all its associated data."""
    gm = get_graph_manager()
    result = gm.clear_project(project_id)
    return jsonify(result)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health_check():
    """Basic health check endpoint."""
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Frontend SPA serving
# ---------------------------------------------------------------------------

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    """Serve the Svelte frontend. Falls back to index.html for SPA routing."""
    file_path = FRONTEND_DIR / path
    if path and file_path.is_file():
        return send_from_directory(str(FRONTEND_DIR), path)
    return send_from_directory(str(FRONTEND_DIR), "index.html")


# ---------------------------------------------------------------------------
# Shutdown hook
# ---------------------------------------------------------------------------

@app.teardown_appcontext
def shutdown(exception=None):
    """Clean up resources when the app context is torn down."""
    pass  # Connections are reused across requests; closed on process exit


def cleanup():
    """Explicitly close connections (called on process exit)."""
    global _graph_manager, _cve_fetcher, _analyzer
    if _graph_manager:
        _graph_manager.close()
        _graph_manager = None
    if _cve_fetcher:
        _cve_fetcher.close()
        _cve_fetcher = None
    if _analyzer:
        _analyzer.close()
        _analyzer = None


import atexit
atexit.register(cleanup)


if __name__ == "__main__":
    app.run(
        host=Config.FLASK_HOST,
        port=Config.FLASK_PORT,
        debug=Config.FLASK_DEBUG,
    )
