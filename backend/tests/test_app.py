"""Tests for the Flask REST API endpoints."""

import io
import json
import os
import tempfile

import pytest

# Patch DATABASE_PATH before importing the app so all singletons use the
# temporary database.
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["DATABASE_PATH"] = _tmp_db.name

# Now import (the Config class reads DATABASE_PATH at import time)
from app import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# Small valid package-lock.json for upload tests
_LOCKFILE = json.dumps({
    "name": "test-app",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "test-app", "version": "1.0.0",
             "dependencies": {"is-odd": "^3.0.1"}},
        "node_modules/is-odd": {
            "version": "3.0.1",
            "dependencies": {"is-number": "^6.0.0"},
        },
        "node_modules/is-number": {"version": "6.0.0"},
    },
})


def _upload(client, content: str, filename: str, project_id: str | None = None):
    """Helper to POST a lockfile to /api/scan."""
    data = {"file": (io.BytesIO(content.encode()), filename)}
    if project_id:
        data["project_id"] = project_id
    return client.post(
        "/api/scan",
        data=data,
        content_type="multipart/form-data",
    )


# ------------------------------------------------------------------

def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_scan_no_file(client):
    resp = client.post("/api/scan", data={}, content_type="multipart/form-data")
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_scan_unsupported(client):
    resp = _upload(client, "hello", "unsupported.lock")
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_scan_valid(client):
    resp = _upload(client, _LOCKFILE, "package-lock.json", project_id="test-proj-1")
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["project_id"] == "test-proj-1"
    assert body["ecosystem"] == "npm"
    assert body["packages_parsed"] >= 2
    assert "ingest_stats" in body
    assert "summary" in body


def test_projects_list(client):
    # Ensure the project from test_scan_valid is present
    _upload(client, _LOCKFILE, "package-lock.json", project_id="test-proj-list")
    resp = client.get("/api/projects")
    assert resp.status_code == 200
    projects = resp.get_json()["projects"]
    ids = [p["project_id"] for p in projects]
    assert "test-proj-list" in ids


def test_graph_endpoint(client):
    _upload(client, _LOCKFILE, "package-lock.json", project_id="test-proj-graph")
    resp = client.get("/api/graph/test-proj-graph")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "nodes" in body
    assert "edges" in body
    assert len(body["nodes"]) >= 2
    # All package nodes should have required fields
    for node in body["nodes"]:
        d = node["data"]
        assert "id" in d
        assert "type" in d


def test_delete_project(client):
    _upload(client, _LOCKFILE, "package-lock.json", project_id="test-proj-del")
    resp = client.delete("/api/projects/test-proj-del")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "cleared"

    # Graph should now be empty / 404
    resp2 = client.get("/api/graph/test-proj-del")
    assert resp2.status_code == 404
