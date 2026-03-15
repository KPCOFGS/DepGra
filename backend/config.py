import os


class Config:
    """Configuration for the Dependency Graph Vulnerability Tracker."""

    DATABASE_PATH = os.environ.get(
        "DATABASE_PATH",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "depgra.db"),
    )

    OSV_API_URL = os.environ.get("OSV_API_URL", "https://api.osv.dev/v1")
    OSV_QUERY_URL = f"{OSV_API_URL}/query"
    OSV_BATCH_URL = f"{OSV_API_URL}/querybatch"

    # Rate limiting
    OSV_MAX_RETRIES = int(os.environ.get("OSV_MAX_RETRIES", "5"))
    OSV_BATCH_SIZE = int(os.environ.get("OSV_BATCH_SIZE", "1000"))

    # Flask
    FLASK_HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
    FLASK_PORT = int(os.environ.get("FLASK_PORT", "5000"))
    FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    # File upload
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(16 * 1024 * 1024)))
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/tmp/depgra_uploads")
