#!/usr/bin/env python3
"""
DepGra — Dependency Vulnerability Tracker

Single-command launcher. Builds the frontend (if needed) and starts the server.

Usage:
    python run.py              # start on default port 5000
    python run.py --port 8080  # custom port
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
FRONTEND_DIST = FRONTEND / "dist" / "index.html"


def check_python_deps():
    """Ensure Python dependencies are installed."""
    try:
        import flask  # noqa: F401
        import httpx  # noqa: F401
        import networkx  # noqa: F401
    except ImportError:
        print("[*] Installing Python dependencies...")
        req_file = BACKEND / "requirements.txt"
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-r", str(req_file)],
            stdout=subprocess.DEVNULL,
        )


def build_frontend():
    """Build the Svelte frontend if dist doesn't exist."""
    if FRONTEND_DIST.exists():
        print("[*] Frontend already built.")
        return

    if not (FRONTEND / "package.json").exists():
        print("[!] Frontend not found. Skipping frontend build.")
        print("    API will still be available at http://localhost:<port>/api/")
        return

    print("[*] Building frontend...")

    # Install npm deps if needed
    if not (FRONTEND / "node_modules").exists():
        print("    Installing npm dependencies...")
        subprocess.check_call(
            ["npm", "install"],
            cwd=str(FRONTEND),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    subprocess.check_call(
        ["npm", "run", "build"],
        cwd=str(FRONTEND),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print("[*] Frontend built successfully.")


def run_server(args):
    """Start the web server."""
    os.environ.setdefault("FLASK_HOST", args.host)
    os.environ.setdefault("FLASK_PORT", str(args.port))

    check_python_deps()

    if not args.skip_frontend:
        build_frontend()

    # Start Flask
    sys.path.insert(0, str(BACKEND))
    from app import app

    print(f"\n[*] DepGra running at http://{args.host}:{args.port}")
    print(f"[*] API available at  http://{args.host}:{args.port}/api/")
    print("[*] Press Ctrl+C to stop.\n")

    app.run(host=args.host, port=args.port, debug=False)


def run_scan(args):
    """Delegate to the CLI scanner."""
    sys.path.insert(0, str(BACKEND))
    from cli import main as cli_main
    # Re-build sys.argv so cli.py's argparse sees the right args
    sys.argv = ["depgra", "scan"] + args.scan_args
    sys.exit(cli_main())


def main():
    parser = argparse.ArgumentParser(description="DepGra — Dependency Vulnerability Tracker")
    subparsers = parser.add_subparsers(dest="command")

    # Default server mode (also works with no subcommand)
    serve_parser = subparsers.add_parser("serve", help="Start the web server (default)")
    serve_parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
    serve_parser.add_argument("--skip-frontend", action="store_true", help="Skip frontend build")

    # Scan subcommand — delegates to cli.py
    scan_parser = subparsers.add_parser("scan", help="Scan a lockfile (CLI mode)")
    scan_parser.add_argument("scan_args", nargs=argparse.REMAINDER, help="Arguments passed to CLI scanner")

    # Support old-style flags directly (no subcommand = serve)
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
    parser.add_argument("--skip-frontend", action="store_true", help="Skip frontend build")

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args)
    else:
        # Default to server mode (handles both "serve" subcommand and no subcommand)
        run_server(args)


if __name__ == "__main__":
    main()
