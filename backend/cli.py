#!/usr/bin/env python3
"""
DepGra CLI — scan lockfiles from the command line.

Usage:
    python -m cli scan <lockfile>
    python -m cli scan <lockfile> --fail-on HIGH
    python -m cli scan <lockfile> --export json --output results.json
    python -m cli scan <lockfile> --export csv --output results.csv
"""

import argparse
import csv
import io
import json
import os
import sys
import tempfile
import uuid

# Ensure backend modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parsers import parse_lockfile, SUPPORTED_FILES
from graph import GraphManager
from cve import CVEFetcher
from analysis import GraphAnalyzer
from pypi_resolver import resolve_pypi_deps

# Severity ordering for --fail-on threshold
_SEVERITY_ORDER = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _severity_rank(sev: str) -> int:
    return _SEVERITY_ORDER.get(sev.upper(), 0)


def _print_summary(stats: dict, vulns: list[dict], file=sys.stderr) -> None:
    """Print a human-readable summary table to stderr."""
    pkg_count = stats.get("total_packages", 0)
    vuln_count = stats.get("total_vulnerabilities", 0)

    # Count by severity
    sev_counts: dict[str, int] = {}
    for v in vulns:
        sev = (v.get("severity") or "UNKNOWN").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    print("\n" + "=" * 50, file=file)
    print("  DepGra Scan Summary", file=file)
    print("=" * 50, file=file)
    print(f"  Packages scanned:  {pkg_count}", file=file)
    print(f"  Vulnerabilities:   {vuln_count}", file=file)
    if sev_counts:
        print("  Breakdown:", file=file)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"):
            count = sev_counts.get(sev, 0)
            if count:
                print(f"    {sev:>10}: {count}", file=file)
    print("=" * 50 + "\n", file=file)


def _build_results(project_id: str, ecosystem: str, parsed: dict,
                   ingest_stats: dict, vuln_stats: dict, stats: dict,
                   vulns: list[dict]) -> dict:
    """Build the JSON-serializable results dict."""
    return {
        "project_id": project_id,
        "ecosystem": ecosystem,
        "packages_parsed": len(parsed["packages"]),
        "ingest_stats": ingest_stats,
        "vulnerability_stats": vuln_stats,
        "summary": stats,
        "vulnerabilities": vulns,
    }


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan subcommand."""
    lockfile = args.lockfile
    if not os.path.isfile(lockfile):
        print(f"Error: file not found: {lockfile}", file=sys.stderr)
        return 1

    # Use a temporary database so CLI scans don't pollute the web app DB
    tmp_db_fd, tmp_db_path = tempfile.mkstemp(suffix=".db", prefix="depgra_cli_")
    os.close(tmp_db_fd)

    try:
        project_id = str(uuid.uuid4())

        # 1. Parse
        print(f"[*] Parsing {os.path.basename(lockfile)}...", file=sys.stderr)
        parsed = parse_lockfile(os.path.abspath(lockfile))
        ecosystem = parsed["ecosystem"]

        # 1b. Resolve transitive deps for PyPI if needed
        if ecosystem == "PyPI" and all(
            len(pkg.get("dependencies", [])) == 0 for pkg in parsed["packages"]
        ):
            print("[*] Resolving transitive PyPI dependencies...", file=sys.stderr)
            parsed["packages"] = resolve_pypi_deps(parsed["packages"], max_depth=2)
            print(f"[*] Resolved to {len(parsed['packages'])} total packages", file=sys.stderr)

        # 2. Ingest into temp DB
        print(f"[*] Ingesting {len(parsed['packages'])} packages...", file=sys.stderr)
        gm = GraphManager(db_path=tmp_db_path)
        gm.clear_project(project_id)
        ingest_stats = gm.ingest_dependencies(project_id, parsed)

        # 3. Fetch CVEs
        print("[*] Fetching CVE data from OSV.dev...", file=sys.stderr)
        fetcher = CVEFetcher()
        packages_for_query = [
            {"name": pkg["name"], "version": pkg["version"], "ecosystem": ecosystem}
            for pkg in parsed["packages"]
            if pkg["version"] != "unknown"
        ]
        vuln_results = fetcher.batch_fetch(packages_for_query)

        # 4. Attach vulns
        vuln_stats = gm.attach_vulnerabilities(project_id, vuln_results)

        # 5. Get stats and vuln list
        stats = gm.get_stats(project_id)
        vulns = gm.get_all_vulnerabilities(project_id)

        # Clean up connections
        fetcher.close()
        gm.close()

        # Print summary to stderr
        _print_summary(stats, vulns)

        # Build results
        results = _build_results(
            project_id, ecosystem, parsed,
            ingest_stats, vuln_stats, stats, vulns,
        )

        # Export or print
        if args.export == "csv":
            output = _export_csv(vulns)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output)
                print(f"[*] CSV results written to {args.output}", file=sys.stderr)
            else:
                print(output)
        elif args.export == "json" or args.export is None:
            output = json.dumps(results, indent=2)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output)
                print(f"[*] JSON results written to {args.output}", file=sys.stderr)
            else:
                print(output)

        # Determine exit code
        if args.fail_on and vulns:
            threshold = _severity_rank(args.fail_on)
            for v in vulns:
                sev = (v.get("severity") or "NONE").upper()
                if _severity_rank(sev) >= threshold:
                    print(
                        f"[!] Failing: found {sev} vulnerability "
                        f"(threshold: {args.fail_on.upper()})",
                        file=sys.stderr,
                    )
                    return 1

        return 0

    finally:
        # Remove temp DB files
        for suffix in ("", "-wal", "-shm"):
            path = tmp_db_path + suffix
            if os.path.exists(path):
                os.remove(path)


def _export_csv(vulns: list[dict]) -> str:
    """Export vulnerabilities as CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["vuln_id", "severity", "summary", "affected_packages", "aliases", "references"])
    for v in vulns:
        affected = "; ".join(
            f"{p['name']}@{p['version']}" for p in v.get("affected_packages", [])
        )
        aliases = "; ".join(v.get("aliases", []))
        refs = "; ".join(v.get("references", []))
        writer.writerow([
            v.get("vuln_id", ""),
            v.get("severity", ""),
            v.get("summary", ""),
            affected,
            aliases,
            refs,
        ])
    return buf.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="depgra",
        description="DepGra CLI — scan lockfiles for dependency vulnerabilities",
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan subcommand
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a lockfile for vulnerabilities",
    )
    scan_parser.add_argument(
        "lockfile",
        help=f"Path to a lockfile ({', '.join(SUPPORTED_FILES)})",
    )
    scan_parser.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "medium", "high", "critical"],
        help="Exit non-zero if vulnerabilities at or above this severity are found",
    )
    scan_parser.add_argument(
        "--export",
        choices=["json", "csv"],
        default=None,
        help="Export format (default: json to stdout)",
    )
    scan_parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write results to FILE instead of stdout",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "scan":
        return cmd_scan(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
