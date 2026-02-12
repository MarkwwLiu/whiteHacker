"""CLI entry point for WhiteHats Security Testing Framework."""

import argparse
import json
import logging
import sys
from pathlib import Path

from colorama import Fore, Style, init as colorama_init

from whitehats import __version__
from whitehats.config import load_config
from whitehats.generator.standalone_exporter import StandaloneExporter
from whitehats.generator.test_generator import TestGenerator
from whitehats.models.target import APITarget, HTTPMethod, URLTarget
from whitehats.modules import ALL_MODULES
from whitehats.reporter.html_reporter import HTMLReporter
from whitehats.reporter.json_reporter import JSONReporter
from whitehats.scanner.api_scanner import APIScanner
from whitehats.scanner.url_scanner import URLScanner
from whitehats.scanner.concurrent_scanner import ConcurrentScanner


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def print_banner():
    colorama_init()
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════╗
║     WhiteHats Security Testing Framework v{__version__}    ║
║         Automated White Hat Security Tests        ║
╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def parse_targets_file(filepath: str) -> list:
    """Parse a JSON targets file.

    Expected format:
    {
        "targets": [
            {
                "type": "api",
                "url": "https://example.com/api/users",
                "method": "GET",
                "params": {"id": "1"},
                "headers": {},
                "body": null
            },
            {
                "type": "url",
                "url": "https://example.com/login"
            }
        ]
    }
    """
    with open(filepath, "r") as f:
        data = json.load(f)

    targets = []
    for t in data.get("targets", []):
        target_type = t.get("type", "url")
        if target_type == "api":
            method = HTTPMethod[t.get("method", "GET").upper()]
            targets.append(
                APITarget(
                    url=t["url"],
                    method=method,
                    headers=t.get("headers", {}),
                    params=t.get("params", {}),
                    body=t.get("body"),
                    auth_token=t.get("auth_token"),
                    name=t.get("name", ""),
                )
            )
        else:
            targets.append(
                URLTarget(
                    url=t["url"],
                    headers=t.get("headers", {}),
                    name=t.get("name", ""),
                )
            )

    return targets


def cmd_scan(args):
    """Execute security scan."""
    config = load_config(args.config)

    # Build targets
    targets = []
    if args.targets_file:
        targets = parse_targets_file(args.targets_file)
    elif args.url:
        if args.api:
            method = HTTPMethod[args.method.upper()]
            body = None
            if args.body:
                body = json.loads(args.body)
            params = {}
            if args.params:
                params = json.loads(args.params)
            headers = {}
            if args.headers:
                headers = json.loads(args.headers)
            targets.append(
                APITarget(
                    url=args.url,
                    method=method,
                    headers=headers,
                    params=params,
                    body=body,
                    auth_token=args.token,
                )
            )
        else:
            targets.append(URLTarget(url=args.url))

    if not targets:
        print(f"{Fore.RED}No targets specified. Use --url or --targets-file.{Style.RESET_ALL}")
        sys.exit(1)

    all_vulns = []

    if len(targets) > 1 and not getattr(args, "no_concurrent", False):
        # Use concurrent scanning for multiple targets
        max_concurrent = config.get("scan", {}).get("max_concurrent", 5)
        print(f"\n{Fore.CYAN}Concurrent scanning {len(targets)} targets (max_workers={max_concurrent}){Style.RESET_ALL}")

        def on_target_done(url, vulns, completed, total):
            print(f"  [{completed}/{total}] {url}: {Fore.RED}{len(vulns)}{Style.RESET_ALL} findings")

        concurrent = ConcurrentScanner(config=config, modules=ALL_MODULES)
        results = concurrent.scan(targets, progress_callback=on_target_done)
        for vulns in results.values():
            all_vulns.extend(vulns)
    else:
        # Single target - sequential scan
        for target in targets:
            print(f"\n{Fore.YELLOW}Scanning: {target.url}{Style.RESET_ALL}")

            if hasattr(target, "method"):
                scanner = APIScanner(config=config, modules=ALL_MODULES)
            else:
                scanner = URLScanner(config=config, modules=ALL_MODULES)

            vulns = scanner.scan(target)
            all_vulns.extend(vulns)

            print(f"  Found {Fore.RED}{len(vulns)}{Style.RESET_ALL} potential issues")

    # Generate reports
    target_info = {
        "urls": [t.url for t in targets],
        "url": targets[0].url if targets else "N/A",
        "scan_type": "multi-target" if len(targets) > 1 else "single-target",
    }

    report_format = config.get("report", {}).get("format", "json")

    if report_format in ("json", "both"):
        reporter = JSONReporter(config)
        path = reporter.generate(all_vulns, target_info)
        print(f"\n{Fore.GREEN}JSON report: {path}{Style.RESET_ALL}")

    if report_format in ("html", "both"):
        reporter = HTMLReporter(config)
        path = reporter.generate(all_vulns, target_info)
        print(f"{Fore.GREEN}HTML report: {path}{Style.RESET_ALL}")

    # Print summary
    print(f"\n{Fore.CYAN}{'=' * 50}")
    print(f"  Scan Complete - {len(all_vulns)} findings")
    print(f"{'=' * 50}{Style.RESET_ALL}")

    severity_counts = {}
    for v in all_vulns:
        sev = v.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    colors = {
        "critical": Fore.RED,
        "high": Fore.RED,
        "medium": Fore.YELLOW,
        "low": Fore.GREEN,
        "info": Fore.CYAN,
    }
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            color = colors.get(sev, "")
            print(f"  {color}{sev.upper():10s}: {count}{Style.RESET_ALL}")


def cmd_generate(args):
    """Generate test cases only (no scanning)."""
    config = load_config(args.config)

    targets = []
    if args.targets_file:
        targets = parse_targets_file(args.targets_file)
    elif args.url:
        if args.api:
            method = HTTPMethod[args.method.upper()]
            body = json.loads(args.body) if args.body else None
            params = json.loads(args.params) if args.params else {}
            headers = json.loads(args.headers) if args.headers else {}
            targets.append(
                APITarget(
                    url=args.url,
                    method=method,
                    headers=headers,
                    params=params,
                    body=body,
                    auth_token=args.token,
                )
            )
        else:
            targets.append(URLTarget(url=args.url))

    if not targets:
        print(f"{Fore.RED}No targets specified.{Style.RESET_ALL}")
        sys.exit(1)

    generator = TestGenerator(config)
    files = generator.generate(targets)

    print(f"\n{Fore.GREEN}Generated {len(files)} test file(s):{Style.RESET_ALL}")
    for f in files:
        print(f"  - {f}")
    print(f"\nRun with: {Fore.CYAN}pytest {config.get('generator', {}).get('output_dir', 'test_cases')}/{Style.RESET_ALL}")


def cmd_export(args):
    """Export a generated test file as a standalone disposable script."""
    config = load_config(args.config)
    exporter = StandaloneExporter(config)

    test_dir = config.get("generator", {}).get("output_dir", "test_cases")

    # If --list flag, show available test files and exit
    if args.list:
        files = exporter.list_exportable(test_dir)
        if not files:
            print(f"{Fore.RED}No exportable test files found in {test_dir}/{Style.RESET_ALL}")
            sys.exit(1)
        print(f"\n{Fore.CYAN}Available test files to export:{Style.RESET_ALL}")
        for i, f in enumerate(files, 1):
            print(f"  {Fore.YELLOW}[{i}]{Style.RESET_ALL} {f}")
        print(f"\nUsage: {Fore.CYAN}whitehats export <file_path>{Style.RESET_ALL}")
        print(f"   or: {Fore.CYAN}whitehats export <file_path> -o my_standalone.py{Style.RESET_ALL}")
        return

    if not args.file:
        print(f"{Fore.RED}Please specify a test file to export. Use --list to see available files.{Style.RESET_ALL}")
        sys.exit(1)

    source = args.file

    # Support numeric selection (e.g. "1" instead of full path)
    if source.isdigit():
        files = exporter.list_exportable(test_dir)
        idx = int(source) - 1
        if 0 <= idx < len(files):
            source = files[idx]
        else:
            print(f"{Fore.RED}Invalid index: {source}. Use --list to see available files.{Style.RESET_ALL}")
            sys.exit(1)

    try:
        output = exporter.export(source_path=source, output_path=args.output)
        print(f"\n{Fore.GREEN}Exported standalone script:{Style.RESET_ALL}")
        print(f"  {output}")
        print(f"\n{Fore.CYAN}Run it anywhere with:{Style.RESET_ALL}")
        print(f"  pytest {output} -v")
    except FileNotFoundError as e:
        print(f"{Fore.RED}{e}{Style.RESET_ALL}")
        sys.exit(1)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="WhiteHats - Automated White Hat Security Testing Framework"
    )
    parser.add_argument("--version", action="version", version=f"WhiteHats {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-c", "--config", type=str, help="Path to config YAML file")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan command ---
    scan_parser = subparsers.add_parser("scan", help="Run security scan")
    scan_parser.add_argument("--url", type=str, help="Target URL")
    scan_parser.add_argument("--api", action="store_true", help="Treat target as API endpoint")
    scan_parser.add_argument("--method", type=str, default="GET", help="HTTP method (default: GET)")
    scan_parser.add_argument("--params", type=str, help="Query params as JSON string")
    scan_parser.add_argument("--body", type=str, help="Request body as JSON string")
    scan_parser.add_argument("--headers", type=str, help="Custom headers as JSON string")
    scan_parser.add_argument("--token", type=str, help="Bearer auth token")
    scan_parser.add_argument("--targets-file", type=str, help="JSON file with multiple targets")

    # --- generate command ---
    gen_parser = subparsers.add_parser("generate", help="Generate test cases without scanning")
    gen_parser.add_argument("--url", type=str, help="Target URL")
    gen_parser.add_argument("--api", action="store_true", help="Treat target as API endpoint")
    gen_parser.add_argument("--method", type=str, default="GET", help="HTTP method")
    gen_parser.add_argument("--params", type=str, help="Query params as JSON string")
    gen_parser.add_argument("--body", type=str, help="Request body as JSON string")
    gen_parser.add_argument("--headers", type=str, help="Custom headers as JSON string")
    gen_parser.add_argument("--token", type=str, help="Bearer auth token")
    gen_parser.add_argument("--targets-file", type=str, help="JSON file with multiple targets")

    # --- export command ---
    export_parser = subparsers.add_parser(
        "export", help="Export a test file as standalone disposable script"
    )
    export_parser.add_argument(
        "file", nargs="?", default=None,
        help="Path to the test file to export (or index number from --list)",
    )
    export_parser.add_argument(
        "-o", "--output", type=str, default=None,
        help="Output path for the standalone script",
    )
    export_parser.add_argument(
        "--list", action="store_true",
        help="List available test files that can be exported",
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "generate":
        cmd_generate(args)
    elif args.command == "export":
        cmd_export(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
