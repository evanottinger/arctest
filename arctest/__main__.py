"""CLI entry point: python -m arctest <command>"""

import argparse
import json
import sys
from pathlib import Path

from .semgrep_analyzer import SemgrepAnalyzer
from .rule_manager import RuleManager, SOURCES


def cmd_scan(args: argparse.Namespace) -> int:
    """Run a scan on the specified path."""
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Path does not exist: {args.path}", file=sys.stderr)
        return 1

    # Build rules directories
    rule_manager = RuleManager()
    external_sources = None
    if args.external_rules:
        external_sources = [s.strip() for s in args.external_rules.split(",")]
        # Verify all sources are cached
        missing = [s for s in external_sources if not rule_manager.is_cached(s)]
        if missing:
            print(f"Error: External rules not cached: {', '.join(missing)}", file=sys.stderr)
            print(f"Run: python -m arctest rules fetch <source>", file=sys.stderr)
            return 1

    rules_dirs = rule_manager.get_all_rule_dirs(
        include_builtin=True,
        external_sources=external_sources,
    )

    analyzer = SemgrepAnalyzer(rules_dirs=rules_dirs)
    result = analyzer.analyze(target_path)

    if args.json or args.output:
        output = result.to_dict()
        if args.output:
            with open(args.output, "w") as f:
                json.dump(output, f, indent=2)
            print(f"Report written to: {args.output}")
        else:
            print(json.dumps(output, indent=2))
    else:
        # Human-readable output
        print(f"Scanned: {result.path}")
        print(f"Rules directories: {len(rules_dirs)}")
        print(f"Findings: {len(result.findings)}")
        if result.errors:
            print(f"Errors: {len(result.errors)}")
            for error in result.errors:
                print(f"  - {error}")
        for finding in result.findings:
            print(f"  [{finding.severity.upper()}] {finding.rule_id}")
            print(f"    {finding.file_path}:{finding.line_number}")
            if finding.message:
                print(f"    {finding.message}")

    # Exit codes: 2 for critical, 1 for high, 0 for clean
    if result.has_critical:
        return 2
    elif result.has_high:
        return 1
    return 0


def cmd_rules_list(args: argparse.Namespace) -> int:
    """List available rule sources."""
    rule_manager = RuleManager()

    print("Available rule sources:")
    print()
    for name, source in SOURCES.items():
        cached = rule_manager.is_cached(name)
        status = "[cached]" if cached else "[not cached]"
        print(f"  {name} {status}")
        print(f"    URL: {source.url}")
        print(f"    Rules path: {source.rules_subpath}")
        if cached:
            path = rule_manager.get_rules_path(name)
            print(f"    Local path: {path}")
        print()

    return 0


def cmd_rules_fetch(args: argparse.Namespace) -> int:
    """Fetch external rule source."""
    rule_manager = RuleManager()

    source_name = args.source
    if source_name not in SOURCES:
        print(f"Error: Unknown source: {source_name}", file=sys.stderr)
        print(f"Available: {', '.join(SOURCES.keys())}", file=sys.stderr)
        return 1

    print(f"Fetching {source_name}...")
    try:
        path = rule_manager.fetch_source(source_name, update=args.update)
        print(f"Rules cached at: {path}")
        return 0
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_rules_update(args: argparse.Namespace) -> int:
    """Update all cached rule sources."""
    rule_manager = RuleManager()

    results = rule_manager.update_all()
    if not results:
        print("No cached rule sources to update.")
        print(f"Run: python -m arctest rules fetch <source>")
        return 0

    print("Update results:")
    has_errors = False
    for name, result in results.items():
        if isinstance(result, Path):
            print(f"  {name}: updated ({result})")
        else:
            print(f"  {name}: {result}")
            has_errors = True

    return 1 if has_errors else 0


def cmd_rules_remove(args: argparse.Namespace) -> int:
    """Remove a cached rule source."""
    rule_manager = RuleManager()

    source_name = args.source
    if rule_manager.remove_source(source_name):
        print(f"Removed: {source_name}")
        return 0
    else:
        print(f"Not cached: {source_name}")
        return 1


def main() -> int:
    # Check for legacy usage first: python -m arctest <path>
    # If the first argument isn't a known command, treat it as legacy scan
    known_commands = {"scan", "rules", "-h", "--help"}
    if len(sys.argv) > 1 and sys.argv[1] not in known_commands:
        legacy_parser = argparse.ArgumentParser(
            prog="arctest",
            description="Scan code for malware patterns using Semgrep rules",
        )
        legacy_parser.add_argument("path", help="File or directory to scan")
        legacy_parser.add_argument("-o", "--output", help="JSON output file")
        legacy_parser.add_argument("--json", action="store_true", help="Output as JSON")
        legacy_parser.add_argument("--external-rules", help="External rule sources")
        args = legacy_parser.parse_args()
        return cmd_scan(args)

    parser = argparse.ArgumentParser(
        prog="arctest",
        description="Scan code for malware patterns using Semgrep rules",
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan code for malware patterns")
    scan_parser.add_argument("path", help="File or directory to scan")
    scan_parser.add_argument("-o", "--output", help="JSON output file")
    scan_parser.add_argument("--json", action="store_true", help="Output as JSON")
    scan_parser.add_argument(
        "--external-rules",
        metavar="SOURCES",
        help="Comma-separated list of external rule sources",
    )

    # Rules command
    rules_parser = subparsers.add_parser("rules", help="Manage external rule sources")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", help="Rules commands")

    # rules list
    rules_subparsers.add_parser("list", help="List available rule sources")

    # rules fetch
    fetch_parser = rules_subparsers.add_parser("fetch", help="Fetch external rules")
    fetch_parser.add_argument("source", help="Source name (e.g., guarddog)")
    fetch_parser.add_argument(
        "--update", "-u",
        action="store_true",
        help="Update if already cached",
    )

    # rules update
    rules_subparsers.add_parser("update", help="Update all cached rule sources")

    # rules remove
    remove_parser = rules_subparsers.add_parser("remove", help="Remove cached rules")
    remove_parser.add_argument("source", help="Source name to remove")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    # Route to appropriate command
    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "rules":
        if args.rules_command == "list":
            return cmd_rules_list(args)
        elif args.rules_command == "fetch":
            return cmd_rules_fetch(args)
        elif args.rules_command == "update":
            return cmd_rules_update(args)
        elif args.rules_command == "remove":
            return cmd_rules_remove(args)
        else:
            rules_parser.print_help()
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
