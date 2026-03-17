#!/usr/bin/env python3
"""Rescan packages from a previous scan's JSON output."""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Re-run a scan using packages from a previous JSON output"
    )
    parser.add_argument("input_json", help="JSON file from a previous scan")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--external-rules", help="External rule sources (e.g., guarddog)")
    parser.add_argument("--run", action="store_true", help="Execute the scan (default: just print command)")

    args = parser.parse_args()

    # Load and extract packages
    input_path = Path(args.input_json)
    with open(input_path) as f:
        data = json.load(f)

    packages = [r["package_name"] for r in data.get("all_results", [])]
    if not packages:
        print(f"Error: No packages found in {input_path}", file=sys.stderr)
        sys.exit(1)

    # Build command
    output_file = args.output or f"rescan_{input_path.stem}.json"
    cmd = [
        sys.executable, "scanner/pypi_scan.py",
        "--packages", *packages,
        "-n", str(len(packages)),
        "-o", output_file,
    ]
    if args.external_rules:
        cmd.extend(["--external-rules", args.external_rules])

    # Print or execute
    print(f"Packages: {len(packages)}")
    print(f"Command: {' '.join(cmd[:6])} ... -n {len(packages)} -o {output_file}")

    if args.run:
        print(f"\nRunning scan...")
        subprocess.run(cmd)
    else:
        print(f"\nTo execute, add --run flag")


if __name__ == "__main__":
    main()
