#!/usr/bin/env python3
"""
Semgrep Rule Scanner for PyPI Packages

Uses Semgrep pattern-matching rules to scan test files in PyPI packages.
Supports both GitHub repos and direct PyPI source distribution downloads.
"""

import argparse
import json
import random
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.pypi_client import PyPIClient, PackageInfo
from arctest.semgrep_analyzer import SemgrepAnalyzer
from arctest.rule_manager import RuleManager, SOURCES


@dataclass
class SemgrepScanResult:
    """Result of Semgrep rule scanning a package."""
    package_name: str
    package_version: str
    github_url: str
    scan_timestamp: str
    success: bool
    error_message: str = ""
    test_files_found: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    findings: list = None
    priority_reason: str = ""

    def __post_init__(self):
        if self.findings is None:
            self.findings = []


def clone_repo(github_url: str, dest_dir: Path) -> Path | None:
    """Clone a GitHub repository."""
    try:
        clone_dir = dest_dir / "repo"
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", github_url, str(clone_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            return None
        return clone_dir
    except Exception:
        return None


def download_sdist(package_name: str, dest_dir: Path) -> Path | None:
    """Download and extract source distribution from PyPI."""
    try:
        # Get package info from PyPI JSON API
        url = f"https://pypi.org/pypi/{package_name}/json"
        with urlopen(url, timeout=30) as response:
            data = json.loads(response.read().decode())

        # Find sdist URL (prefer .tar.gz)
        sdist_url = None
        for file_info in data.get("urls", []):
            if file_info.get("packagetype") == "sdist":
                sdist_url = file_info.get("url")
                break

        if not sdist_url:
            return None

        # Download the sdist
        extract_dir = dest_dir / "repo"
        extract_dir.mkdir(exist_ok=True)

        with urlopen(sdist_url, timeout=60) as response:
            content = response.read()

        # Extract based on file type
        if sdist_url.endswith(".tar.gz") or sdist_url.endswith(".tgz"):
            import io
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
                tar.extractall(extract_dir, filter="data")
        elif sdist_url.endswith(".zip"):
            import io
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                zf.extractall(extract_dir)
        else:
            return None

        # Find the extracted directory (usually package-version/)
        subdirs = [d for d in extract_dir.iterdir() if d.is_dir()]
        if subdirs:
            return subdirs[0]
        return extract_dir

    except Exception:
        return None


def find_test_dirs(repo_dir: Path) -> list[Path]:
    """Find test directories in a repository."""
    test_dirs = []
    for pattern in ["tests", "test", "testing"]:
        for match in repo_dir.glob(pattern):
            if match.is_dir():
                test_dirs.append(match)
    return test_dirs


def scan_package(pkg_info, analyzer: SemgrepAnalyzer, use_pypi: bool = False) -> SemgrepScanResult:
    """Scan a single package using Semgrep rules."""
    result = SemgrepScanResult(
        package_name=pkg_info.name,
        package_version=pkg_info.version,
        github_url=pkg_info.github_url or "",
        scan_timestamp=datetime.now().isoformat(),
        success=False,
        priority_reason=pkg_info.priority_reason,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        repo_dir = None

        # Try GitHub first if available, then fall back to PyPI sdist
        if pkg_info.github_url and not use_pypi:
            print(f"  Cloning {pkg_info.github_url}...")
            repo_dir = clone_repo(pkg_info.github_url, tmppath)
            if not repo_dir:
                print(f"  Clone failed, trying PyPI sdist...")
                repo_dir = download_sdist(pkg_info.name, tmppath)
                if repo_dir:
                    result.github_url = f"pypi:{pkg_info.name}"
        else:
            print(f"  Downloading from PyPI...")
            repo_dir = download_sdist(pkg_info.name, tmppath)
            if repo_dir:
                result.github_url = f"pypi:{pkg_info.name}"

        if not repo_dir:
            result.error_message = "Failed to get source"
            return result

        # Find test directories
        test_dirs = find_test_dirs(repo_dir)
        if not test_dirs:
            result.error_message = "No test directories"
            result.success = True
            return result

        # Count test files
        test_files = []
        for test_dir in test_dirs:
            test_files.extend(test_dir.glob("**/*.py"))
        result.test_files_found = len(test_files)

        if result.test_files_found == 0:
            result.error_message = "No test files"
            result.success = True
            return result

        # Run Semgrep analysis on each test directory
        all_findings = []
        for test_dir in test_dirs:
            print(f"  Analyzing {test_dir.name}/...")
            analysis = analyzer.analyze(test_dir)
            all_findings.extend([f.to_dict() for f in analysis.findings])

        # Aggregate findings
        result.findings = all_findings
        result.total_findings = len(all_findings)

        for finding in all_findings:
            severity = finding.get("severity", "").lower()
            if severity == "critical":
                result.critical_findings += 1
            elif severity == "high":
                result.high_findings += 1
            elif severity == "medium":
                result.medium_findings += 1
            elif severity == "low":
                result.low_findings += 1

        result.success = True

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Scan PyPI packages using Semgrep rules"
    )
    parser.add_argument(
        "-n", "--max-packages",
        type=int,
        default=50,
        help="Maximum packages to scan (default: 50)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("pypi_scan_report.json"),
        help="Output report path",
    )
    parser.add_argument(
        "--packages",
        nargs="+",
        help="Specific packages to scan",
    )
    parser.add_argument(
        "--new-only",
        action="store_true",
        help="Only scan newly created packages",
    )
    parser.add_argument(
        "--pypi-sdist",
        action="store_true",
        help="Download source from PyPI instead of GitHub",
    )
    parser.add_argument(
        "--random-sample",
        type=int,
        metavar="N",
        help="Scan exactly N packages WITH TESTS from random PyPI sample (skips packages without tests)",
    )
    parser.add_argument(
        "--external-rules",
        metavar="SOURCES",
        help="Comma-separated list of external rule sources (e.g., guarddog,semgrep-python-security)",
    )

    args = parser.parse_args()

    # Initialize client and analyzer
    client = PyPIClient()

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
            sys.exit(1)

    rules_dirs = rule_manager.get_all_rule_dirs(
        include_builtin=True,
        external_sources=external_sources,
    )
    excluded_rules = rule_manager.get_excluded_rules(external_sources)
    analyzer = SemgrepAnalyzer(rules_dirs=rules_dirs, excluded_rules=excluded_rules)

    if external_sources:
        print(f"Using {len(rules_dirs)} rule directories (including external: {', '.join(external_sources)})")

    print("Building package list...")

    if args.random_sample:
        # Random sampling mode - will keep trying until N packages with tests are found
        print(f"Fetching PyPI package index for random sampling...")
        all_package_names = PyPIClient.get_all_package_names()
        random.shuffle(all_package_names)

        @dataclass
        class RandomPkgInfo:
            name: str
            version: str = "latest"
            github_url: str = ""
            priority_reason: str = "random_sample"

        # Run the random sampling loop
        target_count = args.random_sample
        results = []
        suspicious_packages = []
        skipped_no_source = []
        skipped_no_tests = []
        package_index = 0

        print(f"\nScanning until {target_count} packages with tests are found...")

        while len(results) < target_count and package_index < len(all_package_names):
            pkg_name = all_package_names[package_index]
            package_index += 1
            pkg = RandomPkgInfo(name=pkg_name)

            print(f"\n[{len(results) + 1} out of {target_count} (tried {package_index})] {pkg.name}")
            result = scan_package(pkg, analyzer, use_pypi=True)

            # Check if this package has tests
            if not result.success:
                print(f"  ✗ {result.error_message} - skipping")
                skipped_no_source.append(pkg_name)
                continue

            if result.test_files_found == 0:
                print(f"  ✗ No test files - skipping")
                skipped_no_tests.append(pkg_name)
                continue

            # Package has tests - count it
            results.append(result)

            if result.total_findings > 0:
                print(f"  ⚠️  {result.total_findings} findings: "
                      f"{result.critical_findings} critical, "
                      f"{result.high_findings} high")
                suspicious_packages.append(result)
            else:
                print(f"  ✓ Clean ({result.test_files_found} test files)")

        if len(results) < target_count:
            print(f"\nWarning: Only found {len(results)} packages with tests out of {package_index} tried")

        # Generate report
        report = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "analyzer": "semgrep",
                "mode": "random_sample",
                "target_packages": target_count,
                "packages_tried": package_index,
                "packages_with_tests": len(results),
                "skipped_no_source": len(skipped_no_source),
                "skipped_no_tests": len(skipped_no_tests),
                "packages_with_findings": len(suspicious_packages),
            },
            "summary": {
                "total_findings": sum(r.total_findings for r in results),
                "critical": sum(r.critical_findings for r in results),
                "high": sum(r.high_findings for r in results),
                "medium": sum(r.medium_findings for r in results),
                "low": sum(r.low_findings for r in results),
            },
            "suspicious_packages": [asdict(r) for r in suspicious_packages],
            "all_results": [asdict(r) for r in results],
            "skipped_packages": {
                "no_source": skipped_no_source,
                "no_tests": skipped_no_tests,
            },
        }

        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)

        # Print summary
        print("\n" + "=" * 60)
        print("SEMGREP SCAN SUMMARY (Random Sample)")
        print("=" * 60)
        print(f"Target: {target_count} packages with tests")
        print(f"Packages tried: {package_index}")
        print(f"Packages with tests scanned: {len(results)}")
        print(f"Skipped (no source): {len(skipped_no_source)}")
        print(f"Skipped (no tests): {len(skipped_no_tests)}")
        print(f"Packages with findings: {len(suspicious_packages)}")
        print(f"Total findings: {report['summary']['total_findings']}")
        print(f"  Critical: {report['summary']['critical']}")
        print(f"  High: {report['summary']['high']}")
        print(f"  Medium: {report['summary']['medium']}")
        print(f"  Low: {report['summary']['low']}")

        if suspicious_packages:
            print("\n⚠️  PACKAGES REQUIRING REVIEW:")
            for pkg in suspicious_packages:
                print(f"  - {pkg.package_name}: {pkg.critical_findings} critical, "
                      f"{pkg.high_findings} high findings")
                source = pkg.github_url if pkg.github_url else f"pypi:{pkg.package_name}"
                print(f"    Source: {source}")

        print(f"\nReport written to: {args.output}")
        return

    if args.new_only:
        packages = client.build_scan_list(
            include_high_value=False,
            include_typosquats=False,
            include_recent=False,
            include_new=True,
            custom_packages=args.packages,
            max_packages=args.max_packages,
        )
    else:
        packages = client.build_scan_list(
            include_high_value=True,
            include_typosquats=True,
            include_recent=True,
            include_new=True,
            custom_packages=args.packages,
            max_packages=args.max_packages,
        )

    # Filter packages based on source availability
    if args.pypi_sdist:
        # Scan all packages using PyPI sdist
        packages_to_scan = packages
        print(f"\nWill scan {len(packages_to_scan)} packages from PyPI")
    else:
        # Prefer GitHub but fall back to PyPI
        packages_to_scan = packages
        github_count = sum(1 for p in packages if p.github_url)
        print(f"\nWill scan {len(packages_to_scan)} packages ({github_count} with GitHub repos)")

    results = []
    suspicious_packages = []

    for i, pkg in enumerate(packages_to_scan, 1):
        print(f"\n[{i} out of {len(packages_to_scan)}] {pkg.name}")
        result = scan_package(pkg, analyzer, use_pypi=args.pypi_sdist)
        results.append(result)

        if result.total_findings > 0:
            print(f"  ⚠️  {result.total_findings} findings: "
                  f"{result.critical_findings} critical, "
                  f"{result.high_findings} high")
            suspicious_packages.append(result)
        elif result.success:
            print(f"  ✓ Clean ({result.test_files_found} test files)")
        else:
            print(f"  ✗ {result.error_message}")

    # Generate report
    report = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "analyzer": "semgrep",
            "total_packages": len(packages_to_scan),
            "successful_scans": sum(1 for r in results if r.success),
            "packages_with_findings": len(suspicious_packages),
        },
        "summary": {
            "total_findings": sum(r.total_findings for r in results),
            "critical": sum(r.critical_findings for r in results),
            "high": sum(r.high_findings for r in results),
            "medium": sum(r.medium_findings for r in results),
            "low": sum(r.low_findings for r in results),
        },
        "suspicious_packages": [asdict(r) for r in suspicious_packages],
        "all_results": [asdict(r) for r in results],
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    print("\n" + "=" * 60)
    print("SEMGREP SCAN SUMMARY")
    print("=" * 60)
    print(f"Packages scanned: {len(packages_to_scan)}")
    print(f"Packages with findings: {len(suspicious_packages)}")
    print(f"Total findings: {report['summary']['total_findings']}")
    print(f"  Critical: {report['summary']['critical']}")
    print(f"  High: {report['summary']['high']}")
    print(f"  Medium: {report['summary']['medium']}")
    print(f"  Low: {report['summary']['low']}")

    if suspicious_packages:
        print("\n⚠️  PACKAGES REQUIRING REVIEW:")
        for pkg in suspicious_packages:
            print(f"  - {pkg.package_name}: {pkg.critical_findings} critical, "
                  f"{pkg.high_findings} high findings")
            source = pkg.github_url if pkg.github_url else f"pypi:{pkg.package_name}"
            print(f"    Source: {source}")

    print(f"\nReport written to: {args.output}")


if __name__ == "__main__":
    main()
