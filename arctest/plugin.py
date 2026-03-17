"""Pytest plugin for malware detection in unit tests."""

from pathlib import Path
from typing import Generator, Any
import pytest

from .config import MalwareGuardConfig
from .semgrep_analyzer import SemgrepAnalyzer
from .rule_manager import RuleManager
from .runtime_monitor.base import InterceptorBase, SecurityBlockedError
from .runtime_monitor.network import NetworkMonitor
from .runtime_monitor.file import FileMonitor
from .runtime_monitor.process import ProcessMonitor
from .runtime_monitor.environ import EnvironMonitor
from .reporting.reporter import Reporter, Finding, StaticFinding


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add command-line options for arctest."""
    group = parser.getgroup("arctest", "Malware detection options")

    group.addoption(
        "--arctest",
        action="store_true",
        default=False,
        help="Enable malware detection scanning",
    )
    group.addoption(
        "--arctest-mode",
        choices=["log", "block"],
        default="log",
        help="Detection mode: 'log' records findings, 'block' halts execution (default: log)",
    )
    group.addoption(
        "--arctest-static-only",
        action="store_true",
        default=False,
        help="Only run static analysis, skip runtime monitoring",
    )
    group.addoption(
        "--arctest-report",
        type=str,
        default=None,
        metavar="PATH",
        help="Path for JSON report output",
    )
    group.addoption(
        "--arctest-config",
        type=str,
        default=None,
        metavar="PATH",
        help="Path to YAML configuration file",
    )
    group.addoption(
        "--arctest-external-rules",
        type=str,
        default=None,
        metavar="SOURCES",
        help="Comma-separated list of external rule sources (e.g., guarddog,semgrep-python-security)",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Initialize the arctest plugin."""
    if not config.getoption("--arctest", default=False):
        return

    # Register marker
    config.addinivalue_line(
        "markers",
        "arctest_skip: skip malware detection for this test",
    )

    # Load configuration
    config_path = config.getoption("--arctest-config")
    guard_config = MalwareGuardConfig.load(config_path)
    guard_config.mode = config.getoption("--arctest-mode")
    guard_config.static_only = config.getoption("--arctest-static-only")
    guard_config.test_root = Path(config.rootdir)

    report_path = config.getoption("--arctest-report")
    if report_path:
        guard_config.report_path = Path(report_path)

    # Parse external rules option
    external_rules_opt = config.getoption("--arctest-external-rules")
    if external_rules_opt:
        guard_config.external_rule_sources = [
            s.strip() for s in external_rules_opt.split(",") if s.strip()
        ]

    # Store in config for access by other hooks
    config._malware_guard_config = guard_config
    config._malware_guard_findings: list[Finding] = []

    # Initialize analyzers with rule directories
    rule_manager = RuleManager()
    rules_dirs = rule_manager.get_all_rule_dirs(
        include_builtin=True,
        external_sources=guard_config.external_rule_sources or None,
    )

    # Add custom rules path if configured
    if guard_config.semgrep_rules_path:
        rules_dirs.append(guard_config.semgrep_rules_path)

    config._malware_semgrep_analyzer = SemgrepAnalyzer(rules_dirs=rules_dirs)

    # Reset interceptor state
    InterceptorBase.reset()


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(
    session: pytest.Session,
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Run static analysis on collected test files before execution."""
    if not hasattr(config, "_malware_guard_config"):
        return

    guard_config: MalwareGuardConfig = config._malware_guard_config
    analyzer: SemgrepAnalyzer = config._malware_semgrep_analyzer

    # Collect unique test file paths
    test_files = {Path(str(item.fspath)) for item in items if item.fspath}

    print(f"\narctest: Analyzing {len(test_files)} test file(s)...")

    for test_file in test_files:
        if test_file.suffix == ".py":
            result = analyzer.analyze_file(test_file)
            # Convert Semgrep findings to StaticFinding for reporter compatibility
            for finding in result.findings:
                static_finding = StaticFinding(
                    severity=finding.severity if finding.severity in ("critical", "high", "medium", "low") else "medium",
                    category=finding.category or "static-analysis",
                    description=finding.message,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    code_snippet=finding.code_snippet,
                    pattern_matched=finding.rule_id,
                )
                config._malware_guard_findings.append(static_finding)

    static_count = len(config._malware_guard_findings)
    if static_count > 0:
        print(f"arctest: Found {static_count} static analysis finding(s)")

    # In block mode, fail collection if critical findings exist
    if guard_config.mode == "block":
        critical_findings = [
            f for f in config._malware_guard_findings
            if f.severity == "critical"
        ]
        if critical_findings:
            pytest.exit(
                f"\narctest: BLOCKED - {len(critical_findings)} critical "
                f"finding(s) detected in static analysis.\n"
                f"Run with --malware-mode=log to see details.",
                returncode=1,
            )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(
    item: pytest.Item,
    nextitem: pytest.Item | None,
) -> Generator[None, None, None]:
    """Wrap test execution with runtime monitoring."""
    config = item.config

    if not hasattr(config, "_malware_guard_config"):
        yield
        return

    guard_config: MalwareGuardConfig = config._malware_guard_config

    # Skip if static-only mode
    if guard_config.static_only:
        yield
        return

    # Skip if test is marked to skip malware guard
    if item.get_closest_marker("arctest_skip"):
        yield
        return

    # Initialize runtime monitors
    monitors = [
        NetworkMonitor(guard_config),
        FileMonitor(guard_config),
        ProcessMonitor(guard_config),
        EnvironMonitor(guard_config),
    ]

    # Set current test name
    InterceptorBase.set_current_test(item.nodeid)

    # Install monitors
    for monitor in monitors:
        try:
            monitor.install()
        except Exception as e:
            # Don't fail if monitor can't install (e.g., pty on Windows)
            pass

    try:
        yield
    except SecurityBlockedError as e:
        # Already recorded finding, re-raise for pytest to handle
        pytest.fail(f"arctest: {e}")
    finally:
        # Uninstall monitors
        for monitor in monitors:
            try:
                monitor.uninstall()
            except Exception:
                pass

        # Collect runtime findings
        runtime_findings = InterceptorBase.get_findings()
        config._malware_guard_findings.extend(runtime_findings)

        # Clear for next test
        InterceptorBase.clear_findings()
        InterceptorBase.set_current_test(None)


def pytest_sessionfinish(
    session: pytest.Session,
    exitstatus: int,
) -> None:
    """Generate final report after all tests complete."""
    config = session.config

    if not hasattr(config, "_malware_guard_config"):
        return

    guard_config: MalwareGuardConfig = config._malware_guard_config
    findings: list[Finding] = config._malware_guard_findings

    # Write JSON report if requested
    if guard_config.report_path:
        reporter = Reporter(use_colors=False)
        reporter.write_json_report(findings, guard_config.report_path)


def pytest_terminal_summary(
    terminalreporter: Any,
    exitstatus: int,
    config: pytest.Config,
) -> None:
    """Add malware guard summary to terminal output."""
    if not hasattr(config, "_malware_guard_findings"):
        return

    findings: list[Finding] = config._malware_guard_findings

    # Use reporter for formatted output
    reporter = Reporter(use_colors=True)
    reporter.print_summary(findings)
