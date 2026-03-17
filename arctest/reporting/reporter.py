"""Reporting components for malware detection findings."""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Literal, Any
import json


@dataclass
class Finding:
    """Base class for all findings."""
    severity: Literal["critical", "high", "medium", "low"]
    category: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    test_name: str | None = None
    code_snippet: str | None = None
    recommendation: str | None = None
    blocked: bool = False
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


@dataclass
class StaticFinding(Finding):
    """Finding from static analysis."""
    finding_type: str = "static"
    import_name: str | None = None
    function_name: str | None = None
    pattern_matched: str | None = None


@dataclass
class RuntimeFinding(Finding):
    """Finding from runtime monitoring."""
    finding_type: str = "runtime"
    operation: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class Reporter:
    """Generate reports from malware detection findings."""

    SEVERITY_ORDER = ["critical", "high", "medium", "low"]
    SEVERITY_COLORS = {
        "critical": "\033[91m",   # Red
        "high": "\033[91m",       # Red
        "medium": "\033[93m",     # Yellow
        "low": "\033[37m",        # White
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors

    def _color(self, text: str, color: str) -> str:
        """Apply ANSI color if colors are enabled."""
        if not self.use_colors:
            return text
        return f"{color}{text}{self.RESET}"

    def print_summary(self, findings: list[Finding]) -> None:
        """Print findings summary to console."""
        if not findings:
            print(self._color("arctest: No suspicious activity detected", "\033[92m"))
            return

        print()
        print(self._color("=" * 60, self.BOLD))
        print(self._color("MALWARE GUARD FINDINGS", self.BOLD))
        print(self._color("=" * 60, self.BOLD))

        # Group by severity
        by_severity: dict[str, list[Finding]] = {s: [] for s in self.SEVERITY_ORDER}
        for f in findings:
            by_severity[f.severity].append(f)

        # Count static vs runtime
        static_count = sum(1 for f in findings if isinstance(f, StaticFinding))
        runtime_count = sum(1 for f in findings if isinstance(f, RuntimeFinding))
        blocked_count = sum(1 for f in findings if f.blocked)

        for severity in self.SEVERITY_ORDER:
            severity_findings = by_severity[severity]
            if not severity_findings:
                continue

            color = self.SEVERITY_COLORS[severity]
            print()
            print(self._color(f"[{severity.upper()}] {len(severity_findings)} finding(s):", color))

            for finding in severity_findings[:10]:  # Limit display
                location = ""
                if finding.file_path:
                    filename = Path(finding.file_path).name
                    if finding.line_number:
                        location = f"{filename}:{finding.line_number} - "
                    else:
                        location = f"{filename} - "

                print(f"  - {location}{finding.description}")

            if len(severity_findings) > 10:
                print(f"  ... and {len(severity_findings) - 10} more")

        print()
        print("-" * 60)
        print(f"Static Analysis: {static_count} finding(s)")
        print(f"Runtime Monitoring: {runtime_count} finding(s)")
        if blocked_count > 0:
            print(self._color(f"Blocked: {blocked_count} operation(s)", self.SEVERITY_COLORS["critical"]))
        print()

    def write_json_report(self, findings: list[Finding], output_path: Path) -> None:
        """Write detailed JSON report."""
        # Summary statistics
        by_severity = {s: 0 for s in self.SEVERITY_ORDER}
        for f in findings:
            by_severity[f.severity] += 1

        report = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "plugin_version": "0.1.0",
                "total_findings": len(findings),
            },
            "summary": {
                "by_severity": by_severity,
                "static_findings": sum(1 for f in findings if isinstance(f, StaticFinding)),
                "runtime_findings": sum(1 for f in findings if isinstance(f, RuntimeFinding)),
                "blocked_count": sum(1 for f in findings if f.blocked),
            },
            "findings": [f.to_dict() for f in findings],
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"Full report written to: {output_path}")

    def format_finding_for_pytest(self, finding: Finding) -> str:
        """Format a finding for pytest terminal output."""
        location = ""
        if finding.file_path:
            filename = Path(finding.file_path).name
            if finding.line_number:
                location = f"{filename}:{finding.line_number} - "
            else:
                location = f"{filename} - "

        return f"[{finding.severity.upper()}] {location}{finding.description}"
