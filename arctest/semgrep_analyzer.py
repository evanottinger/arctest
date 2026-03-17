"""
Semgrep Integration for arctest

This module provides pattern-based code analysis using custom Semgrep rules.
These rules focus on behavioral patterns commonly seen in malware.
"""

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    """A security finding from analysis."""
    rule_id: str
    severity: str
    message: str
    file_path: str
    line_number: int
    code_snippet: str = ""
    category: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "category": self.category,
        }


@dataclass
class AnalysisResult:
    """Result of analyzing a path."""
    path: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(f.severity.lower() in ("critical", "error") for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity.lower() in ("high", "warning") for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity.lower() in ("critical", "error")),
                "high": sum(1 for f in self.findings if f.severity.lower() in ("high", "warning")),
                "medium": sum(1 for f in self.findings if f.severity.lower() == "medium"),
                "low": sum(1 for f in self.findings if f.severity.lower() in ("low", "info")),
            }
        }


class SemgrepAnalyzer:
    """
    Pattern-based code analyzer using Semgrep rules.

    This analyzer uses Semgrep pattern matching to detect potentially
    malicious code patterns in test files.
    """

    # Severity mapping from Semgrep to our categories
    SEVERITY_MAP = {
        "ERROR": "critical",
        "WARNING": "high",
        "INFO": "low",
    }

    def __init__(
        self,
        rules_dirs: list[Path] | Path | None = None,
        excluded_rules: list[str] | None = None,
    ):
        """
        Initialize the analyzer.

        Args:
            rules_dirs: Directory or list of directories containing Semgrep rules.
                       If None, uses the default rules in this package.
            excluded_rules: List of rule IDs to exclude from scanning.
        """
        if rules_dirs is None:
            # Use rules from this package
            package_dir = Path(__file__).parent
            self.rules_dirs = [package_dir / "rules"]
        elif isinstance(rules_dirs, Path):
            self.rules_dirs = [rules_dirs]
        else:
            self.rules_dirs = list(rules_dirs)

        self.excluded_rules = excluded_rules or []

        self._validate_rules_dirs()

    def _validate_rules_dirs(self) -> None:
        """Validate that all rules directories exist and have rules."""
        if not self.rules_dirs:
            raise ValueError("At least one rules directory must be provided")

        total_rules = 0
        for rules_dir in self.rules_dirs:
            if not rules_dir.exists():
                raise ValueError(f"Rules directory does not exist: {rules_dir}")

            rule_files = (
                list(rules_dir.glob("**/*.yml")) +
                list(rules_dir.glob("**/*.yaml"))
            )
            total_rules += len(rule_files)

        if total_rules == 0:
            dirs_str = ", ".join(str(d) for d in self.rules_dirs)
            raise ValueError(f"No rule files found in: {dirs_str}")

    def _run_semgrep(self, target_path: Path) -> dict:
        """
        Run Semgrep with our custom rules on the target path.

        Args:
            target_path: Path to scan (file or directory)

        Returns:
            Semgrep JSON output as a dictionary
        """
        # Build target list - if directory, expand to Python files
        if target_path.is_dir():
            targets = list(target_path.glob("**/*.py"))
            if not targets:
                return {"results": [], "errors": ["No Python files found"]}
            target_args = [str(t) for t in targets]
        else:
            target_args = [str(target_path)]

        cmd = ["semgrep", "--json", "--no-git-ignore", "--metrics", "off"]
        for rules_dir in self.rules_dirs:
            cmd.extend(["--config", str(rules_dir)])
        for rule_id in self.excluded_rules:
            cmd.extend(["--exclude-rule", rule_id])
        cmd.extend(target_args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            # Semgrep returns non-zero if findings exist, so check for JSON output
            if result.stdout:
                return json.loads(result.stdout)
            elif result.returncode != 0:
                return {"errors": [result.stderr], "results": []}
            else:
                return {"results": [], "errors": []}

        except subprocess.TimeoutExpired:
            return {"errors": ["Semgrep timed out"], "results": []}
        except json.JSONDecodeError as e:
            return {"errors": [f"Failed to parse Semgrep output: {e}"], "results": []}
        except FileNotFoundError:
            return {"errors": ["Semgrep not found. Install with: pip install semgrep"], "results": []}

    def analyze(self, path: str | Path) -> AnalysisResult:
        """
        Analyze a file or directory for suspicious patterns.

        Args:
            path: Path to analyze (file or directory)

        Returns:
            AnalysisResult with findings
        """
        target_path = Path(path)
        result = AnalysisResult(path=str(target_path))

        if not target_path.exists():
            result.errors.append(f"Path does not exist: {target_path}")
            return result

        # Run Semgrep
        semgrep_output = self._run_semgrep(target_path)

        # Process errors
        if "errors" in semgrep_output:
            for error in semgrep_output.get("errors", []):
                if isinstance(error, dict):
                    result.errors.append(error.get("message", str(error)))
                else:
                    result.errors.append(str(error))

        # Process findings
        for finding in semgrep_output.get("results", []):
            check_id = finding.get("check_id", "unknown")

            # Check if this rule should be excluded (match by suffix)
            # Semgrep transforms rule IDs to include the config path,
            # e.g., "path.to.config.api-obfuscation" for rule id "api-obfuscation"
            rule_name = check_id.split(".")[-1]  # Get the actual rule name
            if rule_name in self.excluded_rules:
                continue

            severity = finding.get("extra", {}).get("severity", "WARNING")
            message = finding.get("extra", {}).get("message", "")

            # Extract location
            file_path = finding.get("path", "")
            start_line = finding.get("start", {}).get("line", 0)

            # Extract code snippet
            lines = finding.get("extra", {}).get("lines", "")

            # Extract category from metadata
            metadata = finding.get("extra", {}).get("metadata", {})
            category = metadata.get("category", "")

            result.findings.append(Finding(
                rule_id=check_id,
                severity=self.SEVERITY_MAP.get(severity, severity.lower()),
                message=message,
                file_path=file_path,
                line_number=start_line,
                code_snippet=lines,
                category=category,
            ))

        return result

    def analyze_file(self, file_path: str | Path) -> AnalysisResult:
        """Analyze a single file."""
        return self.analyze(file_path)

    def analyze_directory(self, dir_path: str | Path) -> AnalysisResult:
        """Analyze all Python files in a directory."""
        return self.analyze(dir_path)


def analyze_test_files(test_dir: str | Path) -> AnalysisResult:
    """
    Convenience function to analyze test files for malware patterns.

    Args:
        test_dir: Directory containing test files

    Returns:
        AnalysisResult with all findings
    """
    analyzer = SemgrepAnalyzer()
    return analyzer.analyze(test_dir)


# For CLI usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python semgrep_analyzer.py <path>")
        sys.exit(1)

    target = sys.argv[1]
    result = analyze_test_files(target)

    print(json.dumps(result.to_dict(), indent=2))

    if result.has_critical:
        sys.exit(2)
    elif result.has_high:
        sys.exit(1)
    sys.exit(0)
