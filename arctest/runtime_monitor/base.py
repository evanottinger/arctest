"""Base class for runtime monitors."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
import threading

from ..config import MalwareGuardConfig
from ..reporting.reporter import RuntimeFinding


class SecurityBlockedError(Exception):
    """Raised when a security-sensitive operation is blocked."""

    def __init__(self, message: str, finding: RuntimeFinding | None = None):
        super().__init__(message)
        self.finding = finding


class InterceptorBase:
    """Base class for all runtime interceptors."""

    # Class-level state shared across instances
    _findings: list[RuntimeFinding] = []
    _lock = threading.Lock()
    _current_test: str | None = None

    def __init__(self, config: MalwareGuardConfig):
        self.config = config
        self._original_refs: dict[str, Any] = {}
        self._installed = False

    @classmethod
    def set_current_test(cls, test_name: str | None) -> None:
        """Set the current test name for all interceptors."""
        cls._current_test = test_name

    @classmethod
    def get_findings(cls) -> list[RuntimeFinding]:
        """Get all collected findings."""
        with cls._lock:
            return list(cls._findings)

    @classmethod
    def clear_findings(cls) -> None:
        """Clear all findings."""
        with cls._lock:
            cls._findings.clear()

    @classmethod
    def reset(cls) -> None:
        """Reset all class-level state."""
        cls._findings = []
        cls._current_test = None

    def record_finding(self, finding: RuntimeFinding) -> None:
        """Record a finding in a thread-safe manner."""
        with self._lock:
            self._findings.append(finding)

    def create_finding(
        self,
        severity: str,
        category: str,
        description: str,
        operation: str,
        details: dict[str, Any] | None = None,
        blocked: bool = False,
    ) -> RuntimeFinding:
        """Create a runtime finding with current context."""
        return RuntimeFinding(
            severity=severity,
            category=category,
            description=description,
            operation=operation,
            details=details or {},
            test_name=self._current_test,
            blocked=blocked,
            timestamp=datetime.now(),
        )

    def should_block(self, severity: str) -> bool:
        """Determine if an operation should be blocked based on config and severity."""
        if self.config.mode != "block":
            return False
        # Block critical and high severity in block mode
        return severity in ("critical", "high")

    def install(self) -> None:
        """Install the interceptor. Override in subclasses."""
        raise NotImplementedError("Subclasses must implement install()")

    def uninstall(self) -> None:
        """Uninstall the interceptor. Override in subclasses."""
        raise NotImplementedError("Subclasses must implement uninstall()")

    def __enter__(self) -> "InterceptorBase":
        """Context manager entry."""
        self.install()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.uninstall()
