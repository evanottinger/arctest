"""Environment variable access monitoring."""

import os
from typing import Any, Iterator

from ..config import MalwareGuardConfig
from .base import InterceptorBase, SecurityBlockedError


class MonitoredEnviron:
    """Proxy for os.environ that monitors access patterns."""

    def __init__(self, original: os._Environ, monitor: "EnvironMonitor"):
        # Use object.__setattr__ to avoid triggering our __setattr__
        object.__setattr__(self, "_original", original)
        object.__setattr__(self, "_monitor", monitor)

    def __repr__(self) -> str:
        """Bulk access via repr() - often used in print(os.environ)."""
        self._monitor._record_bulk_access("__repr__")
        return repr(self._original)

    def __str__(self) -> str:
        """Bulk access via str()."""
        self._monitor._record_bulk_access("__str__")
        return str(self._original)

    def __iter__(self) -> Iterator[str]:
        """Bulk access via iteration."""
        self._monitor._record_bulk_access("__iter__")
        return iter(self._original)

    def __len__(self) -> int:
        """Get length."""
        return len(self._original)

    def __contains__(self, key: str) -> bool:
        """Check if key exists."""
        return key in self._original

    def __getitem__(self, key: str) -> str:
        """Single key access."""
        self._monitor._record_single_access(key)
        return self._original[key]

    def __setitem__(self, key: str, value: str) -> None:
        """Set environment variable."""
        self._original[key] = value

    def __delitem__(self, key: str) -> None:
        """Delete environment variable."""
        del self._original[key]

    def get(self, key: str, default: str | None = None) -> str | None:
        """Get with default."""
        self._monitor._record_single_access(key)
        return self._original.get(key, default)

    def keys(self) -> Any:
        """Bulk access via keys()."""
        self._monitor._record_bulk_access("keys")
        return self._original.keys()

    def values(self) -> Any:
        """Bulk access via values()."""
        self._monitor._record_bulk_access("values")
        return self._original.values()

    def items(self) -> Any:
        """Bulk access via items()."""
        self._monitor._record_bulk_access("items")
        return self._original.items()

    def copy(self) -> dict[str, str]:
        """Bulk access via copy()."""
        self._monitor._record_bulk_access("copy")
        return self._original.copy()

    def pop(self, key: str, *args: Any) -> str:
        """Pop a key."""
        return self._original.pop(key, *args)

    def setdefault(self, key: str, default: str = "") -> str:
        """Set default value."""
        return self._original.setdefault(key, default)

    def update(self, *args: Any, **kwargs: Any) -> None:
        """Update environ."""
        self._original.update(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Delegate unknown attributes to original."""
        return getattr(self._original, name)


class EnvironMonitor(InterceptorBase):
    """Monitor environment variable access patterns."""

    def __init__(self, config: MalwareGuardConfig):
        super().__init__(config)
        self._bulk_access_recorded = False

    def install(self) -> None:
        """Install environment monitoring."""
        if self._installed:
            return

        # Store original environ
        self._original_refs["environ"] = os.environ

        # Replace with monitored version
        os.environ = MonitoredEnviron(self._original_refs["environ"], self)

        self._installed = True
        self._bulk_access_recorded = False

    def _record_bulk_access(self, method: str) -> None:
        """Record bulk environment variable access."""
        # Only record once per test to avoid noise
        if self._bulk_access_recorded:
            return
        self._bulk_access_recorded = True

        severity = "medium"
        should_block = self.should_block(severity) and self.config.environment.block_bulk_access

        finding = self.create_finding(
            severity=severity,
            category="env_access",
            description=f"Bulk environment variable access via {method}()",
            operation=f"os.environ.{method}",
            details={"method": method, "access_type": "bulk"},
            blocked=should_block,
        )
        self.record_finding(finding)

        if should_block:
            raise SecurityBlockedError(
                f"Blocked bulk environment access via {method}()",
                finding=finding,
            )

    def _record_single_access(self, key: str) -> None:
        """Record single environment variable access."""
        # Check if it's a sensitive variable
        from .patterns import is_sensitive_env_var

        if is_sensitive_env_var(key):
            finding = self.create_finding(
                severity="low",
                category="env_access",
                description=f"Sensitive environment variable access: {key}",
                operation="os.environ.get",
                details={"key": key, "access_type": "single", "sensitive": True},
                blocked=False,  # Don't block single access
            )
            self.record_finding(finding)

    def uninstall(self) -> None:
        """Restore original os.environ."""
        if not self._installed:
            return

        if "environ" in self._original_refs:
            os.environ = self._original_refs["environ"]

        self._original_refs.clear()
        self._installed = False
        self._bulk_access_recorded = False
