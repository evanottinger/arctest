"""File I/O operation monitoring."""

import builtins
import functools
from pathlib import Path
from typing import Any

from ..config import MalwareGuardConfig
from .patterns import is_sensitive_path
from .base import InterceptorBase, SecurityBlockedError


class FileMonitor(InterceptorBase):
    """Monitor and optionally block file operations."""

    def __init__(self, config: MalwareGuardConfig):
        super().__init__(config)

    def install(self) -> None:
        """Install file monitoring patches."""
        if self._installed:
            return

        # Store original
        self._original_refs["open"] = builtins.open

        # Create patched version
        monitor = self
        original_open = builtins.open

        @functools.wraps(builtins.open)
        def patched_open(
            file: Any,
            mode: str = "r",
            *args: Any,
            **kwargs: Any
        ) -> Any:
            return monitor._handle_open(original_open, file, mode, *args, **kwargs)

        # Apply patch
        builtins.open = patched_open
        self._installed = True

    def _handle_open(
        self,
        original_open: Any,
        file: Any,
        mode: str,
        *args: Any,
        **kwargs: Any
    ) -> Any:
        """Handle open() calls."""
        try:
            file_path = Path(file).resolve()
        except (TypeError, OSError):
            # Can't resolve path, let it through
            return original_open(file, mode, *args, **kwargs)

        is_write = any(m in mode for m in ("w", "a", "x", "+"))
        path_str = str(file_path)

        if is_write:
            return self._handle_write(original_open, file, mode, file_path, *args, **kwargs)
        else:
            return self._handle_read(original_open, file, mode, file_path, *args, **kwargs)

    def _handle_write(
        self,
        original_open: Any,
        file: Any,
        mode: str,
        file_path: Path,
        *args: Any,
        **kwargs: Any
    ) -> Any:
        """Handle file write operations."""
        is_allowed = self.config.is_allowed_write_path(file_path)

        # Check if writing to source directories (common malware pattern)
        is_source_mutation = "src" in file_path.parts or "lib" in file_path.parts

        severity = "low"
        if not is_allowed:
            severity = "medium"
        if is_source_mutation:
            severity = "high"

        should_block = self.should_block(severity) and not is_allowed

        finding = self.create_finding(
            severity=severity,
            category="file_write",
            description=f"File write: {file_path}",
            operation="open(write)",
            details={
                "path": str(file_path),
                "mode": mode,
                "allowed": is_allowed,
                "source_mutation": is_source_mutation,
            },
            blocked=should_block,
        )
        self.record_finding(finding)

        if should_block:
            raise SecurityBlockedError(
                f"Blocked file write to {file_path}",
                finding=finding,
            )

        return original_open(file, mode, *args, **kwargs)

    def _handle_read(
        self,
        original_open: Any,
        file: Any,
        mode: str,
        file_path: Path,
        *args: Any,
        **kwargs: Any
    ) -> Any:
        """Handle file read operations."""
        path_str = str(file_path)

        # Check for sensitive path access
        if is_sensitive_path(path_str) or self.config.is_sensitive_path(file_path):
            severity = "critical"
            should_block = self.should_block(severity)

            finding = self.create_finding(
                severity=severity,
                category="sensitive_file_read",
                description=f"Sensitive file read: {file_path}",
                operation="open(read)",
                details={"path": path_str, "mode": mode},
                blocked=should_block,
            )
            self.record_finding(finding)

            if should_block:
                raise SecurityBlockedError(
                    f"Blocked read of sensitive file {file_path}",
                    finding=finding,
                )

        return original_open(file, mode, *args, **kwargs)

    def uninstall(self) -> None:
        """Restore original open function."""
        if not self._installed:
            return

        if "open" in self._original_refs:
            builtins.open = self._original_refs["open"]

        self._original_refs.clear()
        self._installed = False
