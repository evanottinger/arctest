"""Process spawning operation monitoring."""

import os
import subprocess
import functools
import traceback
from typing import Any

from ..config import MalwareGuardConfig
from .base import InterceptorBase, SecurityBlockedError


class ProcessMonitor(InterceptorBase):
    """Monitor and optionally block process spawning operations."""

    def __init__(self, config: MalwareGuardConfig):
        super().__init__(config)

    def install(self) -> None:
        """Install process monitoring patches."""
        if self._installed:
            return

        # Patch pty.spawn (Unix only)
        self._patch_pty()

        # Patch subprocess
        self._patch_subprocess()

        # Patch os functions
        self._patch_os_functions()

        self._installed = True

    def _patch_pty(self) -> None:
        """Patch pty.spawn if available (Unix only)."""
        try:
            import pty

            self._original_refs["pty_spawn"] = pty.spawn
            monitor = self

            @functools.wraps(pty.spawn)
            def patched_spawn(argv: Any, *args: Any, **kwargs: Any) -> Any:
                return monitor._handle_pty_spawn(argv, *args, **kwargs)

            pty.spawn = patched_spawn

        except ImportError:
            # pty not available on Windows
            pass

    def _handle_pty_spawn(self, argv: Any, *args: Any, **kwargs: Any) -> Any:
        """Handle pty.spawn() calls - critical reverse shell indicator."""
        cmd = argv if isinstance(argv, str) else str(argv)

        finding = self.create_finding(
            severity="critical",
            category="process_spawn",
            description=f"PTY spawn detected: {cmd} - likely reverse shell",
            operation="pty.spawn",
            details={"command": cmd},
            blocked=self.should_block("critical"),
        )
        self.record_finding(finding)

        if finding.blocked:
            raise SecurityBlockedError(
                f"Blocked pty.spawn({cmd})",
                finding=finding,
            )

        return self._original_refs["pty_spawn"](argv, *args, **kwargs)

    def _patch_subprocess(self) -> None:
        """Patch subprocess module."""
        self._original_refs["subprocess_popen_init"] = subprocess.Popen.__init__

        monitor = self
        original_init = subprocess.Popen.__init__

        @functools.wraps(subprocess.Popen.__init__)
        def patched_init(
            self_popen: subprocess.Popen,
            args: Any,
            *pargs: Any,
            **kwargs: Any
        ) -> None:
            monitor._handle_subprocess(args, kwargs.get("shell", False))
            return original_init(self_popen, args, *pargs, **kwargs)

        subprocess.Popen.__init__ = patched_init

    def _handle_subprocess(self, args: Any, shell: bool) -> None:
        """Handle subprocess.Popen() calls."""
        cmd = args if isinstance(args, str) else " ".join(str(a) for a in args) if hasattr(args, "__iter__") else str(args)

        severity = "high" if shell else "medium"
        should_block = self.should_block(severity) and shell

        finding = self.create_finding(
            severity=severity,
            category="process_spawn",
            description=f"Subprocess: {cmd}" + (" (shell=True)" if shell else ""),
            operation="subprocess.Popen",
            details={"command": cmd, "shell": shell},
            blocked=should_block,
        )
        self.record_finding(finding)

        if should_block:
            raise SecurityBlockedError(
                f"Blocked subprocess with shell=True: {cmd}",
                finding=finding,
            )

    def _patch_os_functions(self) -> None:
        """Patch os.system, os.popen, os.dup2."""
        # os.system
        if hasattr(os, "system"):
            self._original_refs["os_system"] = os.system
            monitor = self

            @functools.wraps(os.system)
            def patched_system(command: str) -> int:
                return monitor._handle_os_system(command)

            os.system = patched_system

        # os.popen
        if hasattr(os, "popen"):
            self._original_refs["os_popen"] = os.popen
            monitor = self

            @functools.wraps(os.popen)
            def patched_popen(cmd: str, *args: Any, **kwargs: Any) -> Any:
                return monitor._handle_os_popen(cmd, *args, **kwargs)

            os.popen = patched_popen

        # os.dup2 - used in reverse shells
        self._original_refs["os_dup2"] = os.dup2
        monitor = self

        @functools.wraps(os.dup2)
        def patched_dup2(fd: int, fd2: int) -> int:
            return monitor._handle_os_dup2(fd, fd2)

        os.dup2 = patched_dup2

    def _handle_os_system(self, command: str) -> int:
        """Handle os.system() calls."""
        finding = self.create_finding(
            severity="high",
            category="process_spawn",
            description=f"Shell command via os.system: {command}",
            operation="os.system",
            details={"command": command},
            blocked=self.should_block("high"),
        )
        self.record_finding(finding)

        if finding.blocked:
            raise SecurityBlockedError(
                f"Blocked os.system({command})",
                finding=finding,
            )

        return self._original_refs["os_system"](command)

    def _handle_os_popen(self, cmd: str, *args: Any, **kwargs: Any) -> Any:
        """Handle os.popen() calls."""
        finding = self.create_finding(
            severity="high",
            category="process_spawn",
            description=f"Shell command via os.popen: {cmd}",
            operation="os.popen",
            details={"command": cmd},
            blocked=self.should_block("high"),
        )
        self.record_finding(finding)

        if finding.blocked:
            raise SecurityBlockedError(
                f"Blocked os.popen({cmd})",
                finding=finding,
            )

        return self._original_refs["os_popen"](cmd, *args, **kwargs)

    def _is_pytest_internal_call(self) -> bool:
        """Check if the call is coming from pytest internals (e.g., capture mechanism)."""
        stack = traceback.extract_stack()
        for frame in stack:
            # Check for pytest internal modules
            if "_pytest" in frame.filename or "pytest" in frame.filename:
                if "capture" in frame.filename or "capture" in frame.name:
                    return True
            # Check for contextlib (used by pytest capture)
            if "contextlib" in frame.filename:
                return True
        return False

    def _handle_os_dup2(self, fd: int, fd2: int) -> int:
        """Handle os.dup2() calls - used in reverse shells."""
        # Skip pytest's internal dup2 calls (used for stdout/stderr capture)
        if self._is_pytest_internal_call():
            return self._original_refs["os_dup2"](fd, fd2)

        # File descriptors 0, 1, 2 are stdin, stdout, stderr
        # Redirecting these is a common reverse shell technique
        is_stdio_redirect = fd2 in (0, 1, 2)

        severity = "high" if is_stdio_redirect else "low"
        should_block = self.should_block(severity) and is_stdio_redirect

        if is_stdio_redirect:
            finding = self.create_finding(
                severity=severity,
                category="process_spawn",
                description=f"File descriptor redirection: dup2({fd}, {fd2}) - reverse shell technique",
                operation="os.dup2",
                details={"fd": fd, "fd2": fd2, "stdio_redirect": is_stdio_redirect},
                blocked=should_block,
            )
            self.record_finding(finding)

            if should_block:
                raise SecurityBlockedError(
                    f"Blocked os.dup2 stdio redirection",
                    finding=finding,
                )

        return self._original_refs["os_dup2"](fd, fd2)

    def uninstall(self) -> None:
        """Restore original functions."""
        if not self._installed:
            return

        # Restore pty.spawn
        try:
            import pty
            if "pty_spawn" in self._original_refs:
                pty.spawn = self._original_refs["pty_spawn"]
        except ImportError:
            pass

        # Restore subprocess
        if "subprocess_popen_init" in self._original_refs:
            subprocess.Popen.__init__ = self._original_refs["subprocess_popen_init"]

        # Restore os functions
        if "os_system" in self._original_refs:
            os.system = self._original_refs["os_system"]
        if "os_popen" in self._original_refs:
            os.popen = self._original_refs["os_popen"]
        if "os_dup2" in self._original_refs:
            os.dup2 = self._original_refs["os_dup2"]

        self._original_refs.clear()
        self._installed = False
