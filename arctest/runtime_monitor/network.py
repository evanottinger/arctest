"""Network operation monitoring."""

import socket
import functools
from typing import Any

from ..config import MalwareGuardConfig
from .base import InterceptorBase, SecurityBlockedError


class NetworkMonitor(InterceptorBase):
    """Monitor and optionally block network operations."""

    def __init__(self, config: MalwareGuardConfig):
        super().__init__(config)

    def install(self) -> None:
        """Install network monitoring patches."""
        if self._installed:
            return

        # Store originals
        self._original_refs["socket_connect"] = socket.socket.connect
        self._original_refs["socket_bind"] = socket.socket.bind

        # Create patched versions
        monitor = self

        @functools.wraps(socket.socket.connect)
        def patched_connect(self_socket: socket.socket, address: Any) -> Any:
            return monitor._handle_connect(self_socket, address)

        @functools.wraps(socket.socket.bind)
        def patched_bind(self_socket: socket.socket, address: Any) -> Any:
            return monitor._handle_bind(self_socket, address)

        # Apply patches
        socket.socket.connect = patched_connect
        socket.socket.bind = patched_bind

        # Try to patch requests library
        self._patch_requests()

        self._installed = True

    def _handle_connect(self, sock: socket.socket, address: Any) -> Any:
        """Handle socket.connect() calls."""
        host = str(address[0]) if isinstance(address, tuple) else str(address)
        port = address[1] if isinstance(address, tuple) and len(address) > 1 else None

        # Check if this is an allowed connection
        is_allowed = host in self.config.network.allowed_hosts
        is_blocked_port = port in self.config.network.blocked_ports if port else False

        severity = "low" if is_allowed else "high"
        if is_blocked_port:
            severity = "critical"

        should_block = self.should_block(severity) and not is_allowed

        finding = self.create_finding(
            severity=severity,
            category="network",
            description=f"Outbound connection to {host}:{port}",
            operation="socket.connect",
            details={"host": host, "port": port, "allowed": is_allowed},
            blocked=should_block,
        )
        self.record_finding(finding)

        if should_block:
            raise SecurityBlockedError(
                f"Blocked outbound connection to {host}:{port}",
                finding=finding,
            )

        return self._original_refs["socket_connect"](sock, address)

    def _handle_bind(self, sock: socket.socket, address: Any) -> Any:
        """Handle socket.bind() calls."""
        host = str(address[0]) if isinstance(address, tuple) else str(address)
        port = address[1] if isinstance(address, tuple) and len(address) > 1 else None

        severity = "medium"
        should_block = self.should_block(severity)

        finding = self.create_finding(
            severity=severity,
            category="network",
            description=f"Server socket binding on {host}:{port}",
            operation="socket.bind",
            details={"host": host, "port": port},
            blocked=should_block,
        )
        self.record_finding(finding)

        if should_block:
            raise SecurityBlockedError(
                f"Blocked server binding on {host}:{port}",
                finding=finding,
            )

        return self._original_refs["socket_bind"](sock, address)

    def _patch_requests(self) -> None:
        """Patch the requests library if available."""
        try:
            import requests
            import requests.api

            self._original_refs["requests_get"] = requests.get
            self._original_refs["requests_post"] = requests.post
            self._original_refs["requests_request"] = requests.api.request

            monitor = self

            def patched_request(method: str, url: str, **kwargs: Any) -> Any:
                return monitor._handle_requests_call(method, url, **kwargs)

            def patched_get(url: str, **kwargs: Any) -> Any:
                return monitor._handle_requests_call("GET", url, **kwargs)

            def patched_post(url: str, **kwargs: Any) -> Any:
                return monitor._handle_requests_call("POST", url, **kwargs)

            requests.api.request = patched_request
            requests.get = patched_get
            requests.post = patched_post

        except ImportError:
            pass

    def _handle_requests_call(self, method: str, url: str, **kwargs: Any) -> Any:
        """Handle requests library calls."""
        severity = "medium"
        should_block = self.should_block(severity)

        finding = self.create_finding(
            severity=severity,
            category="network",
            description=f"HTTP {method} request to {url}",
            operation=f"requests.{method.lower()}",
            details={"method": method, "url": url},
            blocked=should_block,
        )
        self.record_finding(finding)

        if should_block:
            raise SecurityBlockedError(
                f"Blocked HTTP {method} to {url}",
                finding=finding,
            )

        # Call original
        return self._original_refs["requests_request"](method, url, **kwargs)

    def uninstall(self) -> None:
        """Restore original network functions."""
        if not self._installed:
            return

        # Restore socket methods
        if "socket_connect" in self._original_refs:
            socket.socket.connect = self._original_refs["socket_connect"]
        if "socket_bind" in self._original_refs:
            socket.socket.bind = self._original_refs["socket_bind"]

        # Restore requests library
        try:
            import requests
            import requests.api

            if "requests_get" in self._original_refs:
                requests.get = self._original_refs["requests_get"]
            if "requests_post" in self._original_refs:
                requests.post = self._original_refs["requests_post"]
            if "requests_request" in self._original_refs:
                requests.api.request = self._original_refs["requests_request"]
        except ImportError:
            pass

        self._original_refs.clear()
        self._installed = False
