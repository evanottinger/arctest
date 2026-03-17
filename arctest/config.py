"""Configuration dataclasses for arctest."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
import os


@dataclass
class NetworkConfig:
    """Network monitoring configuration."""
    enabled: bool = True
    block_outbound: bool = True
    allowed_hosts: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1", "::1"])
    blocked_ports: list[int] = field(default_factory=lambda: [22, 23, 3389, 4444])


@dataclass
class FileSystemConfig:
    """File system monitoring configuration."""
    enabled: bool = True
    allowed_write_paths: list[str] = field(default_factory=list)
    sensitive_paths: list[str] = field(default_factory=lambda: [
        "~/.ssh/",
        "~/.aws/",
        "~/.gnupg/",
        "/etc/passwd",
        "/etc/shadow",
    ])
    block_sensitive_reads: bool = True
    block_external_writes: bool = True


@dataclass
class ProcessConfig:
    """Process monitoring configuration."""
    enabled: bool = True
    block_pty_spawn: bool = True
    block_shell: bool = True
    allowed_executables: list[str] = field(default_factory=lambda: ["python", "pytest"])


@dataclass
class EnvironConfig:
    """Environment variable monitoring configuration."""
    enabled: bool = True
    block_bulk_access: bool = False
    sensitive_patterns: list[str] = field(default_factory=lambda: [
        "AWS_*",
        "*_KEY",
        "*_SECRET",
        "*_TOKEN",
        "*_PASSWORD",
    ])


@dataclass
class MalwareGuardConfig:
    """Main configuration for arctest plugin."""
    mode: Literal["log", "block"] = "log"
    use_semgrep: bool = False
    semgrep_rules_path: Path | None = None
    static_only: bool = False
    report_path: Path | None = None
    external_rule_sources: list[str] = field(default_factory=list)

    network: NetworkConfig = field(default_factory=NetworkConfig)
    file_system: FileSystemConfig = field(default_factory=FileSystemConfig)
    process: ProcessConfig = field(default_factory=ProcessConfig)
    environment: EnvironConfig = field(default_factory=EnvironConfig)

    # Runtime state
    test_root: Path | None = None

    def __post_init__(self) -> None:
        """Expand paths and set defaults."""
        if self.test_root is None:
            self.test_root = Path.cwd()

        # Add temp directory to allowed write paths
        import tempfile
        self.file_system.allowed_write_paths.append(tempfile.gettempdir())

    @classmethod
    def load(cls, config_path: str | None = None) -> "MalwareGuardConfig":
        """Load configuration from YAML file or return defaults."""
        if config_path is None:
            return cls()

        try:
            import yaml
            with open(config_path) as f:
                data = yaml.safe_load(f) or {}

            # Parse nested configs
            network = NetworkConfig(**data.pop("network", {}))
            file_system = FileSystemConfig(**data.pop("file_system", {}))
            process = ProcessConfig(**data.pop("process", {}))
            environment = EnvironConfig(**data.pop("environment", {}))

            return cls(
                network=network,
                file_system=file_system,
                process=process,
                environment=environment,
                **data
            )
        except ImportError:
            # yaml not installed, use defaults
            return cls()
        except Exception:
            # Config file issues, use defaults
            return cls()

    def is_sensitive_path(self, path: Path) -> bool:
        """Check if a path matches sensitive patterns."""
        path_str = str(path)
        home = str(Path.home())

        for sensitive in self.file_system.sensitive_paths:
            # Expand ~ to home directory
            expanded = sensitive.replace("~", home)
            if expanded in path_str or path_str.startswith(expanded.rstrip("/")):
                return True

        return False

    def is_allowed_write_path(self, path: Path) -> bool:
        """Check if writing to this path is allowed."""
        path_resolved = path.resolve()

        # Always allow writing in test directory
        if self.test_root and str(path_resolved).startswith(str(self.test_root.resolve())):
            # But not in src/ directories
            if "src" not in path_resolved.parts:
                return True

        # Check explicit allow list
        for allowed in self.file_system.allowed_write_paths:
            allowed_expanded = os.path.expandvars(os.path.expanduser(allowed))
            if str(path_resolved).startswith(allowed_expanded):
                return True

        return False
