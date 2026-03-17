"""
Rule Manager for External Semgrep Rule Sources

This module handles fetching, caching, and managing external Semgrep rule sources
like GuardDog and Semgrep Registry rules.
"""

import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RuleSource:
    """Definition of an external rule source."""
    name: str
    url: str
    rules_subpath: str  # Path within the repo to the rules
    excluded_rules: list[str] = field(default_factory=list)  # Rules to exclude from this source


# Available external rule sources
# Note: semgrep-python removed - too many false positives from best-practice/maintainability
# rules. GuardDog's 36 malware-focused rules provide better signal-to-noise for malware detection.
SOURCES: dict[str, RuleSource] = {
    "guarddog": RuleSource(
        name="guarddog",
        url="https://github.com/DataDog/guarddog",
        rules_subpath="guarddog/analyzer/sourcecode",
        excluded_rules=[
            # api-obfuscation: Flags normal getattr() usage, too broad
            "api-obfuscation",
            # shady-links: Duplicates built-in suspicious-url with less control
            "shady-links",
        ],
    ),
}


class RuleManager:
    """
    Manages external Semgrep rule sources.

    Handles cloning, updating, and caching of external rule repositories.
    """

    def __init__(self, cache_dir: Path | None = None):
        """
        Initialize the rule manager.

        Args:
            cache_dir: Directory for caching external rules.
                      Defaults to ~/.arctest/rules
        """
        if cache_dir is None:
            cache_dir = Path.home() / ".arctest" / "rules"
        self.cache_dir = cache_dir

    def _ensure_cache_dir(self) -> None:
        """Create the cache directory if it doesn't exist."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_repo_dir(self, source: RuleSource) -> Path:
        """Get the directory where a source's repo is cloned."""
        return self.cache_dir / f".repos" / source.name

    def _get_rules_dir(self, source: RuleSource) -> Path:
        """Get the directory containing the actual rules for a source."""
        return self._get_repo_dir(source) / source.rules_subpath

    def list_sources(self) -> list[str]:
        """List available rule source names."""
        return list(SOURCES.keys())

    def get_source(self, name: str) -> RuleSource | None:
        """Get a rule source by name."""
        return SOURCES.get(name)

    def is_cached(self, source_name: str) -> bool:
        """Check if a rule source is already cached."""
        source = SOURCES.get(source_name)
        if source is None:
            return False
        return self._get_rules_dir(source).exists()

    def fetch_source(self, source_name: str, update: bool = False) -> Path:
        """
        Clone or update a rule source, return path to rules.

        Args:
            source_name: Name of the source to fetch (e.g., "guarddog")
            update: If True, pull latest changes for existing repos

        Returns:
            Path to the directory containing the rules

        Raises:
            ValueError: If source_name is not recognized
            RuntimeError: If git clone/pull fails
        """
        source = SOURCES.get(source_name)
        if source is None:
            available = ", ".join(SOURCES.keys())
            raise ValueError(f"Unknown source: {source_name}. Available: {available}")

        self._ensure_cache_dir()
        repo_dir = self._get_repo_dir(source)

        if repo_dir.exists():
            if update:
                # Pull latest changes
                try:
                    subprocess.run(
                        ["git", "-C", str(repo_dir), "pull", "--ff-only"],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                except subprocess.CalledProcessError as e:
                    raise RuntimeError(f"Failed to update {source_name}: {e.stderr}")
        else:
            # Clone the repository (shallow clone to save space)
            repo_dir.parent.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", source.url, str(repo_dir)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Failed to clone {source_name}: {e.stderr}")

        rules_dir = self._get_rules_dir(source)
        if not rules_dir.exists():
            raise RuntimeError(
                f"Rules directory not found after clone: {source.rules_subpath}"
            )

        return rules_dir

    def update_all(self) -> dict[str, Path | str]:
        """
        Update all cached rule sources.

        Returns:
            Dict mapping source names to their rules path or error message
        """
        results: dict[str, Path | str] = {}

        for source_name in SOURCES:
            if self.is_cached(source_name):
                try:
                    path = self.fetch_source(source_name, update=True)
                    results[source_name] = path
                except RuntimeError as e:
                    results[source_name] = f"Error: {e}"

        return results

    def remove_source(self, source_name: str) -> bool:
        """
        Remove a cached rule source.

        Args:
            source_name: Name of the source to remove

        Returns:
            True if removed, False if not found
        """
        source = SOURCES.get(source_name)
        if source is None:
            return False

        repo_dir = self._get_repo_dir(source)
        if repo_dir.exists():
            shutil.rmtree(repo_dir)
            return True
        return False

    def get_rules_path(self, source_name: str) -> Path | None:
        """
        Get the path to cached rules for a source.

        Args:
            source_name: Name of the source

        Returns:
            Path to rules directory if cached, None otherwise
        """
        source = SOURCES.get(source_name)
        if source is None:
            return None

        rules_dir = self._get_rules_dir(source)
        if rules_dir.exists():
            return rules_dir
        return None

    def get_excluded_rules(self, source_names: list[str] | None = None) -> list[str]:
        """
        Get list of rule IDs to exclude for the given sources.

        Args:
            source_names: List of source names to get exclusions for.
                         If None, returns exclusions for all sources.

        Returns:
            List of rule IDs to exclude
        """
        excluded = []
        sources_to_check = source_names if source_names else list(SOURCES.keys())

        for source_name in sources_to_check:
            source = SOURCES.get(source_name)
            if source and source.excluded_rules:
                excluded.extend(source.excluded_rules)

        return excluded

    def get_all_rule_dirs(
        self,
        include_builtin: bool = True,
        external_sources: list[str] | None = None,
    ) -> list[Path]:
        """
        Return all rule directories (builtin + cached external).

        Args:
            include_builtin: Whether to include the built-in rules
            external_sources: List of external source names to include.
                            If None, includes all cached sources.

        Returns:
            List of paths to rule directories
        """
        dirs: list[Path] = []

        # Add builtin rules
        if include_builtin:
            builtin = Path(__file__).parent / "rules"
            if builtin.exists():
                dirs.append(builtin)

        # Add external sources
        if external_sources is None:
            # Include all cached sources
            for source_name in SOURCES:
                path = self.get_rules_path(source_name)
                if path:
                    dirs.append(path)
        else:
            # Include only specified sources
            for source_name in external_sources:
                path = self.get_rules_path(source_name)
                if path:
                    dirs.append(path)

        return dirs
