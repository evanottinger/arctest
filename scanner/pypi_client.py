#!/usr/bin/env python3
"""
PyPI Client for Package Information

Provides API access to PyPI for package metadata, RSS feeds, and package lists.
Does not perform any scanning - use pypi_scan.py for that.
"""

import re
from dataclasses import dataclass
from typing import Optional
from urllib.request import urlopen

import requests


@dataclass
class PackageInfo:
    """Information about a PyPI package."""

    name: str
    version: str
    download_url: str
    downloads_last_month: int = 0
    author: str = ""
    maintainer: str = ""
    home_page: str = ""
    requires_python: str = ""
    release_date: str = ""
    priority_reason: str = ""
    github_url: str = ""


class PyPIClient:
    """Client for PyPI package information."""

    PYPI_API_URL = "https://pypi.org/pypi"

    # High-value packages (popular, widely used) - expanded list
    HIGH_VALUE_PACKAGES = [
        # Web frameworks
        "requests", "flask", "django", "fastapi", "aiohttp", "tornado", "bottle",
        "starlette", "httpx", "urllib3",
        # Data science
        "numpy", "pandas", "scipy", "matplotlib", "scikit-learn", "tensorflow",
        "pytorch", "keras",
        # Cloud/DevOps
        "boto3", "azure-core", "google-cloud-core", "kubernetes", "docker",
        "ansible", "fabric", "paramiko",
        # Security/Crypto
        "cryptography", "pycryptodome", "bcrypt", "passlib", "certifi",
        # Parsing/Serialization
        "pyyaml", "toml", "lxml", "beautifulsoup4", "html5lib", "xmltodict",
        # Database
        "sqlalchemy", "psycopg2", "pymongo", "redis", "elasticsearch",
        # Utils
        "pillow", "click", "colorama", "tqdm", "rich", "pytest", "setuptools",
        "pip", "wheel", "virtualenv", "poetry", "black", "flake8", "mypy",
        # Async
        "celery", "asyncio", "gevent", "eventlet", "twisted",
    ]

    # Known typosquatting patterns to check - expanded
    TYPOSQUAT_PATTERNS = [
        # Misspellings of popular packages
        ("requests", ["reqeusts", "requets", "request", "reqests", "reequests", "requsts", "rquests"]),
        ("numpy", ["numpi", "numppy", "nunpy", "numy", "numpie", "numby"]),
        ("pandas", ["panda", "pandass", "pandsa", "pands", "pandos"]),
        ("django", ["djano", "djanog", "djnago", "djanogo", "djang"]),
        ("flask", ["flasks", "flaask", "flaskk", "flaski", "flak"]),
        ("urllib3", ["urllib", "urlib3", "urllib33", "urllb3", "urlllib3"]),
        ("colorama", ["colourama", "coloram", "colorsama", "coloramma", "colrama"]),
        ("setuptools", ["setuptool", "setup-tools", "setuptoolss", "setiptools", "setuptoools"]),
        ("beautifulsoup4", ["beautifulsoup", "beutifulsoup4", "beautifulsoup5", "bs4"]),
        ("tensorflow", ["tenserflow", "tensorflw", "tensorfow", "tesnorflow"]),
        ("scikit-learn", ["scikitlearn", "sklearn", "scikit", "scikit-learns"]),
        ("cryptography", ["cryptograpy", "cyptography", "cryptographyy", "crytography"]),
        ("boto3", ["boto", "botto3", "boto33", "botoo3"]),
        ("pillow", ["pillo", "pilllow", "pilloow", "pil"]),
        ("pytest", ["pytset", "pyest", "pytests", "py-test"]),
        ("pip", ["pipp", "piip", "pyp"]),
        ("paramiko", ["parammiko", "paramikko", "parmiko", "paramiiko"]),
        ("psycopg2", ["psycog2", "psycopg", "psycopgg2", "psycpg2"]),
        ("pyyaml", ["pyaml", "pyyml", "pyyamll", "pyyyaml"]),
        ("aiohttp", ["aiohtp", "aoihttp", "aiohtpp", "aiiohttp"]),
    ]

    # Suspicious package name patterns
    SUSPICIOUS_PATTERNS = [
        "-dev",
        "-test",
        "-debug",
        "-beta",
        "free-",
        "-free",
        "-pro",
        "-premium",
    ]

    # Known malicious packages (historical - for reference and pattern matching)
    # Sources: PyPI blog, Kaspersky, Zscaler ThreatLabz, The Hacker News
    KNOWN_MALWARE_PACKAGES = [
        # 2024 incidents
        "aiocpa",  # Obfuscated malicious code added in v0.1.13
        "gptplus",  # JarkaStealer malware
        "claudeai-eng",  # JarkaStealer malware
        "zebo",  # Infostealer
        "cometlogger",  # Infostealer
        # 2025 incidents
        "semantic-types",  # Malicious payload added Jan 2025
        "termncolor",  # SilentSync RAT (typosquat of termcolor)
        "sisaws",  # SilentSync RAT
        "secmeasure",  # SilentSync RAT
        # Solana-targeting packages (May 2025)
        "sol-instruct", "sol-structs", "sol-utils",
        # Common typosquat targets that have been exploited
        "python-binance",  # Various typosquats
        "discord.py",  # Various typosquats
    ]

    # Patterns commonly seen in malicious package names
    MALWARE_NAME_PATTERNS = [
        r"^py[a-z]+-[a-z]+$",  # py-something patterns
        r".*stealer.*",
        r".*logger.*",
        r".*grabber.*",
        r".*inject.*",
        r".*discord.*token.*",
        r".*crypto.*wallet.*",
        r".*sol(ana)?[-_].*",  # Solana targeting
        r".*gpt.*plus.*",  # AI package typosquats
        r".*claude.*ai.*",  # AI package typosquats
        r".*openai.*[0-9].*",  # OpenAI typosquats with numbers
    ]

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def get_package_info(self, package_name: str) -> Optional[PackageInfo]:
        """Fetch package information from PyPI."""
        try:
            response = self.session.get(f"{self.PYPI_API_URL}/{package_name}/json")
            if response.status_code == 404:
                return None
            response.raise_for_status()
            data = response.json()

            info = data.get("info", {})
            releases = data.get("releases", {})
            urls = data.get("urls", [])

            # Get the latest version's sdist URL
            download_url = ""
            for url_info in urls:
                if url_info.get("packagetype") == "sdist":
                    download_url = url_info.get("url", "")
                    break

            # If no sdist, try bdist_wheel
            if not download_url:
                for url_info in urls:
                    if url_info.get("packagetype") == "bdist_wheel":
                        download_url = url_info.get("url", "")
                        break

            # Get release date
            release_date = ""
            if urls:
                release_date = urls[0].get("upload_time", "")

            # Extract GitHub URL from package metadata
            github_url = self._extract_github_url(info)

            return PackageInfo(
                name=package_name,
                version=info.get("version", ""),
                download_url=download_url,
                author=info.get("author", ""),
                maintainer=info.get("maintainer", ""),
                home_page=info.get("home_page", ""),
                requires_python=info.get("requires_python", ""),
                release_date=release_date,
                github_url=github_url,
            )

        except requests.RequestException as e:
            print(f"  Error fetching {package_name}: {e}")
            return None

    def _extract_github_url(self, info: dict) -> str:
        """Extract GitHub repository URL from package metadata."""
        github_pattern = re.compile(
            r"https?://(?:www\.)?github\.com/([^/]+/[^/]+?)(?:\.git)?(?:/|$)"
        )

        # Check various metadata fields for GitHub URLs
        fields_to_check = [
            info.get("home_page", ""),
            info.get("project_url", ""),
            info.get("package_url", ""),
            info.get("download_url", ""),
        ]

        # Check project_urls dict
        project_urls = info.get("project_urls") or {}
        for key, url in project_urls.items():
            if url:
                fields_to_check.append(url)

        # Search for GitHub URL in all fields
        for field in fields_to_check:
            if field:
                match = github_pattern.search(field)
                if match:
                    repo_path = match.group(1).rstrip("/")
                    # Clean up the repo path (remove .git suffix, extra paths)
                    repo_path = repo_path.split("/tree/")[0]
                    repo_path = repo_path.split("/blob/")[0]
                    repo_path = repo_path.split("/issues")[0]
                    repo_path = repo_path.split("/pull")[0]
                    if "/" in repo_path:
                        return f"https://github.com/{repo_path}"

        return ""

    def get_recent_packages(self, limit: int = 100) -> list[str]:
        """Fetch recently updated packages from PyPI RSS feed."""
        import xml.etree.ElementTree as ET

        recent_packages = []
        try:
            # PyPI RSS feed for recent updates
            response = self.session.get(
                "https://pypi.org/rss/updates.xml",
                headers={"Accept": "application/xml"},
                timeout=30,
            )
            response.raise_for_status()

            root = ET.fromstring(response.content)

            # Parse RSS items
            for item in root.findall(".//item"):
                title = item.find("title")
                if title is not None and title.text:
                    # Title format: "package-name version"
                    parts = title.text.strip().split()
                    if parts:
                        package_name = parts[0]
                        if package_name not in recent_packages:
                            recent_packages.append(package_name)
                            if len(recent_packages) >= limit:
                                break

        except Exception as e:
            print(f"  Error fetching recent packages: {e}")

        return recent_packages

    def get_new_packages(self, limit: int = 100) -> list[str]:
        """Fetch newly created packages from PyPI RSS feed."""
        import xml.etree.ElementTree as ET

        new_packages = []
        try:
            # PyPI RSS feed for new packages
            response = self.session.get(
                "https://pypi.org/rss/packages.xml",
                headers={"Accept": "application/xml"},
                timeout=30,
            )
            response.raise_for_status()

            root = ET.fromstring(response.content)

            # Parse RSS items
            for item in root.findall(".//item"):
                title = item.find("title")
                if title is not None and title.text:
                    # Title format: "package-name version"
                    parts = title.text.strip().split()
                    if parts:
                        package_name = parts[0]
                        if package_name not in new_packages:
                            new_packages.append(package_name)
                            if len(new_packages) >= limit:
                                break

        except Exception as e:
            print(f"  Error fetching new packages: {e}")

        return new_packages

    def get_typosquat_candidates(self) -> list[str]:
        """Get list of potential typosquatting package names."""
        candidates = []
        for original, typos in self.TYPOSQUAT_PATTERNS:
            candidates.extend(typos)
        return candidates

    def is_known_malware(self, package_name: str) -> bool:
        """Check if package is in known malware list."""
        return package_name.lower() in [p.lower() for p in self.KNOWN_MALWARE_PACKAGES]

    def matches_malware_pattern(self, package_name: str) -> Optional[str]:
        """Check if package name matches known malware naming patterns."""
        name_lower = package_name.lower()
        for pattern in self.MALWARE_NAME_PATTERNS:
            if re.match(pattern, name_lower):
                return pattern
        return None

    def get_suspicious_new_packages(self, packages: list[str]) -> list[tuple[str, str]]:
        """Filter new packages for suspicious names. Returns (name, reason) tuples."""
        suspicious = []
        for name in packages:
            # Check known malware
            if self.is_known_malware(name):
                suspicious.append((name, "known_malware"))
                continue

            # Check malware patterns
            pattern = self.matches_malware_pattern(name)
            if pattern:
                suspicious.append((name, f"matches_pattern:{pattern}"))
                continue

            # Check suspicious name patterns
            name_lower = name.lower()
            for sus_pattern in self.SUSPICIOUS_PATTERNS:
                if sus_pattern in name_lower:
                    suspicious.append((name, f"suspicious_name:{sus_pattern}"))
                    break

        return suspicious

    def build_scan_list(
        self,
        include_high_value: bool = True,
        include_typosquats: bool = True,
        include_recent: bool = True,
        include_new: bool = True,
        check_known_malware: bool = True,
        custom_packages: list[str] = None,
        max_packages: int = 10,
    ) -> list[PackageInfo]:
        """Build a prioritized list of packages to scan."""
        packages = []
        seen_names = set()

        def add_package(name: str, reason: str) -> bool:
            """Add a package if not already in list and under limit."""
            if len(packages) >= max_packages:
                return False
            if name in seen_names:
                return False
            pkg_info = self.get_package_info(name)
            if pkg_info:
                pkg_info.priority_reason = reason
                packages.append(pkg_info)
                seen_names.add(name)
                return True
            return False

        # Add custom packages first (highest priority)
        if custom_packages:
            print("Adding custom packages...")
            for name in custom_packages:
                add_package(name, "custom")

        # Check known malware packages (highest priority - they may have been re-uploaded)
        if check_known_malware and len(packages) < max_packages:
            print("Checking known malware packages...")
            for name in self.KNOWN_MALWARE_PACKAGES:
                if len(packages) >= max_packages:
                    break
                if add_package(name, "KNOWN_MALWARE"):
                    print(f"  WARNING: Found known malware package still on PyPI: {name}")

        # Add typosquat candidates (high priority for finding malware)
        if include_typosquats and len(packages) < max_packages:
            print("Checking typosquat candidates...")
            for name in self.get_typosquat_candidates():
                if len(packages) >= max_packages:
                    break
                if add_package(name, "typosquat_candidate"):
                    print(f"  Found: {name}")

        # Add newly created packages - prioritize suspicious ones
        if include_new and len(packages) < max_packages:
            print("Fetching newly created packages...")
            new_pkgs = self.get_new_packages(limit=max_packages * 3)
            print(f"  Found {len(new_pkgs)} new packages")

            # First add suspicious new packages
            suspicious = self.get_suspicious_new_packages(new_pkgs)
            if suspicious:
                print(f"  Found {len(suspicious)} suspicious new packages:")
                for name, reason in suspicious:
                    if len(packages) >= max_packages:
                        break
                    if add_package(name, f"suspicious_new:{reason}"):
                        print(f"    - {name} ({reason})")

            # Then add remaining new packages
            for name in new_pkgs:
                if len(packages) >= max_packages:
                    break
                add_package(name, "newly_created")

        # Add recently updated packages
        if include_recent and len(packages) < max_packages:
            print("Fetching recently updated packages...")
            recent_pkgs = self.get_recent_packages(limit=max_packages * 2)
            print(f"  Found {len(recent_pkgs)} recent updates")

            # First add suspicious recent packages
            suspicious = self.get_suspicious_new_packages(recent_pkgs)
            if suspicious:
                print(f"  Found {len(suspicious)} suspicious recently updated packages:")
                for name, reason in suspicious:
                    if len(packages) >= max_packages:
                        break
                    if add_package(name, f"suspicious_recent:{reason}"):
                        print(f"    - {name} ({reason})")

            for name in recent_pkgs:
                if len(packages) >= max_packages:
                    break
                add_package(name, "recently_updated")

        # Add high-value packages (for baseline and high-impact detection)
        if include_high_value and len(packages) < max_packages:
            print("Adding high-value packages...")
            for name in self.HIGH_VALUE_PACKAGES:
                if len(packages) >= max_packages:
                    break
                add_package(name, "high_value")

        return packages[:max_packages]

    @staticmethod
    def get_all_package_names() -> list[str]:
        """Fetch all package names from PyPI Simple API."""
        print("Fetching package index from PyPI...")
        with urlopen("https://pypi.org/simple/", timeout=60) as response:
            html = response.read().decode()

        # Extract package names from links
        packages = re.findall(r'href="/simple/([^/]+)/"', html)
        print(f"Found {len(packages):,} packages on PyPI")
        return packages
