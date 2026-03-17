"""Detection patterns for runtime monitoring.

Note: The AST analyzer patterns have been removed. This file now only contains
patterns used by the runtime monitors for detecting sensitive file/env access.
"""

import re


# Sensitive path patterns (compiled regex)
SENSITIVE_PATHS: list[re.Pattern] = [
    re.compile(r"[~]?[/\\]\.ssh[/\\]", re.IGNORECASE),
    re.compile(r"[~]?[/\\]\.aws[/\\]", re.IGNORECASE),
    re.compile(r"[~]?[/\\]\.gnupg[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]etc[/\\]passwd", re.IGNORECASE),
    re.compile(r"[/\\]etc[/\\]shadow", re.IGNORECASE),
    re.compile(r"[/\\]etc[/\\]hosts", re.IGNORECASE),
    re.compile(r"id_rsa", re.IGNORECASE),
    re.compile(r"id_ed25519", re.IGNORECASE),
    re.compile(r"id_ecdsa", re.IGNORECASE),
    re.compile(r"id_dsa", re.IGNORECASE),
    re.compile(r"\.pem$", re.IGNORECASE),
    re.compile(r"\.key$", re.IGNORECASE),
    re.compile(r"credentials", re.IGNORECASE),
    re.compile(r"\.kube[/\\]config", re.IGNORECASE),
    re.compile(r"\.docker[/\\]config\.json", re.IGNORECASE),
    # Windows paths
    re.compile(r"%USERPROFILE%[/\\]\.ssh", re.IGNORECASE),
    re.compile(r"%APPDATA%", re.IGNORECASE),
]

# Environment variable access patterns
ENV_BULK_ACCESS_METHODS = {"keys", "values", "items", "__iter__", "__repr__", "__str__"}

# Suspicious environment variable patterns
SENSITIVE_ENV_PATTERNS: list[re.Pattern] = [
    re.compile(r".*_KEY$", re.IGNORECASE),
    re.compile(r".*_SECRET$", re.IGNORECASE),
    re.compile(r".*_TOKEN$", re.IGNORECASE),
    re.compile(r".*_PASSWORD$", re.IGNORECASE),
    re.compile(r"^AWS_", re.IGNORECASE),
    re.compile(r"^GITHUB_TOKEN$", re.IGNORECASE),
    re.compile(r"^API_KEY$", re.IGNORECASE),
    re.compile(r"^DATABASE_URL$", re.IGNORECASE),
]


def is_sensitive_path(path_str: str) -> bool:
    """Check if a path string matches sensitive patterns."""
    for pattern in SENSITIVE_PATHS:
        if pattern.search(path_str):
            return True
    return False


def is_sensitive_env_var(var_name: str) -> bool:
    """Check if an environment variable name matches sensitive patterns."""
    for pattern in SENSITIVE_ENV_PATTERNS:
        if pattern.match(var_name):
            return True
    return False
