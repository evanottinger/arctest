# arctest

A security research project for detecting malware hidden in Python test files, inspired by the xz-utils backdoor incident of 2024.

## Overview

This project provides:
1. **arctest** - A pytest plugin for static and runtime malware detection
2. **arctest CLI** - Command-line scanner for local code analysis
3. **Semgrep Rule Scanner** - Pattern-based rules for scanning PyPI packages at scale

## Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/arctestgit
cd arctest

# Install dependencies
pipenv install

# Install semgrep (required for rule-based scanning)
pipenv run pip install semgrep
```

## arctest CLI

The arctest CLI provides direct access to the Semgrep-based malware scanner for analyzing local code.

### Scanning Local Code

```bash
# Scan a file
python -m arctest scan path/to/file.py

# Scan a directory
python -m arctest scan path/to/directory/

# Output results as JSON
python -m arctest scan path/to/code --json

# Save JSON output to file
python -m arctest scan path/to/code -o results.json
```

### Using External Rules

Extend detection capabilities by including rules from external sources like GuardDog:

```bash
# First, fetch the external rules (one-time setup)
python -m arctest rules fetch guarddog

# Scan with external rules
python -m arctest scan path/to/code --external-rules guarddog

# Combine multiple external sources
python -m arctest scan path/to/code --external-rules guarddog,other-source
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `path` | File or directory to scan |
| `--json` | Output results as JSON |
| `-o, --output PATH` | Save JSON output to file |
| `--external-rules SOURCES` | Comma-separated list of external rule sources |

## Managing External Rules

arctest can fetch and use rules from external sources to expand detection coverage.

### Listing Available Sources

```bash
python -m arctest rules list
```

Output shows available sources with their cache status:

```
Available rule sources:

  guarddog [cached]
    URL: https://github.com/DataDog/guarddog
    Rules path: guarddog/analyzer/sourcecode
    Local path: /home/user/.arctest/rules/.repos/guarddog/guarddog/analyzer/sourcecode
```

### Fetching Rules

Download rules from an external source:

```bash
python -m arctest rules fetch guarddog
```

Rules are cloned to `~/.arctest/rules/.repos/` and cached for future use.

### Updating Cached Rules

Pull the latest changes for all cached rule sources:

```bash
python -m arctest rules update
```

### Removing Cached Rules

Remove a cached rule source to free disk space:

```bash
python -m arctest rules remove guarddog
```

## Semgrep Rule Scanner (PyPI)

The Semgrep rule scanner uses custom pattern-matching rules to detect suspicious patterns in test files without relying on hardcoded IOCs (indicators of compromise).

### Running the Scanner

#### Scan specific packages
```bash
pipenv run python scanner/pypi_scan.py --packages requests flask django
```

#### Scan newly created PyPI packages
```bash
pipenv run python scanner/pypi_scan.py --new-only --max-packages 50
```

#### Scan random sample from all PyPI packages
```bash
pipenv run python scanner/pypi_scan.py --random-sample 100
```

This guarantees exactly 100 packages **with test files** are scanned. Packages without tests or that fail to download are automatically replaced with new random packages.

#### Full scan with all package sources
```bash
pipenv run python scanner/pypi_scan.py --max-packages 200 --pypi-sdist -o report.json
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--packages PKG [PKG ...]` | Specific packages to scan |
| `--max-packages N` | Maximum packages to scan (default: 50) |
| `--new-only` | Only scan newly created packages |
| `--pypi-sdist` | Download source from PyPI instead of GitHub |
| `--random-sample N` | Scan exactly N packages with tests from random PyPI sample |
| `-o, --output PATH` | Output report path (default: pypi_scan_report.json) |

### Analyzing Output

The scanner produces a JSON report with the following structure:

```json
{
  "scan_metadata": {
    "timestamp": "2024-01-21T19:36:59.494008",
    "analyzer": "semgrep",
    "total_packages": 100,
    "successful_scans": 85,
    "packages_with_findings": 3
  },
  "summary": {
    "total_findings": 15,
    "critical": 0,
    "high": 5,
    "medium": 2,
    "low": 8
  },
  "suspicious_packages": [...],
  "all_results": [...]
}
```

#### Quick Analysis Commands

```bash
# View summary
cat report.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['summary'])"

# List flagged packages
cat report.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d['suspicious_packages']:
    print(f\"{p['package_name']}: {p['high_findings']} high, {p['low_findings']} low\")
"

# Show high-severity findings
python3 << 'EOF'
import json
with open('report.json') as f:
    data = json.load(f)
for pkg in data['suspicious_packages']:
    for f in pkg['findings']:
        if f['severity'] == 'high':
            print(f"{pkg['package_name']}: {f['rule_id'].split('.')[-1]}")
            print(f"  {f['code_snippet'][:80]}")
EOF
```

### Rescanning Previous Results

The `scanner/rescan.py` helper re-runs scans using packages from a previous JSON report, useful for testing rule changes or adding external rules:

```bash
# Preview the rescan command (dry run)
python scanner/rescan.py pypi_scan_report.json

# Execute the rescan
python scanner/rescan.py pypi_scan_report.json --run

# Rescan with external rules
python scanner/rescan.py pypi_scan_report.json --run --external-rules guarddog

# Save to a different output file
python scanner/rescan.py pypi_scan_report.json --run -o rescan_results.json
```

| Option | Description |
|--------|-------------|
| `input_json` | JSON file from a previous scan |
| `--run` | Execute the scan (default: just print command) |
| `-o, --output PATH` | Output file path |
| `--external-rules SOURCES` | External rule sources (e.g., guarddog) |

## Detection Rules

Rules are located in `arctest/rules/` and organized by attack category.

### Built-in Rules

| Rule File | Category | What It Detects |
|-----------|----------|-----------------|
| `reverse_shell.yml` | Reverse Shells | Socket+dup2 redirection patterns, pty.spawn with shells, socket connections combined with shell spawning, suspicious pty+socket import combinations |
| `data_exfiltration.yml` | Credential Theft | SSH key file access, AWS credentials access, bulk environment variable harvesting with network sinks, /etc/passwd access, browser data theft, sensitive config file access (.env, .netrc, .kube/config) |
| `code_execution.yml` | Code Execution | Base64 decode → exec/eval taint flows, dynamic builtin access (getattr on __builtins__), hex/unicode obfuscated function calls, remote code fetch and execute, compile() with exec mode, writes to .py source files |
| `network_operations.yml` | Network Activity | Server socket binding to external interfaces, HTTP server handlers, outbound socket connections, sensitive data in HTTP requests (taint tracking), DNS lookups |
| `obfuscation.yml` | Obfuscation | Base64+exec taint flows (extended patterns), code obfuscation techniques (BlankOBF, char code assembly), suspicious URLs (ngrok, Discord webhooks, pastebin), unicode homoglyph attacks, steganography indicators |

Some rules in `obfuscation.yml` are adapted from [GuardDog](https://github.com/DataDog/guarddog) by DataDog (Apache 2.0 license).

### Severity Levels

arctest maps Semgrep severities to threat levels:

| Severity | Semgrep Level | Description | Example Detections |
|----------|---------------|-------------|-------------------|
| **Critical** | ERROR | High-confidence malware indicators | Socket+pty.spawn combo, SSH key theft, base64→exec |
| **High** | WARNING | Suspicious patterns requiring review | Env harvesting, external socket connections, dynamic builtins |
| **Medium** | WARNING | Potentially risky operations | External server binding, outbound connections |
| **Low** | INFO | Informational findings | HTTP requests, DNS lookups, HTTP server handlers |

### Understanding False Positives

The scanner may flag legitimate test code:

| Pattern | Common False Positive | How to Identify |
|---------|----------------------|-----------------|
| `external-http-request` | Integration tests hitting APIs | Check if URL is from config/fixture |
| `server-socket-bind` | Test HTTP servers | Check if binding to localhost |
| `env-exfiltration` | Debug logging | Check context - is it `print(os.environ)` or debug? |
| `compile-exec` | Testing code execution features | Common in pytest, AST tools |

**Localhost operations are excluded** - the rules filter out `127.0.0.1`, `localhost`, and `::1` to reduce noise.

## arctest Plugin

### Running with pytest

```bash
# Log mode (detect and report, don't block)
pipenv run pytest --arctest=log tests/

# Block mode (fail tests on detection)
pipenv run pytest --arctest=block tests/
```

### Sample Malware Tests

The `tests/` directory contains intentionally malicious test files for validation:

- `test_rev_shell.py` - Reverse shell pattern
- `test_steal_ssh_keys.py` - SSH key access
- `test_print_env.py` - Environment harvesting
- `test_http_server.py` - HTTP server in test
- `test_mutate_file.py` - File system manipulation

## Scanning at Scale

### Performance Expectations

| Sample Size | Approximate Time | Notes |
|-------------|------------------|-------|
| 50 packages | 2-3 minutes | Good for testing |
| 100 packages | 5-10 minutes | Reasonable sample |
| 1000 packages | 30-60 minutes | Comprehensive scan |

### Limitations

1. **Test file coverage**: Many packages don't include tests in PyPI distributions
2. **GitHub dependency**: Some scans require cloning repos (slower)
3. **False positives**: Network libraries legitimately use socket operations
4. **Scope**: Currently scans test files only; malware often hides in `setup.py`

## Contributing

### Adding New Rules

1. Create a YAML file in `arctest/rules/`
2. Follow Semgrep rule syntax
3. Test against sample malware in `tests/`
4. Verify false positive rate on real packages

### Rule Template

Basic pattern matching:

```yaml
rules:
  - id: my-detection-rule
    languages:
      - python
    message: >-
      Description of what was detected and why it's suspicious.
    metadata:
      description: Short description
      category: category_name
      severity: high
    patterns:
      - pattern: suspicious_pattern(...)
    severity: WARNING
```

Taint tracking for data flow analysis:

```yaml
rules:
  - id: my-taint-rule
    languages:
      - python
    message: >-
      Detected sensitive data flowing to dangerous sink.
    metadata:
      description: Taint tracking rule
      category: data_flow
      severity: critical
    mode: taint
    pattern-sources:
      - pattern: sensitive_source()
      - pattern: os.environ
    pattern-sinks:
      - pattern: dangerous_sink(...)
      - pattern: requests.post(...)
    severity: ERROR
```

### Adding External Rule Sources

To add a new external rule source, edit `arctest/rule_manager.py`:

```python
SOURCES: dict[str, RuleSource] = {
    "guarddog": RuleSource(
        name="guarddog",
        url="https://github.com/DataDog/guarddog",
        rules_subpath="guarddog/analyzer/sourcecode",
        excluded_rules=[
            # Rules to exclude from this source
            "api-obfuscation",  # Too many false positives
        ],
    ),
    # Add new source here:
    "my-source": RuleSource(
        name="my-source",
        url="https://github.com/org/repo",
        rules_subpath="path/to/semgrep/rules",
        excluded_rules=[],
    ),
}
```

After adding, users can fetch and use the new source:

```bash
python -m arctest rules fetch my-source
python -m arctest scan code/ --external-rules my-source
```
