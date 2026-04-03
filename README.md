# repoaudit

A fast, single-binary security scanner for Git repositories. Audit code for security risks before installing dependencies or running untrusted projects.

## Features

- **Pattern Scanning** — Detects network/exfiltration vectors, code injection, credential access, shell execution, and suspicious file I/O
- **Dependency CVEs** — Integrates with [pip-audit](https://pypi.org/project/pip-audit/) for Python dependency vulnerability scanning
- **Filesystem Scanning** — Integrates with [Trivy](https://trivy.dev/) for comprehensive vulnerability, secret, and misconfiguration detection
- **Remote Repos** — Shallow-clone and scan any Git URL directly
- **JSON Output** — Machine-readable output for CI/CD integration

## Installation

### Homebrew (macOS/Linux)

```bash
brew tap vosiander/tap
brew install repoaudit
```

### From Source

```bash
go install github.com/vosiander/repo-audit@latest
```

### Binary Releases

Download pre-built binaries from [Releases](https://github.com/vosiander/repo-audit/releases).

## Usage

```bash
# Scan a local directory
repoaudit ./path/to/repo

# Scan a remote repository
repoaudit https://github.com/user/repo

# Skip external tools
repoaudit ./repo --skip-trivy --skip-pip-audit

# JSON output for CI/CD
repoaudit ./repo --json
```

## What It Detects

| Category | Examples |
|----------|----------|
| **Network / Exfiltration** | `requests`, `urllib`, `socket`, `curl`, `wget` |
| **Code Injection** | `eval()`, `exec()`, `pickle.loads()`, base64 decoding |
| **Credential Access** | `.ssh/`, `.aws/`, API keys, environment variable reads |
| **Subprocess / Shell** | `subprocess.run()`, `os.system()`, `shell=True` |
| **File I/O** | Writes to `/etc/`, `/tmp/`, home directory dotfiles |
| **Install Hooks** | `setup.py` cmdclass, post-install scripts |

## Example Output

```
────────────────────────────────────────────────────────────
  Network / Exfiltration
────────────────────────────────────────────────────────────
  ✔ Network library imports — none found
  ✘ Network function calls — 2 hit(s)
    → src/api.py:45
      requests.post(url, data=payload)

────────────────────────────────────────────────────────────
  SUMMARY
────────────────────────────────────────────────────────────
  Dangerous findings: 1
  Warnings:           0

  Dangerous patterns found — review carefully before installing.
```

## Optional Dependencies

For full scanning capabilities, install these tools:

- **[Trivy](https://trivy.dev/)** — Vulnerability, secret, and misconfiguration scanner
  ```bash
  brew install trivy
  ```

- **[pip-audit](https://pypi.org/project/pip-audit/)** — Python dependency CVE scanner
  ```bash
  pip install pip-audit
  ```

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Audit
  run: |
    brew install vosiander/tap/repoaudit
    repoaudit . --json > audit-results.json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No dangerous findings |
| 1 | Dangerous patterns detected |

## License

MIT
