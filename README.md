# 🛡️ Security Headers Scanner Pro

### Scan, Analyze & Improve Your Website's Security Headers

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![Code Quality](https://img.shields.io/badge/Quality-A%2B-brightgreen.svg)]()



---

## ✨ Features

**Security Headers Scanner Pro** provides comprehensive security assessment through:

| Feature | Description | Command |
|---------|-------------|---------|
| 🔐 **Security Headers** | Checks 9 modern security headers by default | `scan` |
| 🔒 **SSL/TLS Analysis** | Certificate & protocol validation | `ssl` |
| 🔎 **Tech Fingerprinting** | Identifies frameworks & libraries | `fingerprint` |
| 🌐 **Subdomain Discovery** | Finds associated subdomains | `subdomains` |
| 📁 **Directory Scanning** | Detects exposed directories | `dirs` |
| 🛡️ **Full Audit** | Complete security assessment | `audit` |
| 📊 **Multiple Reports** | Text, JSON, HTML, CSV, Markdown | `--format` |
| 📈 **Scoring & Grading** | Weighted 0–100 security-header scores | Built-in |
| 💾 **History & Storage** | Save & retrieve scan results | REST API |
| 🔌 **REST API** | Programmatic access | `serve` |

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#-features)
3. [Quick Start](#-quick-start)
4. [Installation](#-installation)
5. [Usage Guide](#usage-guide)
6. [Assessment Results](#understanding-security-assessment-results)
7. [Developer Guide](#-for-developers)
8. [Publishing to GitHub](#publishing-to-github)
9. [FAQ](#frequently-asked-questions)

---

## Overview

**Security Headers Scanner Pro** is a comprehensive security assessment tool that validates HTTP security headers, SSL/TLS configuration, and web application security posture. It analyzes websites against industry security standards and best practices.

### Key Benefits

| Vulnerability Type | Risk | Mitigation |
|-------------------|------|------------|
| Cross-Site Scripting (XSS) | High | Validates Content-Security-Policy |
| Clickjacking Attacks | High | Enforces X-Frame-Options |
| Man-in-the-Middle (MITM) | Critical | Validates HSTS & TLS Configuration |
| MIME Type Sniffing | Medium | Checks X-Content-Type-Options |

### Purpose

HTTP security headers are critical directives sent by servers to web browsers that instruct them on how to handle content security, encryption, and threat mitigation. Many organizations fail to properly configure these headers, leaving their applications vulnerable to attacks.

---

## ⚡ Quick Start

**Time needed: 5 minutes**

### Step 1: Install Python
Make sure you have Python 3.10 or higher:

```bash
# Check your Python version
python --version

# If not installed, download from:
# https://www.python.org/downloads/
```

### Step 2: Download the Project
```bash
# Method 1: Download ZIP from GitHub
# (Green "Code" button → Download ZIP)

# Method 2: Clone with Git
git clone https://github.com/Aman9422/security-header-scanner.git
cd security-header-scanner
```

### Step 3: Install Dependencies
```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate it:
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install required packages
pip install --require-hashes -r requirements.lock
```

`requirements.lock` pins the full dependency graph and package hashes for reproducible installs on Python 3.10+. `requirements.txt` contains the upgradeable version ranges used to regenerate the lock.

### Step 4: Execute Initial Scan

```bash
python main.py scan https://example.com
```

Example output:

```
======================================================================
              🛡️  SECURITY HEADERS SCANNER PRO
======================================================================
  Target: https://example.com
  Score: 15% (F) - CRITICAL RISK
======================================================================

  ❌ Missing Headers Found:
     • Strict-Transport-Security (HIGH)
     • Content-Security-Policy (HIGH)
     • X-Frame-Options (HIGH)
```

### Sample Results

| Website | Score | Grade | Key Headers |
|---------|-------|-------|-------------|
| GitHub | 50% | C- | ✅ HSTS, CSP, X-Frame-Options, XCTO |
| Google | 35% | F | ⚠️ CSP is Report-Only (not blocking) |
| Example | 0% | F | ❌ Missing all security headers |

---

## 📦 Installation

### Option 1: Windows

```bash
# 1. Install Python from https://python.org

# 2. Open Command Prompt and run:
cd security-header-scanner
python -m venv venv
venv\Scripts\activate
pip install --require-hashes -r requirements.lock

# 3. Run the scanner:
python main.py scan https://example.com
```

### Option 2: Mac/Linux

```bash
# 1. Open Terminal and install Python if needed:
# Mac: brew install python3
# Linux: sudo apt install python3

# 2. Navigate to project:
cd security-header-scanner

# 3. Install dependencies:
python3 -m venv venv
source venv/bin/activate
pip install --require-hashes -r requirements.lock

# 4. Run:
python main.py scan https://example.com
```

### Option 3: Using GitHub Codespaces (No Installation!)

```bash
# 1. Go to GitHub repository
# 2. Press "." to open in Codespaces
# 3. Run: python main.py scan https://example.com
```

---

## Usage Guide

### Single Website Scan

```bash
python main.py scan https://google.com
```

**Output Includes:**
- Overall security score (0-100%)
- Detected security headers with values
- Missing or misconfigured headers
- Remediation guidance

---

### Generate HTML Report

```bash
python main.py scan https://google.com --format html --output report.html
```

Open the generated `report.html` file in a web browser for detailed visual analysis.

---

### Batch Scanning (REST API)

Batch scanning is available through the authenticated API (there is no `main.py batch` CLI command):

```bash
curl -X POST "http://127.0.0.1:5000/api/v1/batch" \
  -H "Authorization: Bearer $SECURITY_SCANNER_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"urls":["https://example.com","https://example.org"]}'
```

The API validates every target before starting the batch and returns JSON with per-target results and an average score.

### Output Format Options

```bash
# JSON format (for programmatic access)
python main.py scan https://example.com --format json

# CSV format (for data analysis tools)
python main.py scan https://example.com --format csv --output report.csv

# Markdown format (for documentation)
python main.py scan https://example.com --format markdown --output report.md
```

---

### 🔌 Start API Server (For Developers)

Want to integrate with your CI/CD pipeline? Configure bearer tokens before starting the server. The API fails closed when no tokens are configured.

```bash
export SECURITY_SCANNER_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export SECURITY_SCANNER_READ_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export SECURITY_SCANNER_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python main.py serve
```

The API runs on Waitress, not Flask's development server, and binds to `127.0.0.1:5000` by default. Keep it behind a trusted reverse proxy if you bind it to a network interface. The health check is public; other endpoints require a bearer token. Scanner tokens can scan and read, reader tokens can read history/reports, and admin tokens can also clean up stored scans.

`trusted_proxy_hops` defaults to `0`, so `X-Forwarded-For` is ignored. Set it only to the exact number of trusted reverse proxies that sanitize forwarded headers. The in-memory `max_urls_per_minute` limiter is for a single process; for multi-worker deployments, set `api.rate_limit_backend: redis` and provide `SECURITY_SCANNER_REDIS_URL`. Startup checks Redis and fails closed when the shared backend is unavailable.

API targets default to TCP ports `80` and `443`. Use `allowed_hosts` for exact hostnames or `*.example.com` subdomain patterns and/or `allowed_cidrs` for resolved IP networks. When both allowlists are configured, both must match; every resolved address is checked. Empty host and CIDR lists allow any globally routable target. Private, loopback, link-local, and reserved addresses remain blocked unless `allow_private_networks: true` is explicitly set, even when a CIDR matches. Nonstandard ports must be added to `allowed_ports`; redirects and DNS rebinding remain blocked.

API scans resolve destinations again immediately before connecting, pin each socket to validated IP addresses while preserving the Host header and TLS hostname verification, ignore ambient proxy variables, and do not follow redirects. Sensitive query values (such as tokens, keys, passwords, and secrets) are redacted in responses, reports, errors, and stored records; the unredacted URL is still used for scanning, and history lookup uses an opaque URL key. Cookie findings report `Secure`, `HttpOnly`, and `SameSite` attributes only—the cookie values are never persisted. Enforce outbound network egress rules as defense in depth.

**API Endpoints:**

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/api/v1/health` | Public health check |
| GET / POST | `/api/v1/scan` | Scan one URL; `format` supports `json`, `text`, `html`, `markdown`, `csv` (scanner token) |
| GET | `/api/v1/history` | View scan history (reader token) |
| GET | `/api/v1/history/<url>` | View history for a URL (reader token) |
| GET | `/api/v1/headers` | List headers checked (reader token) |
| POST | `/api/v1/batch` | Batch scan a JSON `urls` array (scanner token) |
| POST | `/api/v1/compare` | Compare stored scans by `scan_id_1` and `scan_id_2` (reader token) |
| POST | `/api/v1/report` | Render a stored scan as JSON, text, HTML, Markdown, or CSV (reader token) |
| POST | `/api/v1/cleanup` | Delete scans older than `days` (admin token) |

**Example API Call:**

```bash
curl -X POST "http://127.0.0.1:5000/api/v1/scan?format=json" \
  -H "Authorization: Bearer $SECURITY_SCANNER_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

---

### 📜 View Scan History

History is available from the authenticated API; there is no `python main.py history` CLI command:

```bash
curl "http://127.0.0.1:5000/api/v1/history" \
  -H "Authorization: Bearer $SECURITY_SCANNER_READ_TOKEN"
```

---

### 🔧 List All Security Headers

```bash
python main.py headers
```

Shows the nine modern security headers checked by default.

---

## 📈 Understanding Results

### Score & Grades

| Score | Grade | Meaning |
|-------|-------|---------|
| 90-100% | A+ | Excellent! Well protected |
| 80-89% | A | Great security |
| 70-79% | B | Good, but some issues |
| 50-69% | C | Average, needs improvement |
| 25-49% | D | Poor security |
| 0-24% | F | Critical vulnerabilities |

### Header Status Explained

| Status | Symbol | Meaning |
|--------|--------|---------|
| ✅ PRESENT | Green | Header is properly configured |
| ⚠️ WEAK | Yellow | Header exists but could be better |
| ❌ MISSING | Red | Header not found (security risk!) |
| ❌ MISCONFIGURED | Red | Header is set wrong |

### Risk Levels

| Level | Color | Action Needed |
|-------|-------|---------------|
| EXCELLENT | 🟢 Green | Keep it up! |
| GOOD | 🟢 Green | Minor improvements possible |
| MEDIUM | 🟡 Yellow | Should address issues |
| LOW | 🟠 Orange | Important fixes needed |
| CRITICAL | 🔴 Red | Immediate action required! |

---

### SSL/TLS Certificate Analysis

```bash
python main.py ssl example.com
python main.py ssl example.com --port 8443
python main.py ssl example.com --format json --output ssl_report.json
```

**Output Includes:**
- Certificate validity and expiration status
- TLS protocol version and cipher suite details
- Key size and signature algorithm information
- Configuration grade and security assessment

---

### Technology Detection

```bash
python main.py fingerprint https://example.com
python main.py fingerprint https://example.com --format json
```

**Detection Capabilities:**
- Frontend frameworks (React, Vue, Angular, Svelte, etc.)
- Backend technologies (Node.js, Django, PHP, Ruby, etc.)
- Content Management Systems (WordPress, Drupal, Joomla, etc.)
- Client-side JavaScript libraries and frameworks
- Server software and versions

---

### Subdomain Enumeration

```bash
python main.py subdomains example.com
python main.py subdomains example.com --quick    # Fast scan (50 concurrent workers)
python main.py subdomains example.com --format json
```

**Output Includes:**
- Enumerated subdomains with alive/dead status
- Resolved IP addresses
- Detected network services per subdomain

---

### Sensitive Directory and File Discovery

```bash
python main.py dirs https://example.com
python main.py dirs https://example.com --quick  # Restricted to sensitive paths
python main.py dirs https://example.com --format json
```

**Output Includes:**
- Discovered directories and file paths
- HTTP response status codes
- Accessible sensitive files and configuration endpoints

---

### Comprehensive Security Audit

Executes all security assessments in a single operation:

```bash
python main.py audit https://example.com
python main.py audit https://example.com --format json --output full_audit.json
```

**Assessment Modules:**
1. HTTP Security Headers validation
2. SSL/TLS Certificate and protocol analysis
3. Technology stack fingerprinting
4. Subdomain enumeration and verification
5. Sensitive directory and path discovery

**Output:**
- Consolidated security assessment report
- Overall risk score and grade
- Critical findings and remediation recommendations

---

### Command Reference

```bash
# Display all available commands
python main.py --help

# Display command-specific usage information
python main.py scan --help
python main.py ssl --help
python main.py audit --help
```

---

## 🛠️ For Developers

### Project Structure

```
security-header-scanner/
├── main.py                  # CLI entry point (8 commands)
├── src/
│   ├── __init__.py         # Package initialization
│   ├── scanner.py          # Core security header scanning engine
│   ├── ssl_analyzer.py     # SSL/TLS certificate analysis
│   ├── fingerprinter.py    # Technology detection & fingerprinting
│   ├── subdomain_scanner.py # Subdomain discovery
│   ├── directory_scanner.py # Directory & sensitive file scanning
│   ├── headers.py          # Security header definitions & validators
│   ├── analyzer.py         # Scoring, grading & risk assessment
│   ├── cvss_scoring.py     # CVSS v3.1 vulnerability scoring
│   ├── reporter.py         # Multi-format report generation
│   ├── storage.py          # JSON-based result persistence
│   ├── api.py              # Flask REST API server
│   └── utils.py            # Utility functions
├── tests/
│   ├── __init__.py
│   └── test_scanner.py     # 29 comprehensive unit tests
├── data/                   # Scan results storage (auto-created)
├── examples/
│   └── sample_urls.txt     # Example URLs for batch scanning
├── config.yaml             # Configuration settings
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── LICENSE                # MIT License
├── CONTRIBUTING.md        # Contribution guidelines
└── setup.sh              # Setup script
```

### Key Modules

| Module | Purpose | Key Responsibility |
|--------|---------|------------------|
| `scanner.py` | Main scanning engine | Fetches headers, validates, scores |
| `headers.py` | Security header definitions | 13+ header specs, validation rules |
| `reporter.py` | Multi-format reporting | Text, JSON, HTML, CSV, Markdown |
| `ssl_analyzer.py` | TLS/certificate analysis | Certificate validation, TLS grading |
| `fingerprinter.py` | Tech detection | Identifies frameworks, CMS, libraries |
| `api.py` | REST API server | Flask endpoints for CI/CD integration |
| `subdomain_scanner.py` | Subdomain discovery | DNS enumeration, service detection |
| `directory_scanner.py` | Path brute-forcing | Finds exposed directories, files |
| `cvss_scoring.py` | Vulnerability scoring | CVSS v3.1 scoring system |
| `analyzer.py` | Risk assessment | Grades, scoring, compliance checks |
| `storage.py` | Data persistence | Saves/retrieves scan results |

### Run Tests

```bash
# Run all tests with verbose output
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=src --cov-report=html

# Run specific test class
pytest tests/test_scanner.py::TestHeaderValidation -v

# Run with performance profiling
pytest tests/ -v --durations=10
```

**Test Status:** Run `pytest tests/` to execute the complete regression suite. CI runs the suite against Python 3.10–3.12, installs the hash-pinned lock, gates on Bandit medium-or-higher findings, and audits locked dependencies with `pip-audit`.

To refresh the lock after editing `requirements.txt`, install the pinned lock-maintenance tool and compile hashes:

```bash
python -m pip install pip-tools==7.6.2
pip-compile --resolver=backtracking --generate-hashes --output-file requirements.lock requirements.txt
```

### Configuration

Edit `config.yaml` to customize:

```yaml
scanner:
  timeout: 30           # Request timeout (seconds)
  max_retries: 3        # Retry failed requests
  rate_limit_delay: 1.0 # Delay between requests

api:
  host: "127.0.0.1" # Local-only by default; expose only behind a protected proxy
  port: 5000
  threads: 8
  trusted_proxy_hops: 0 # Trust X-Forwarded-For only from this many known proxies
  rate_limit_backend: memory # Set to redis for multi-worker deployments
  cors_origins: []
  allow_private_networks: false
  allowed_hosts: [] # Exact hostnames or *.example.com patterns
  allowed_cidrs: [] # Optional IPv4/IPv6 destination networks
  allowed_ports: [80, 443]
  max_request_bytes: 1048576
  max_urls_per_minute: 30

storage:
  type: "json"       # json or sqlite
  path: "./data"     # JSON directory; SQLite accepts a database file or directory
  max_history: 1000   # Set to null to disable the count cap
  auto_cleanup_days: 30 # Set to null to disable age-based cleanup
```

JSON index updates are atomic and locked; JSON data files and SQLite databases use owner-only POSIX permissions. SQLite uses WAL and busy timeouts for concurrent workers. Retention settings are applied on startup and after new scans.

---

## Publishing to GitHub

### Repository Setup

1. Navigate to [GitHub new repository](https://github.com/new)
2. Configure repository:
   - Repository name: `security-header-scanner`
   - Visibility: Public
   - Initialize with: None (push existing code)

### Initial Commit and Push

```bash
cd security-header-scanner

git init
git add .
git commit -m "Initial commit: Security Headers Scanner Pro"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/security-header-scanner.git
git push -u origin main
```

### Continuous Integration

After pushing to GitHub, enable the following automations:
- Automated test execution on push
- Code quality checks
- Coverage report generation

---

## Version History and Recent Updates

### v2.0 - Code Quality and Documentation Improvements

**Critical Fixes:**
- Fixed missing `datetime` import in audit command
- Removed 11 unused imports for improved code cleanliness
- Comprehensive code audit and quality verification
- All 29 unit tests passing
- Code quality assessment: A+

**New Features:**
- Complete security audit command integrating all scanners
- Multi-format report generation (Text, JSON, HTML, CSV, Markdown)
- CVSS v3.1 vulnerability scoring system
- REST API server with Flask framework
- Batch scanning capabilities
- Technology stack fingerprinting
- Subdomain enumeration and verification
- Sensitive directory discovery

**Documentation Improvements:**
- Comprehensive README with all command documentation
- Inline code documentation and docstrings
- Sample URLs and configuration examples
- Developer guide with module structure

---

## Frequently Asked Questions

**Q: What is the license?**  
A: MIT License - free to use, modify, and distribute for both personal and commercial purposes.

**Q: Can this be used for commercial applications?**  
A: Yes, the MIT License permits commercial use. Attribution of the original copyright holder is required.

**Q: Does the scanner support local networks?**  
A: Yes. Use localhost or internal IP addresses with the scan command.

**Q: How accurate are the assessments?**  
A: The scanner validates headers against W3C standards and OWASP recommendations.

**Q: Can custom headers be added?**  
A: Yes. Edit `src/headers.py` to add new security header definitions.

**Q: Is rate limiting available?**  
A: Yes, configurable via `config.yaml`.

## References and Resources

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [HTTP Header Security Best Practices](https://portswigger.net/web-security)
- [W3C Content Security Policy Specification](https://w3c.github.io/webappsec-csp/)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for complete terms and conditions.
