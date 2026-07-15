# 🛡️ Security Headers Scanner Pro

A comprehensive, production-grade security headers analysis tool for developers and security professionals.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Stars](https://img.shields.io/badge/Stars-Welcome-orange.svg)

## ✨ Features

### Core Capabilities
- **🔍 Comprehensive Header Analysis** — Checks 15+ security headers
- **📊 Risk Scoring** — CVSS-style scoring with severity levels
- **💡 Smart Remediation** — Actionable fix suggestions for each issue
- **📈 Historical Tracking** — Compare scans over time
- **📋 Multiple Output Formats** — JSON, HTML, CSV, and CLI reports
- **🔄 Batch Scanning** — Scan multiple URLs from files
- **⚡ Rate Limiting Aware** — Polite scanning with configurable delays
- **🌐 Proxy Support** — Route through proxies for testing
- **🔗 API Endpoints** — REST API for CI/CD integration

### Security Headers Checked

| Header | Purpose |
|--------|---------|
| Content-Security-Policy | XSS & injection protection |
| Strict-Transport-Security | Force HTTPS connections |
| X-Frame-Options | Clickjacking prevention |
| X-Content-Type-Options | MIME-type sniffing prevention |
| X-XSS-Protection | Legacy XSS filter (deprecated but still checked) |
| Referrer-Policy | Control referrer information |
| Permissions-Policy | Restrict browser features |
| Cross-Origin-Opener-Policy | Isolates browsing context |
| Cross-Origin-Resource-Policy | Resource sharing control |
| Cross-Origin-Embedder-Policy | Embedding restrictions |
| Cache-Control | Sensitive data caching |
| X-Permitted-Cross-Domain-Policies | Adobe Flash/ACRF |
| Expect-CT | Certificate transparency |

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/security-header-scanner.git
cd security-header-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan a single URL
python main.py scan https://example.com

# Scan with detailed output
python main.py scan https://example.com --verbose

# Scan multiple URLs from file
python main.py batch urls.txt

# Generate HTML report
python main.py scan https://example.com --format html --output report.html

# Start API server
python main.py serve --port 5000
```

## 📖 Examples

### CLI Output
```
╔══════════════════════════════════════════════════════════════════╗
║              🛡️  SECURITY HEADERS SCANNER PRO                    ║
╠══════════════════════════════════════════════════════════════════╣
║  Target: https://example.com                                     ║
║  Scan Time: 2024-01-15 10:30:45                                 ║
╚══════════════════════════════════════════════════════════════════╝

📊 OVERALL SCORE: 72/100 (MEDIUM RISK)

╔══════════════════════════════════════════════════════════════════╗
║ HEADER ANALYSIS                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║ ✅ Strict-Transport-Security      PRESENT  (Score: +15)          ║
║ ✅ X-Content-Type-Options          PRESENT  (Score: +10)         ║
║ ⚠️  Content-Security-Policy        WEAK     (Score: +5)          ║
║ ❌ X-Frame-Options                 MISSING  (Score: -10)        ║
║ ❌ Referrer-Policy                 MISSING  (Score: -8)          ║
╚══════════════════════════════════════════════════════════════════╝

🔧 REMEDIATION PRIORITY:
   1. [HIGH] Add X-Frame-Options header
   2. [MEDIUM] Add Referrer-Policy header
   3. [LOW] Strengthen Content-Security-Policy
```

## 🔧 Configuration

Create `config.yaml` for customization:

```yaml
scanner:
  timeout: 30
  max_retries: 3
  rate_limit_delay: 1.0
  follow_redirects: true
  
headers:
  custom_rules:
    Content-Security-Policy:
      min_score: 20
      required_directives:
        - default-src
        - script-src
  
  thresholds:
    critical: 0
    high: 20
    medium: 50
    low: 80
    
proxy:
  enabled: false
  http: "http://proxy:8080"
  https: "http://proxy:8080"
  
api:
  host: "0.0.0.0"
  port: 5000
  debug: false
```

## 🧪 Run Tests

```bash
pytest tests/ -v --cov=src
```

## 📦 API Usage

### Start Server
```bash
python main.py serve
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/scan?url=https://example.com` | Scan a URL |
| GET | `/api/v1/batch` | Get batch scan status |
| POST | `/api/v1/batch` | Submit batch scan |
| GET | `/api/v1/history` | Get scan history |
| GET | `/api/v1/health` | Health check |

### API Example

```bash
# Scan a URL
curl "http://localhost:5000/api/v1/scan?url=https://example.com"

# Response
{
  "url": "https://example.com",
  "score": 72,
  "grade": "B",
  "headers": {
    "strict-transport-security": {"status": "present", "score": 15},
    "x-frame-options": {"status": "missing", "score": -10}
  },
  "recommendations": [...]
}
```

## 🏗️ Project Structure

```
security-header-scanner/
├── src/
│   ├── __init__.py
│   ├── scanner.py           # Core scanning engine
│   ├── headers.py            # Header definitions & validators
│   ├── analyzer.py           # Risk scoring & analysis
│   ├── reporter.py           # Report generation
│   ├── api.py                # REST API
│   ├── storage.py            # History & persistence
│   └── utils.py              # Utilities
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   ├── test_analyzer.py
│   └── test_headers.py
├── config.yaml               # Configuration
├── main.py                  # CLI entry point
├── requirements.txt
└── README.md
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- OWASP Security Headers Project
- Mozilla Observatory
- NIST CVSS Scoring

---

**Made with ❤️ for developers who care about security**
