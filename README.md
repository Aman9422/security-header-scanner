# 🛡️ Security Headers Scanner Pro

### Scan, Analyze & Improve Your Website's Security Headers

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-29%20passing-brightgreen.svg)]()

---

## 📖 Table of Contents

1. [What is this?](#what-is-this)
2. [Quick Start (5 minutes)](#-quick-start)
3. [Installation](#-installation)
4. [How to Use](#-how-to-use)
5. [Understanding Results](#-understanding-results)
6. [For Developers](#-for-developers)
7. [Publish to GitHub](#-publish-to-github)

---

## 🎯 What is this?

**Security Headers Scanner Pro** is a tool that checks if a website has proper security headers configured. 

### Think of it like a security checklist:

| Without Security Headers | With Security Headers |
|------------------------|----------------------|
| 😰 Vulnerable to XSS attacks | ✅ Protected from XSS |
| 😰 Can be clicked-jacked | ✅ Can't be embedded in frames |
| 😰 Data can be intercepted | ✅ Forces HTTPS encryption |
| 😰 Browser can guess file types | ✅ File types are enforced |

### Why does this matter?

```
┌─────────────────────────────────────────────────────────┐
│  When you visit a website, the server sends:            │
│                                                          │
│  1. The webpage (HTML)                                   │
│  2. Security headers (invisible instructions)            │
│                                                          │
│  These headers tell browsers HOW to protect users        │
└─────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start

**Time needed: 5 minutes**

### Step 1: Install Python
Make sure you have Python 3.8 or higher:

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
pip install -r requirements.txt
```

### Step 4: Run Your First Scan! 🚀
```bash
python main.py scan https://example.com
```

**That's it!** You'll see something like this:

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
pip install -r requirements.txt

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
pip install -r requirements.txt

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

## 📚 How to Use

### 🔍 Scan a Single Website

```bash
python main.py scan https://google.com
```

**Output:** Beautiful text report with:
- Overall security score
- List of headers found
- Missing headers with fixes
- Risk level assessment

---

### 📊 Generate HTML Report (Pretty Report!)

```bash
python main.py scan https://google.com --format html --output report.html
```

Then open `report.html` in your browser for a beautiful visual report!

---

### 📋 Batch Scan (Multiple Websites)

```bash
# Create a file with URLs (one per line)
echo "https://google.com" > urls.txt
echo "https://github.com" >> urls.txt
echo "https://apple.com" >> urls.txt

# Scan all at once
python main.py batch urls.txt
```

**Sample urls.txt:**
```
# Lines starting with # are comments
https://google.com
https://github.com
https://apple.com
https://microsoft.com
```

---

### 📜 Generate Other Formats

```bash
# JSON (for developers/CI-CD)
python main.py scan https://example.com --format json

# CSV (for Excel/Sheets)
python main.py scan https://example.com --format csv

# Markdown (for README files)
python main.py scan https://example.com --format markdown
```

---

### 🔌 Start API Server (For Developers)

Want to integrate with your CI/CD pipeline?

```bash
# Start the API server
python main.py serve

# API will run at: http://localhost:5000
```

**API Endpoints:**

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/api/v1/scan?url=https://example.com` | Scan a URL |
| GET | `/api/v1/history` | View scan history |
| GET | `/api/v1/headers` | List all headers checked |

**Example API Call:**
```bash
curl "http://localhost:5000/api/v1/scan?url=https://example.com"
```

---

### 📜 View Scan History

```bash
python main.py history
```

---

### 🔧 List All Security Headers

```bash
python main.py headers
```

Shows all 13 security headers the tool checks for!

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

## 🛠️ For Developers

### Project Structure

```
security-header-scanner/
├── main.py              # CLI entry point
├── src/
│   ├── scanner.py       # Core scanning engine
│   ├── headers.py       # Security header definitions
│   ├── analyzer.py      # Scoring & analysis
│   ├── reporter.py      # Report generation
│   ├── storage.py       # Save/load history
│   └── api.py          # REST API server
├── tests/
│   └── test_scanner.py # Unit tests
└── config.yaml         # Configuration
```

### Run Tests

```bash
pytest tests/ -v
```

### Configuration

Edit `config.yaml` to customize:

```yaml
scanner:
  timeout: 30           # Request timeout (seconds)
  max_retries: 3        # Retry failed requests
  rate_limit_delay: 1.0 # Delay between requests

api:
  host: "0.0.0.0"
  port: 5000
```

---

## 🚀 Publish to GitHub

### Step 1: Create Repository on GitHub

1. Go to: **https://github.com/new**
2. Repository name: `security-header-scanner`
3. Select: **Public**
4. Click: **Create repository**

### Step 2: Push Your Code

```bash
cd security-header-scanner

# Initialize git
git init

# Add all files
git add .

# Create first commit
git commit -m "Initial commit: Security Headers Scanner Pro"

# Connect to GitHub
git remote add origin https://github.com/YOUR_USERNAME/security-header-scanner.git

# Push!
git branch -M main
git push -u origin main
```

### Step 3: Enable GitHub Actions

After pushing, GitHub will automatically:
- ✅ Run tests on every push
- ✅ Check code quality
- ✅ Generate coverage reports

---

## ❓ Common Questions

### Q: Is this free?
**A:** Yes! MIT License - free to use, modify, and distribute.

### Q: Can I use this commercially?
**A:** Yes! Just keep the copyright notice.

### Q: Does this scan my local website?
**A:** Yes! Use localhost or your local IP:
```bash
python main.py scan http://localhost:3000
```

### Q: How accurate is it?
**A:** Very! It validates headers against real browser behavior and security standards.

### Q: Can I add more headers?
**A:** Yes! Edit `src/headers.py` to add new headers.

---

## 🙏 Credits

- Security header definitions based on [OWASP](https://owasp.org/)
- Scoring inspired by [Mozilla Observatory](https://observatory.mozilla.org/)
- Built with ❤️ for the developer community

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Made with ❤️ by Aman9422**

[![Star this repo](https://img.shields.io/github/stars/Aman9422/security-header-scanner?style=social)](https://github.com/Aman9422/security-header-scanner)
[![Follow on GitHub](https://img.shields.io/github/followers/Aman9422?style=social)](https://github.com/Aman9422)
