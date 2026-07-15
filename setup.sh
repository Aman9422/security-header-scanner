#!/bin/bash

# ===========================================
# GitHub Publishing Script
# ===========================================
# Run this script from the project directory
# ===========================================

set -e

echo "🚀 Security Headers Scanner Pro - GitHub Setup"
echo "=============================================="
echo ""

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install git first."
    exit 1
fi

# Get GitHub username
read -p "Enter your GitHub username (e.g., Aman9422): " GITHUB_USERNAME

if [ -z "$GITHUB_USERNAME" ]; then
    echo "❌ Username cannot be empty"
    exit 1
fi

REPO_NAME="security-header-scanner"
REMOTE_URL="https://github.com/${GITHUB_USERNAME}/${REPO_NAME}.git"

echo ""
echo "📋 Repository: $REMOTE_URL"
echo ""

# Initialize git if not already
if [ ! -d ".git" ]; then
    echo "📦 Initializing git repository..."
    git init
fi

# Configure git user (if not set)
if [ -z "$(git config user.email)" ]; then
    echo "⚙️  Setting up git user config..."
    read -p "Enter your GitHub email: " EMAIL
    git config user.email "$EMAIL"
    git config user.name "$GITHUB_USERNAME"
fi

# Add all files
echo "📝 Adding files to git..."
git add .

# Create initial commit
echo ""
echo "💾 Creating initial commit..."
git commit -m "Initial commit: Security Headers Scanner Pro v2.0

✨ Features:
- 13 security headers with smart validators
- Multi-format reports (HTML, JSON, CSV, Markdown)
- CLI interface with beautiful output
- REST API for CI/CD integration
- Batch scanning capability
- History storage with SQLite/JSON
- Comprehensive unit tests

🛡️ Security Headers Checked:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Resource-Policy
- Cross-Origin-Embedder-Policy
- And more...

📦 Tech Stack: Python, Flask, Rich, Requests"

# Check if remote already exists
if git remote -v | grep -q "origin"; then
    echo ""
    read -p "⚠️  Remote 'origin' already exists. Update it? (y/n): " UPDATE_REMOTE
    if [ "$UPDATE_REMOTE" = "y" ]; then
        git remote set-url origin "$REMOTE_URL"
    fi
else
    git remote add origin "$REMOTE_URL"
fi

echo ""
echo "=============================================="
echo "✅ Setup complete!"
echo "=============================================="
echo ""
echo "📋 Next steps:"
echo ""
echo "1. Create the repository on GitHub:"
echo "   👉 https://github.com/new"
echo "      - Repository name: $REPO_NAME"
echo "      - Description: Security Headers Scanner Pro - A comprehensive security header analysis tool"
echo "      - Make it PUBLIC"
echo "      - Don't initialize with README (we already have one)"
echo ""
echo "2. Push to GitHub:"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "3. Enable GitHub Actions (optional):"
echo "   👉 https://github.com/$GITHUB_USERNAME/$REPO_NAME/settings/actions"
echo ""
echo "=============================================="
