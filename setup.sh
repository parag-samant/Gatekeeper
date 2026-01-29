#!/bin/bash
# Gatekeeper CVE Advisory System - Setup Script

set -e

echo "=============================================="
echo "  Gatekeeper CVE Advisory System Setup"
echo "=============================================="
echo

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is required but not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Found Python $PYTHON_VERSION"

# Check minimum Python version
REQUIRED_MAJOR=3
REQUIRED_MINOR=10
ACTUAL_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
ACTUAL_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

if [ "$ACTUAL_MAJOR" -lt "$REQUIRED_MAJOR" ] || ([ "$ACTUAL_MAJOR" -eq "$REQUIRED_MAJOR" ] && [ "$ACTUAL_MINOR" -lt "$REQUIRED_MINOR" ]); then
    echo "ERROR: Python 3.10 or higher is required. Found $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment
echo
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo
echo "Installing dependencies..."
pip install -r requirements.txt

# Create directories
echo
echo "Creating data directories..."
mkdir -p data logs

# Check for .env file
echo
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo
    echo "IMPORTANT: Please edit .env and add your credentials:"
    echo "  - GMAIL_USER: Your Gmail address"
    echo "  - GMAIL_APP_PASSWORD: Your Gmail app password"
    echo "  - OPENROUTER_API_KEY: Your OpenRouter API key"
    echo "  - RECIPIENT_EMAIL: Email address to receive advisories"
    echo
else
    echo ".env file already exists"
fi

echo
echo "=============================================="
echo "  Setup Complete!"
echo "=============================================="
echo
echo "Next steps:"
echo "  1. Edit .env file with your credentials"
echo "  2. Run with: source venv/bin/activate && python -m gatekeeper.main"
echo "  3. Or use Docker: docker-compose up -d"
echo
