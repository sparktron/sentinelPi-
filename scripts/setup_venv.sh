#!/usr/bin/env bash
# =============================================================================
# SentinelPi — Development Virtual Environment Setup
# =============================================================================
# Sets up a Python venv for local development and testing.
# Does NOT require root or install system-wide.
#
# Usage:
#   bash scripts/setup_venv.sh
#   source venv/bin/activate
#   python -m pytest tests/
#   python -m sentinelpi.main --check-config

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "[*] Setting up development virtual environment..."

# Find Python 3.11+
PYTHON=""
for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$major" -ge 3 && "$minor" -ge 11 ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done
if [[ -z "$PYTHON" ]]; then
    echo "[ERROR] Python 3.11+ is required."
    exit 1
fi
echo "[*] Using: $PYTHON ($("$PYTHON" --version))"

# Create venv
if [[ ! -d "venv" ]]; then
    "$PYTHON" -m venv venv
    echo "[*] Virtual environment created."
else
    echo "[*] Virtual environment already exists."
fi

# Install dependencies
source venv/bin/activate
pip install --quiet --upgrade pip setuptools wheel
pip install --quiet -r requirements.txt
pip install --quiet -r requirements-dev.txt 2>/dev/null || true

# Install project in editable mode if pyproject.toml exists
if [[ -f "pyproject.toml" ]]; then
    pip install --quiet -e .
fi

echo ""
echo "[*] Setup complete. Activate with:"
echo "      source venv/bin/activate"
echo ""
echo "[*] Run tests:"
echo "      python -m pytest tests/ -v"
echo ""
echo "[*] Check config:"
echo "      SENTINELPI_CONFIG=config/sentinelpi.yaml python -m sentinelpi.main --check-config"
echo ""
echo "[*] Start monitoring (requires appropriate network permissions):"
echo "      SENTINELPI_CONFIG=config/sentinelpi.yaml python -m sentinelpi.main"
