#!/usr/bin/env bash
# =============================================================================
# SentinelPi Installer
# =============================================================================
# Installs SentinelPi as a systemd service on Raspberry Pi OS / Debian-based Linux.
#
# What this script does:
#   1. Creates a dedicated 'sentinelpi' system user (no login shell).
#   2. Copies project files to /opt/sentinelpi.
#   3. Creates a Python virtual environment and installs dependencies.
#   4. Sets up configuration, logging, and data directories.
#   5. Grants CAP_NET_RAW to the venv Python binary for packet capture.
#   6. Installs the systemd service.
#
# Usage:
#   sudo bash scripts/install.sh
#
# Uninstall:
#   sudo systemctl stop sentinelpi
#   sudo systemctl disable sentinelpi
#   sudo rm /etc/systemd/system/sentinelpi.service
#   sudo userdel sentinelpi
#   sudo rm -rf /opt/sentinelpi /var/lib/sentinelpi /var/log/sentinelpi /etc/sentinelpi

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { error "$@"; exit 1; }

# -----------------------------------------------------------------------
# Pre-flight checks
# -----------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root (use sudo)."
fi

info "SentinelPi Installer"
info "===================="

# Detect the source directory (where install.sh lives)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
info "Source directory: $PROJECT_DIR"

# Check for Python 3.11+
PYTHON=""
for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$major" -ge 3 && "$minor" -ge 11 ]]; then
            PYTHON="$candidate"
            info "Found Python: $PYTHON ($ver)"
            break
        fi
    fi
done
if [[ -z "$PYTHON" ]]; then
    die "Python 3.11+ is required. Install with: sudo apt install python3.11 python3.11-venv"
fi

# -----------------------------------------------------------------------
# System user
# -----------------------------------------------------------------------
SENTINELPI_USER="sentinelpi"
if ! id "$SENTINELPI_USER" &>/dev/null; then
    info "Creating system user: $SENTINELPI_USER"
    useradd --system --shell /usr/sbin/nologin --home-dir /opt/sentinelpi "$SENTINELPI_USER"
else
    info "User '$SENTINELPI_USER' already exists."
fi

# Add sentinelpi user to adm group for auth log access
usermod -aG adm "$SENTINELPI_USER" 2>/dev/null || true

# -----------------------------------------------------------------------
# Directory structure
# -----------------------------------------------------------------------
INSTALL_DIR="/opt/sentinelpi"
CONFIG_DIR="/etc/sentinelpi"
DATA_DIR="/var/lib/sentinelpi"
LOG_DIR="/var/log/sentinelpi"

info "Creating directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

# -----------------------------------------------------------------------
# Copy project files
# -----------------------------------------------------------------------
info "Copying project files to $INSTALL_DIR..."
# Clean previous install (but keep venv if it exists to speed up reinstalls)
find "$INSTALL_DIR" -maxdepth 1 ! -name 'venv' ! -name '.' -exec rm -rf {} + 2>/dev/null || true

cp -r "$PROJECT_DIR/src/sentinelpi" "$INSTALL_DIR/"
cp "$PROJECT_DIR/requirements.txt" "$INSTALL_DIR/"
if [[ -f "$PROJECT_DIR/pyproject.toml" ]]; then
    cp "$PROJECT_DIR/pyproject.toml" "$INSTALL_DIR/"
fi

# -----------------------------------------------------------------------
# Virtual environment
# -----------------------------------------------------------------------
VENV_DIR="$INSTALL_DIR/venv"
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating Python virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
else
    info "Virtual environment already exists — upgrading pip..."
fi

"$VENV_DIR/bin/pip" install --quiet --upgrade pip setuptools wheel
info "Installing Python dependencies..."
"$VENV_DIR/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

# -----------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------
if [[ ! -f "$CONFIG_DIR/sentinelpi.yaml" ]]; then
    info "Installing default configuration to $CONFIG_DIR/sentinelpi.yaml"
    cp "$PROJECT_DIR/config/sentinelpi.yaml" "$CONFIG_DIR/sentinelpi.yaml"
else
    warn "Config file already exists at $CONFIG_DIR/sentinelpi.yaml — not overwriting."
    warn "Check $PROJECT_DIR/config/sentinelpi.yaml for new options."
fi

# -----------------------------------------------------------------------
# Permissions
# -----------------------------------------------------------------------
info "Setting permissions..."
chown -R "$SENTINELPI_USER:$SENTINELPI_USER" "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
chown -R root:"$SENTINELPI_USER" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
chmod 640 "$CONFIG_DIR/sentinelpi.yaml"

# Grant packet capture capability to the venv Python binary
VENV_PYTHON="$VENV_DIR/bin/python3"
# Resolve symlinks to the actual binary
REAL_PYTHON="$(readlink -f "$VENV_PYTHON")"
info "Granting CAP_NET_RAW to $REAL_PYTHON..."
if command -v setcap &>/dev/null; then
    setcap cap_net_raw+eip "$REAL_PYTHON" 2>/dev/null || {
        warn "Failed to set capabilities — packet capture will require root."
        warn "You can set this manually with: sudo setcap cap_net_raw+eip $REAL_PYTHON"
    }
else
    warn "'setcap' not found. Install with: sudo apt install libcap2-bin"
    warn "Packet capture will require running as root without this."
fi

# -----------------------------------------------------------------------
# Systemd service
# -----------------------------------------------------------------------
info "Installing systemd service..."
cp "$PROJECT_DIR/systemd/sentinelpi.service" /etc/systemd/system/sentinelpi.service
systemctl daemon-reload
systemctl enable sentinelpi

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
info "============================================"
info "SentinelPi installation complete!"
info "============================================"
info ""
info "Next steps:"
info "  1. Edit config:  sudo nano $CONFIG_DIR/sentinelpi.yaml"
info "     - Set your network interface (ip link show)"
info "     - Set your subnet and gateway IP"
info "     - Add trusted devices"
info ""
info "  2. Test config:  $VENV_DIR/bin/python -m sentinelpi.main --check-config"
info ""
info "  3. Start:        sudo systemctl start sentinelpi"
info "     Status:       sudo systemctl status sentinelpi"
info "     Logs:         sudo journalctl -u sentinelpi -f"
info "     Dashboard:    http://localhost:8888/"
info ""
info "  4. (Optional) Stop:  sudo systemctl stop sentinelpi"
info ""
