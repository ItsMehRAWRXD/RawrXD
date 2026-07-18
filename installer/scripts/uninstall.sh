#!/bin/bash
# uninstall.sh
# Phase H.3 Batch 4/5: Linux/macOS Uninstallation Script

set -e

INSTALL_DIR="${1:-/opt/rawrxd}"
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

# Check root/sudo
if [ "$EUID" -ne 0 ]; then
    error "Please run as root or with sudo"
    exit 1
fi

log "RawrXD Uninstaller"
log "Platform: $PLATFORM"
log "Install directory: $INSTALL_DIR"

# Confirm
read -p "Are you sure you want to uninstall RawrXD? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log "Uninstallation cancelled"
    exit 0
fi

# Backup configuration
if [ -f "$INSTALL_DIR/config/rawrxd.yaml" ]; then
    BACKUP_DIR="$HOME/RawrXD_Backup_$(date +%Y%m%d_%H%M%S)"
    log "Backing up configuration to $BACKUP_DIR..."
    mkdir -p "$BACKUP_DIR"
    cp -r "$INSTALL_DIR/config" "$BACKUP_DIR/"
fi

# Stop and remove service
if [ "$PLATFORM" == "darwin" ]; then
    log "Stopping launchd service..."
    launchctl unload /Library/LaunchDaemons/ai.rawrxd.sovereign.plist 2>/dev/null || true
    rm -f /Library/LaunchDaemons/ai.rawrxd.sovereign.plist
else
    log "Stopping systemd service..."
    systemctl stop rawrxd 2>/dev/null || true
    systemctl disable rawrxd 2>/dev/null || true
    rm -f /etc/systemd/system/rawrxd.service
    systemctl daemon-reload
fi

# Remove symlink
if [ -L "/usr/local/bin/rawrxd" ]; then
    log "Removing symlink..."
    rm -f /usr/local/bin/rawrxd
fi

# Remove installation directory
if [ -d "$INSTALL_DIR" ]; then
    log "Removing installation directory..."
    rm -rf "$INSTALL_DIR"
fi

# Remove user (Linux only)
if [ "$PLATFORM" != "darwin" ]; then
    if id "rawrxd" &>/dev/null; then
        log "Removing rawrxd user..."
        userdel rawrxd 2>/dev/null || true
    fi
fi

log ""
log "RawrXD uninstalled successfully!"
if [ -n "$BACKUP_DIR" ]; then
    log "Configuration backed up to: $BACKUP_DIR"
fi
