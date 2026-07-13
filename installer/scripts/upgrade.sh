#!/bin/bash
# upgrade.sh
# Phase H.3 Batch 5/5: Cross-Platform Upgrade Script

set -e

VERSION="${1:-latest}"
INSTALL_DIR="${2:-/opt/rawrxd}"
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO:${NC} $1"
}

# Check root/sudo
if [ "$EUID" -ne 0 ]; then
    error "Please run as root or with sudo"
    exit 1
fi

log "RawrXD Upgrade Script"
log "Target version: $VERSION"
log "Platform: $PLATFORM ($ARCH)"

# Check if installed
if [ ! -d "$INSTALL_DIR" ]; then
    error "RawrXD not found at $INSTALL_DIR"
    log "Run install.sh instead: curl -fsSL https://rawrxd.ai/install.sh | sudo bash"
    exit 1
fi

# Get current version
CURRENT_VERSION="unknown"
if [ -f "$INSTALL_DIR/bin/RawrXD" ]; then
    CURRENT_VERSION=$("$INSTALL_DIR/bin/RawrXD" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
fi

log "Current version: $CURRENT_VERSION"

# Check for latest version if not specified
if [ "$VERSION" == "latest" ]; then
    log "Checking for latest version..."
    LATEST_URL="https://api.github.com/repos/ItsMehRAWRXD/RawrXD/releases/latest"
    
    if command -v curl &> /dev/null; then
        VERSION=$(curl -fsSL "$LATEST_URL" | grep -oP '"tag_name": "v\K[^"]+' || echo "")
    elif command -v wget &> /dev/null; then
        VERSION=$(wget -qO- "$LATEST_URL" | grep -oP '"tag_name": "v\K[^"]+' || echo "")
    fi
    
    if [ -z "$VERSION" ]; then
        error "Could not determine latest version"
        exit 1
    fi
    
    log "Latest version: $VERSION"
fi

# Compare versions
if [ "$CURRENT_VERSION" == "$VERSION" ]; then
    log "Already running version $VERSION"
    exit 0
fi

# Check if delta patch is available
info "Checking for delta patch..."
DELTA_PATCH_URL="https://patches.rawrxd.ai/v${CURRENT_VERSION}_to_v${VERSION}.json"
USE_DELTA=false

if command -v curl &> /dev/null; then
    if curl -fsSL "$DELTA_PATCH_URL" -o /dev/null 2>/dev/null; then
        USE_DELTA=true
    fi
elif command -v wget &> /dev/null; then
    if wget -q --spider "$DELTA_PATCH_URL" 2>/dev/null; then
        USE_DELTA=true
    fi
fi

# Stop service
log "Stopping RawrXD service..."
if [ "$PLATFORM" == "darwin" ]; then
    launchctl unload /Library/LaunchDaemons/ai.rawrxd.sovereign.plist 2>/dev/null || true
else
    systemctl stop rawrxd 2>/dev/null || true
fi

# Backup current installation
BACKUP_DIR="/tmp/rawrxd_backup_$(date +%s)"
log "Creating backup at $BACKUP_DIR..."
cp -r "$INSTALL_DIR" "$BACKUP_DIR"

# Perform upgrade
if [ "$USE_DELTA" == true ]; then
    log "Using delta patch for upgrade..."
    # Download and apply delta patch
    # This would use the delta_patch.ps1 equivalent for bash
    warn "Delta patching not yet implemented for bash, using full upgrade"
    USE_DELTA=false
fi

if [ "$USE_DELTA" == false ]; then
    log "Performing full upgrade..."
    
    # Download new version
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    if [ "$PLATFORM" == "darwin" ]; then
        DOWNLOAD_URL="https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$VERSION/RawrXD-$VERSION-macOS.tar.gz"
    else
        DOWNLOAD_URL="https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$VERSION/RawrXD-$VERSION-$ARCH.AppImage"
    fi
    
    log "Downloading from $DOWNLOAD_URL..."
    
    if command -v curl &> /dev/null; then
        curl -fsSL "$DOWNLOAD_URL" -o rawrxd-download
    elif command -v wget &> /dev/null; then
        wget -q "$DOWNLOAD_URL" -O rawrxd-download
    fi
    
    # Preserve config
    log "Preserving configuration..."
    if [ -f "$INSTALL_DIR/config/rawrxd.yaml" ]; then
        cp "$INSTALL_DIR/config/rawrxd.yaml" "$TEMP_DIR/config_backup.yaml"
    fi
    
    # Remove old binaries
    log "Removing old binaries..."
    rm -rf "$INSTALL_DIR/bin"
    
    # Install new version
    log "Installing new version..."
    if [[ "$DOWNLOAD_URL" == *.tar.gz ]]; then
        tar -xzf rawrxd-download
        cp -r RawrXD/* "$INSTALL_DIR/"
    else
        mkdir -p "$INSTALL_DIR/bin"
        mv rawrxd-download "$INSTALL_DIR/bin/RawrXD"
        chmod +x "$INSTALL_DIR/bin/RawrXD"
    fi
    
    # Restore config
    if [ -f "$TEMP_DIR/config_backup.yaml" ]; then
        log "Restoring configuration..."
        cp "$TEMP_DIR/config_backup.yaml" "$INSTALL_DIR/config/rawrxd.yaml"
    fi
    
    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"
fi

# Fix permissions
if [ "$PLATFORM" != "darwin" ]; then
    chown -R rawrxd:rawrxd "$INSTALL_DIR" 2>/dev/null || true
fi

# Start service
log "Starting RawrXD service..."
if [ "$PLATFORM" == "darwin" ]; then
    launchctl load /Library/LaunchDaemons/ai.rawrxd.sovereign.plist
else
    systemctl start rawrxd
fi

# Verify upgrade
sleep 2
NEW_VERSION=$("$INSTALL_DIR/bin/RawrXD" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")

if [ "$NEW_VERSION" == "$VERSION" ]; then
    log ""
    log "Upgrade successful!"
    log "Previous version: $CURRENT_VERSION"
    log "Current version: $NEW_VERSION"
    log ""
    log "Cleaning up backup..."
    rm -rf "$BACKUP_DIR"
else
    error "Upgrade verification failed!"
    warn "Restoring from backup..."
    rm -rf "$INSTALL_DIR"
    mv "$BACKUP_DIR" "$INSTALL_DIR"
    
    if [ "$PLATFORM" == "darwin" ]; then
        launchctl load /Library/LaunchDaemons/ai.rawrxd.sovereign.plist
    else
        systemctl start rawrxd
    fi
    
    error "Restored to version $CURRENT_VERSION"
    exit 1
fi
