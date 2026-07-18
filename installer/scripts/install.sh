#!/bin/bash
# install.sh
# Phase H.3 Batch 4/5: Linux/macOS Installation Script

set -e

VERSION="${1:-1.0.0}"
INSTALL_DIR="${2:-/opt/rawrxd}"
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

log "RawrXD Sovereign Installer v$VERSION"
log "Platform: $PLATFORM ($ARCH)"
log "Install directory: $INSTALL_DIR"

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
elif [ "$PLATFORM" == "darwin" ]; then
    PKG_MANAGER="brew"
else
    warn "Unknown package manager, proceeding with manual installation"
    PKG_MANAGER="manual"
fi

log "Package manager: $PKG_MANAGER"

# Create directories
log "Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$INSTALL_DIR/config"
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/data"

# Download binary
log "Downloading RawrXD v$VERSION..."

if [ "$PLATFORM" == "darwin" ]; then
    DOWNLOAD_URL="https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$VERSION/RawrXD-$VERSION-macOS.tar.gz"
else
    DOWNLOAD_URL="https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$VERSION/RawrXD-$VERSION-$ARCH.AppImage"
fi

TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

if command -v curl &> /dev/null; then
    curl -fsSL "$DOWNLOAD_URL" -o rawrxd-download
elif command -v wget &> /dev/null; then
    wget -q "$DOWNLOAD_URL" -O rawrxd-download
else
    error "Neither curl nor wget found. Please install one of them."
    exit 1
fi

# Extract or install
if [[ "$DOWNLOAD_URL" == *.tar.gz ]]; then
    log "Extracting archive..."
    tar -xzf rawrxd-download
    cp -r RawrXD/* "$INSTALL_DIR/"
else
    log "Installing AppImage..."
    mv rawrxd-download "$INSTALL_DIR/bin/RawrXD"
    chmod +x "$INSTALL_DIR/bin/RawrXD"
fi

# Create config from template
if [ ! -f "$INSTALL_DIR/config/rawrxd.yaml" ]; then
    log "Creating default configuration..."
    cat > "$INSTALL_DIR/config/rawrxd.yaml" << 'EOF'
# RawrXD Configuration
version: "1.0.0"

server:
  host: "0.0.0.0"
  port: 8080

inference:
  default_model: "default"
  max_tokens: 4096
  temperature: 0.7

logging:
  level: "info"
  file: "/opt/rawrxd/logs/rawrxd.log"

features:
  autonomous: true
  hotpatch: true
  telemetry: true
EOF
fi

# Create systemd service (Linux only)
if [ "$PLATFORM" != "darwin" ] && [ -d "/etc/systemd/system" ]; then
    log "Creating systemd service..."
    cat > /etc/systemd/system/rawrxd.service << EOF
[Unit]
Description=RawrXD Sovereign AI Runtime
After=network.target

[Service]
Type=simple
User=rawrxd
Group=rawrxd
ExecStart=$INSTALL_DIR/bin/RawrXD --config $INSTALL_DIR/config/rawrxd.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Create user if doesn't exist
    if ! id "rawrxd" &>/dev/null; then
        log "Creating rawrxd user..."
        useradd -r -s /bin/false -d "$INSTALL_DIR" rawrxd
    fi

    # Set permissions
    chown -R rawrxd:rawrxd "$INSTALL_DIR"
    chmod 750 "$INSTALL_DIR"

    # Enable and start service
    systemctl daemon-reload
    systemctl enable rawrxd
    log "Service enabled. Start with: sudo systemctl start rawrxd"
fi

# Create launchd plist (macOS only)
if [ "$PLATFORM" == "darwin" ]; then
    log "Creating launchd service..."
    cat > /Library/LaunchDaemons/ai.rawrxd.sovereign.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.rawrxd.sovereign</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/bin/RawrXD</string>
        <string>--config</string>
        <string>$INSTALL_DIR/config/rawrxd.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/logs/service.log</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/logs/error.log</string>
</dict>
</plist>
EOF

    log "Service created. Load with: sudo launchctl load /Library/LaunchDaemons/ai.rawrxd.sovereign.plist"
fi

# Create symlink in /usr/local/bin
if [ -d "/usr/local/bin" ]; then
    log "Creating symlink..."
    ln -sf "$INSTALL_DIR/bin/RawrXD" /usr/local/bin/rawrxd
fi

# Cleanup
cd /
rm -rf "$TEMP_DIR"

log ""
log "RawrXD v$VERSION installed successfully!"
log ""
log "Installation directory: $INSTALL_DIR"
log "Configuration file: $INSTALL_DIR/config/rawrxd.yaml"
log "Log directory: $INSTALL_DIR/logs"
log ""
log "To start RawrXD:"
if [ "$PLATFORM" == "darwin" ]; then
    log "  sudo launchctl load /Library/LaunchDaemons/ai.rawrxd.sovereign.plist"
else
    log "  sudo systemctl start rawrxd"
fi
log ""
log "To verify installation:"
log "  rawrxd --version"
