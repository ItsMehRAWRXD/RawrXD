#!/bin/bash
# install.sh
# Phase F.1 Batch 1/5: One-line installer for RawrXD Sovereign
# Usage: curl -sSL https://rawrxd.ai/install | bash

set -e

# Configuration
PRODUCT_NAME="RawrXD Sovereign Runtime"
PRODUCT_SHORT="rawrxd"
VERSION="${RWRXD_VERSION:-1.0.0}"
INSTALL_DIR="${RWRXD_INSTALL_DIR:-/usr/local}"
BIN_DIR="$INSTALL_DIR/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[INSTALL]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            DISTRO=$NAME
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macOS"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        OS="windows"
        DISTRO="Windows"
    else
        error "Unsupported operating system: $OSTYPE"
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="x64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) error "Unsupported architecture: $ARCH" ;;
    esac
    
    log "Detected: $DISTRO ($OS) on $ARCH"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check for required tools
    local required=(curl tar)
    for tool in "${required[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "Required tool not found: $tool"
        fi
    done
    
    # Check disk space (need at least 2GB)
    local available_space
    available_space=$(df "$INSTALL_DIR" | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 2097152 ]; then
        error "Insufficient disk space. Need at least 2GB free."
    fi
    
    success "Prerequisites check passed"
}

# Download and install
download_and_install() {
    log "Downloading $PRODUCT_NAME v$VERSION..."
    
    local download_url
    local temp_dir
    
    # Construct download URL
    case $OS in
        linux)
            if command -v dpkg &> /dev/null; then
                # Debian/Ubuntu
                download_url="https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$VERSION/rawrxd_${VERSION}_amd64.deb"
                PACKAGE_TYPE="deb"
            elif command -v rpm &> /dev/null; then
                # RHEL/CentOS/Fedora
                download_url="https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$VERSION/rawrxd-${VERSION}-1.x86_64.rpm"
                PACKAGE_TYPE="rpm"
            else
                # Generic tarball
                download_url="https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$VERSION/rawrxd-${VERSION}-linux-${ARCH}.tar.gz"
                PACKAGE_TYPE="tar"
            fi
            ;;
        macos)
            download_url="https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$VERSION/rawrxd-${VERSION}-macos-${ARCH}.dmg"
            PACKAGE_TYPE="dmg"
            ;;
        windows)
            download_url="https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$VERSION/rawrxd-${VERSION}-windows-${ARCH}.msi"
            PACKAGE_TYPE="msi"
            ;;
    esac
    
    # Create temp directory
    temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT
    
    # Download
    log "Downloading from: $download_url"
    if ! curl -fsSL "$download_url" -o "$temp_dir/download.$PACKAGE_TYPE"; then
        error "Failed to download package"
    fi
    
    # Verify checksum
    log "Verifying package integrity..."
    local checksum_url="${download_url}.sha256"
    if curl -fsSL "$checksum_url" -o "$temp_dir/checksum.sha256" 2>/dev/null; then
        cd "$temp_dir"
        if ! sha256sum -c checksum.sha256; then
            error "Package checksum verification failed"
        fi
        cd - > /dev/null
        success "Checksum verified"
    else
        warn "Could not verify checksum (no checksum file available)"
    fi
    
    # Install
    log "Installing package..."
    case $PACKAGE_TYPE in
        deb)
            sudo dpkg -i "$temp_dir/download.deb" || sudo apt-get install -f -y
            ;;
        rpm)
            sudo rpm -i "$temp_dir/download.rpm" || sudo yum install -y "$temp_dir/download.rpm"
            ;;
        tar)
            sudo tar -xzf "$temp_dir/download.tar.gz" -C "$INSTALL_DIR"
            ;;
        dmg)
            # Mount DMG and copy app
            hdiutil attach "$temp_dir/download.dmg"
            cp -R "/Volumes/RawrXD Sovereign/RawrXD.app" /Applications/
            hdiutil detach "/Volumes/RawrXD Sovereign"
            ;;
        msi)
            error "Windows MSI installation requires Windows Installer. Please run the MSI directly."
            ;;
    esac
    
    success "Package installed successfully"
}

# Post-installation setup
post_install() {
    log "Running post-installation setup..."
    
    # Create config directory
    local config_dir
    if [ "$OS" = "macos" ]; then
        config_dir="$HOME/Library/Application Support/RawrXD"
    else
        config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/rawrxd"
    fi
    
    mkdir -p "$config_dir"
    
    # Create default config if it doesn't exist
    if [ ! -f "$config_dir/config.yaml" ]; then
        cat > "$config_dir/config.yaml" << 'EOF'
# RawrXD Sovereign Runtime Configuration
version: "1.0.0"

# Runtime settings
runtime:
  threads: auto  # auto-detect CPU cores
  gpu: true
  memory_limit_gb: 0  # 0 = unlimited

# Benchmark settings
benchmark:
  default_model: "phi-3-mini-Q4"
  confidence_level: 0.95
  warmup_runs: 5
  measured_runs: 50

# Autonomy settings
autonomy:
  enabled: true
  safety_envelope: true
  max_concurrent_agents: 16

# Telemetry
telemetry:
  enabled: true
  anonymize: true
  endpoint: "https://telemetry.rawrxd.ai"
EOF
        log "Created default configuration at: $config_dir/config.yaml"
    fi
    
    # Add to PATH if needed
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        local shell_rc
        if [ -n "$ZSH_VERSION" ]; then
            shell_rc="$HOME/.zshrc"
        elif [ -n "$BASH_VERSION" ]; then
            shell_rc="$HOME/.bashrc"
        else
            shell_rc="$HOME/.profile"
        fi
        
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$shell_rc"
        log "Added $BIN_DIR to PATH in $shell_rc"
        warn "Please run: source $shell_rc"
    fi
    
    success "Post-installation setup complete"
}

# Verify installation
verify_installation() {
    log "Verifying installation..."
    
    if ! command -v rawrxd &> /dev/null; then
        error "rawrxd command not found in PATH"
    fi
    
    local version
    version=$(rawrxd --version 2>/dev/null || echo "unknown")
    success "RawrXD installed: $version"
    
    # Run quick validation
    log "Running quick validation..."
    if rawrxd validate --quick; then
        success "Validation passed"
    else
        warn "Validation had issues, but installation may still work"
    fi
}

# Print usage
print_usage() {
    cat << 'EOF'
Usage: install.sh [OPTIONS]

Options:
  -v, --version VERSION    Install specific version (default: latest)
  -d, --dir DIRECTORY      Installation directory (default: /usr/local)
  -h, --help              Show this help message

Environment Variables:
  RWRXD_VERSION            Version to install
  RWRXD_INSTALL_DIR        Installation directory

Examples:
  curl -sSL https://rawrxd.ai/install | bash
  curl -sSL https://rawrxd.ai/install | bash -s -- --version 1.0.0
EOF
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            -d|--dir)
                INSTALL_DIR="$2"
                BIN_DIR="$INSTALL_DIR/bin"
                shift 2
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
}

# Main
main() {
    log "Installing $PRODUCT_NAME v$VERSION..."
    
    parse_args "$@"
    detect_os
    check_prerequisites
    download_and_install
    post_install
    verify_installation
    
    echo ""
    success "Installation complete!"
    echo ""
    log "Quick start:"
    echo "  rawrxd --help              # Show help"
    echo "  rawrxd benchmark --quick   # Run quick benchmark"
    echo "  rawrxd serve               # Start runtime server"
    echo ""
    log "Documentation: https://docs.rawrxd.ai"
    log "Support: https://github.com/ItsMehRAWRXD/RawrXD/issues"
}

# Run main
main "$@"
