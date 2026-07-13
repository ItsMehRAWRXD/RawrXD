#!/bin/bash
# Installation Script for RawrXD Benchmark Suite
# Copyright (c) 2026 RawrXD Team

set -e

# Configuration
INSTALL_DIR="${INSTALL_DIR:-/opt/rawrxd/benchmarks}"
CONFIG_DIR="${CONFIG_DIR:-/etc/rawrxd}"
LOG_DIR="${LOG_DIR:-/var/log/rawrxd}"
DATA_DIR="${DATA_DIR:-/var/lib/rawrxd}"
USER="${RAWRXD_USER:-rawrxd}"
GROUP="${RAWRXD_GROUP:-rawrxd}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INSTALL]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    
    print_info "Detected OS: $OS $VER"
}

# Install dependencies
install_dependencies() {
    print_status "Installing dependencies..."
    
    case "$OS" in
        "Ubuntu"|"Debian GNU/Linux")
            apt-get update
            apt-get install -y \
                build-essential \
                cmake \
                python3 \
                python3-pip \
                python3-venv \
                libssl-dev \
                pkg-config
            ;;
        "CentOS Linux"|"Red Hat Enterprise Linux"|"Fedora")
            yum groupinstall -y "Development Tools"
            yum install -y \
                cmake3 \
                python3 \
                python3-pip \
                openssl-devel \
                pkgconfig
            ;;
        "Darwin")
            if ! command -v brew &> /dev/null; then
                print_error "Homebrew is required on macOS"
                exit 1
            fi
            brew install cmake python3 openssl pkg-config
            ;;
        *)
            print_warning "Unknown OS. Please install dependencies manually."
            ;;
    esac
    
    print_status "Dependencies installed"
}

# Create user and group
create_user() {
    print_status "Creating user and group..."
    
    if ! getent group "$GROUP" > /dev/null; then
        groupadd --system "$GROUP"
    fi
    
    if ! id "$USER" > /dev/null 2>&1; then
        useradd --system \
                --gid "$GROUP" \
                --home-dir "$DATA_DIR" \
                --shell /bin/false \
                --create-home \
                "$USER"
    fi
    
    print_status "User $USER created"
}

# Create directories
create_directories() {
    print_status "Creating directories..."
    
    mkdir -p "$INSTALL_DIR"/{bin,lib,scripts,tools,api,dashboard}
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"/{results,baselines,metrics,backups}
    
    chown -R "$USER:$GROUP" "$DATA_DIR"
    chown -R "$USER:$GROUP" "$LOG_DIR"
    
    print_status "Directories created"
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    python3 -m pip install --user \
        aiohttp \
        aiohttp-cors \
        click \
        jinja2 \
        numpy \
        scipy \
        pyyaml \
        requests
    
    print_status "Python dependencies installed"
}

# Build from source
build_from_source() {
    print_status "Building from source..."
    
    if [ ! -d "build" ]; then
        mkdir build
    fi
    
    cd build
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
        -DRAWRXD_BUILD_TESTS=ON
    
    cmake --build . --parallel $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)
    
    cd ..
    
    print_status "Build complete"
}

# Install binaries
install_binaries() {
    print_status "Installing binaries..."
    
    # Copy from build directory
    if [ -d "build" ]; then
        cp build/integrated_benchmark_runner "$INSTALL_DIR/bin/"
        cp build/benchmark_runner "$INSTALL_DIR/bin/"
        cp build/phase_e_benchmark "$INSTALL_DIR/bin/"
    fi
    
    # Copy scripts
    cp scripts/*.sh "$INSTALL_DIR/scripts/"
    chmod +x "$INSTALL_DIR/scripts/"*.sh
    
    # Copy Python tools
    cp tools/*.py "$INSTALL_DIR/tools/"
    chmod +x "$INSTALL_DIR/tools/"*.py
    
    # Copy API server
    cp api/*.py "$INSTALL_DIR/api/"
    
    # Copy dashboard
    cp -r dashboard/* "$INSTALL_DIR/dashboard/"
    
    # Set ownership
    chown -R "$USER:$GROUP" "$INSTALL_DIR"
    
    print_status "Binaries installed"
}

# Install configuration
install_config() {
    print_status "Installing configuration..."
    
    if [ ! -f "$CONFIG_DIR/benchmark.conf" ]; then
        cat > "$CONFIG_DIR/benchmark.conf" << 'EOF'
# RawrXD Benchmark Suite Configuration

[backend]
sovereign_host=localhost
sovereign_port=8080
ollama_host=localhost
ollama_port=11434

[benchmark]
default_iterations=100
warmup_iterations=10
parallel_workers=4
timeout_seconds=300

[paths]
results_dir=/var/lib/rawrxd/results
baseline_dir=/var/lib/rawrxd/baselines
log_dir=/var/log/rawrxd

[logging]
level=info
max_size_mb=100
max_files=10

[security]
level=standard
require_encryption=true
require_authentication=true
EOF
        
        chmod 644 "$CONFIG_DIR/benchmark.conf"
    fi
    
    # Create environment file
    cat > "$CONFIG_DIR/environment" << EOF
RAWRXD_INSTALL_DIR=$INSTALL_DIR
RAWRXD_CONFIG_DIR=$CONFIG_DIR
RAWRXD_LOG_DIR=$LOG_DIR
RAWRXD_DATA_DIR=$DATA_DIR
PATH=\$PATH:$INSTALL_DIR/bin
EOF
    
    chmod 644 "$CONFIG_DIR/environment"
    
    print_status "Configuration installed"
}

# Install systemd service
install_service() {
    print_status "Installing systemd service..."
    
    if [ -d /etc/systemd/system ]; then
        cat > /etc/systemd/system/rawrxd-benchmarks.service << EOF
[Unit]
Description=RawrXD Benchmark Suite
After=network.target

[Service]
Type=simple
User=$USER
Group=$GROUP
WorkingDirectory=$DATA_DIR
EnvironmentFile=$CONFIG_DIR/environment
ExecStart=$INSTALL_DIR/bin/integrated_benchmark_runner --daemon --config $CONFIG_DIR/benchmark.conf
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        print_status "Systemd service installed"
    fi
}

# Create symlinks
create_symlinks() {
    print_status "Creating symlinks..."
    
    # Create symlinks in /usr/local/bin
    if [ -d /usr/local/bin ]; then
        ln -sf "$INSTALL_DIR/bin/integrated_benchmark_runner" /usr/local/bin/rawrxd-benchmark
        ln -sf "$INSTALL_DIR/scripts/run_performance_benchmarks.sh" /usr/local/bin/rawrxd-run
        ln -sf "$INSTALL_DIR/scripts/monitor.sh" /usr/local/bin/rawrxd-monitor
    fi
    
    print_status "Symlinks created"
}

# Print post-install info
print_post_install() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              Installation Complete!                          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    print_info "Installation Directory: $INSTALL_DIR"
    print_info "Configuration Directory: $CONFIG_DIR"
    print_info "Log Directory: $LOG_DIR"
    print_info "Data Directory: $DATA_DIR"
    echo ""
    print_info "Quick Start:"
    echo "  rawrxd-benchmark --help"
    echo "  rawrxd-run --mode quick"
    echo "  rawrxd-monitor status"
    echo ""
    print_info "Service Management:"
    echo "  sudo systemctl start rawrxd-benchmarks"
    echo "  sudo systemctl enable rawrxd-benchmarks"
    echo "  sudo systemctl status rawrxd-benchmarks"
    echo ""
    print_info "Documentation:"
    echo "  cat $INSTALL_DIR/README.md"
    echo "  cat $INSTALL_DIR/PROJECT_OVERVIEW.md"
    echo ""
}

# Main installation
main() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     RawrXD Benchmark Suite - Installation                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    detect_os
    install_dependencies
    create_user
    create_directories
    install_python_deps
    build_from_source
    install_binaries
    install_config
    install_service
    create_symlinks
    print_post_install
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --prefix)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --user)
            USER="$2"
            shift 2
            ;;
        --group)
            GROUP="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --prefix DIR    Installation directory (default: /opt/rawrxd/benchmarks)"
            echo "  --user USER     System user (default: rawrxd)"
            echo "  --group GROUP   System group (default: rawrxd)"
            echo "  --help          Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run as root check
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root or with sudo"
    exit 1
fi

main
