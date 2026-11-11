#!/bin/bash
# Production Deployment Script for RawrXD Benchmark Suite
# Copyright (c) 2026 RawrXD Team
# Usage: ./deploy.sh [environment] [version]

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="rawrxd-benchmarks"
DEPLOY_USER="${DEPLOY_USER:-rawrxd}"
DEPLOY_GROUP="${DEPLOY_GROUP:-rawrxd}"
INSTALL_DIR="${INSTALL_DIR:-/opt/rawrxd/benchmarks}"
CONFIG_DIR="${CONFIG_DIR:-/etc/rawrxd}"
LOG_DIR="${LOG_DIR:-/var/log/rawrxd}"
DATA_DIR="${DATA_DIR:-/var/lib/rawrxd}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/rawrxd}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[DEPLOY]${NC} $1"
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

# Pre-deployment checks
pre_deploy_checks() {
    print_status "Running pre-deployment checks..."
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run as root or with sudo"
        exit 1
    fi
    
    # Check available disk space (need at least 1GB)
    AVAILABLE_SPACE=$(df /opt | tail -1 | awk '{print $4}')
    if [ "$AVAILABLE_SPACE" -lt 1048576 ]; then
        print_error "Insufficient disk space. Need at least 1GB free."
        exit 1
    fi
    
    # Check if required ports are available
    for port in 8080 11434; do
        if netstat -tuln | grep -q ":$port "; then
            print_warning "Port $port is already in use"
        fi
    done
    
    # Verify build artifacts exist
    if [ ! -d "$SCRIPT_DIR/../build" ]; then
        print_error "Build directory not found. Run build_verification.sh first."
        exit 1
    fi
    
    print_status "Pre-deployment checks passed"
}

# Create system user and group
create_system_user() {
    print_status "Creating system user and group..."
    
    # Create group if it doesn't exist
    if ! getent group "$DEPLOY_GROUP" > /dev/null; then
        groupadd --system "$DEPLOY_GROUP"
        print_status "Created group: $DEPLOY_GROUP"
    fi
    
    # Create user if it doesn't exist
    if ! id "$DEPLOY_USER" > /dev/null 2>&1; then
        useradd --system --gid "$DEPLOY_GROUP" \
                --home-dir "$DATA_DIR" \
                --shell /bin/false \
                --comment "RawrXD Benchmark Suite" \
                "$DEPLOY_USER"
        print_status "Created user: $DEPLOY_USER"
    fi
}

# Create directory structure
create_directories() {
    print_status "Creating directory structure..."
    
    # Create directories
    mkdir -p "$INSTALL_DIR/bin"
    mkdir -p "$INSTALL_DIR/lib"
    mkdir -p "$INSTALL_DIR/scripts"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR/results"
    mkdir -p "$DATA_DIR/baselines"
    mkdir -p "$BACKUP_DIR"
    
    # Set ownership
    chown -R "$DEPLOY_USER:$DEPLOY_GROUP" "$INSTALL_DIR"
    chown -R "$DEPLOY_USER:$DEPLOY_GROUP" "$DATA_DIR"
    chown -R "$DEPLOY_USER:$DEPLOY_GROUP" "$LOG_DIR"
    chown root:"$DEPLOY_GROUP" "$CONFIG_DIR"
    chmod 755 "$CONFIG_DIR"
    
    print_status "Directory structure created"
}

# Install binaries
install_binaries() {
    print_status "Installing binaries..."
    
    local build_dir="$SCRIPT_DIR/../build"
    
    # Install main executables
    install -m 755 "$build_dir/integrated_benchmark_runner" "$INSTALL_DIR/bin/"
    install -m 755 "$build_dir/benchmark_runner" "$INSTALL_DIR/bin/"
    install -m 755 "$build_dir/phase_e_benchmark" "$INSTALL_DIR/bin/"
    
    # Install test executables (optional)
    if [ -f "$build_dir/http_client_tests" ]; then
        install -m 755 "$build_dir/http_client_tests" "$INSTALL_DIR/bin/"
    fi
    if [ -f "$build_dir/backend_adapter_tests" ]; then
        install -m 755 "$build_dir/backend_adapter_tests" "$INSTALL_DIR/bin/"
    fi
    if [ -f "$build_dir/e2e_tests" ]; then
        install -m 755 "$build_dir/e2e_tests" "$INSTALL_DIR/bin/"
    fi
    
    # Install scripts
    install -m 755 "$SCRIPT_DIR/run_performance_benchmarks.sh" "$INSTALL_DIR/scripts/"
    install -m 755 "$SCRIPT_DIR/run_integration_tests.sh" "$INSTALL_DIR/scripts/"
    install -m 755 "$SCRIPT_DIR/backup.sh" "$INSTALL_DIR/scripts/"
    
    # Set ownership
    chown -R "$DEPLOY_USER:$DEPLOY_GROUP" "$INSTALL_DIR"
    
    print_status "Binaries installed to $INSTALL_DIR/bin"
}

# Install configuration files
install_config() {
    print_status "Installing configuration files..."
    
    # Create default configuration if it doesn't exist
    if [ ! -f "$CONFIG_DIR/benchmark.conf" ]; then
        cat > "$CONFIG_DIR/benchmark.conf" << 'EOF'
# RawrXD Benchmark Suite Configuration
# Production deployment settings

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

[validation]
min_sample_size=30
max_outlier_percentage=5.0
confidence_level=0.95
EOF
        
        chmod 644 "$CONFIG_DIR/benchmark.conf"
        print_status "Created default configuration"
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
}

# Install systemd service
install_systemd_service() {
    print_status "Installing systemd service..."
    
    cat > /etc/systemd/system/rawrxd-benchmarks.service << EOF
[Unit]
Description=RawrXD Benchmark Suite
After=network.target

[Service]
Type=simple
User=$DEPLOY_USER
Group=$DEPLOY_GROUP
WorkingDirectory=$DATA_DIR
EnvironmentFile=$CONFIG_DIR/environment
ExecStart=$INSTALL_DIR/bin/integrated_benchmark_runner --daemon --config $CONFIG_DIR/benchmark.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rawrxd-benchmarks

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    print_status "Systemd service installed"
}

# Install logrotate configuration
install_logrotate() {
    print_status "Installing logrotate configuration..."
    
    cat > /etc/logrotate.d/rawrxd-benchmarks << EOF
$LOG_DIR/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 $DEPLOY_USER $DEPLOY_GROUP
    sharedscripts
    postrotate
        systemctl reload rawrxd-benchmarks > /dev/null 2>&1 || true
    endscript
}
EOF
    
    print_status "Logrotate configuration installed"
}

# Setup firewall rules (if ufw is available)
setup_firewall() {
    print_status "Configuring firewall..."
    
    if command -v ufw > /dev/null; then
        # Allow benchmark suite to communicate with backends
        ufw allow out 8080/tcp comment 'RawrXD: Sovereign backend'
        ufw allow out 11434/tcp comment 'RawrXD: Ollama backend'
        print_status "Firewall rules added"
    else
        print_warning "ufw not available, skipping firewall configuration"
    fi
}

# Post-deployment verification
post_deploy_verify() {
    print_status "Running post-deployment verification..."
    
    # Check binary execution
    if ! "$INSTALL_DIR/bin/integrated_benchmark_runner" --help > /dev/null 2>&1; then
        print_error "Binary verification failed"
        exit 1
    fi
    
    # Check permissions
    if [ "$(stat -c %U "$INSTALL_DIR")" != "$DEPLOY_USER" ]; then
        print_error "Ownership verification failed"
        exit 1
    fi
    
    # Test configuration loading
    if [ ! -r "$CONFIG_DIR/benchmark.conf" ]; then
        print_error "Configuration file not readable"
        exit 1
    fi
    
    print_status "Post-deployment verification passed"
}

# Print deployment summary
print_summary() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              Deployment Complete!                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    print_info "Installation Directory: $INSTALL_DIR"
    print_info "Configuration Directory: $CONFIG_DIR"
    print_info "Log Directory: $LOG_DIR"
    print_info "Data Directory: $DATA_DIR"
    echo ""
    print_status "Next steps:"
    echo "  1. Review configuration: sudo nano $CONFIG_DIR/benchmark.conf"
    echo "  2. Start service: sudo systemctl start rawrxd-benchmarks"
    echo "  3. Enable auto-start: sudo systemctl enable rawrxd-benchmarks"
    echo "  4. Check status: sudo systemctl status rawrxd-benchmarks"
    echo "  5. View logs: sudo journalctl -u rawrxd-benchmarks -f"
    echo ""
    print_status "To run benchmarks manually:"
    echo "  sudo -u $DEPLOY_USER $INSTALL_DIR/bin/integrated_benchmark_runner --help"
}

# Rollback function
rollback() {
    print_warning "Rolling back deployment..."
    
    systemctl stop rawrxd-benchmarks 2>/dev/null || true
    systemctl disable rawrxd-benchmarks 2>/dev/null || true
    
    rm -f /etc/systemd/system/rawrxd-benchmarks.service
    rm -f /etc/logrotate.d/rawrxd-benchmarks
    
    systemctl daemon-reload
    
    print_status "Rollback complete"
}

# Main deployment function
main() {
    local environment="${1:-production}"
    local version="${2:-latest}"
    
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     RawrXD Benchmark Suite - Production Deployment          ║"
    echo "║     Environment: $environment"
    echo "║     Version: $version"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Set environment-specific variables
    case "$environment" in
        development)
            INSTALL_DIR="/opt/rawrxd-dev/benchmarks"
            CONFIG_DIR="/etc/rawrxd-dev"
            LOG_DIR="/var/log/rawrxd-dev"
            DATA_DIR="/var/lib/rawrxd-dev"
            ;;
        staging)
            INSTALL_DIR="/opt/rawrxd-staging/benchmarks"
            CONFIG_DIR="/etc/rawrxd-staging"
            LOG_DIR="/var/log/rawrxd-staging"
            DATA_DIR="/var/lib/rawrxd-staging"
            ;;
        production|*)
            # Use defaults
            ;;
    esac
    
    # Run deployment steps
    pre_deploy_checks
    create_system_user
    create_directories
    install_binaries
    install_config
    install_systemd_service
    install_logrotate
    setup_firewall
    post_deploy_verify
    
    print_summary
}

# Show usage
usage() {
    echo "Usage: $0 [OPTIONS] [ENVIRONMENT] [VERSION]"
    echo ""
    echo "Environments:"
    echo "  development    Deploy to development environment"
    echo "  staging        Deploy to staging environment"
    echo "  production     Deploy to production environment (default)"
    echo ""
    echo "Options:"
    echo "  -r, --rollback    Rollback deployment"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                           # Deploy to production"
    echo "  $0 staging                   # Deploy to staging"
    echo "  $0 --rollback                # Rollback production"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--rollback)
            rollback
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        development|staging|production)
            ENVIRONMENT="$1"
            shift
            ;;
        *)
            VERSION="$1"
            shift
            ;;
    esac
done

# Handle errors
trap 'print_error "Deployment failed on line $LINENO"' ERR

# Run main
main "${ENVIRONMENT:-production}" "${VERSION:-latest}"
