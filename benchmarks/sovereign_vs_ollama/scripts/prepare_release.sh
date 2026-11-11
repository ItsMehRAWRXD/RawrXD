#!/bin/bash
# Release Preparation Script for RawrXD Benchmark Suite
# Copyright (c) 2026 RawrXD Team

set -e

# Configuration
VERSION="${1:-1.0.0}"
RELEASE_DIR="releases/rawrxd-benchmarks-${VERSION}"
ARCHIVE_NAME="rawrxd-benchmarks-${VERSION}.tar.gz"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[RELEASE]${NC} $1"
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

# Clean previous releases
clean_releases() {
    print_status "Cleaning previous releases..."
    rm -rf releases/
    mkdir -p releases
}

# Run full test suite
run_tests() {
    print_status "Running full test suite..."
    
    # Build tests
    cd build
    ctest --output-on-failure -j$(nproc)
    cd ..
    
    print_status "All tests passed"
}

# Run security scan
security_scan() {
    print_status "Running security scan..."
    
    python3 tools/security_scanner.py scan -o security_report.json
    
    if [ $? -ne 0 ]; then
        print_error "Security scan failed! Fix issues before releasing."
        exit 1
    fi
    
    print_status "Security scan passed"
}

# Run compliance check
compliance_check() {
    print_status "Running compliance check..."
    
    python3 tools/compliance_checker.py check -o compliance_report.json
    
    print_status "Compliance check complete"
}

# Update version numbers
update_versions() {
    print_status "Updating version numbers..."
    
    # Update CMakeLists.txt
    sed -i "s/VERSION .*/VERSION ${VERSION}/" CMakeLists.txt
    
    # Update Python tools
    for file in tools/*.py; do
        sed -i "s/__version__ = .*/__version__ = \"${VERSION}\"/" "$file" 2>/dev/null || true
    done
    
    # Update documentation
    sed -i "s/Version: .*/Version: ${VERSION}/" PROJECT_OVERVIEW.md
    
    print_status "Version numbers updated"
}

# Generate changelog
generate_changelog() {
    print_status "Generating changelog..."
    
    cat > CHANGELOG.md << EOF
# Changelog

## [${VERSION}] - $(date +%Y-%m-%d)

### Added
- Complete benchmark suite with 53+ files
- HTTP client with connection pooling
- Sovereign and Ollama backend adapters
- Statistical validation framework (Phase E)
- Web dashboard with real-time metrics
- REST API server
- Distributed load generator
- Security manager with RBAC
- Audit logging for compliance
- CI/CD pipeline with GitHub Actions

### Security
- API key and JWT authentication
- Role-based access control
- TLS encryption support
- Vulnerability scanning
- GDPR, SOC2, ISO27001 compliance

### Documentation
- Complete API documentation
- Security hardening guide
- Performance tuning guide
- Troubleshooting guide

## Previous Versions

See git history for previous changes.
EOF
    
    print_status "Changelog generated"
}

# Create release directory
prepare_release() {
    print_status "Preparing release directory..."
    
    mkdir -p "${RELEASE_DIR}"
    
    # Copy source files
    cp -r include "${RELEASE_DIR}/"
    cp -r src "${RELEASE_DIR}/"
    cp -r tests "${RELEASE_DIR}/"
    cp -r scripts "${RELEASE_DIR}/"
    cp -r tools "${RELEASE_DIR}/"
    cp -r api "${RELEASE_DIR}/"
    cp -r dashboard "${RELEASE_DIR}/"
    cp -r docs "${RELEASE_DIR}/"
    
    # Copy build files
    cp CMakeLists.txt "${RELEASE_DIR}/"
    cp docker-compose.yml "${RELEASE_DIR}/"
    cp Dockerfile "${RELEASE_DIR}/"
    cp quickstart.sh "${RELEASE_DIR}/"
    
    # Copy documentation
    cp README.md "${RELEASE_DIR}/"
    cp PROJECT_OVERVIEW.md "${RELEASE_DIR}/"
    cp CHANGELOG.md "${RELEASE_DIR}/"
    cp LICENSE "${RELEASE_DIR}/" 2>/dev/null || true
    
    # Create config directory
    mkdir -p "${RELEASE_DIR}/config"
    cp config/benchmark.conf "${RELEASE_DIR}/config/" 2>/dev/null || true
    
    print_status "Release directory prepared"
}

# Build release binaries
build_binaries() {
    print_status "Building release binaries..."
    
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    cmake --build . --parallel
    
    # Create bin directory in release
    mkdir -p "../${RELEASE_DIR}/bin"
    
    # Copy binaries
    cp integrated_benchmark_runner "../${RELEASE_DIR}/bin/"
    cp benchmark_runner "../${RELEASE_DIR}/bin/"
    cp phase_e_benchmark "../${RELEASE_DIR}/bin/"
    
    cd ..
    
    print_status "Release binaries built"
}

# Create archive
create_archive() {
    print_status "Creating release archive..."
    
    tar -czf "releases/${ARCHIVE_NAME}" -C releases "rawrxd-benchmarks-${VERSION}"
    
    # Calculate checksums
    cd releases
    sha256sum "${ARCHIVE_NAME}" > "${ARCHIVE_NAME}.sha256"
    md5sum "${ARCHIVE_NAME}" > "${ARCHIVE_NAME}.md5"
    cd ..
    
    print_status "Release archive created: releases/${ARCHIVE_NAME}"
}

# Generate release notes
generate_release_notes() {
    print_status "Generating release notes..."
    
    cat > "releases/RELEASE_NOTES_${VERSION}.md" << EOF
# RawrXD Benchmark Suite ${VERSION} Release Notes

## Release Date
$(date +%Y-%m-%d)

## What's New

### Core Features
- Complete HTTP client with connection pooling and retry logic
- Sovereign and Ollama backend adapters with unified interface
- Statistical validation framework with Phase E compliance
- Integrated benchmark runner with warmup and measurement cycles

### Advanced Features
- Real-time web dashboard with Chart.js visualizations
- REST API server for remote benchmark control
- Distributed load generator for horizontal scaling
- Statistical analyzer with t-tests and effect sizes
- Automated report generation (HTML/PDF)

### Security & Compliance
- Security manager with RBAC and multiple auth methods
- Comprehensive audit logging with tamper detection
- Vulnerability scanner with SARIF output
- Compliance checker for GDPR, SOC2, ISO27001
- Incident response automation

### Operations
- Complete deployment automation with systemd
- Monitoring and metrics collection
- Log aggregation and analysis
- Backup and recovery automation
- Performance tuning guide

## Installation

### Quick Install
\`\`\`bash
wget https://github.com/ItsMehRAWRXD/rawrxd/releases/download/v${VERSION}/${ARCHIVE_NAME}
tar -xzf ${ARCHIVE_NAME}
cd rawrxd-benchmarks-${VERSION}
./quickstart.sh
\`\`\`

### Docker
\`\`\`bash
docker-compose up -d
\`\`\`

## Verification

SHA256: \`$(cat releases/${ARCHIVE_NAME}.sha256 | awk '{print $1}')\`

## Documentation

- [Project Overview](PROJECT_OVERVIEW.md)
- [Security Hardening](docs/security_hardening.md)
- [Performance Tuning](docs/performance_tuning.md)
- [API Documentation](docs/http_client_api.md)

## Support

- GitHub Issues: https://github.com/ItsMehRAWRXD/rawrxd/issues
- Security: security@rawrxd.local

---

**Full Changelog**: [CHANGELOG.md](CHANGELOG.md)
EOF
    
    print_status "Release notes generated"
}

# Verify release
verify_release() {
    print_status "Verifying release..."
    
    # Check archive exists
    if [ ! -f "releases/${ARCHIVE_NAME}" ]; then
        print_error "Release archive not found"
        exit 1
    fi
    
    # Verify checksums
    cd releases
    sha256sum -c "${ARCHIVE_NAME}.sha256" || exit 1
    cd ..
    
    # Test extraction
    local test_dir=$(mktemp -d)
    tar -xzf "releases/${ARCHIVE_NAME}" -C "$test_dir"
    
    if [ ! -f "$test_dir/rawrxd-benchmarks-${VERSION}/README.md" ]; then
        print_error "Release archive verification failed"
        rm -rf "$test_dir"
        exit 1
    fi
    
    rm -rf "$test_dir"
    
    print_status "Release verification passed"
}

# Print summary
print_summary() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              Release ${VERSION} Complete!                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    print_info "Release Archive: releases/${ARCHIVE_NAME}"
    print_info "Size: $(du -h releases/${ARCHIVE_NAME} | cut -f1)"
    print_info "SHA256: $(cat releases/${ARCHIVE_NAME}.sha256 | awk '{print $1}')"
    echo ""
    print_info "Next Steps:"
    echo "  1. Review release notes: releases/RELEASE_NOTES_${VERSION}.md"
    echo "  2. Test the release archive"
    echo "  3. Create GitHub release with the archive"
    echo "  4. Update documentation website"
    echo ""
}

# Main
main() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     RawrXD Benchmark Suite - Release Preparation            ║"
    echo "║     Version: ${VERSION}"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    clean_releases
    run_tests
    security_scan
    compliance_check
    update_versions
    generate_changelog
    prepare_release
    build_binaries
    create_archive
    generate_release_notes
    verify_release
    print_summary
}

# Show usage
usage() {
    echo "Usage: $0 [VERSION]"
    echo ""
    echo "Example:"
    echo "  $0 1.0.0"
    echo "  $0 1.1.0-beta"
}

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    exit 0
fi

main
