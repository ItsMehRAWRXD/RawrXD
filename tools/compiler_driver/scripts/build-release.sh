#!/bin/bash
# RAWRXD Compiler Driver - Release Build Script
# Cross-platform release build automation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
VERSION="1.0.0"
BUILD_DIR="build"
RELEASE_DIR="release"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Main build process
main() {
    log_info "RAWRXD Compiler Driver Release Build"
    log_info "Version: $VERSION"
    echo ""

    # Clean previous builds
    log_info "Cleaning previous builds..."
    rm -rf "$BUILD_DIR" "$RELEASE_DIR"
    mkdir -p "$BUILD_DIR"
    mkdir -p "$RELEASE_DIR"

    # Build
    log_info "Building..."
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
        # Windows build
        ./build.bat
    else
        # Unix build
        make clean
        make
    fi

    if [ $? -ne 0 ]; then
        log_error "Build failed!"
        exit 1
    fi

    # Run tests
    log_info "Running tests..."
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
        cd tests && ./smoke_test.bat && cd ..
    else
        cd tests && ./smoke_test.sh && cd ..
    fi

    if [ $? -ne 0 ]; then
        log_warn "Some tests failed!"
    fi

    # Create release package
    log_info "Creating release package..."
    
    # Copy files
    cp -r bin "$RELEASE_DIR/"
    cp -r include "$RELEASE_DIR/"
    cp -r src "$RELEASE_DIR/"
    cp -r examples "$RELEASE_DIR/"
    cp -r tests "$RELEASE_DIR/"
    cp -r docs "$RELEASE_DIR/"
    cp README.md "$RELEASE_DIR/"
    cp LICENSE "$RELEASE_DIR/"
    cp CHANGELOG.md "$RELEASE_DIR/"
    cp CONTRIBUTING.md "$RELEASE_DIR/"
    cp CODE_OF_CONDUCT.md "$RELEASE_DIR/"
    cp FAQ.md "$RELEASE_DIR/"
    cp SECURITY.md "$RELEASE_DIR/"
    cp Makefile "$RELEASE_DIR/"
    cp build.bat "$RELEASE_DIR/"
    cp install.bat "$RELEASE_DIR/"
    cp uninstall.bat "$RELEASE_DIR/"

    # Create archive
    log_info "Creating archive..."
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
        # Windows - use PowerShell
        powershell -Command "Compress-Archive -Path '$RELEASE_DIR/*' -DestinationPath 'rawrxd-compiler-v$VERSION.zip' -Force"
    else
        # Unix
        tar -czf "rawrxd-compiler-v$VERSION.tar.gz" "$RELEASE_DIR"
    fi

    # Generate checksums
    log_info "Generating checksums..."
    if command -v sha256sum &> /dev/null; then
        sha256sum "rawrxd-compiler-v$VERSION".* > checksums.txt
    elif command -v shasum &> /dev/null; then
        shasum -a 256 "rawrxd-compiler-v$VERSION".* > checksums.txt
    else
        log_warn "No checksum utility found"
    fi

    echo ""
    log_info "Release build complete!"
    log_info "Package: rawrxd-compiler-v$VERSION"
    echo ""
    ls -lh rawrxd-compiler-v$VERSION.* 2>/dev/null || dir rawrxd-compiler-v$VERSION.*
}

# Run main
main "$@"
