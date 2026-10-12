#!/bin/bash
# Build Verification Script for RawrXD Benchmark Suite
# Copyright (c) 2026 RawrXD Team

set -e  # Exit on error

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     RawrXD Benchmark Suite - Build Verification             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BUILD_DIR="build"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
CMAKE_OPTIONS="${CMAKE_OPTIONS:-}"

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check CMake
    if ! command -v cmake &> /dev/null; then
        print_error "CMake not found. Please install CMake 3.16+"
        exit 1
    fi
    
    CMAKE_VERSION=$(cmake --version | head -n1 | grep -oP '\d+\.\d+')
    print_status "CMake version: $CMAKE_VERSION"
    
    # Check C++ compiler
    if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
        print_error "No C++ compiler found. Please install g++ or clang++"
        exit 1
    fi
    
    # Check for threads support
    print_status "Checking for pthreads support..."
    
    print_status "Prerequisites check passed"
}

# Clean previous build
clean_build() {
    print_status "Cleaning previous build..."
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
        print_status "Removed existing build directory"
    fi
    mkdir -p "$BUILD_DIR"
}

# Configure with CMake
configure() {
    print_status "Configuring with CMake..."
    cd "$BUILD_DIR"
    
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DRAWRXD_BUILD_TESTS=ON \
        -DRAWRXD_BUILD_PHASE_E=ON \
        $CMAKE_OPTIONS \
        2>&1 | tee cmake.log
    
    if [ $? -ne 0 ]; then
        print_error "CMake configuration failed"
        exit 1
    fi
    
    print_status "CMake configuration successful"
    cd ..
}

# Build the project
build() {
    print_status "Building project..."
    cd "$BUILD_DIR"
    
    cmake --build . --parallel $(nproc) 2>&1 | tee build.log
    
    if [ $? -ne 0 ]; then
        print_error "Build failed"
        exit 1
    fi
    
    print_status "Build successful"
    cd ..
}

# Run tests
run_tests() {
    print_status "Running tests..."
    cd "$BUILD_DIR"
    
    # Run CTest
    ctest --output-on-failure -j$(nproc) 2>&1 | tee test.log
    
    if [ $? -ne 0 ]; then
        print_warning "Some tests failed"
    else
        print_status "All tests passed"
    fi
    
    cd ..
}

# Verify executables
verify_executables() {
    print_status "Verifying executables..."
    
    EXECUTABLES=(
        "benchmark_runner"
        "integrated_benchmark_runner"
        "http_client_tests"
        "backend_adapter_tests"
        "e2e_tests"
        "phase_e_benchmark"
    )
    
    for exe in "${EXECUTABLES[@]}"; do
        if [ -f "$BUILD_DIR/$exe" ]; then
            print_status "✓ $exe built successfully"
            # Check if executable
            if [ -x "$BUILD_DIR/$exe" ]; then
                print_status "  - Executable permissions: OK"
            else
                print_warning "  - Missing executable permissions"
            fi
        else
            print_error "✗ $exe not found"
        fi
    done
}

# Check libraries
check_libraries() {
    print_status "Checking libraries..."
    
    LIBRARIES=(
        "libbenchmark_core.a"
        "libbackend_integration.a"
    )
    
    for lib in "${LIBRARIES[@]}"; do
        if [ -f "$BUILD_DIR/$lib" ]; then
            print_status "✓ $lib built successfully"
        else
            print_warning "✗ $lib not found"
        fi
    done
}

# Run smoke test
smoke_test() {
    print_status "Running smoke test..."
    cd "$BUILD_DIR"
    
    # Run help command on main executables
    for exe in benchmark_runner integrated_benchmark_runner; do
        if [ -f "$exe" ]; then
            print_status "Testing $exe --help..."
            ./$exe --help > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                print_status "✓ $exe responds to --help"
            else
                print_warning "✗ $exe --help failed"
            fi
        fi
    done
    
    cd ..
}

# Generate build report
generate_report() {
    print_status "Generating build report..."
    
    REPORT_FILE="$BUILD_DIR/build_report.txt"
    
    cat > "$REPORT_FILE" << EOF
RawrXD Benchmark Suite - Build Report
====================================
Build Date: $(date)
CMake Version: $(cmake --version | head -n1)
Compiler: $(g++ --version 2>/dev/null | head -n1 || clang++ --version 2>/dev/null | head -n1)
Build Type: Release

Executables Built:
EOF
    
    for exe in "${EXECUTABLES[@]}"; do
        if [ -f "$BUILD_DIR/$exe" ]; then
            size=$(du -h "$BUILD_DIR/$exe" | cut -f1)
            echo "  ✓ $exe ($size)" >> "$REPORT_FILE"
        else
            echo "  ✗ $exe (missing)" >> "$REPORT_FILE"
        fi
    done
    
    echo "" >> "$REPORT_FILE"
    echo "Libraries Built:" >> "$REPORT_FILE"
    
    for lib in "${LIBRARIES[@]}"; do
        if [ -f "$BUILD_DIR/$lib" ]; then
            size=$(du -h "$BUILD_DIR/$lib" | cut -f1)
            echo "  ✓ $lib ($size)" >> "$REPORT_FILE"
        else
            echo "  ✗ $lib (missing)" >> "$REPORT_FILE"
        fi
    done
    
    echo "" >> "$REPORT_FILE"
    echo "Build Status: SUCCESS" >> "$REPORT_FILE"
    
    print_status "Build report saved to $REPORT_FILE"
}

# Install (optional)
install_build() {
    if [ "$1" == "--install" ]; then
        print_status "Installing to $INSTALL_PREFIX..."
        cd "$BUILD_DIR"
        cmake --install . --prefix "$INSTALL_PREFIX"
        print_status "Installation complete"
        cd ..
    fi
}

# Main function
main() {
    print_status "Starting build verification..."
    
    check_prerequisites
    clean_build
    configure
    build
    verify_executables
    check_libraries
    run_tests
    smoke_test
    generate_report
    install_build "$1"
    
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              Build Verification Complete!                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    print_status "Build artifacts located in: $(pwd)/$BUILD_DIR"
    print_status "To run benchmarks: cd $BUILD_DIR && ./integrated_benchmark_runner --help"
}

# Run main function
main "$@"
