#!/bin/bash

# RawrXD Build Script for Linux/macOS
# Usage: ./build.sh [Debug|Release] [options]

set -e

BUILD_TYPE="Release"
ENABLE_CUDA="OFF"
ENABLE_VULKAN="OFF"
ENABLE_TESTS="ON"
ENABLE_EXAMPLES="ON"
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        Debug|Release)
            BUILD_TYPE="$1"
            ;;
        --cuda)
            ENABLE_CUDA="ON"
            ;;
        --vulkan)
            ENABLE_VULKAN="ON"
            ;;
        --no-tests)
            ENABLE_TESTS="OFF"
            ;;
        --no-examples)
            ENABLE_EXAMPLES="OFF"
            ;;
        -j)
            JOBS="$2"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
    shift
done

echo "=========================================="
echo "RawrXD Build Script"
echo "=========================================="
echo "Build Type: $BUILD_TYPE"
echo "CUDA: $ENABLE_CUDA"
echo "Vulkan: $ENABLE_VULKAN"
echo "Tests: $ENABLE_TESTS"
echo "Examples: $ENABLE_EXAMPLES"
echo "Jobs: $JOBS"
echo "=========================================="

# Create build directory
mkdir -p build
cd build

# Configure
echo ""
echo "[1/3] Configuring with CMake..."
cmake .. \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DRAWRXD_ENABLE_CUDA="$ENABLE_CUDA" \
    -DRAWRXD_ENABLE_VULKAN="$ENABLE_VULKAN" \
    -DRAWRXD_BUILD_TESTS="$ENABLE_TESTS" \
    -DRAWRXD_BUILD_EXAMPLES="$ENABLE_EXAMPLES"

# Build
echo ""
echo "[2/3] Building with $JOBS parallel jobs..."
cmake --build . --parallel "$JOBS"

# Test (if enabled)
if [ "$ENABLE_TESTS" = "ON" ]; then
    echo ""
    echo "[3/3] Running tests..."
    ctest --output-on-failure
fi

echo ""
echo "=========================================="
echo "Build completed successfully!"
echo "Output: build/bin/"
echo "=========================================="
