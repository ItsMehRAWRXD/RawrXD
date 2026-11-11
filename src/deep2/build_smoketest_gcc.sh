#!/bin/bash
# Build script for Deep2Engine Smoketest using GCC
# Tests core Deep2Engine functionality

echo "Building Deep2Engine Smoketest with GCC..."
echo ""

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SRC_DIR}/smoketest_build"

mkdir -p "${BUILD_DIR}"

echo "Compiling Deep2Engine_SmokeTest_Minimal.cpp..."

g++ -std=c++20 -O3 -mavx2 -mfma -Wall -Wextra \
    -I"${SRC_DIR}" \
    -D_CRT_SECURE_NO_WARNINGS \
    -o "${BUILD_DIR}/Deep2Engine_SmokeTest_Minimal.exe" \
    "${SRC_DIR}/Deep2Engine_SmokeTest_Minimal.cpp" \
    -lpthread

if [ $? -ne 0 ]; then
    echo ""
    echo "BUILD FAILED"
    exit 1
fi

echo ""
echo "BUILD SUCCESSFUL"
echo "Executable: ${BUILD_DIR}/Deep2Engine_SmokeTest_Minimal.exe"
echo ""
echo "Running smoketest..."
echo ""

"${BUILD_DIR}/Deep2Engine_SmokeTest_Minimal.exe"

exit $?
