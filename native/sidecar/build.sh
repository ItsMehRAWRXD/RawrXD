#!/bin/bash
# RawrXD Native Sidecar Build Script
# King style - One command to build everything

echo "========================================"
echo "  RawrXD Native Sidecar Build"
echo "========================================"
echo ""

BUILD_DIR="build"
INSTALL_DIR="../../vscode-extension/native"

# Create build directory
mkdir -p $BUILD_DIR
cd $BUILD_DIR

# Configure with CMake
echo "[1/4] Configuring with CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++
if [ $? -ne 0 ]; then
    echo "[ERROR] CMake configuration failed"
    exit 1
fi

# Build
echo ""
echo "[2/4] Building..."
cmake --build . --config Release --parallel
if [ $? -ne 0 ]; then
    echo "[ERROR] Build failed"
    exit 1
fi

# Verify binary exists
echo ""
echo "[3/4] Verifying binary..."
if [ ! -f "bin/RawrXD_Sidecar" ]; then
    echo "[ERROR] Binary not found at expected location"
    exit 1
fi

# Copy to extension directory
echo ""
echo "[4/4] Installing to extension..."
mkdir -p $INSTALL_DIR
cp bin/RawrXD_Sidecar $INSTALL_DIR/
if [ $? -ne 0 ]; then
    echo "[ERROR] Installation failed"
    exit 1
fi

echo ""
echo "========================================"
echo "  Build Complete!"
echo "========================================"
echo "Binary: $INSTALL_DIR/RawrXD_Sidecar"
echo ""
echo "Next steps:"
echo "  1. Test the bridge: npm run test:bridge"
echo "  2. Launch VSCode extension"
echo "  3. Run command: RawrXD: Start Agent Mode"
echo "========================================"

cd ..
