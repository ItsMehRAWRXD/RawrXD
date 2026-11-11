#!/usr/bin/env bash
# KartGib Release Build Script
# Builds and packages the complete KartGib Engine for distribution

set -e

echo "========================================"
echo "KartGib Engine - Release Build Script"
echo "========================================"
echo ""

ROOT_DIR="F:/rawrxd/kartgib"
BUILD_DIR="$ROOT_DIR/build/msvc/Release"
PACKAGE_DIR="$ROOT_DIR/package"
VERSION="1.0.0-alpha"

echo "Step 1: Clean build directory..."
if [ -d "$PACKAGE_DIR" ]; then
    rm -rf "$PACKAGE_DIR"
fi
mkdir -p "$PACKAGE_DIR"

echo ""
echo "Step 2: Build KartGib (Release)..."
cmake --build "$ROOT_DIR/build/msvc" --config Release --parallel 8

if [ $? -ne 0 ]; then
    echo "ERROR: Build failed!"
    exit 1
fi

echo ""
echo "Step 3: Verify executable exists..."
if [ ! -f "$BUILD_DIR/KartGib.exe" ]; then
    echo "ERROR: KartGib.exe not found!"
    exit 1
fi
echo "OK: KartGib.exe found"

echo ""
echo "Step 4: Copy executable and dependencies..."
cp "$BUILD_DIR/KartGib.exe" "$PACKAGE_DIR/"

# Copy DLLs if they exist
if [ -d "$BUILD_DIR" ]; then
    cp "$BUILD_DIR"/*.dll "$PACKAGE_DIR/" 2>/dev/null || true
fi

# Copy shaders
if [ -d "$BUILD_DIR/shaders" ]; then
    mkdir -p "$PACKAGE_DIR/shaders"
    cp "$BUILD_DIR/shaders/"*.spv "$PACKAGE_DIR/shaders/" 2>/dev/null || true
fi

echo ""
echo "Step 5: Create directories for assets..."
mkdir -p "$PACKAGE_DIR/Assets"
mkdir -p "$PACKAGE_DIR/Assets/Scenes"
mkdir -p "$PACKAGE_DIR/Assets/Textures"
mkdir -p "$PACKAGE_DIR/Assets/Models"
mkdir -p "$PACKAGE_DIR/Assets/Audio"
mkdir -p "$PACKAGE_DIR/Assets/Materials"
mkdir -p "$PACKAGE_DIR/Assets/Scripts"
mkdir -p "$PACKAGE_DIR/Assets/Shaders"

echo ""
echo "Step 6: Create launch script..."
cat > "$PACKAGE_DIR/run_kartgib.bat" << 'EOF'
@echo off
title KartGib Engine - Sunshine KartGib
echo ============================================
echo KartGib Engine v1.0.0-alpha
echo Sunshine KartGib Engine
echo ============================================
echo.
echo Controls:
echo   W/A/S/D   - Drive kart / Move camera
F5            - Save scene
F9            - Load scene
F6            - Record input
F7            - Replay input
F8            - Debug triangle mode
ESC           - Quit
echo.
echo ============================================
echo.
KartGib.exe --seed 20261025 --biome tropical %*
echo.
echo KartGib has closed.
pause
EOF

echo ""
echo "Step 7: Create uninstall script..."
cat > "$PACKAGE_DIR/uninstall.bat" << 'EOF'
@echo off
echo Uninstalling KartGib Engine...
cd /d %~dp0
cd ..
rd /s /q KartGib
echo KartGib has been uninstalled.
pause
EOF

echo ""
echo "Step 8: Create version file..."
cat > "$PACKAGE_DIR/version.txt" << EOF
KartGib Engine v1.0.0-alpha
Build Date: $(date)
Build Type: Release
Vulkan SDK: 1.4.357
Compiler: MSVC 19.44.35228.0
Platform: Windows x64
EOF

echo ""
echo "Step 9: Create README..."
cat > "$PACKAGE_DIR/README.txt" << 'EOF'
========================================
KartGib Engine v1.0.0-alpha
Sunshine KartGib Engine
========================================

SYSTEM REQUIREMENTS:
- Windows 10/11 (64-bit)
- Vulkan 1.2 compatible GPU
- 4GB RAM minimum (8GB recommended)
- DirectX 11 compatible graphics card

QUICK START:
1. Double-click KartGib.exe or run_kartgib.bat
2. Use W/A/S/D to drive the kart
3. Press F5 to save, F9 to load
4. Press F8 for debug triangle mode
5. Press ESC to quit

CONTROLS:
  W/A/S/D   - Drive kart / Move camera
  ESC       - Quit game
  F5        - Save scene to kartgib_save.json
  F9        - Load scene from kartgib_save.json
  F6        - Record input sequence
  F7        - Replay input sequence
  F8        - Toggle debug triangle mode

FEATURES:
- Procedural world generation
- Vulkan rendering with HDR pipeline
- Vehicle physics and combat
- Scene save/load persistence
- Input recording and replay
- Asset pipeline (models, textures, audio)
- Native visual editor
- Play-in-editor support

BUILD INFO:
- Compiler: MSVC 19.44.35228.0
- C++ Standard: C++20
- Graphics API: Vulkan 1.4.357
- Platform: Windows x64
- Build Type: Release

SUPPORT:
For issues, please check the KartGib repository.

========================================
EOF

echo ""
echo "========================================"
echo "Build Complete!"
echo "========================================"
echo "Package location: $PACKAGE_DIR"
echo "Executable: $PACKAGE_DIR/KartGib.exe"
echo "Launch script: $PACKAGE_DIR/run_kartgib.bat"
echo ""
echo "To test: cd $PACKAGE_DIR && KartGib.exe --seed 20261025 --biome tropical"
echo ""
echo "Package size:"
du -sh "$PACKAGE_DIR" 2>/dev/null || true
echo ""
echo "Next steps:"
echo "1. Test the executable on a clean machine"
echo "2. Verify WorldForge terrain renders"
echo "3. Test save/load (F5/F9)"
echo "4. Test input replay (F6/F7)"
echo "5. Package for distribution"