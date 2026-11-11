#!/bin/bash
# =============================================================================
# build_sovereign_engine_gcc.sh
# Phase 22: Build script for Sovereign Engine Controller using GCC
# Links Phase 11 (ASM Loader) with Phase 22/23 (C++ Engine + Swarm)
# =============================================================================

set -e

# Configuration
PROJECT_ROOT="/d/RawrXD"
BUILD_DIR="$PROJECT_ROOT/build"
SRC_DIR="$PROJECT_ROOT/src"
ASM_DIR="$PROJECT_ROOT/asm"

# Toolchain
GCC="/c/ProgramData/mingw64/mingw64/bin/gcc.exe"
GXX="/c/ProgramData/mingw64/mingw64/bin/g++.exe"
ML64="/c/VS2022Enterprise/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64/ml64.exe"

# Create build directories
mkdir -p "$BUILD_DIR/obj"
mkdir -p "$BUILD_DIR/bin"

echo "========================================================================"
echo "Phase 11: Assembling x64 ASM Loader"
echo "========================================================================"

# Assemble Phase 11 loader
"$ML64" /c /W3 /nologo /Fo "$BUILD_DIR/obj/RawrXD_120B_Loader.obj" "$ASM_DIR/RawrXD_120B_Loader.asm" || {
    echo "ERROR: Phase 11 assembly failed"
    exit 1
}

echo "Phase 11 assembly complete."
echo ""

echo "========================================================================"
echo "Phase 22: Compiling C++ Engine Core"
echo "========================================================================"

# Compile C++ sources
SOURCES=(
    "$SRC_DIR/core/sovereign_thread_pool.cpp"
    "$SRC_DIR/core/sovereign_engine_controller_integration.cpp"
)

for source in "${SOURCES[@]}"; do
    if [ -f "$source" ]; then
        obj_name=$(basename "$source" .cpp).obj
        echo "Compiling $obj_name..."
        "$GXX" -c -O2 -std=c++17 -I"$SRC_DIR" -I"$SRC_DIR/core" -DNDEBUG -o "$BUILD_DIR/obj/$obj_name" "$source" || {
            echo "ERROR: Compilation failed for $source"
            exit 1
        }
    else
        echo "Warning: $source not found, skipping..."
    fi
done

echo ""
echo "========================================================================"
echo "Phase 22: Linking Engine"
echo "========================================================================"

# Link everything
"$GXX" -o "$BUILD_DIR/bin/sovereign_engine.exe" \
    "$BUILD_DIR/obj/"*.obj \
    -lkernel32 -lws2_32 \
    -static-libgcc -static-libstdc++ || {
    echo "ERROR: Linking failed"
    exit 1
}

echo ""
echo "========================================================================"
echo "Build Complete"
echo "========================================================================"
echo "Output: $BUILD_DIR/bin/sovereign_engine.exe"
echo ""
