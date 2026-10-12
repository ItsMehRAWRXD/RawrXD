#!/bin/bash
# =============================================================================
# build_and_link_gcc.sh
# Complete build and link using GCC
# =============================================================================

set -e

PROJECT_ROOT="/d/RawrXD"
BUILD_DIR="$PROJECT_ROOT/build"
BIN_DIR="$BUILD_DIR/bin"
SRC_DIR="$PROJECT_ROOT/src"
ASM_DIR="$PROJECT_ROOT/asm"

echo "============================================================================="
echo "Sovereign Engine - Complete GCC Build"
echo "============================================================================="

# Create directories
mkdir -p "$BUILD_DIR/obj"
mkdir -p "$BIN_DIR"

# =============================================================================
# Compile C++ files
# =============================================================================

echo ""
echo "[C++] Compiling source files..."

# Core files
CORE_FILES=(
    "$SRC_DIR/core/sovereign_thread_pool.cpp"
    "$SRC_DIR/core/sovereign_memory_pool.cpp"
    "$SRC_DIR/core/sovereign_kv_cache_manager.cpp"
    "$SRC_DIR/core/sovereign_engine_controller_integration.cpp"
    "$SRC_DIR/core/sovereign_ring_attention_integration.cpp"
    "$SRC_DIR/core/sovereign_engine_controller_ring_extension.cpp"
)

for file in "${CORE_FILES[@]}"; do
    if [ -f "$file" ]; then
        obj_name=$(basename "$file" .cpp)
        echo "  Compiling $obj_name.cpp..."
        g++ -std=c++17 -O2 -Wall -c -o "$BUILD_DIR/obj/${obj_name}.obj" "$file" \
            -I"$SRC_DIR" -I"$SRC_DIR/core" -I"$SRC_DIR/swarm" -I"$ASM_DIR"
    fi
done

# =============================================================================
# Compile tests
# =============================================================================

echo ""
echo "[Tests] Compiling test files..."

TEST_FILES=(
    "$SRC_DIR/tests/test_engine_controller_integration.cpp"
    "$SRC_DIR/tests/test_ring_integration.cpp"
)

for file in "${TEST_FILES[@]}"; do
    if [ -f "$file" ]; then
        test_name=$(basename "$file" .cpp)
        echo "  Compiling $test_name.cpp..."
        g++ -std=c++17 -O2 -Wall -c -o "$BUILD_DIR/obj/${test_name}.obj" "$file" \
            -I"$SRC_DIR" -I"$SRC_DIR/core" -I"$SRC_DIR/swarm" -I"$ASM_DIR"
    fi
done

# =============================================================================
# Link executables
# =============================================================================

echo ""
echo "[Link] Creating executables..."

# Collect all object files
OBJ_FILES=$(find "$BUILD_DIR/obj" -name "*.obj" -o -name "*.o" | tr '\n' ' ')

echo "  Object files: $OBJ_FILES"

# Link test executables
echo "  Linking test_ring_integration.exe..."
g++ -o "$BIN_DIR/test_ring_integration.exe" \
    "$BUILD_DIR/obj/test_ring_integration.obj" \
    "$BUILD_DIR/obj/sovereign_thread_pool.obj" \
    "$BUILD_DIR/obj/sovereign_memory_pool.obj" \
    "$BUILD_DIR/obj/sovereign_kv_cache_manager.obj" \
    "$BUILD_DIR/obj/sovereign_engine_controller_integration.obj" \
    "$BUILD_DIR/obj/sovereign_ring_attention_integration.obj" \
    "$BUILD_DIR/obj/sovereign_engine_controller_ring_extension.obj" \
    -lkernel32 -lws2_32

echo "  Linking test_engine_controller_integration.exe..."
g++ -o "$BIN_DIR/test_engine_controller_integration.exe" \
    "$BUILD_DIR/obj/test_engine_controller_integration.obj" \
    "$BUILD_DIR/obj/sovereign_thread_pool.obj" \
    "$BUILD_DIR/obj/sovereign_memory_pool.obj" \
    "$BUILD_DIR/obj/sovereign_kv_cache_manager.obj" \
    "$BUILD_DIR/obj/sovereign_engine_controller_integration.obj" \
    -lkernel32 -lws2_32

# =============================================================================
# Summary
# =============================================================================

echo ""
echo "============================================================================="
echo "BUILD COMPLETE"
echo "============================================================================="
echo ""
echo "Executables:"
ls -la "$BIN_DIR/"*.exe 2>/dev/null || echo "  (none yet)"
echo ""
echo "Run tests with:"
echo "  $BIN_DIR/test_ring_integration.exe"
echo "  $BIN_DIR/test_engine_controller_integration.exe"
echo ""
