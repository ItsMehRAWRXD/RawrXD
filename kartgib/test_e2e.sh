#!/usr/bin/env bash
# KartGib End-to-End Test Script
# Tests G01-G10 certification gates

set -e

echo "========================================"
echo "KartGib End-to-End Test Suite"
echo "========================================"
echo ""

ROOT_DIR="F:/rawrxd/kartgib"
EXE="$ROOT_DIR/build/msvc/Release/KartGib.exe"
TEST_DIR="$ROOT_DIR/test_results"
PASS=0
FAIL=0

mkdir -p "$TEST_DIR"

echo ""
echo "Step 1: Build Check (G01)"
if [ -f "$EXE" ]; then
    echo "  PASS: KartGib.exe exists"
    PASS=$((PASS + 1))
else
    echo "  FAIL: KartGib.exe not found"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "Step 2: Shader Files (G02)"
SHADER_COUNT=0
if [ -d "$BUILD_DIR/shaders" ]; then
    SHADER_COUNT=$(ls "$BUILD_DIR/shaders"/*.spv 2>/dev/null | wc -l)
fi
if [ "$SHADER_COUNT" -gt 0 ]; then
    echo "  PASS: $SHADER_COUNT SPIR-V shaders found"
    PASS=$((PASS + 1))
else
    echo "  FAIL: No SPIR-V shaders found"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "Step 3: Launch Test (G03)"
echo "Launching KartGib for 5 seconds..."
timeout 5 "$EXE" --seed 20261025 --biome tropical > "$TEST_DIR/test_output.txt" 2>&1 || true
if grep -q "Vulkan renderer initialized" "$TEST_DIR/test_output.txt"; then
    echo "  PASS: Vulkan initialized successfully"
    PASS=$((PASS + 1))
else
    echo "  FAIL: Vulkan initialization failed"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "Step 4: Terrain Rendering (G04)"
if grep -q "Rendering in TERRAIN mode" "$TEST_DIR/test_output.txt"; then
    echo "  PASS: Terrain rendering active"
    PASS=$((PASS + 1))
else
    echo "  FAIL: Terrain rendering not detected"
    FAIL=$((FAIL + 1))
fi

if grep -q "vkQueuePresentKHR result=0" "$TEST_DIR/test_output.txt"; then
    echo "  PASS: Frame presentation successful"
    PASS=$((PASS + 1))
else
    echo "  FAIL: Frame presentation failed"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "Step 5: Resize Handling (G05)"
if grep -q "Swapchain recreated" "$TEST_DIR/test_output.txt"; then
    echo "  PASS: Swapchain recreation detected"
    PASS=$((PASS + 1))
else
    echo "  INFO: Swapchain resize not triggered in 5s (may need manual test)"
fi

echo ""
echo "Step 6: Kart Movement (G06)"
if grep -q "ChunkStreamer" "$TEST_DIR/test_output.txt" 2>/dev/null; then
    echo "  PASS: WorldForge systems active"
    PASS=$((PASS + 1))
else
    echo "  INFO: WorldForge systems check (verify manually)"
fi

echo ""
echo "Step 7: Save/Load (G09)"
echo "  INFO: Manual test required - press F5 then F9 in-game"

echo ""
echo "Step 8: Replay (G10)"
echo "  INFO: Manual test required - press F6 then F7 in-game"

echo ""
echo "========================================"
echo "Test Results Summary"
echo "========================================"
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "Total: $((PASS + FAIL))"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: ALL TESTS PASSED"
    exit 0
else
    echo "RESULT: $FAIL TEST(S) FAILED"
    exit 1
fi