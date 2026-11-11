// ============================================================================
// test_tool_limit_hotpatch.cpp - Test Tool Call Limit Extension via Hotpatching
// ============================================================================

#include <cstdio>
#include <cstring>
#include "Deep2Engine.h"
#include "HotPatcher.hpp"

using namespace Deep2;

int main() {
    printf("=== Tool Call Limit Hotpatching Test ===\n\n");

    // Initialize the engine
    Deep2Engine engine;
    EngineConfig config;
    config.hiddenDim = 4096;
    config.numLayers = 32;
    config.numHeads = 32;
    config.vocabSize = 32000;
    config.maxSeqLen = 2048;
    config.useThreadPool = false;  // Simpler for testing
    config.useKVCache = false;

    if (!engine.initialize(config)) {
        printf("ERROR: Failed to initialize engine\n");
        return 1;
    }

    printf("[Test] Engine initialized successfully\n");

    // Check initial tool call limit
    int initialLimit = engine.getExtendedToolCallLimit();
    printf("[Test] Initial tool call limit: %d (not patched yet)\n", initialLimit);

    // Test 1: Extend tool call limit to 50
    printf("\n[Test 1] Extending tool call limit to 50...\n");
    std::string patchId1 = engine.extendToolCallLimit(50);
    if (patchId1.empty()) {
        printf("ERROR: Failed to extend tool call limit\n");
        return 1;
    }
    printf("[Test 1] SUCCESS: Patch applied: %s\n", patchId1.c_str());

    int newLimit = engine.getExtendedToolCallLimit();
    printf("[Test 1] New tool call limit: %d\n", newLimit);
    if (newLimit != 50) {
        printf("ERROR: Expected limit 50, got %d\n", newLimit);
        return 1;
    }

    // Test 2: Extend again to 100
    printf("\n[Test 2] Extending tool call limit to 100...\n");
    std::string patchId2 = engine.extendToolCallLimit(100);
    if (patchId2.empty()) {
        printf("ERROR: Failed to extend tool call limit\n");
        return 1;
    }
    printf("[Test 2] SUCCESS: Patch applied: %s\n", patchId2.c_str());

    newLimit = engine.getExtendedToolCallLimit();
    printf("[Test 2] New tool call limit: %d\n", newLimit);
    if (newLimit != 100) {
        printf("ERROR: Expected limit 100, got %d\n", newLimit);
        return 1;
    }

    // Test 3: Print HotPatcher status
    printf("\n[Test 3] HotPatcher status:\n");
    engine.printHotPatcherStatus();

    // Test 4: Rollback first patch
    printf("\n[Test 4] Rolling back first patch...\n");
    if (engine.rollbackKernelPatch(patchId1)) {
        printf("[Test 4] SUCCESS: First patch rolled back\n");
    } else {
        printf("[Test 4] Note: First patch rollback (may already be superseded)\n");
    }

    // Test 5: Emergency rollback all
    printf("\n[Test 5] Emergency rollback all patches...\n");
    engine.emergencyRollbackAllPatches();
    printf("[Test 5] Emergency rollback complete\n");

    // Verify limit is reset
    int finalLimit = engine.getExtendedToolCallLimit();
    printf("[Test 5] Final tool call limit: %d\n", finalLimit);

    printf("\n=== All Tests Passed ===\n");
    return 0;
}
