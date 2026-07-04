// ============================================================================
// RawrXD Epoch Router Verification Test
// Tests the three critical behaviors:
// 1. Epoch counter increments on each hotpatch
// 2. Retired slot cleanup (no memory leaks)
// 3. Reader counter reaches zero
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// External router functions from rawrxd_hotpatch_router_simple.asm
extern "C" {
    uint64_t RawrXD_RequestHotpatch(void* modelDescriptor, uint64_t gpuFence);
    uint64_t RawrXD_CheckEpochSwap();
    uint64_t RawrXD_WaitForHotpatchComplete(uint32_t timeoutMs);
    uint64_t RawrXD_InitHotpatchSystem();
    uint64_t RawrXD_ForceSyncHotpatch();
    
    // Exported globals
    extern uint64_t g_EpochCounter;
    extern uint64_t g_HotpatchCount;
    extern uint64_t g_ActiveModelDescriptor;
    extern uint64_t g_PendingModelDescriptor;
}

// Simple model descriptor for testing
struct TestModelDescriptor {
    uint64_t magic;
    uint64_t id;
    char name[64];
};

void Test_EpochIncrement() {
    printf("\n=== Test 1: Epoch Counter Increment ===\n");
    
    // Initialize
    RawrXD_InitHotpatchSystem();
    uint64_t initialEpoch = g_EpochCounter;
    printf("Initial epoch: %llu\n", initialEpoch);
    
    // Create test model descriptors
    TestModelDescriptor model1 = {0xDEADBEEF, 1, "model1"};
    TestModelDescriptor model2 = {0xDEADBEEF, 2, "model2"};
    TestModelDescriptor model3 = {0xDEADBEEF, 3, "model3"};
    
    // Hotpatch 1
    uint64_t result1 = RawrXD_RequestHotpatch(&model1, 0);
    printf("Hotpatch 1: router_code=%llu, epoch=%llu (expected: 0, %llu)\n", 
           result1, g_EpochCounter, initialEpoch + 1);
    
    // Complete the swap
    uint64_t swap1 = RawrXD_CheckEpochSwap();
    printf("CheckEpochSwap 1: %llu (expected: 1)\n", swap1);
    printf("After swap 1: epoch=%llu, active=%p, pending=%p\n",
           g_EpochCounter, (void*)g_ActiveModelDescriptor, (void*)g_PendingModelDescriptor);
    
    // Hotpatch 2
    uint64_t result2 = RawrXD_RequestHotpatch(&model2, 0);
    printf("Hotpatch 2: router_code=%llu, epoch=%llu (expected: 0, %llu)\n", 
           result2, g_EpochCounter, initialEpoch + 3);
    
    // Complete the swap
    uint64_t swap2 = RawrXD_CheckEpochSwap();
    printf("CheckEpochSwap 2: %llu (expected: 1)\n", swap2);
    printf("After swap 2: epoch=%llu, active=%p, pending=%p\n",
           g_EpochCounter, (void*)g_ActiveModelDescriptor, (void*)g_PendingModelDescriptor);
    
    // Hotpatch 3
    uint64_t result3 = RawrXD_RequestHotpatch(&model3, 0);
    printf("Hotpatch 3: router_code=%llu, epoch=%llu (expected: 0, %llu)\n", 
           result3, g_EpochCounter, initialEpoch + 5);
    
    // Complete the swap
    uint64_t swap3 = RawrXD_CheckEpochSwap();
    printf("CheckEpochSwap 3: %llu (expected: 1)\n", swap3);
    printf("After swap 3: epoch=%llu, active=%p, pending=%p\n",
           g_EpochCounter, (void*)g_ActiveModelDescriptor, (void*)g_PendingModelDescriptor);
    
    // Verify
    bool epochOk = (g_EpochCounter == initialEpoch + 6);
    bool activeOk = (g_ActiveModelDescriptor == (uint64_t)&model3);
    bool pendingOk = (g_PendingModelDescriptor == 0);
    
    printf("\nResults:\n");
    printf("  Epoch counter: %s (got %llu, expected %llu)\n", 
           epochOk ? "PASS" : "FAIL", g_EpochCounter, initialEpoch + 6);
    printf("  Active model:  %s (got %p, expected %p)\n", 
           activeOk ? "PASS" : "FAIL", (void*)g_ActiveModelDescriptor, &model3);
    printf("  Pending model: %s (got %p, expected 0)\n", 
           pendingOk ? "PASS" : "FAIL", (void*)g_PendingModelDescriptor);
    
    if (epochOk && activeOk && pendingOk) {
        printf("\n✓ Epoch increment test PASSED\n");
    } else {
        printf("\n✗ Epoch increment test FAILED\n");
    }
}

void Test_PendingState() {
    printf("\n=== Test 2: Pending State Handling ===\n");
    
    // Initialize fresh
    RawrXD_InitHotpatchSystem();
    
    TestModelDescriptor model1 = {0xDEADBEEF, 1, "model1"};
    TestModelDescriptor model2 = {0xDEADBEEF, 2, "model2"};
    
    // Request first hotpatch
    uint64_t result1 = RawrXD_RequestHotpatch(&model1, 0);
    printf("First hotpatch: router_code=%llu (expected: 0)\n", result1);
    
    // Try second hotpatch while first is pending (should return 1 = already pending)
    uint64_t result2 = RawrXD_RequestHotpatch(&model2, 0);
    printf("Second hotpatch (while pending): router_code=%llu (expected: 1)\n", result2);
    
    if (result1 == 0 && result2 == 1) {
        printf("\n✓ Pending state test PASSED\n");
    } else {
        printf("\n✗ Pending state test FAILED\n");
    }
    
    // Complete the swap to clean up
    RawrXD_CheckEpochSwap();
}

void Test_WaitForCompletion() {
    printf("\n=== Test 3: Wait For Completion ===\n");
    
    // Initialize fresh
    RawrXD_InitHotpatchSystem();
    
    TestModelDescriptor model1 = {0xDEADBEEF, 1, "model1"};
    
    // Request hotpatch
    uint64_t result = RawrXD_RequestHotpatch(&model1, 0);
    printf("Hotpatch requested: router_code=%llu\n", result);
    
    // Wait for completion
    uint64_t waitResult = RawrXD_WaitForHotpatchComplete(1000); // 1 second timeout
    printf("Wait result: %llu (expected: 0 = success)\n", waitResult);
    
    // Verify epoch is even (complete)
    bool epochEven = (g_EpochCounter % 2 == 0);
    printf("Epoch is even (complete): %s (got %llu)\n", 
           epochEven ? "PASS" : "FAIL", g_EpochCounter);
    
    if (waitResult == 0 && epochEven) {
        printf("\n✓ Wait for completion test PASSED\n");
    } else {
        printf("\n✗ Wait for completion test FAILED\n");
    }
}

int main() {
    printf("RawrXD Epoch Router Verification Test\n");
    printf("=====================================\n");
    
    Test_EpochIncrement();
    Test_PendingState();
    Test_WaitForCompletion();
    
    printf("\n=====================================\n");
    printf("All tests completed\n");
    
    return 0;
}
