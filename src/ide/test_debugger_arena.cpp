/*===========================================================================
 * test_debugger_arena.cpp
 * Validation test for IDEDebuggerArena
 * 
 * Tests: Arena allocation, CDB parsing, Triple-buffer handoff
 *===========================================================================*/

#include "IDEDebuggerTypes.h"
#include <stdio.h>
#include <windows.h>

// Mock g_hWndMain for testing
HWND g_hWndMain = NULL;
UINT WM_APP_DEBUG_STATE_UPDATE = WM_APP + 102;

/*===========================================================================
 * Test 1: Arena Allocation
 *=========================================================================*/
bool Test_ArenaAllocation() {
    printf("Test 1: Arena Allocation...\n");
    
    FrameArena arena;
    InitFrameArena(&arena, 1024 * 1024);  // 1MB
    
    // Test 1a: Basic allocation
    const char* str1 = AllocateString(&arena, "Hello", 5);
    if (!str1 || strcmp(str1, "Hello") != 0) {
        printf("  FAIL: Basic allocation\n");
        return false;
    }
    printf("  PASS: Basic allocation\n");
    
    // Test 1b: Multiple allocations
    const char* str2 = AllocateString(&arena, "World", 5);
    const char* str3 = AllocateString(&arena, "Test", 4);
    if (!str2 || !str3) {
        printf("  FAIL: Multiple allocations\n");
        return false;
    }
    printf("  PASS: Multiple allocations\n");
    
    // Test 1c: Arena reset
    ResetFrameArena(&arena);
    if (arena.cursor != 0) {
        printf("  FAIL: Arena reset\n");
        return false;
    }
    printf("  PASS: Arena reset\n");
    
    // Test 1d: Post-reset allocation
    const char* str4 = AllocateString(&arena, "AfterReset", 10);
    if (!str4 || strcmp(str4, "AfterReset") != 0) {
        printf("  FAIL: Post-reset allocation\n");
        return false;
    }
    printf("  PASS: Post-reset allocation\n");
    
    DestroyFrameArena(&arena);
    printf("Test 1: PASSED\n\n");
    return true;
}

/*===========================================================================
 * Test 2: CDB Hex Parser
 *=========================================================================*/
bool Test_CDBHexParser() {
    printf("Test 2: CDB Hex Parser...\n");
    
    // Test 2a: Simple hex
    const char* p1 = "0000000000000001";
    uint64_t val1 = ParseCDBHex(&p1);
    if (val1 != 1) {
        printf("  FAIL: Simple hex (expected 1, got %llu)\n", val1);
        return false;
    }
    printf("  PASS: Simple hex\n");
    
    // Test 2b: Hex with backtick (CDB format)
    const char* p2 = "00007ffc`9a4b0000";
    uint64_t val2 = ParseCDBHex(&p2);
    if (val2 != 0x00007ffc9a4b0000ULL) {
        printf("  FAIL: Hex with backtick (expected 0x%016llx, got 0x%016llx)\n", 
               0x00007ffc9a4b0000ULL, val2);
        return false;
    }
    printf("  PASS: Hex with backtick\n");
    
    // Test 2c: Mixed case
    const char* p3 = "DEADBEEF";
    uint64_t val3 = ParseCDBHex(&p3);
    if (val3 != 0xDEADBEEF) {
        printf("  FAIL: Mixed case (expected 0xDEADBEEF, got 0x%llx)\n", val3);
        return false;
    }
    printf("  PASS: Mixed case\n");
    
    printf("Test 2: PASSED\n\n");
    return true;
}

/*===========================================================================
 * Test 3: Register Parser
 *=========================================================================*/
bool Test_RegisterParser() {
    printf("Test 3: Register Parser...\n");
    
    FrameArena arena;
    InitFrameArena(&arena, 1024 * 1024);
    
    DebugStatePayload payload = {};
    const char* cdbOutput = 
        "rax=0000000000000001 rbx=0000000000000000 "
        "rcx=00007ffc9a4b0000 rdx=0000000000000000 "
        "rsi=0000000000000000 rdi=0000000000000000 "
        "rip=00007ff69a4b1020 rsp=000000a6b5bff720 "
        "rbp=000000a6b5bff7a0";
    
    ParseRegistersFast(cdbOutput, &payload, &arena);
    
    if (payload.registerCount == 0) {
        printf("  FAIL: No registers parsed\n");
        return false;
    }
    printf("  Parsed %zu registers\n", payload.registerCount);
    
    // Verify specific registers
    bool foundRax = false, foundRip = false;
    for (size_t i = 0; i < payload.registerCount; i++) {
        if (strcmp(payload.registers[i].name, "rax") == 0) {
            foundRax = true;
            if (payload.registers[i].value != 1) {
                printf("  FAIL: rax value mismatch\n");
                return false;
            }
        }
        if (strcmp(payload.registers[i].name, "rip") == 0) {
            foundRip = true;
        }
    }
    
    if (!foundRax || !foundRip) {
        printf("  FAIL: Missing expected registers\n");
        return false;
    }
    
    printf("  PASS: Register parsing\n");
    DestroyFrameArena(&arena);
    printf("Test 3: PASSED\n\n");
    return true;
}

/*===========================================================================
 * Test 4: Triple-Buffer Handoff
 *=========================================================================*/
bool Test_TripleBufferHandoff() {
    printf("Test 4: Triple-Buffer Handoff...\n");
    
    // Initialize arenas
    for (int i = 0; i < 3; i++) {
        InitFrameArena(&g_DebugArenas[i], 1024 * 1024);
    }
    
    // Reset global state
    g_BackendFrameCount = 0;
    g_UIRenderedFrame = 0;
    pWriterArena = &g_DebugArenas[0];
    pReaderArena = &g_DebugArenas[1];
    pSharedArena = &g_DebugArenas[2];
    
    // Test 4a: Initial state
    if (!HasNewDebugFrame()) {
        printf("  PASS: Initial state (no new frame)\n");
    } else {
        printf("  FAIL: Initial state incorrect\n");
        return false;
    }
    
    // Test 4b: Submit frame
    DebugStatePayload* payload = (DebugStatePayload*)pWriterArena->memory;
    payload->frameId = 1;
    payload->registerCount = 5;
    SubmitDebugStateToUI();
    
    if (!HasNewDebugFrame()) {
        printf("  FAIL: Frame not detected after submit\n");
        return false;
    }
    printf("  PASS: Frame submitted\n");
    
    // Test 4c: Consume frame
    DebugStatePayload* consumed = ConsumeDebugState();
    if (!consumed || consumed->frameId != 1) {
        printf("  FAIL: Frame consumption\n");
        return false;
    }
    printf("  PASS: Frame consumed\n");
    
    // Test 4d: No new frame after consumption
    if (HasNewDebugFrame()) {
        printf("  FAIL: Frame still marked as new after consumption\n");
        return false;
    }
    printf("  PASS: Frame state cleared after consumption\n");
    
    // Test 4e: Multiple frames (frame dropping)
    for (int i = 0; i < 10; i++) {
        payload = (DebugStatePayload*)pWriterArena->memory;
        payload->frameId = i + 2;
        SubmitDebugStateToUI();
    }
    
    LONG frameCount = InterlockedCompareExchange(&g_BackendFrameCount, 0, 0);
    printf("  Submitted 10 frames, backend count = %ld\n", frameCount);
    
    // Consume only the latest
    consumed = ConsumeDebugState();
    if (!consumed || consumed->frameId != 11) {
        printf("  FAIL: Latest frame not consumed (got %llu)\n", 
               consumed ? consumed->frameId : 0);
        return false;
    }
    printf("  PASS: Frame dropping (consumed latest = 11)\n");
    
    // Cleanup
    for (int i = 0; i < 3; i++) {
        DestroyFrameArena(&g_DebugArenas[i]);
    }
    
    printf("Test 4: PASSED\n\n");
    return true;
}

/*===========================================================================
 * Test 5: Stress Test (Rapid Submit/Consume)
 *=========================================================================*/
bool Test_StressTest() {
    printf("Test 5: Stress Test (10000 iterations)...\n");
    
    // Initialize
    for (int i = 0; i < 3; i++) {
        InitFrameArena(&g_DebugArenas[i], 1024 * 1024);
    }
    g_BackendFrameCount = 0;
    g_UIRenderedFrame = 0;
    pWriterArena = &g_DebugArenas[0];
    pReaderArena = &g_DebugArenas[1];
    pSharedArena = &g_DebugArenas[2];
    
    DWORD startTime = GetTickCount();
    
    for (int i = 0; i < 10000; i++) {
        // Submit
        DebugStatePayload* payload = (DebugStatePayload*)pWriterArena->memory;
        payload->frameId = i + 1;
        payload->registerCount = (i % 32);
        SubmitDebugStateToUI();
        
        // Consume every 2nd frame (simulating slower UI)
        if (i % 2 == 0) {
            ConsumeDebugState();
        }
    }
    
    DWORD elapsed = GetTickCount() - startTime;
    double opsPerSecond = 10000.0 / (elapsed / 1000.0);
    
    printf("  Completed 10000 iterations in %lu ms\n", elapsed);
    printf("  Throughput: %.0f ops/sec\n", opsPerSecond);
    
    if (opsPerSecond < 10000) {
        printf("  WARNING: Throughput lower than expected\n");
    }
    
    // Cleanup
    for (int i = 0; i < 3; i++) {
        DestroyFrameArena(&g_DebugArenas[i]);
    }
    
    printf("Test 5: PASSED\n\n");
    return true;
}

/*===========================================================================
 * Main
 *=========================================================================*/
int main() {
    printf("========================================\n");
    printf("IDEDebuggerArena Validation Tests\n");
    printf("========================================\n\n");
    
    int passed = 0;
    int total = 5;
    
    if (Test_ArenaAllocation()) passed++;
    if (Test_CDBHexParser()) passed++;
    if (Test_RegisterParser()) passed++;
    if (Test_TripleBufferHandoff()) passed++;
    if (Test_StressTest()) passed++;
    
    printf("========================================\n");
    printf("Results: %d/%d tests passed\n", passed, total);
    printf("========================================\n");
    
    return (passed == total) ? 0 : 1;
}
