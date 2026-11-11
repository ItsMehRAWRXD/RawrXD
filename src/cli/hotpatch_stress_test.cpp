// ============================================================================
// Hotpatch Router Stress Test
// Concurrent multi-threaded validation of ASM synchronization primitives
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// ASM exports
extern "C" {
    uint64_t RawrXD_RequestHotpatch(void* modelDescriptor, void* gpuFence);
    uint64_t RawrXD_CheckEpochSwap(void);
    uint64_t RawrXD_WaitForHotpatchComplete(uint32_t timeoutMs);
    uint64_t RawrXD_InitHotpatchSystem(void);
    
    extern volatile uint64_t g_EpochCounter;
    extern volatile uint64_t g_HotpatchCount;
    extern volatile uint64_t g_DeferredHotpatchCount;
}

// Test configuration
#define STRESS_ITERATIONS       1000
#define NUM_REQUESTER_THREADS   4
#define NUM_CHECKER_THREADS     2
#define TEST_DURATION_MS        30000  // 30 seconds max

// Statistics
volatile LONG g_SuccessCount = 0;
volatile LONG g_PendingCount = 0;
volatile LONG g_ActiveCount = 0;
volatile LONG g_ErrorCount = 0;
volatile LONG g_SwapCount = 0;
volatile BOOL g_Shutdown = FALSE;

// Dummy model descriptor
struct ModelDescriptor {
    uint64_t id;
    uint64_t data[7];  // Pad to 64 bytes
};

// Requester thread: Continuously requests hotpatches
DWORD WINAPI RequesterThread(LPVOID param) {
    int threadId = (int)(size_t)param;
    ModelDescriptor desc = {};
    desc.id = threadId;
    
    for (int i = 0; i < STRESS_ITERATIONS / NUM_REQUESTER_THREADS; i++) {
        desc.id = (threadId * 1000000ULL) + i;
        
        uint64_t result = RawrXD_RequestHotpatch(&desc, nullptr);
        
        switch (result) {
            case 0:  // Success
                InterlockedIncrement(&g_SuccessCount);
                break;
            case 1:  // Already pending
                InterlockedIncrement(&g_PendingCount);
                break;
            case 2:  // Inference active
                InterlockedIncrement(&g_ActiveCount);
                break;
            default: // Error
                InterlockedIncrement(&g_ErrorCount);
                break;
        }
        
        // Small random delay to create timing variations
        if (i % 10 == 0) {
            Sleep(1);
        }
    }
    
    return 0;
}

// Checker thread: Continuously checks for epoch swaps
DWORD WINAPI CheckerThread(LPVOID param) {
    int threadId = (int)(size_t)param;
    (void)threadId;
    
    while (!g_Shutdown) {
        uint64_t result = RawrXD_CheckEpochSwap();
        if (result == 1) {
            InterlockedIncrement(&g_SwapCount);
        }
        
        // Yield to prevent tight spinning
        Sleep(0);
    }
    
    return 0;
}

// Monitor thread: Prints stats periodically
DWORD WINAPI MonitorThread(LPVOID param) {
    (void)param;
    
    for (int i = 0; i < 10; i++) {
        Sleep(3000);  // Every 3 seconds
        
        printf("[MONITOR] Success: %ld, Pending: %ld, Active: %ld, Swaps: %ld, Errors: %ld, Epoch: %llu\n",
               g_SuccessCount, g_PendingCount, g_ActiveCount, g_SwapCount, g_ErrorCount, g_EpochCounter);
    }
    
    return 0;
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("================================================================================\n");
    printf("RawrXD Hotpatch Router Stress Test\n");
    printf("================================================================================\n");
    printf("Threads: %d requesters, %d checkers\n", NUM_REQUESTER_THREADS, NUM_CHECKER_THREADS);
    printf("Target: %d iterations per requester thread\n", STRESS_ITERATIONS / NUM_REQUESTER_THREADS);
    printf("================================================================================\n\n");
    
    // Initialize hotpatch system
    uint64_t initResult = RawrXD_InitHotpatchSystem();
    if (initResult != 0) {
        printf("[ERROR] Failed to initialize hotpatch system: %llu\n", initResult);
        return 1;
    }
    printf("[INFO] Hotpatch system initialized\n");
    
    // Create threads
    HANDLE hRequesters[NUM_REQUESTER_THREADS];
    HANDLE hCheckers[NUM_CHECKER_THREADS];
    HANDLE hMonitor;
    
    printf("[INFO] Spawning threads...\n");
    
    // Spawn checker threads first
    for (int i = 0; i < NUM_CHECKER_THREADS; i++) {
        hCheckers[i] = CreateThread(nullptr, 0, CheckerThread, (LPVOID)(size_t)i, 0, nullptr);
        if (!hCheckers[i]) {
            printf("[ERROR] Failed to create checker thread %d\n", i);
            return 1;
        }
    }
    
    // Spawn requester threads
    for (int i = 0; i < NUM_REQUESTER_THREADS; i++) {
        hRequesters[i] = CreateThread(nullptr, 0, RequesterThread, (LPVOID)(size_t)i, 0, nullptr);
        if (!hRequesters[i]) {
            printf("[ERROR] Failed to create requester thread %d\n", i);
            return 1;
        }
    }
    
    // Spawn monitor thread
    hMonitor = CreateThread(nullptr, 0, MonitorThread, nullptr, 0, nullptr);
    
    printf("[INFO] All threads spawned, running stress test...\n\n");
    
    // Wait for all requester threads to complete
    WaitForMultipleObjects(NUM_REQUESTER_THREADS, hRequesters, TRUE, TEST_DURATION_MS);
    
    // Signal shutdown for checker threads
    g_Shutdown = TRUE;
    
    // Wait for checker threads
    WaitForMultipleObjects(NUM_CHECKER_THREADS, hCheckers, TRUE, 5000);
    
    // Wait for monitor
    WaitForSingleObject(hMonitor, 5000);
    
    // Cleanup handles
    for (int i = 0; i < NUM_REQUESTER_THREADS; i++) {
        CloseHandle(hRequesters[i]);
    }
    for (int i = 0; i < NUM_CHECKER_THREADS; i++) {
        CloseHandle(hCheckers[i]);
    }
    CloseHandle(hMonitor);
    
    // Final stats
    printf("\n================================================================================\n");
    printf("Stress Test Complete\n");
    printf("================================================================================\n");
    printf("Results:\n");
    printf("  Successful requests:  %ld\n", g_SuccessCount);
    printf("  Pending (contended):  %ld\n", g_PendingCount);
    printf("  Active (deferred):    %ld\n", g_ActiveCount);
    printf("  Epoch swaps:          %ld\n", g_SwapCount);
    printf("  Errors:               %ld\n", g_ErrorCount);
    printf("  Final epoch:          %llu\n", g_EpochCounter);
    printf("  Final hotpatch count: %llu\n", g_HotpatchCount);
    printf("================================================================================\n");
    
    if (g_ErrorCount == 0 && g_SuccessCount > 0) {
        printf("[PASS] Stress test completed with 0 errors\n");
        return 0;
    } else if (g_ErrorCount > 0) {
        printf("[FAIL] Stress test encountered %ld errors\n", g_ErrorCount);
        return 1;
    } else {
        printf("[WARN] No successful requests - check logic\n");
        return 1;
    }
}
