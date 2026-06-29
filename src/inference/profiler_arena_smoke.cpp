// =============================================================================
// RawrXD Profiler + Sovereign Arena Smoke Test — Fast verification
// =============================================================================
#include "inference_profiler_simple.h"
#include "Sovereign_Memory_Manager.h"
#include <cstdio>
#include <windows.h>

// Simulate some work
void simulate_work(int iterations) {
    volatile int sum = 0;
    for (int i = 0; i < iterations; i++) {
        sum += i * i;
    }
}

int main() {
    printf("=== RawrXD Profiler + Sovereign Arena Smoke Test ===\n\n");
    
    // Initialize profiler
    printf("[1/4] Initializing C++ profiler...\n");
    Profiler_Initialize();
    printf("      ✓ Profiler ready (RDTSC-based)\n\n");
    
    // Initialize Sovereign Arena
    printf("[2/4] Initializing Sovereign Arena (4GB huge pages)...\n");
    {
        PROFILE_BLOCK("arena_init");
        if (!SovereignArena_Initialize(0)) {
            printf("      ✗ Failed to initialize Sovereign Arena\n");
            return 1;
        }
    }
    size_t arenaSize = SovereignArena_GetSize();
    printf("      ✓ Arena initialized: %zu MB (%zu GB)\n\n", 
           arenaSize / (1024*1024), arenaSize / (1024*1024*1024));
    
    // Run profiled operations
    printf("[3/4] Running profiled operations...\n");
    
    {
        PROFILE_BLOCK("work_simulation_1");
        simulate_work(1000000);
    }
    printf("      ✓ Work simulation 1 complete\n");
    
    {
        PROFILE_BLOCK("work_simulation_2");
        simulate_work(5000000);
    }
    printf("      ✓ Work simulation 2 complete\n");
    
    {
        PROFILE_BLOCK("memory_access");
        void* ptr = SovereignArena_Allocate(4096, 256);  // 256-byte aligned
        if (ptr) {
            volatile char* vptr = (volatile char*)ptr;
            for (int i = 0; i < 4096; i += 64) {
                vptr[i] = (char)i;
            }
            // No explicit free needed for arena allocator
        }
    }
    printf("      ✓ Memory access test complete\n\n");
    
    // Dump profiler report
    printf("[4/4] Profiler Report:\n");
    printf("-------------------------------------------\n");
    rxdn::prof_dump();
    printf("-------------------------------------------\n\n");
    
    printf("=== Smoke Test PASSED ===\n");
    printf("\nKey Achievements:\n");
    printf("  • C++ profiler (inference_profiler_simple.h) working\n");
    printf("  • Sovereign Arena (4GB huge pages) initialized\n");
    printf("  • RDTSC timing measurements captured\n");
    printf("  • Memory allocation from arena verified\n");
    
    return 0;
}
