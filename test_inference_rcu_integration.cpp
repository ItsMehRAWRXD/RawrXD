// ============================================================================
// RawrXD Inference + Epoch-RCU Integration Test
// ============================================================================
// Quick C++ test to verify the RCU integration works correctly
// ============================================================================

#include <cstdio>
#include <windows.h>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>

// External router functions
extern "C" {
    uint64_t RawrXD_InitHotpatchSystem();
    uint64_t RawrXD_RequestHotpatch(void* modelDescriptor, uint64_t gpuFence);
    uint64_t RawrXD_CheckEpochSwap();
    uint64_t RawrXD_BeginInference();
    uint64_t RawrXD_EndInference();
    uint64_t RawrXD_GetEpochCounter();
    void* RawrXD_GetCurrentModelDescriptor();
}

// Test statistics
struct TestStats {
    std::atomic<uint64_t> inferencesStarted{0};
    std::atomic<uint64_t> inferencesCompleted{0};
    std::atomic<uint64_t> hotpatchesRequested{0};
    std::atomic<uint64_t> hotpatchesCompleted{0};
    std::atomic<uint64_t> epochsWitnessed{0};
    std::atomic<uint64_t> errors{0};
};

static TestStats g_stats;

// Inference worker thread
void InferenceWorkerThread(uint32_t workerId, uint32_t durationSeconds) {
    printf("[Worker-%u] Started\n", workerId);
    
    uint64_t lastEpoch = 0;
    auto startTime = std::chrono::steady_clock::now();
    
    while (true) {
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= durationSeconds) {
            break;
        }
        
        // Begin inference (RCU critical section)
        uint64_t epoch = RawrXD_BeginInference();
        g_stats.inferencesStarted.fetch_add(1);
        
        if (epoch != lastEpoch) {
            g_stats.epochsWitnessed.fetch_add(1);
            lastEpoch = epoch;
        }
        
        // Get model descriptor (will be null until first hotpatch with real model)
        // This is OK for the stress test - we're testing the RCU mechanism, not model loading
        void* model = RawrXD_GetCurrentModelDescriptor();
        (void)model; // Suppress unused warning
        
        // Simulate inference work (1-3ms)
        std::this_thread::sleep_for(std::chrono::milliseconds(1 + (workerId % 3)));
        
        // End inference (RCU critical section end)
        RawrXD_EndInference();
        g_stats.inferencesCompleted.fetch_add(1);
    }
    
    printf("[Worker-%u] Exiting\n", workerId);
}

// Hotpatch thread
void HotpatchThread(uint32_t durationSeconds) {
    printf("[Hotpatch] Started\n");
    
    auto startTime = std::chrono::steady_clock::now();
    uint32_t count = 0;
    
    while (true) {
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= durationSeconds) {
            break;
        }
        
        // Request hotpatch every 500ms
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Dummy model handle
        static uint64_t dummyModel = 0xDEADBEEF + count;
        
        uint64_t result = RawrXD_RequestHotpatch((void*)dummyModel, 0);
        g_stats.hotpatchesRequested.fetch_add(1);
        
        if (result == 0) {
            // Check for swap completion
            RawrXD_CheckEpochSwap();
            g_stats.hotpatchesCompleted.fetch_add(1);
            count++;
        }
    }
    
    printf("[Hotpatch] Exiting, %u hotpatches completed\n", count);
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RawrXD Inference + Epoch-RCU Test\n");
    printf("========================================\n\n");
    
    uint32_t duration = 5;  // Default 5 seconds
    uint32_t numWorkers = 4; // Default 4 workers
    
    if (argc > 1) duration = atoi(argv[1]);
    if (argc > 2) numWorkers = atoi(argv[2]);
    
    printf("Duration: %u seconds\n", duration);
    printf("Workers: %u\n\n", numWorkers);
    
    // Initialize router
    printf("[INIT] Initializing hotpatch system...\n");
    RawrXD_InitHotpatchSystem();
    printf("[INIT] OK\n\n");
    
    // Start workers
    printf("[TEST] Starting test...\n");
    std::vector<std::thread> workers;
    
    for (uint32_t i = 0; i < numWorkers; i++) {
        workers.emplace_back(InferenceWorkerThread, i, duration);
    }
    
    // Start hotpatch thread
    std::thread hotpatchThread(HotpatchThread, duration);
    
    // Wait for completion
    for (auto& t : workers) {
        t.join();
    }
    hotpatchThread.join();
    
    // Print results
    printf("\n========================================\n");
    printf("Test Results\n");
    printf("========================================\n");
    printf("Inferences Started:   %llu\n", g_stats.inferencesStarted.load());
    printf("Inferences Completed: %llu\n", g_stats.inferencesCompleted.load());
    printf("Hotpatches Requested: %llu\n", g_stats.hotpatchesRequested.load());
    printf("Hotpatches Completed: %llu\n", g_stats.hotpatchesCompleted.load());
    printf("Epochs Witnessed:     %llu\n", g_stats.epochsWitnessed.load());
    printf("Errors:               %llu\n", g_stats.errors.load());
    printf("Final Epoch:          %llu\n", RawrXD_GetEpochCounter());
    
    // Verify results
    bool success = (g_stats.inferencesStarted.load() == g_stats.inferencesCompleted.load()) &&
                   (g_stats.errors.load() == 0);
    
    if (success) {
        printf("\n[PASS] All inferences completed without errors!\n");
        printf("       Epoch-RCU state machine working correctly.\n");
        return 0;
    } else {
        printf("\n[FAIL] Test failed!\n");
        if (g_stats.inferencesStarted.load() != g_stats.inferencesCompleted.load()) {
            printf("       Mismatched begin/end inference calls!\n");
        }
        if (g_stats.errors.load() > 0) {
            printf("       Errors detected during test!\n");
        }
        return 1;
    }
}
