/*===========================================================================
 * test_ssm_saturation.cpp
 * VAL-028.4: Validation Gates - Adversarial Testing
 * 
 * Stress tests for SovereignSharedMemoryServer under saturation.
 * Tests race conditions, IOCP overflow, and backpressure hysteresis.
 *===========================================================================*/

#include "SovereignSharedMemoryServer.h"
#include "ControlBlock.h"
#include "IOCPSpillManager.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <atomic>
#include <vector>
#include <chrono>

/*===========================================================================
 * TEST CONFIGURATION
 *===========================================================================*/
#define TEST_DURATION_SECONDS           60
#define FAST_THREAD_COUNT               4       // Thread Group A
#define SPILL_THREAD_COUNT              2       // Thread Group B
#define VALIDATOR_THREAD_COUNT          1

// Payload sizes
#define FAST_PAYLOAD_SIZE               1024    // 1KB (small, frequent)
#define SPILL_PAYLOAD_SIZE              65536   // 64KB (large, bursty)

// Pressure targets
#define TARGET_FAST_PRESSURE            0.85f   // 85% for fast path focus
#define TARGET_SPILL_PRESSURE_MIN       0.90f   // 90% to trigger spill
#define TARGET_SPILL_PRESSURE_MAX       0.98f   // 98% for emergency

/*===========================================================================
 * TELEMETRY STRUCTURE
 *===========================================================================*/
struct SpillStressTelemetry {
    // Counters
    std::atomic<uint64_t> submitted{0};
    std::atomic<uint64_t> completed{0};
    std::atomic<uint64_t> dropped{0};
    std::atomic<uint64_t> fastWrites{0};
    std::atomic<uint64_t> coldWrites{0};
    std::atomic<uint64_t> emergencyDrops{0};
    
    // Latency tracking (microseconds)
    std::atomic<uint64_t> totalLatencyUs{0};
    std::atomic<uint64_t> maxLatencyUs{0};
    std::atomic<uint64_t> minLatencyUs{0xFFFFFFFFFFFFFFFF};
    
    // Path switching
    std::atomic<uint64_t> fastToColdSwitches{0};
    std::atomic<uint64_t> coldToFastSwitches{0};
    std::atomic<uint64_t> pathSwitchesUnderPressure{0};
    
    // Backpressure
    std::atomic<uint64_t> backpressureEnableCount{0};
    std::atomic<uint64_t> backpressureDisableCount{0};
    std::atomic<uint64_t> rapidTransitions{0};  // < 100ms between toggles
    uint64_t lastBackpressureToggleTime{0};
    
    // Queue depth
    std::atomic<uint32_t> queueHighWatermark{0};
    std::atomic<uint32_t> currentQueueDepth{0};
    
    // Race condition detection
    std::atomic<uint64_t> sequenceMismatches{0};
    std::atomic<uint64_t> tornReads{0};
    std::atomic<uint64_t> stateViolations{0};
};

/*===========================================================================
 * TEST STATE
 *===========================================================================*/
static struct {
    SovereignSharedMemoryServer* srv;
    SpillStressTelemetry telemetry;
    std::atomic<bool> shutdownRequested{false};
    std::atomic<bool> ioThrottled{false};      // For IOCP saturation test
    HANDLE hThreads[FAST_THREAD_COUNT + SPILL_THREAD_COUNT + VALIDATOR_THREAD_COUNT];
    int threadCount{0};
} g_test;

/*===========================================================================
 * BACKPRESSURE CALLBACK
 *===========================================================================*/
static void OnBackpressure(bool enable, float pressure) {
    uint64_t now = GetTickCount64();
    
    if (enable) {
        g_test.telemetry.backpressureEnableCount.fetch_add(1);
    } else {
        g_test.telemetry.backpressureDisableCount.fetch_add(1);
    }
    
    // Check for rapid transitions (flapping)
    uint64_t lastToggle = g_test.telemetry.lastBackpressureToggleTime;
    if (lastToggle != 0 && (now - lastToggle) < 100) {
        g_test.telemetry.rapidTransitions.fetch_add(1);
    }
    g_test.telemetry.lastBackpressureToggleTime = now;
    
    printf("[Backpressure] %s at %.1f%%\n", 
           enable ? "ENABLED" : "DISABLED", pressure * 100.0f);
}

/*===========================================================================
 * THREAD GROUP A: Fast Path Focus
 * Continuously writes small buffers to maintain 85% pressure
 *===========================================================================*/
static DWORD WINAPI FastPathThreadProc(LPVOID lpParam) {
    int threadId = (int)(size_t)lpParam;
    uint8_t buffer[FAST_PAYLOAD_SIZE];
    
    // Fill with pattern for validation
    for (int i = 0; i < FAST_PAYLOAD_SIZE; i++) {
        buffer[i] = (uint8_t)(i & 0xFF);
    }
    
    while (!g_test.shutdownRequested.load()) {
        // Check current pressure
        float pressure = SSM_GetPressure(g_test.srv);
        
        // If pressure too high, slow down
        if (pressure > TARGET_FAST_PRESSURE) {
            Sleep(1);
            continue;
        }
        
        // Measure latency
        auto start = std::chrono::high_resolution_clock::now();
        
        BufferDescriptor desc;
        BOOL result = SSM_WriteFast(g_test.srv, buffer, FAST_PAYLOAD_SIZE, &desc);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto latencyUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        // Update telemetry
        g_test.telemetry.submitted.fetch_add(1);
        if (result) {
            g_test.telemetry.completed.fetch_add(1);
            g_test.telemetry.fastWrites.fetch_add(1);
            
            // Latency tracking
            g_test.telemetry.totalLatencyUs.fetch_add(latencyUs);
            
            uint64_t maxLatency = g_test.telemetry.maxLatencyUs.load();
            while (latencyUs > maxLatency && 
                   !g_test.telemetry.maxLatencyUs.compare_exchange_weak(maxLatency, latencyUs)) {}
            
            uint64_t minLatency = g_test.telemetry.minLatencyUs.load();
            while (latencyUs < minLatency && 
                   !g_test.telemetry.minLatencyUs.compare_exchange_weak(minLatency, latencyUs)) {}
        } else {
            g_test.telemetry.dropped.fetch_add(1);
        }
    }
    
    printf("[FastPath Thread %d] Exiting\n", threadId);
    return 0;
}

/*===========================================================================
 * THREAD GROUP B: Spill Path Focus
 * Bursts large buffers to force 90-98% pressure range
 *===========================================================================*/
static DWORD WINAPI SpillPathThreadProc(LPVOID lpParam) {
    int threadId = (int)(size_t)lpParam;
    uint8_t buffer[SPILL_PAYLOAD_SIZE];
    
    // Fill with different pattern
    for (int i = 0; i < SPILL_PAYLOAD_SIZE; i++) {
        buffer[i] = (uint8_t)((i + 0xAA) & 0xFF);
    }
    
    while (!g_test.shutdownRequested.load()) {
        float pressure = SSM_GetPressure(g_test.srv);
        
        // Burst when pressure is low
        if (pressure < TARGET_SPILL_PRESSURE_MIN) {
            // Burst write
            for (int i = 0; i < 10 && !g_test.shutdownRequested.load(); i++) {
                BufferDescriptor desc;
                BOOL result = SSM_WriteCold(g_test.srv, buffer, SPILL_PAYLOAD_SIZE, &desc);
                
                g_test.telemetry.submitted.fetch_add(1);
                if (result) {
                    g_test.telemetry.completed.fetch_add(1);
                    g_test.telemetry.coldWrites.fetch_add(1);
                } else {
                    g_test.telemetry.dropped.fetch_add(1);
                }
            }
        }
        
        // If IO throttled (for saturation test), keep writing
        if (g_test.ioThrottled.load()) {
            // Force writes that will trigger emergency drops
            for (int i = 0; i < 100 && !g_test.shutdownRequested.load(); i++) {
                BufferDescriptor desc;
                SSM_Write(g_test.srv, buffer, SPILL_PAYLOAD_SIZE, &desc);
                g_test.telemetry.submitted.fetch_add(1);
            }
        }
        
        Sleep(10); // 10ms between bursts
    }
    
    printf("[SpillPath Thread %d] Exiting\n", threadId);
    return 0;
}

/*===========================================================================
 * VALIDATOR THREAD
 * Monitors for race conditions and state violations
 *===========================================================================*/
static DWORD WINAPI ValidatorThreadProc(LPVOID lpParam) {
    (void)lpParam;
    
    uint64_t lastSequence = 0;
    uint64_t lastFastWrites = 0;
    uint64_t lastColdWrites = 0;
    
    while (!g_test.shutdownRequested.load()) {
        Sleep(100); // 100ms sampling
        
        // Check sequence monotonicity
        uint64_t currentSeq = SSM_PeekNextSequence(g_test.srv);
        if (currentSeq < lastSequence) {
            g_test.telemetry.sequenceMismatches.fetch_add(1);
            printf("[VALIDATOR ERROR] Sequence went backwards: %llu -> %llu\n",
                   lastSequence, currentSeq);
        }
        lastSequence = currentSeq;
        
        // Track path switches
        uint64_t fastWrites = g_test.telemetry.fastWrites.load();
        uint64_t coldWrites = g_test.telemetry.coldWrites.load();
        
        if (fastWrites != lastFastWrites && coldWrites != lastColdWrites) {
            // Both changed - potential path switch
            float pressure = SSM_GetPressure(g_test.srv);
            if (pressure > 0.85f) {
                g_test.telemetry.pathSwitchesUnderPressure.fetch_add(1);
            }
        }
        
        lastFastWrites = fastWrites;
        lastColdWrites = coldWrites;
        
        // Update queue depth watermark
        uint32_t depth = (uint32_t)(SSM_GetPressure(g_test.srv) * 100);
        uint32_t currentMax = g_test.telemetry.queueHighWatermark.load();
        if (depth > currentMax) {
            g_test.telemetry.queueHighWatermark.store(depth);
        }
    }
    
    printf("[Validator] Exiting\n");
    return 0;
}

/*===========================================================================
 * TEST SCENARIOS
 *===========================================================================*/

// Gate 1: Path-Switching Race Condition Test
static BOOL Test_PathSwitchingRace() {
    printf("\n=== GATE 1: Path-Switching Race Condition Test ===\n");
    printf("Testing transitions around 90%% pressure threshold...\n\n");
    
    // Reset telemetry
    ZeroMemory(&g_test.telemetry, sizeof(g_test.telemetry));
    g_test.telemetry.minLatencyUs.store(0xFFFFFFFFFFFFFFFF);
    
    // Run for 10 seconds with oscillating pressure
    auto startTime = std::chrono::steady_clock::now();
    auto endTime = startTime + std::chrono::seconds(10);
    
    while (std::chrono::steady_clock::now() < endTime) {
        float pressure = SSM_GetPressure(g_test.srv);
        
        // Force oscillation around threshold
        if (pressure < 0.88f) {
            // Burst to push over threshold
            uint8_t buf[32768];
            for (int i = 0; i < 50; i++) {
                BufferDescriptor desc;
                SSM_Write(g_test.srv, buf, sizeof(buf), &desc);
            }
        } else if (pressure > 0.92f) {
            // Let it drain
            Sleep(5);
        }
    }
    
    // Validate results
    uint64_t switchesUnderPressure = g_test.telemetry.pathSwitchesUnderPressure.load();
    uint64_t sequenceMismatches = g_test.telemetry.sequenceMismatches.load();
    
    printf("Results:\n");
    printf("  Path switches under pressure: %llu\n", switchesUnderPressure);
    printf("  Sequence mismatches: %llu\n", sequenceMismatches);
    printf("  Completed writes: %llu\n", g_test.telemetry.completed.load());
    printf("  Dropped writes: %llu\n", g_test.telemetry.dropped.load());
    
    // Pass criteria: No sequence mismatches, some path switches observed
    BOOL passed = (sequenceMismatches == 0) && (switchesUnderPressure > 0);
    printf("\n%s\n\n", passed ? "PASS" : "FAIL");
    
    return passed;
}

// Gate 2: IOCP Saturation Stress Test
static BOOL Test_IOCPSaturation() {
    printf("\n=== GATE 2: IOCP Saturation Stress Test ===\n");
    printf("Throttling IOCP to force emergency drops...\n\n");
    
    // Reset telemetry
    ZeroMemory(&g_test.telemetry, sizeof(g_test.telemetry));
    g_test.telemetry.minLatencyUs.store(0xFFFFFFFFFFFFFFFF);
    
    // Enable IO throttling
    g_test.ioThrottled.store(true);
    
    // Run for 5 seconds with throttled IO
    Sleep(5000);
    
    // Disable throttling
    g_test.ioThrottled.store(false);
    
    // Validate results
    uint64_t emergencyDrops = g_test.telemetry.emergencyDrops.load();
    uint64_t totalSubmitted = g_test.telemetry.submitted.load();
    
    printf("Results:\n");
    printf("  Total submitted: %llu\n", totalSubmitted);
    printf("  Emergency drops: %llu\n", emergencyDrops);
    printf("  Drop rate: %.2f%%\n", 
           totalSubmitted > 0 ? (emergencyDrops * 100.0 / totalSubmitted) : 0.0);
    
    // Pass criteria: System handled saturation without crashing
    // Some drops expected, but system remained stable
    BOOL passed = (totalSubmitted > 0) && (emergencyDrops > 0);
    printf("\n%s\n\n", passed ? "PASS" : "FAIL");
    
    return passed;
}

// Gate 3: Backpressure Hysteresis Validation
static BOOL Test_BackpressureHysteresis() {
    printf("\n=== GATE 3: Backpressure Hysteresis Validation ===\n");
    printf("Checking for flapping (rapid enable/disable)...\n\n");
    
    // Reset telemetry
    ZeroMemory(&g_test.telemetry, sizeof(g_test.telemetry));
    g_test.telemetry.minLatencyUs.store(0xFFFFFFFFFFFFFFFF);
    
    // Run for 10 seconds, varying pressure
    auto startTime = std::chrono::steady_clock::now();
    auto endTime = startTime + std::chrono::seconds(10);
    
    while (std::chrono::steady_clock::now() < endTime) {
        float pressure = SSM_GetPressure(g_test.srv);
        
        // Oscillate around 80% threshold
        if (pressure < 0.78f) {
            // Push up
            uint8_t buf[16384];
            for (int i = 0; i < 20; i++) {
                BufferDescriptor desc;
                SSM_Write(g_test.srv, buf, sizeof(buf), &desc);
            }
        } else if (pressure > 0.82f) {
            // Let drain
            Sleep(10);
        }
    }
    
    // Validate results
    uint64_t enableCount = g_test.telemetry.backpressureEnableCount.load();
    uint64_t disableCount = g_test.telemetry.backpressureDisableCount.load();
    uint64_t rapidTransitions = g_test.telemetry.rapidTransitions.load();
    
    printf("Results:\n");
    printf("  Backpressure enable count: %llu\n", enableCount);
    printf("  Backpressure disable count: %llu\n", disableCount);
    printf("  Rapid transitions (< 100ms): %llu\n", rapidTransitions);
    
    // Pass criteria: No rapid transitions (flapping)
    // Some transitions expected, but not rapid-fire
    float rapidRatio = (enableCount + disableCount) > 0 ? 
        (rapidTransitions * 100.0 / (enableCount + disableCount)) : 0;
    printf("  Rapid transition ratio: %.2f%%\n", rapidRatio);
    
    BOOL passed = (rapidRatio < 10.0); // Less than 10% rapid
    printf("\n%s\n\n", passed ? "PASS" : "FAIL");
    
    return passed;
}

/*===========================================================================
 * MAIN TEST HARNESS
 *===========================================================================*/
int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("=============================================================================\n");
    printf("VAL-028.4: SovereignSharedMemoryServer Saturation Tests\n");
    printf("=============================================================================\n\n");
    
    // Initialize server
    printf("Initializing SovereignSharedMemoryServer...\n");
    g_test.srv = (SovereignSharedMemoryServer*)malloc(sizeof(SovereignSharedMemoryServer));
    if (!g_test.srv) {
        printf("FAILED: Memory allocation\n");
        return 1;
    }
    
    if (!SSM_Initialize(g_test.srv, 16, L"test_spill.bin", OnBackpressure)) {
        printf("FAILED: Server initialization\n");
        free(g_test.srv);
        return 1;
    }
    
    printf("Server initialized. Starting worker threads...\n\n");
    
    // Create worker threads
    g_test.threadCount = 0;
    
    // Fast path threads
    for (int i = 0; i < FAST_THREAD_COUNT; i++) {
        g_test.hThreads[g_test.threadCount++] = CreateThread(
            nullptr, 0, FastPathThreadProc, (LPVOID)(size_t)i, 0, nullptr);
    }
    
    // Spill path threads
    for (int i = 0; i < SPILL_THREAD_COUNT; i++) {
        g_test.hThreads[g_test.threadCount++] = CreateThread(
            nullptr, 0, SpillPathThreadProc, (LPVOID)(size_t)i, 0, nullptr);
    }
    
    // Validator thread
    g_test.hThreads[g_test.threadCount++] = CreateThread(
        nullptr, 0, ValidatorThreadProc, nullptr, 0, nullptr);
    
    printf("Created %d worker threads\n", g_test.threadCount);
    printf("  - Fast path threads: %d\n", FAST_THREAD_COUNT);
    printf("  - Spill path threads: %d\n", SPILL_THREAD_COUNT);
    printf("  - Validator threads: %d\n\n", VALIDATOR_THREAD_COUNT);
    
    // Run validation gates
    BOOL gate1Pass = Test_PathSwitchingRace();
    BOOL gate2Pass = Test_IOCPSaturation();
    BOOL gate3Pass = Test_BackpressureHysteresis();
    
    // Shutdown
    printf("Shutting down...\n");
    g_test.shutdownRequested.store(true);
    
    WaitForMultipleObjects(g_test.threadCount, g_test.hThreads, TRUE, 10000);
    
    for (int i = 0; i < g_test.threadCount; i++) {
        CloseHandle(g_test.hThreads[i]);
    }
    
    SSM_Shutdown(g_test.srv);
    free(g_test.srv);
    
    // Final report
    printf("\n=============================================================================\n");
    printf("FINAL RESULTS\n");
    printf("=============================================================================\n");
    printf("Gate 1 (Path-Switching Race): %s\n", gate1Pass ? "PASS" : "FAIL");
    printf("Gate 2 (IOCP Saturation):     %s\n", gate2Pass ? "PASS" : "FAIL");
    printf("Gate 3 (Backpressure Hysteresis): %s\n", gate3Pass ? "PASS" : "FAIL");
    printf("\n");
    printf("Overall: %s\n", (gate1Pass && gate2Pass && gate3Pass) ? "ALL GATES PASSED" : "SOME GATES FAILED");
    printf("=============================================================================\n");
    
    return (gate1Pass && gate2Pass && gate3Pass) ? 0 : 1;
}
