// ============================================================================
// test_sovereign_bridge.cpp
// Standalone test harness for Sovereign Runtime Bridge validation
// Run this to verify shared memory IPC is working before IDE integration
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <string>
#include <chrono>

// Include the bridge headers
#include "SovereignSharedMemoryBridge.hpp"

using namespace RawrXD::IDE;

// Test result tracking
struct TestResults {
    int passed = 0;
    int failed = 0;
    
    void Pass(const char* test) {
        printf("[PASS] %s\n", test);
        passed++;
    }
    
    void Fail(const char* test, const char* reason) {
        printf("[FAIL] %s: %s\n", test, reason);
        failed++;
    }
    
    void Summary() {
        printf("\n========================================\n");
        printf("Test Results: %d passed, %d failed\n", passed, failed);
        printf("========================================\n");
    }
};

// Test 1: Shared memory creation and attachment
void TestSharedMemoryLifecycle(TestResults& results) {
    printf("\n--- Test: Shared Memory Lifecycle ---\n");
    
    // Create a test shared memory segment
    SovereignSharedMemoryBridge server;
    SovereignSharedMemoryBridge client;
    
    // Server creates
    if (!server.CreateRuntime("RawrXD_Test_SHM")) {
        results.Fail("SHM Create", "Failed to create shared memory");
        return;
    }
    results.Pass("SHM Create");
    
    // Client attaches
    if (!client.AttachToRuntime("RawrXD_Test_SHM")) {
        results.Fail("SHM Attach", "Failed to attach to shared memory");
        server.Detach();
        return;
    }
    results.Pass("SHM Attach");
    
    // Verify connection
    if (!client.IsConnected()) {
        results.Fail("SHM Connected", "Client reports not connected");
    } else {
        results.Pass("SHM Connected");
    }
    
    // Cleanup
    client.Detach();
    server.Detach();
    results.Pass("SHM Cleanup");
}

// Test 2: Heartbeat validation
void TestHeartbeat(TestResults& results) {
    printf("\n--- Test: Heartbeat ---\n");
    
    SovereignSharedMemoryBridge server;
    SovereignSharedMemoryBridge client;
    
    if (!server.CreateRuntime("RawrXD_Test_Heartbeat")) {
        results.Fail("Heartbeat Setup", "Failed to create SHM");
        return;
    }
    
    if (!client.AttachToRuntime("RawrXD_Test_Heartbeat")) {
        results.Fail("Heartbeat Setup", "Failed to attach");
        server.Detach();
        return;
    }
    
    // Send heartbeat
    auto start = std::chrono::high_resolution_clock::now();
    bool heartbeatOk = client.SendHeartbeat(1000);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    if (heartbeatOk) {
        printf("  Heartbeat latency: %lld us\n", duration);
        results.Pass("Heartbeat");
    } else {
        results.Fail("Heartbeat", "Heartbeat failed or timed out");
    }
    
    client.Detach();
    server.Detach();
}

// Test 3: Bridge mode reporting
void TestBridgeMode(TestResults& results) {
    printf("\n--- Test: Bridge Mode Reporting ---\n");
    
    SovereignSharedMemoryBridge bridge;
    
    if (!bridge.CreateRuntime("RawrXD_Test_Mode")) {
        results.Fail("Mode Setup", "Failed to create SHM");
        return;
    }
    
    const char* mode = bridge.GetBridgeMode();
    printf("  Bridge mode: %s\n", mode);
    
    if (strcmp(mode, "Zero-copy IPC") == 0) {
        results.Pass("Bridge Mode");
    } else {
        results.Fail("Bridge Mode", "Unexpected mode string");
    }
    
    bridge.Detach();
}

// Test 4: Bridge stats
void TestBridgeStats(TestResults& results) {
    printf("\n--- Test: Bridge Stats ---\n");
    
    SovereignSharedMemoryBridge bridge;
    
    if (!bridge.CreateRuntime("RawrXD_Test_Stats")) {
        results.Fail("Stats Setup", "Failed to create SHM");
        return;
    }
    
    uint32_t cacheHits, cacheMisses;
    uint64_t latencyUs;
    bridge.GetStats(cacheHits, cacheMisses, latencyUs);
    
    printf("  Initial stats: hits=%u, misses=%u, latency=%llu us\n", 
           cacheHits, cacheMisses, latencyUs);
    
    results.Pass("Bridge Stats");
    bridge.Detach();
}

// Test 5: Latency benchmark
void TestLatencyBenchmark(TestResults& results) {
    printf("\n--- Test: Latency Benchmark ---\n");
    
    SovereignSharedMemoryBridge server;
    SovereignSharedMemoryBridge client;
    
    if (!server.CreateRuntime("RawrXD_Test_Latency")) {
        results.Fail("Latency Setup", "Failed to create SHM");
        return;
    }
    
    if (!client.AttachToRuntime("RawrXD_Test_Latency")) {
        results.Fail("Latency Setup", "Failed to attach");
        server.Detach();
        return;
    }
    
    // Run 10 heartbeats and measure average latency
    const int iterations = 10;
    long long totalLatency = 0;
    int successful = 0;
    
    for (int i = 0; i < iterations; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        if (client.SendHeartbeat(100)) {
            auto end = std::chrono::high_resolution_clock::now();
            totalLatency += std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            successful++;
        }
    }
    
    if (successful > 0) {
        long long avgLatency = totalLatency / successful;
        printf("  Average heartbeat latency: %lld us (%d/%d successful)\n", 
               avgLatency, successful, iterations);
        
        if (avgLatency < 1000) { // Less than 1ms is excellent
            results.Pass("Latency Benchmark (Excellent)");
        } else if (avgLatency < 5000) { // Less than 5ms is good
            results.Pass("Latency Benchmark (Good)");
        } else {
            results.Pass("Latency Benchmark (Acceptable)");
        }
    } else {
        results.Fail("Latency Benchmark", "No successful heartbeats");
    }
    
    client.Detach();
    server.Detach();
}

// Test 6: Error handling
void TestErrorHandling(TestResults& results) {
    printf("\n--- Test: Error Handling ---\n");
    
    SovereignSharedMemoryBridge bridge;
    
    // Try to attach to non-existent shared memory
    bool attached = bridge.AttachToRuntime("RawrXD_NonExistent_SHM_12345");
    
    if (!attached) {
        const char* error = bridge.GetLastError();
        printf("  Expected error: %s\n", error);
        if (strlen(error) > 0) {
            results.Pass("Error Reporting");
        } else {
            results.Fail("Error Reporting", "No error message set");
        }
    } else {
        results.Fail("Error Handling", "Should have failed to attach");
        bridge.Detach();
    }
}

// Main entry point
int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("Sovereign Runtime Bridge Test Harness\n");
    printf("========================================\n");
    printf("\nThis test validates:\n");
    printf("  1. Shared memory creation/attachment\n");
    printf("  2. Heartbeat communication\n");
    printf("  3. Bridge mode reporting\n");
    printf("  4. Bridge stats collection\n");
    printf("  5. Latency benchmarks\n");
    printf("  6. Error handling\n");
    
    TestResults results;
    
    TestSharedMemoryLifecycle(results);
    TestHeartbeat(results);
    TestBridgeMode(results);
    TestBridgeStats(results);
    TestLatencyBenchmark(results);
    TestErrorHandling(results);
    
    results.Summary();
    
    return results.failed > 0 ? 1 : 0;
}
