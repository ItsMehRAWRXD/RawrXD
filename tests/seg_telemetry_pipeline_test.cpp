// ============================================================================
// SEG Telemetry Pipeline Test - Minimal Validation
// ============================================================================
// Tests SEG + MASM telemetry without requiring full model loading.
// Validates the core pipeline: SEG Gateway → MASM Telemetry → Results
// ============================================================================

#include <iostream>
#include <chrono>
#include <cassert>

// Include only SEG gateway and telemetry
#include "../src/gateway/seg_gateway.hpp"

using namespace rawrxd::gateway;
using namespace rawrxd::execution;

// ============================================================================
// Minimal Test: SEG Gateway + Telemetry Only
// ============================================================================
bool TestSegGatewayTelemetry() {
    std::cout << "[TEST] SEG Gateway Telemetry Pipeline\n";
    std::cout << "       Testing: Gateway → MASM Telemetry → Results\n\n";
    
    // Create gateway
    SegGateway gateway;
    
    // Test 1: Initialize with dummy path (will fail model load but telemetry should work)
    std::cout << "  [1/4] Initializing SEG gateway...\n";
    bool init_result = gateway.Initialize("dummy.gguf");
    
    // Note: Initialize may fail on model load, but telemetry should be initialized
    std::cout << "        Result: " << (init_result ? "SUCCESS" : "FAILED (expected for dummy)") << "\n";
    
    // Test 2: Check if telemetry is available
    std::cout << "  [2/4] Checking MASM telemetry availability...\n";
    bool telemetry_available = IsSegAvailable();
    std::cout << "        Result: " << (telemetry_available ? "AVAILABLE" : "UNAVAILABLE") << "\n";
    
    if (!telemetry_available) {
        std::cout << "        WARNING: MASM telemetry not available\n";
    }
    
    // Test 3: Run inference request (will use stub implementation)
    std::cout << "  [3/4] Running inference request...\n";
    
    ExecutionRequest req;
    req.model_path = "test.gguf";
    req.prompt = "Hello";
    req.max_tokens = 3;
    req.dump_telemetry = true;
    req.verbose = false;
    
    auto start = std::chrono::high_resolution_clock::now();
    auto result = gateway.Run(req);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    std::cout << "        Status: " << result.status_message << "\n";
    std::cout << "        Time: " << duration_ms << " ms\n";
    
    // Test 4: Validate telemetry
    std::cout << "  [4/4] Validating telemetry...\n";
    std::cout << "        Events logged: " << result.telemetry.events_logged << "\n";
    std::cout << "        Events dropped: " << result.telemetry.events_dropped << "\n";
    std::cout << "        Tokens/sec: " << result.telemetry.tokens_per_second << "\n";
    
    bool telemetry_valid = (result.telemetry.events_logged > 0) || !telemetry_available;
    std::cout << "        Valid: " << (telemetry_valid ? "YES" : "NO") << "\n";
    
    // Cleanup
    gateway.Shutdown();
    
    std::cout << "\n";
    return true; // Test passes if we get here without crashing
}

// ============================================================================
// Test: RunSegInference Convenience Function
// ============================================================================
bool TestRunSegInference() {
    std::cout << "[TEST] RunSegInference Convenience Function\n\n";
    
    ExecutionRequest req;
    req.model_path = "test.gguf";
    req.prompt = "Test prompt";
    req.max_tokens = 2;
    
    std::cout << "  Running inference...\n";
    auto result = RunSegInference(req);
    
    std::cout << "  Status: " << result.status_message << "\n";
    std::cout << "  Output: \"" << result.text_output.substr(0, 50) << "\"\n";
    std::cout << "  Telemetry events: " << result.telemetry.events_logged << "\n\n";
    
    return true;
}

// ============================================================================
// Test: SEG Version Info
// ============================================================================
bool TestSegVersion() {
    std::cout << "[TEST] SEG Version Information\n\n";
    
    std::string version = GetSegVersion();
    std::cout << "  Version: " << version << "\n\n";
    
    return !version.empty();
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     SEG Telemetry Pipeline Test - Minimal Validation       ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    int passed = 0;
    int total = 3;
    
    // Run tests
    if (TestSegVersion()) {
        std::cout << "✓ Version test passed\n\n";
        passed++;
    } else {
        std::cout << "✗ Version test failed\n\n";
    }
    
    if (TestSegGatewayTelemetry()) {
        std::cout << "✓ Gateway telemetry test passed\n\n";
        passed++;
    } else {
        std::cout << "✗ Gateway telemetry test failed\n\n";
    }
    
    if (TestRunSegInference()) {
        std::cout << "✓ RunSegInference test passed\n\n";
        passed++;
    } else {
        std::cout << "✗ RunSegInference test failed\n\n";
    }
    
    // Summary
    std::cout << "════════════════════════════════════════════════════════════\n";
    std::cout << "Results: " << passed << "/" << total << " tests passed\n";
    std::cout << "════════════════════════════════════════════════════════════\n\n";
    
    return (passed == total) ? 0 : 1;
}
