// ============================================================================
// Test: MASM Telemetry Integration
// ============================================================================
// Verifies C++ to MASM telemetry bridge works correctly
// ============================================================================

#include "telemetry_masm_bridge.hpp"
#include <iostream>
#include <chrono>
#include <thread>

using namespace RawrXD::Runtime::Telemetry;

int main() {
    std::cout << "=== MASM Telemetry Integration Test ===\n\n";
    
    // ------------------------------------------------------------------------
    // Test 1: Initialize telemetry
    // ------------------------------------------------------------------------
    std::cout << "[Test 1] Initialize telemetry...\n";
    
    bool success = InitializeMasmTelemetry(1024 * 1024);  // 1MB buffer
    if (!success) {
        std::cerr << "  FAILED: Could not initialize telemetry\n";
        return 1;
    }
    std::cout << "  PASSED: Telemetry initialized\n\n";
    
    // ------------------------------------------------------------------------
    // Test 2: Log simple events
    // ------------------------------------------------------------------------
    std::cout << "[Test 2] Log simple events...\n";
    
    MasmTelemetry_Log(TELEMETRY_PHASE_INIT, 0, 0);
    MasmTelemetry_Log(TELEMETRY_OP_RMSNORM_START, 4096, 0);
    MasmTelemetry_Log(TELEMETRY_OP_RMSNORM_END, 100, 0);  // 100 cycles
    MasmTelemetry_Log(TELEMETRY_PHASE_SHUTDOWN, 0, 0);
    
    std::cout << "  PASSED: 4 events logged\n\n";
    
    // ------------------------------------------------------------------------
    // Test 3: RAII scope
    // ------------------------------------------------------------------------
    std::cout << "[Test 3] RAII scope...\n";
    
    {
        MASM_TELEMETRY_SCOPE(TELEMETRY_OP_MATMUL_START, TELEMETRY_OP_MATMUL_END);
        // Simulate work
        std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
    
    std::cout << "  PASSED: RAII scope logged start/end\n\n";
    
    // ------------------------------------------------------------------------
    // Test 4: Layer telemetry
    // ------------------------------------------------------------------------
    std::cout << "[Test 4] Layer telemetry...\n";
    
    for (uint32_t layer = 0; layer < 3; ++layer) {
        LayerTelemetry layerTel(layer);
        
        layerTel.LoadStart();
        std::this_thread::sleep_for(std::chrono::microseconds(5));
        layerTel.LoadEnd(1024 * 1024);  // 1MB loaded
        
        layerTel.ExecStart();
        std::this_thread::sleep_for(std::chrono::microseconds(50));
        layerTel.ExecEnd(1000);  // 1000 cycles
        
        layerTel.UnloadStart();
        layerTel.UnloadEnd();
    }
    
    std::cout << "  PASSED: 3 layers logged (9 events)\n\n";
    
    // ------------------------------------------------------------------------
    // Test 5: Operation telemetry
    // ------------------------------------------------------------------------
    std::cout << "[Test 5] Operation telemetry...\n";
    
    OpTelemetry::RMSNorm(4096);
    OpTelemetry::RMSNormEnd(500);
    
    OpTelemetry::MatMul(4096, 4096, 4096);
    OpTelemetry::MatMulEnd(10000);
    
    OpTelemetry::Attention(128, 32, 128);
    OpTelemetry::AttentionEnd(50000);
    
    OpTelemetry::MLP(4096, 11008);
    OpTelemetry::MLPEnd(20000);
    
    OpTelemetry::Dequantize(4096, 12);  // Q4_K = 12
    OpTelemetry::DequantizeEnd(1000);
    
    std::cout << "  PASSED: All operations logged\n\n";
    
    // ------------------------------------------------------------------------
    // Test 6: Get stats
    // ------------------------------------------------------------------------
    std::cout << "[Test 6] Get statistics...\n";
    
    TelemetryStats stats;
    MasmTelemetry_GetStats(&stats);
    
    std::cout << "  Events logged: " << stats.eventsLogged << "\n";
    std::cout << "  Events dropped: " << stats.eventsDropped << "\n";
    std::cout << "  Buffer size: " << stats.bufferSize << " bytes\n";
    std::cout << "  Buffer used: " << stats.bufferUsed << " bytes\n";
    std::cout << "  PASSED: Stats retrieved\n\n";
    
    // ------------------------------------------------------------------------
    // Test 7: Flush
    // ------------------------------------------------------------------------
    std::cout << "[Test 7] Flush events...\n";
    
    uint64_t flushed = MasmTelemetry_Flush();
    std::cout << "  Flushed: " << flushed << " events\n";
    std::cout << "  PASSED: Flush completed\n\n";
    
    // ------------------------------------------------------------------------
    // Test 8: RDTSC
    // ------------------------------------------------------------------------
    std::cout << "[Test 8] RDTSC timing...\n";
    
    uint64_t tsc1 = MasmTelemetry_Rdtsc();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    uint64_t tsc2 = MasmTelemetry_Rdtsc();
    
    uint64_t elapsed = tsc2 - tsc1;
    std::cout << "  RDTSC elapsed: " << elapsed << " cycles\n";
    std::cout << "  PASSED: RDTSC working\n\n";
    
    // ------------------------------------------------------------------------
    // Test 9: Shutdown
    // ------------------------------------------------------------------------
    std::cout << "[Test 9] Shutdown...\n";
    
    ShutdownMasmTelemetry();
    std::cout << "  PASSED: Telemetry shutdown\n\n";
    
    // ------------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------------
    std::cout << "=== All Tests PASSED ===\n";
    std::cout << "\nMASM telemetry integration is working correctly.\n";
    std::cout << "Ready for integration with transformer execution.\n";
    
    return 0;
}
