// ============================================================================
// Telemetry-Only Test - Demonstrates MASM Telemetry Core
// ============================================================================
// Runs without requiring a model file - just shows telemetry working
// ============================================================================

#include "../runtime/telemetry_masm_bridge.hpp"
#include "../runtime/telemetry_ids.hpp"
#include <iostream>
#include <chrono>
#include <thread>

using namespace RawrXD::Runtime;
using namespace RawrXD::Runtime::Telemetry;

int main() {
    std::cout << "=== MASM Telemetry Core Test ===\n\n";
    
    // Initialize telemetry with 1MB buffer
    std::cout << "[1/5] Initializing MASM telemetry...\n";
    if (!InitializeMasmTelemetry(1024 * 1024)) {
        std::cerr << "FAILED: Could not initialize telemetry\n";
        return 1;
    }
    std::cout << "      ✓ Telemetry initialized (1MB buffer)\n\n";
    
    // Get initial stats
    TelemetryStats stats;
    MasmTelemetry_GetStats(&stats);
    std::cout << "[2/5] Initial stats:\n";
    std::cout << "      Events logged:  " << stats.eventsLogged << "\n";
    std::cout << "      Events dropped: " << stats.eventsDropped << "\n";
    std::cout << "      Buffer size:    " << (stats.bufferSize / 1024) << " KB\n";
    std::cout << "      Buffer used:    " << (stats.bufferUsed / 1024) << " KB\n\n";
    
    // Log some events
    std::cout << "[3/5] Logging telemetry events...\n";
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Simulate transformer operations with telemetry
    for (int layer = 0; layer < 4; ++layer) {
        // Layer start
        MasmTelemetry_Log(TELEMETRY_LAYER_START, layer, 0);
        
        // RMSNorm
        MasmTelemetry_Log(TELEMETRY_RMSNORM_START, 4096, 0);
        std::this_thread::sleep_for(std::chrono::microseconds(10));
        MasmTelemetry_Log(TELEMETRY_RMSNORM_END, layer, 0);
        
        // Attention
        MasmTelemetry_Log(TELEMETRY_ATTENTION_START, layer, 0);
        MasmTelemetry_Log(TELEMETRY_ATTENTION_QKV, 4096, 32);  // hidden=4096, heads=32
        std::this_thread::sleep_for(std::chrono::microseconds(50));
        MasmTelemetry_Log(TELEMETRY_ATTENTION_END, layer, 0);
        
        // MLP
        MasmTelemetry_Log(TELEMETRY_MLP_START, layer, 0);
        MasmTelemetry_Log(TELEMETRY_MLP_GATE, 4096, 11008);  // hidden=4096, intermediate=11008
        std::this_thread::sleep_for(std::chrono::microseconds(30));
        MasmTelemetry_Log(TELEMETRY_MLP_END, layer, 0);
        
        // Layer end
        MasmTelemetry_Log(TELEMETRY_LAYER_END, layer, 0);
    }
    
    // Generation events
    MasmTelemetry_Log(TELEMETRY_GENERATION_START, 0, 0);
    for (int token = 0; token < 5; ++token) {
        MasmTelemetry_Log(TELEMETRY_GENERATION_TOKEN, token, 0);
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    MasmTelemetry_Log(TELEMETRY_GENERATION_END, 5, 0);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "      ✓ Logged events in " << duration.count() << " ms\n\n";
    
    // Get final stats
    std::cout << "[4/5] Final stats:\n";
    MasmTelemetry_GetStats(&stats);
    std::cout << "      Events logged:  " << stats.eventsLogged << "\n";
    std::cout << "      Events dropped: " << stats.eventsDropped << "\n";
    std::cout << "      Buffer used:    " << (stats.bufferUsed / 1024.0) << " KB\n";
    std::cout << "      Events/sec:     " << (stats.eventsLogged * 1000.0 / duration.count()) << "\n\n";
    
    // Flush telemetry
    std::cout << "[5/5] Flushing telemetry...\n";
    uint64_t flushed = MasmTelemetry_Flush();
    std::cout << "      ✓ Flushed " << flushed << " events\n\n";
    
    // Shutdown
    ShutdownMasmTelemetry();
    std::cout << "=== Test Complete ===\n";
    
    return 0;
}
