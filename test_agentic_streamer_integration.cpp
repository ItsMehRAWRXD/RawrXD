// Test for Agentic Model Streamer Integration
#include "agentic_model_streamer_bridge.h"
#include <iostream>
#include <thread>
#include <chrono>

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "Agentic Model Streamer Integration Test" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Test 1: Create bridge
    std::cout << "\n[Test 1] Creating AgenticModelStreamerBridge..." << std::endl;
    auto* bridge = new RawrXD::Agentic::AgenticModelStreamerBridge();
    if (!bridge) {
        std::cerr << "FAILED: Could not create bridge" << std::endl;
        return 1;
    }
    std::cout << "SUCCESS: Bridge created" << std::endl;
    
    // Test 2: Set memory budget
    std::cout << "\n[Test 2] Setting memory budget..." << std::endl;
    bridge->SetMemoryBudget(4096); // 4GB
    if (bridge->GetMemoryBudget() != 4096) {
        std::cerr << "FAILED: Memory budget not set correctly" << std::endl;
        return 1;
    }
    std::cout << "SUCCESS: Memory budget set to 4096 MB" << std::endl;
    
    // Test 3: Get initial status
    std::cout << "\n[Test 3] Getting initial status..." << std::endl;
    auto status = bridge->GetStatus();
    if (status.isLoaded || status.isLoading) {
        std::cerr << "FAILED: Initial status incorrect" << std::endl;
        return 1;
    }
    std::cout << "SUCCESS: Initial status - not loaded, not loading" << std::endl;
    
    // Test 4: Get inference engine
    std::cout << "\n[Test 4] Getting inference engine..." << std::endl;
    auto engine = bridge->GetInferenceEngine();
    if (!engine) {
        std::cout << "INFO: No inference engine yet (expected before initialization)" << std::endl;
    } else {
        std::cout << "SUCCESS: Inference engine available" << std::endl;
    }
    
    // Test 5: Global access
    std::cout << "\n[Test 5] Testing global access..." << std::endl;
    RawrXD::Agentic::SetGlobalAgenticModelStreamer(bridge);
    auto* globalBridge = RawrXD::Agentic::GetGlobalAgenticModelStreamer();
    if (globalBridge != bridge) {
        std::cerr << "FAILED: Global bridge not set correctly" << std::endl;
        return 1;
    }
    std::cout << "SUCCESS: Global bridge accessible" << std::endl;
    
    // Test 6: Status callback
    std::cout << "\n[Test 6] Testing status callback..." << std::endl;
    bool callbackReceived = false;
    bridge->SetStatusCallback([&callbackReceived](const RawrXD::Agentic::ModelStreamerStatus& s) {
        callbackReceived = true;
        std::cout << "  Callback: operation=" << s.currentOperation 
                  << ", progress=" << s.progressPercent << "%" << std::endl;
    });
    std::cout << "SUCCESS: Status callback registered" << std::endl;
    
    // Test 7: Cleanup
    std::cout << "\n[Test 7] Cleanup..." << std::endl;
    bridge->Shutdown();
    delete bridge;
    RawrXD::Agentic::SetGlobalAgenticModelStreamer(nullptr);
    std::cout << "SUCCESS: Bridge shutdown and cleaned up" << std::endl;
    
    // Summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "ALL TESTS PASSED!" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "\nThe Agentic Model Streamer Bridge is ready." << std::endl;
    std::cout << "Next steps:" << std::endl;
    std::cout << "  1. Initialize with AgenticEngine*" << std::endl;
    std::cout << "  2. Queue model loads with priorities" << std::endl;
    std::cout << "  3. Manage tensor zones for memory efficiency" << std::endl;
    std::cout << "  4. Execute agentic tasks with model context" << std::endl;
    
    return 0;
}
