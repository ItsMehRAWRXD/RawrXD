// tests/test_cross_config.cpp
// Test: Cross-configuration compatibility (Debug DLL with Release EXE, etc.)
#include "RawrXDCore.h"
#include <iostream>
#include <cassert>

int main() {
    std::cout << "=== Test: Cross-Configuration Compatibility ===" << std::endl;
    
    // This test verifies that the DLL can be used from executables
    // built with different configurations, as long as the runtime matches
    // (/MD with /MD, /MDd with /MDd)
    
    assert(RawrXDCore_Initialize() == true);
    std::cout << "Core initialized" << std::endl;
    
    // Test that all basic operations work
    RawrXDConfig config;
    RawrXDCore_GetDefaultConfig(&config);
    config.workerThreadCount = 4;
    assert(RawrXDCore_Configure(&config) == true);
    std::cout << "Configuration works" << std::endl;
    
    // Test model operations
    RawrXDModel* model = RawrXDCore_LoadModel("cross_config_test.gguf");
    assert(model != nullptr);
    std::cout << "Model load works" << std::endl;
    
    RawrXDInferenceContext* ctx = RawrXDCore_CreateContext(model);
    assert(ctx != nullptr);
    std::cout << "Context creation works" << std::endl;
    
    RawrXDInferenceParams params;
    RawrXDCore_GetDefaultInferenceParams(&params);
    params.maxTokens = 3;
    
    int tokens = RawrXDCore_RunInference(ctx, "cross config test", &params,
        [](int id, const char* text, void*) -> bool {
            std::cout << "  Token " << id << ": " << text << std::endl;
            return true;
        }, nullptr);
    
    assert(tokens > 0);
    std::cout << "Inference works (" << tokens << " tokens)" << std::endl;
    
    // Test memory stats
    RawrXDMemoryStats stats;
    RawrXDCore_GetMemoryStats(&stats);
    assert(stats.totalAllocated > 0);
    std::cout << "Memory stats work" << std::endl;
    
    // Test hardware caps
    RawrXDHardwareCaps caps;
    RawrXDCore_GetHardwareCaps(&caps);
    assert(caps.cpuCoreCount > 0);
    std::cout << "Hardware caps work" << std::endl;
    
    // Test error handling
    RawrXDError err = RawrXDCore_GetLastError();
    assert(err == RAWXD_OK);
    const char* errStr = RawrXDCore_GetErrorString(err);
    assert(errStr != nullptr);
    std::cout << "Error handling works" << std::endl;
    
    // Cleanup
    RawrXDCore_DestroyContext(ctx);
    RawrXDCore_UnloadModel(model);
    RawrXDCore_Shutdown();
    
    std::cout << "=== PASSED ===" << std::endl;
    return 0;
}