// tests/test_win32ide_integration.cpp
// Test: Win32IDE integration with RawrXDCore DLL
#include "RawrXDCore.h"
#include <iostream>
#include <string>
#include <cassert>

int main() {
    std::cout << "=== Test: Win32IDE Integration ===" << std::endl;
    
    assert(RawrXDCore_Initialize() == true);
    std::cout << "RawrXDCore initialized for Win32IDE" << std::endl;
    
    // Test configuration for IDE
    RawrXDConfig config;
    RawrXDCore_GetDefaultConfig(&config);
    config.enableVulkan = true;        // GPU rendering
    config.enableMASM = true;          // Assembly kernels
    config.enableTelemetry = true;     // IDE telemetry
    config.workerThreadCount = 8;      // Background workers
    config.maxMemoryMB = 4096;         // 4GB limit
    
    assert(RawrXDCore_Configure(&config) == true);
    std::cout << "IDE configuration applied" << std::endl;
    
    // Test model management for IDE (multiple models)
    RawrXDModel* model1 = RawrXDCore_LoadModel("models/qwen2.5-7b-instruct-q4_k_m.gguf");
    RawrXDModel* model2 = RawrXDCore_LoadModel("models/codellama-13b-instruct-q4_k_m.gguf");
    RawrXDModel* model3 = RawrXDCore_LoadModel("models/phi-3-mini-4k-instruct-q4_k_m.gguf");
    
    assert(model1 != nullptr);
    assert(model2 != nullptr);
    assert(model3 != nullptr);
    
    std::cout << "Models loaded:" << std::endl;
    std::cout << "  1: " << RawrXDCore_GetModelName(model1) << " (" 
              << RawrXDCore_GetModelLayerCount(model1) << " layers)" << std::endl;
    std::cout << "  2: " << RawrXDCore_GetModelName(model2) << " (" 
              << RawrXDCore_GetModelLayerCount(model2) << " layers)" << std::endl;
    std::cout << "  3: " << RawrXDCore_GetModelName(model3) << " (" 
              << RawrXDCore_GetModelLayerCount(model3) << " layers)" << std::endl;
    
    // Test concurrent contexts (simulating multiple editor tabs)
    RawrXDInferenceContext* ctx1 = RawrXDCore_CreateContext(model1);
    RawrXDInferenceContext* ctx2 = RawrXDCore_CreateContext(model2);
    RawrXDInferenceContext* ctx3 = RawrXDCore_CreateContext(model3);
    
    assert(ctx1 != nullptr);
    assert(ctx2 != nullptr);
    assert(ctx3 != nullptr);
    std::cout << "3 concurrent inference contexts created" << std::endl;
    
    // Simulate tab switching - use different contexts
    RawrXDInferenceParams params;
    RawrXDCore_GetDefaultInferenceParams(&params);
    params.maxTokens = 5;
    
    // Tab 1: Code completion
    int tokens1 = RawrXDCore_RunInference(ctx1, "void foo() {", &params,
        [](int, const char*, void*) { return true; }, nullptr);
    std::cout << "  Tab 1 (code completion): " << tokens1 << " tokens" << std::endl;
    
    // Tab 2: Chat
    int tokens2 = RawrXDCore_RunInference(ctx2, "Explain this code:", &params,
        [](int, const char*, void*) { return true; }, nullptr);
    std::cout << "  Tab 2 (chat): " << tokens2 << " tokens" << std::endl;
    
    // Tab 3: Refactoring
    int tokens3 = RawrXDCore_RunInference(ctx3, "Refactor:", &params,
        [](int, const char*, void*) { return true; }, nullptr);
    std::cout << "  Tab 3 (refactoring): " << tokens3 << " tokens" << std::endl;
    
    // Test hardware caps for IDE UI
    RawrXDHardwareCaps caps;
    RawrXDCore_GetHardwareCaps(&caps);
    std::cout << "Hardware caps for IDE UI:" << std::endl;
    std::cout << "  CPU: " << caps.cpuCoreCount << " cores" << std::endl;
    std::cout << "  RAM: " << caps.systemMemoryMB << " MB" << std::endl;
    std::cout << "  GPUs: " << caps.gpuCount << std::endl;
    for (int i = 0; i < caps.gpuCount; ++i) {
        std::cout << "    GPU " << i << ": " << caps.gpuNames[i] 
                  << " (" << caps.gpuMemoryMB[i] << " MB)" << std::endl;
    }
    
    // Test memory monitoring
    RawrXDMemoryStats stats;
    RawrXDCore_GetMemoryStats(&stats);
    std::cout << "Memory stats:" << std::endl;
    std::cout << "  Allocated: " << stats.totalAllocated / (1024*1024) << " MB" << std::endl;
    std::cout << "  GPU Allocated: " << stats.gpuAllocated / (1024*1024) << " MB" << std::endl;
    
    // Cleanup
    RawrXDCore_DestroyContext(ctx1);
    RawrXDCore_DestroyContext(ctx2);
    RawrXDCore_DestroyContext(ctx3);
    std::cout << "Contexts destroyed" << std::endl;
    
    RawrXDCore_UnloadModel(model1);
    RawrXDCore_UnloadModel(model2);
    RawrXDCore_UnloadModel(model3);
    std::cout << "Models unloaded" << std::endl;
    
    RawrXDCore_Shutdown();
    std::cout << "=== PASSED ===" << std::endl;
    return 0;
}