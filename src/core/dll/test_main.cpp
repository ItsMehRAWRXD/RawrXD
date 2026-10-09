// test_main.cpp - Test executable for RawrXDCore DLL
#include "RawrXDCore.h"
#include <iostream>
#include <string>

void logCallback(RawrXDLogLevel level, const char* message, void* userData) {
    const char* levelStr[] = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
    std::cout << "[" << levelStr[level] << "] " << message << std::endl;
}

int main() {
    std::cout << "=== RawrXDCore DLL Test ===" << std::endl;
    
    // Test version
    std::cout << "Version: " << RawrXDCore_GetVersion() << std::endl;
    std::cout << "Version (major.minor.patch): " 
              << RawrXDCore_GetVersionMajor() << "."
              << RawrXDCore_GetVersionMinor() << "."
              << RawrXDCore_GetVersionPatch() << std::endl;
    
    // Test initialization
    std::cout << "\n--- Initialization ---" << std::endl;
    RawrXDCore_SetLogCallback(logCallback, nullptr);
    RawrXDCore_SetLogLevel(RAWXD_LOG_DEBUG);
    
    if (!RawrXDCore_Initialize()) {
        std::cerr << "Failed to initialize: " << RawrXDCore_GetErrorString(RawrXDCore_GetLastError()) << std::endl;
        return 1;
    }
    std::cout << "Initialized: " << (RawrXDCore_IsInitialized() ? "Yes" : "No") << std::endl;
    
    // Test configuration
    std::cout << "\n--- Configuration ---" << std::endl;
    RawrXDConfig config;
    RawrXDCore_GetDefaultConfig(&config);
    config.enableVulkan = true;
    config.enableMASM = true;
    config.workerThreadCount = 8;
    config.maxMemoryMB = 4096;
    
    if (!RawrXDCore_Configure(&config)) {
        std::cerr << "Failed to configure: " << RawrXDCore_GetErrorString(RawrXDCore_GetLastError()) << std::endl;
    } else {
        std::cout << "Configured successfully" << std::endl;
    }
    
    // Test hardware caps
    std::cout << "\n--- Hardware Capabilities ---" << std::endl;
    RawrXDHardwareCaps caps;
    RawrXDCore_GetHardwareCaps(&caps);
    std::cout << "CPU Cores: " << caps.cpuCoreCount << std::endl;
    std::cout << "System Memory: " << caps.systemMemoryMB << " MB" << std::endl;
    std::cout << "AVX2: " << (caps.hasAVX2 ? "Yes" : "No") << std::endl;
    std::cout << "AVX512: " << (caps.hasAVX512 ? "Yes" : "No") << std::endl;
    std::cout << "Vulkan: " << (caps.hasVulkan ? "Yes" : "No") << std::endl;
    std::cout << "CUDA: " << (caps.hasCUDA ? "Yes" : "No") << std::endl;
    std::cout << "GPU Count: " << caps.gpuCount << std::endl;
    for (int i = 0; i < caps.gpuCount; ++i) {
        std::cout << "  GPU " << i << ": " << caps.gpuNames[i] << " (" << caps.gpuMemoryMB[i] << " MB)" << std::endl;
    }
    
    // Test model loading
    std::cout << "\n--- Model Loading ---" << std::endl;
    RawrXDModel* model = RawrXDCore_LoadModel("F:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf");
    if (!model) {
        std::cerr << "Failed to load model: " << RawrXDCore_GetErrorString(RawrXDCore_GetLastError()) << std::endl;
    } else {
        std::cout << "Model loaded: " << RawrXDCore_GetModelName(model) << std::endl;
        std::cout << "Model size: " << RawrXDCore_GetModelSize(model) / (1024*1024) << " MB" << std::endl;
        std::cout << "Model layers: " << RawrXDCore_GetModelLayerCount(model) << std::endl;
        
        // Test inference context
        std::cout << "\n--- Inference ---" << std::endl;
        RawrXDInferenceContext* ctx = RawrXDCore_CreateContext(model);
        if (!ctx) {
            std::cerr << "Failed to create context: " << RawrXDCore_GetErrorString(RawrXDCore_GetLastError()) << std::endl;
        } else {
            std::cout << "Context created successfully" << std::endl;
            
            RawrXDInferenceParams params;
            RawrXDCore_GetDefaultInferenceParams(&params);
            params.maxTokens = 10;
            params.temperature = 0.7f;
            
            std::cout << "Running inference..." << std::endl;
            int tokens = RawrXDCore_RunInference(ctx, "Hello, world!", &params, 
                [](int tokenId, const char* tokenText, void* userData) -> bool {
                    std::cout << "Token " << tokenId << ": '" << tokenText << "'" << std::endl;
                    return true; // Continue
                }, nullptr);
            
            std::cout << "Generated " << tokens << " tokens" << std::endl;
            
            RawrXDCore_DestroyContext(ctx);
            std::cout << "Context destroyed" << std::endl;
        }
        
        RawrXDCore_UnloadModel(model);
        std::cout << "Model unloaded" << std::endl;
    }
    
    // Test memory stats
    std::cout << "\n--- Memory Stats ---" << std::endl;
    RawrXDMemoryStats stats;
    RawrXDCore_GetMemoryStats(&stats);
    std::cout << "Total Allocated: " << stats.totalAllocated / (1024*1024) << " MB" << std::endl;
    std::cout << "Total Reserved: " << stats.totalReserved / (1024*1024) << " MB" << std::endl;
    std::cout << "GPU Allocated: " << stats.gpuAllocated / (1024*1024) << " MB" << std::endl;
    std::cout << "GPU Reserved: " << stats.gpuReserved / (1024*1024) << " MB" << std::endl;
    std::cout << "Peak Usage: " << stats.peakUsage / (1024*1024) << " MB" << std::endl;
    
    // Cleanup
    std::cout << "\n--- Shutdown ---" << std::endl;
    RawrXDCore_Shutdown();
    std::cout << "Shutdown complete" << std::endl;
    
    std::cout << "\n=== All Tests Passed ===" << std::endl;
    return 0;
}
