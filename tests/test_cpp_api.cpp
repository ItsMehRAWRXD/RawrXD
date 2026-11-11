// tests/test_cpp_api.cpp
// Test: C++ API wrapper functionality
#include "RawrXDCore.h"
#include <iostream>
#include <string>
#include <functional>
#include <cassert>

using namespace rawrxd;

void logCallback(RawrXDLogLevel level, const char* message, void* userData) {
    const char* levelStr[] = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
    std::cout << "[" << levelStr[level] << "] " << message << std::endl;
}

int main() {
    std::cout << "=== Test: C++ API ===" << std::endl;
    
    // Test Core static methods
    Core::SetLogCallback(logCallback);
    Core::SetLogLevel(RAWRXD_LOG_DEBUG);
    
    assert(Core::Initialize() == true);
    std::cout << "C++ Core initialized: " << Core::GetVersion() << std::endl;
    
    // Test Config
    Core::Config config;
    config.enableVulkan = true;
    config.enableMASM = true;
    config.workerThreadCount = 4;
    config.maxMemoryMB = 2048;
    
    assert(Core::Initialize(&config) == true);
    std::cout << "Configured with custom settings" << std::endl;
    
    // Test Model
    Core::Model model("models/test.gguf");
    assert(static_cast<bool>(model) == true);
    std::cout << "Model loaded: " << model.name() << std::endl;
    std::cout << "  Size: " << model.size() / (1024*1024) << " MB" << std::endl;
    std::cout << "  Layers: " << model.layerCount() << std::endl;
    
    // Test move semantics
    Core::Model model2 = std::move(model);
    assert(static_cast<bool>(model) == false);
    assert(static_cast<bool>(model2) == true);
    std::cout << "Move semantics work" << std::endl;
    
    // Test InferenceContext
    Core::InferenceContext ctx(model2);
    assert(static_cast<bool>(ctx) == true);
    std::cout << "Inference context created" << std::endl;
    
    // Test inference run
    RawrXDInferenceParams params;
    RawrXDCore_GetDefaultInferenceParams(&params);
    params.maxTokens = 5;
    params.temperature = 0.5f;
    
    int tokens = ctx.run("Test prompt", params, [](int id, const char* text) {
        std::cout << "  Token " << id << ": '" << text << "'" << std::endl;
        return true;
    });
    
    assert(tokens > 0);
    std::cout << "Generated " << tokens << " tokens" << std::endl;
    
    // Test move semantics for context
    Core::InferenceContext ctx2 = std::move(ctx);
    assert(static_cast<bool>(ctx) == false);
    assert(static_cast<bool>(ctx2) == true);
    std::cout << "Context move semantics work" << std::endl;
    
    // Test hardware caps
    RawrXDHardwareCaps caps;
    Core::GetHardwareCaps(caps);
    std::cout << "CPU Cores: " << caps.cpuCoreCount << std::endl;
    std::cout << "GPU Count: " << caps.gpuCount << std::endl;
    
    // Test memory stats
    RawrXDMemoryStats stats;
    Core::GetMemoryStats(stats);
    std::cout << "Memory allocated: " << stats.totalAllocated / (1024*1024) << " MB" << std::endl;
    
    Core::TrimMemory();
    std::cout << "Memory trimmed" << std::endl;
    
    // Test error handling
    assert(Core::GetLastError() == RAWXD_OK);
    std::cout << "Last error: " << Core::GetErrorString(Core::GetLastError()) << std::endl;
    
    Core::Shutdown();
    std::cout << "=== PASSED ===" << std::endl;
    return 0;
}