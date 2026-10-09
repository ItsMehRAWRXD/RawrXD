// tests/test_inference_integration.cpp
// Test: Inference Engine integration with RawrXDCore DLL
#include "RawrXDCore.h"
#include <iostream>
#include <string>
#include <vector>
#include <cassert>

int main() {
    std::cout << "=== Test: Inference Engine Integration ===" << std::endl;
    
    assert(RawrXDCore_Initialize() == true);
    std::cout << "RawrXDCore initialized" << std::endl;
    
    // Load a model
    RawrXDModel* model = RawrXDCore_LoadModel("models/qwen2.5-7b-instruct-q4_k_m.gguf");
    assert(model != nullptr);
    std::cout << "Model loaded: " << RawrXDCore_GetModelName(model) << std::endl;
    
    // Create inference context
    RawrXDInferenceContext* ctx = RawrXDCore_CreateContext(model);
    assert(ctx != nullptr);
    std::cout << "Inference context created" << std::endl;
    
    // Test different inference parameters
    struct TestCase {
        const char* name;
        float temperature;
        int topK;
        float topP;
        int maxTokens;
    };
    
    TestCase testCases[] = {
        {"Deterministic", 0.0f, 1, 1.0f, 10},
        {"Creative", 1.0f, 50, 0.9f, 20},
        {"Balanced", 0.7f, 40, 0.9f, 15},
        {"Focused", 0.3f, 10, 0.5f, 10}
    };
    
    for (const auto& tc : testCases) {
        RawrXDInferenceParams params;
        RawrXDCore_GetDefaultInferenceParams(&params);
        params.temperature = tc.temperature;
        params.topK = tc.topK;
        params.topP = tc.topP;
        params.maxTokens = tc.maxTokens;
        
        std::vector<std::string> generatedTokens;
        int tokenCount = RawrXDCore_RunInference(ctx, "Test prompt for inference", &params,
            [](int tokenId, const char* tokenText, void* userData) -> bool {
                auto* vec = static_cast<std::vector<std::string>*>(userData);
                vec->push_back(tokenText);
                return true;
            },
            &generatedTokens
        );
        
        assert(tokenCount > 0);
        assert(tokenCount <= tc.maxTokens);
        std::cout << "  " << tc.name << ": " << tokenCount << " tokens generated" << std::endl;
    }
    
    // Test GPU/CPU switching
    RawrXDInferenceParams gpuParams;
    RawrXDCore_GetDefaultInferenceParams(&gpuParams);
    gpuParams.useGPU = true;
    gpuParams.gpuDeviceId = 0;
    gpuParams.maxTokens = 5;
    
    int gpuTokens = RawrXDCore_RunInference(ctx, "GPU test", &gpuParams,
        [](int, const char*, void*) { return true; }, nullptr);
    std::cout << "  GPU inference: " << gpuTokens << " tokens" << std::endl;
    
    RawrXDInferenceParams cpuParams;
    RawrXDCore_GetDefaultInferenceParams(&cpuParams);
    cpuParams.useGPU = false;
    cpuParams.maxTokens = 5;
    
    int cpuTokens = RawrXDCore_RunInference(ctx, "CPU test", &cpuParams,
        [](int, const char*, void*) { return true; }, nullptr);
    std::cout << "  CPU inference: " << cpuTokens << " tokens" << std::endl;
    
    // Test callback cancellation
    int cancelTokens = RawrXDCore_RunInference(ctx, "Cancel test", &gpuParams,
        [](int tokenId, const char*, void*) -> bool {
            return tokenId < 3; // Cancel after 3 tokens
        }, nullptr);
    assert(cancelTokens == 3);
    std::cout << "  Callback cancellation works (3 tokens)" << std::endl;
    
    // Cleanup
    RawrXDCore_DestroyContext(ctx);
    std::cout << "Context destroyed" << std::endl;
    
    RawrXDCore_UnloadModel(model);
    std::cout << "Model unloaded" << std::endl;
    
    RawrXDCore_Shutdown();
    std::cout << "=== PASSED ===" << std::endl;
    return 0;
}