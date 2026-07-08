/**
 * @file test_simple.cpp
 * @brief Simple test to verify inference engine works
 */

#include <iostream>
#include "GGMLBackend.h"

using namespace RawrXD::Inference;

int main() {
    std::cout << "RawrXD Inference Engine Test" << std::endl;
    std::cout << "============================" << std::endl << std::endl;
    
    // Test 1: Create backend
    std::cout << "Test 1: Creating GGMLBackend..." << std::endl;
    GGMLBackendConfig config;
    config.backendType = GGMLBackendConfig::BackendType::CPU;
    config.maxContextSize = 512;
    config.tensorBufferSize = 64 * 1024 * 1024;  // 64MB
    
    auto backend = GGMLBackend::Create(config);
    if (!backend) {
        std::cerr << "FAILED: Could not create backend" << std::endl;
        return 1;
    }
    std::cout << "PASSED: Backend created" << std::endl << std::endl;
    
    // Test 2: Initialize backend
    std::cout << "Test 2: Initializing backend..." << std::endl;
    if (!backend->Initialize()) {
        std::cerr << "FAILED: Could not initialize backend: " << backend->GetLastError() << std::endl;
        return 1;
    }
    std::cout << "PASSED: Backend initialized (type: " << backend->GetBackendType() << ")" << std::endl << std::endl;
    
    // Test 3: Check initial state
    std::cout << "Test 3: Checking initial state..." << std::endl;
    if (backend->IsModelLoaded()) {
        std::cerr << "FAILED: Model should not be loaded initially" << std::endl;
        return 1;
    }
    std::cout << "PASSED: No model loaded (as expected)" << std::endl << std::endl;
    
    // Test 4: Try to load non-existent model
    std::cout << "Test 4: Loading non-existent model..." << std::endl;
    if (backend->LoadModel("/nonexistent/model.gguf")) {
        std::cerr << "FAILED: Should not load non-existent model" << std::endl;
        return 1;
    }
    std::string error = backend->GetLastError();
    std::cout << "PASSED: Correctly failed to load (error: " << (error.empty() ? "none" : error.substr(0, 50)) << "...)" << std::endl << std::endl;
    
    // Test 5: Context management
    std::cout << "Test 5: Context management..." << std::endl;
    backend->ClearKVCache();
    size_t ctxLen = backend->GetContextLength();
    size_t maxLen = backend->GetMaxContextLength();
    std::cout << "PASSED: Context length=" << ctxLen << ", max=" << maxLen << std::endl << std::endl;
    
    // Test 6: Token sampling (dummy)
    std::cout << "Test 6: Token sampling..." << std::endl;
    std::vector<float> dummyLogits(1000, 0.0f);
    for (int i = 0; i < 1000; i++) {
        dummyLogits[i] = static_cast<float>(i) / 100.0f;
    }
    
    int token = backend->SampleToken(dummyLogits, 1.0f, 40, 0.9f, 1.0f);
    if (token < 0 || token >= 1000) {
        std::cerr << "FAILED: Sampled token out of range: " << token << std::endl;
        return 1;
    }
    std::cout << "PASSED: Sampled token=" << token << std::endl << std::endl;
    
    // Test 7: Shutdown
    std::cout << "Test 7: Shutdown..." << std::endl;
    backend->Shutdown();
    if (backend->IsInitialized()) {
        std::cerr << "FAILED: Backend still initialized after shutdown" << std::endl;
        return 1;
    }
    std::cout << "PASSED: Backend shutdown" << std::endl << std::endl;
    
    std::cout << "============================" << std::endl;
    std::cout << "All tests PASSED!" << std::endl;
    
    return 0;
}
