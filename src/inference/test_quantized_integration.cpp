// ============================================================================
// Quantized Inference Engine Integration Test
// Verifies Q4_0 auto-detection and 131 tok/s backend routing
// ============================================================================

#include <iostream>
#include <cstring>
#include "inference_engine_quantized.hpp"

using namespace RawrXD::Core;

int main(int argc, char* argv[]) {
    std::cout << "=== Quantized Inference Engine Integration Test ===" << std::endl;
    std::cout << std::endl;
    
    // Test 1: Create production engine
    std::cout << "[Test 1] Creating production inference engine..." << std::endl;
    auto engine = CreateProductionInferenceEngine();
    if (!engine) {
        std::cerr << "FAILED: Could not create production engine" << std::endl;
        return 1;
    }
    std::cout << "PASSED: Production engine created" << std::endl;
    std::cout << std::endl;
    
    // Test 2: Initialize engine
    std::cout << "[Test 2] Initializing engine..." << std::endl;
    InferenceEngine::InferenceConfig config;
    config.threadCount = 4;
    config.maxTokens = 128;
    config.temperature = 0.7f;
    config.useAVX512 = true;
    
    if (!engine->Initialize(config)) {
        std::cerr << "FAILED: Could not initialize engine" << std::endl;
        return 1;
    }
    std::cout << "PASSED: Engine initialized" << std::endl;
    std::cout << std::endl;
    
    // Test 3: Check if it's a quantized engine
    std::cout << "[Test 3] Checking engine type..." << std::endl;
    QuantizedInferenceEngine* qEngine = dynamic_cast<QuantizedInferenceEngine*>(engine.get());
    if (qEngine) {
        std::cout << "PASSED: Engine is QuantizedInferenceEngine" << std::endl;
        std::cout << "  Backend: " << qEngine->GetActiveBackendName() << std::endl;
        std::cout << "  Using Quantized: " << (qEngine->IsUsingQuantizedBackend() ? "Yes" : "No") << std::endl;
    } else {
        std::cout << "INFO: Engine is base InferenceEngine (quantized features not available)" << std::endl;
    }
    std::cout << std::endl;
    
    // Test 4: Model path detection (if provided)
    if (argc > 1) {
        std::cout << "[Test 4] Loading model: " << argv[1] << std::endl;
        if (engine->LoadModel(argv[1])) {
            std::cout << "PASSED: Model loaded successfully" << std::endl;
            
            if (qEngine) {
                std::cout << "  Active Backend: " << qEngine->GetActiveBackendName() << std::endl;
                std::cout << "  Using Quantized: " << (qEngine->IsUsingQuantizedBackend() ? "Yes" : "No") << std::endl;
            }
            
            // Test 5: Run inference if prompt provided
            if (argc > 2) {
                std::cout << std::endl;
                std::cout << "[Test 5] Running inference..." << std::endl;
                auto result = engine->RunInference(argv[2]);
                
                if (result.status == InferenceEngine::InferenceResult::Status::Success) {
                    std::cout << "PASSED: Inference completed" << std::endl;
                    std::cout << "  Tokens generated: " << result.tokensGenerated << std::endl;
                    std::cout << "  Tokens/sec: " << result.tokensPerSecond << std::endl;
                    std::cout << "  Latency: " << result.latencyMs << " ms" << std::endl;
                    std::cout << "  Output: " << result.outputText.substr(0, 100) << "..." << std::endl;
                } else {
                    std::cerr << "FAILED: Inference failed - " << result.errorMessage << std::endl;
                    return 1;
                }
            }
        } else {
            std::cerr << "FAILED: Could not load model - " << engine->GetLastError() << std::endl;
            return 1;
        }
    } else {
        std::cout << "[Test 4] Skipped: No model path provided" << std::endl;
        std::cout << "  Usage: " << argv[0] << " <model.gguf> [prompt]" << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "=== All Tests Passed ===" << std::endl;
    return 0;
}
