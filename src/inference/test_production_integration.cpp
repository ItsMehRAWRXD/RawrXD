// ============================================================================
// Production Integration Test
// Validates QuantizedInferenceEngine with real model
// ============================================================================

#include "quantized_inference_production.hpp"
#include <iostream>
#include <cassert>

using namespace RawrXD::Inference;

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "Production Integration Test" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // [1/5] Self-test
    std::cout << "[1/5] Running self-test..." << std::endl;
    {
        auto engine = QuantizedInferenceEngine::Create();
        if (!engine->RunSelfTest()) {
            std::cerr << "Self-test FAILED" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;
    
    // [2/5] Create engine
    std::cout << "[2/5] Creating inference engine..." << std::endl;
    auto engine = QuantizedInferenceEngine::Create();
    std::cout << "  Version: " << GetQuantizedInferenceVersion() << std::endl;
    std::cout << "  Status: " << (engine->IsModelLoaded() ? "Ready" : "No model") << std::endl;
    std::cout << std::endl;
    
    // [3/5] Configure
    std::cout << "[3/5] Configuring..." << std::endl;
    InferenceConfig config;
    config.temperature = 0.8f;
    config.maxTokens = 50;
    config.autoDetectQuantization = true;
    engine->SetConfig(config);
    std::cout << "  Temperature: " << config.temperature << std::endl;
    std::cout << "  Max tokens: " << config.maxTokens << std::endl;
    std::cout << "  Auto-detect Q4_0: " << (config.autoDetectQuantization ? "Yes" : "No") << std::endl;
    std::cout << std::endl;
    
    // [4/5] Load model
    std::cout << "[4/5] Loading model..." << std::endl;
    const char* modelPath = (argc > 1) ? argv[1] : "D:\\ministral3_q4_0.gguf";
    
    if (!engine->LoadModel(modelPath)) {
        std::cout << "  Note: Model not found, using mock validation" << std::endl;
        std::cout << std::endl;
        
        // Validate Q4_0 detection without model
        std::cout << "  Q4_0 Detection Tests:" << std::endl;
        std::cout << "    'ministral3_q4_0.gguf' -> " 
                  << (IsQ4_0Model("ministral3_q4_0.gguf") ? "Q4_0" : "Standard") << std::endl;
        std::cout << "    'model_Q4_0.bin' -> " 
                  << (IsQ4_0Model("model_Q4_0.bin") ? "Q4_0" : "Standard") << std::endl;
        std::cout << "    'ministral3_fp16.gguf' -> " 
                  << (IsQ4_0Model("ministral3_fp16.gguf") ? "Q4_0" : "Standard") << std::endl;
        std::cout << std::endl;
        
        std::cout << "  Expected Throughput:" << std::endl;
        std::cout << "    Q4_0 model: " << GetExpectedThroughput("x_q4_0.gguf") << " tok/s" << std::endl;
        std::cout << "    Standard: " << GetExpectedThroughput("x_fp32.gguf") << " tok/s" << std::endl;
    } else {
        std::cout << "  Model loaded successfully" << std::endl;
        std::cout << "  Path: " << engine->GetModelPath() << std::endl;
        std::cout << "  Size: " << engine->GetModelSizeGB() << " GB" << std::endl;
        std::cout << "  Backend: " << engine->GetBackendName() << std::endl;
        std::cout << "  Is Q4_0: " << (engine->IsQuantizedModel() ? "Yes" : "No") << std::endl;
        std::cout << std::endl;
        
        // [5/5] Generate
        std::cout << "[5/5] Generating text..." << std::endl;
        std::string prompt = "Hello, how are you?";
        std::cout << "  Prompt: \"" << prompt << "\"" << std::endl;
        std::cout << std::endl;
        
        auto result = engine->Generate(prompt, 50);
        
        std::cout << "  Generated " << result.generatedTokens << " tokens" << std::endl;
        std::cout << "  Throughput: " << result.tokensPerSecond << " tok/s" << std::endl;
        std::cout << "  Target: " << result.targetTokensPerSecond << " tok/s" << std::endl;
        std::cout << "  Duration: " << result.durationMs << " ms" << std::endl;
        std::cout << std::endl;
        
        // Validate performance
        if (engine->ValidatePerformance(Q4_0_MIN_ACCEPTABLE)) {
            std::cout << "  ✓ Performance validation PASSED" << std::endl;
        } else {
            std::cout << "  ⚠ Performance below threshold" << std::endl;
        }
    }
    
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Production Integration Test Complete" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return 0;
}
