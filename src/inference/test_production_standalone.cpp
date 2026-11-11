// ============================================================================
// Production Integration Test (Standalone)
// Validates QuantizedInferenceEngine without full router dependencies
// ============================================================================

#include "quantized_inference_production.hpp"
#include <iostream>
#include <cassert>

using namespace RawrXD::Inference;

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "Production Integration Test (Standalone)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // [1/5] Version check
    std::cout << "[1/5] Version check..." << std::endl;
    std::cout << "  Version: " << GetQuantizedInferenceVersion() << std::endl;
    std::cout << "  Q4_0 Target: " << Q4_0_TARGET_THROUGHPUT << " tok/s" << std::endl;
    std::cout << "  Standard Target: " << STANDARD_TARGET_THROUGHPUT << " tok/s" << std::endl;
    std::cout << std::endl;
    
    // [2/5] Q4_0 Detection Tests
    std::cout << "[2/5] Q4_0 Detection Tests..." << std::endl;
    
    struct TestCase {
        const char* path;
        bool expected;
    };
    
    TestCase tests[] = {
        {"ministral3_q4_0.gguf", true},
        {"model_Q4_0.bin", true},
        {"MODEL_Q4_0.GGUF", true},
        {"ministral3_fp16.gguf", false},
        {"model_q8_0.gguf", false},
        {"model.bin", false},
        {nullptr, false}
    };
    
    bool allPassed = true;
    for (int i = 0; tests[i].path != nullptr; i++) {
        bool result = IsQ4_0Model(tests[i].path);
        bool pass = (result == tests[i].expected);
        std::cout << "  " << (pass ? "✓" : "✗") << " " 
                  << tests[i].path << " -> " 
                  << (result ? "Q4_0" : "Standard")
                  << (pass ? "" : " (EXPECTED: " + std::string(tests[i].expected ? "Q4_0" : "Standard") + ")")
                  << std::endl;
        if (!pass) allPassed = false;
    }
    
    if (!allPassed) {
        std::cerr << "Q4_0 detection tests FAILED" << std::endl;
        return 1;
    }
    std::cout << std::endl;
    
    // [3/5] Throughput Calculation Tests
    std::cout << "[3/5] Throughput Calculation Tests..." << std::endl;
    
    float q4Tps = GetExpectedThroughput("x_q4_0.gguf");
    float stdTps = GetExpectedThroughput("x_fp32.gguf");
    
    std::cout << "  Q4_0 model: " << q4Tps << " tok/s" 
              << (q4Tps == Q4_0_TARGET_THROUGHPUT ? " ✓" : " ✗") << std::endl;
    std::cout << "  Standard model: " << stdTps << " tok/s" 
              << (stdTps == STANDARD_TARGET_THROUGHPUT ? " ✓" : " ✗") << std::endl;
    
    if (q4Tps != Q4_0_TARGET_THROUGHPUT || stdTps != STANDARD_TARGET_THROUGHPUT) {
        std::cerr << "Throughput calculation tests FAILED" << std::endl;
        return 1;
    }
    std::cout << std::endl;
    
    // [4/5] Format Tests
    std::cout << "[4/5] Format Tests..." << std::endl;
    std::cout << "  0 tok/s: " << FormatThroughput(0.0f) << std::endl;
    std::cout << "  31.5 tok/s: " << FormatThroughput(31.5f) << std::endl;
    std::cout << "  131.0 tok/s: " << FormatThroughput(131.0f) << std::endl;
    std::cout << "  372.0 tok/s: " << FormatThroughput(372.0f) << std::endl;
    std::cout << std::endl;
    
    // [5/5] Configuration Tests
    std::cout << "[5/5] Configuration Tests..." << std::endl;
    
    InferenceConfig config;
    std::cout << "  Default config:" << std::endl;
    std::cout << "    Temperature: " << config.temperature << std::endl;
    std::cout << "    Top-K: " << config.topK << std::endl;
    std::cout << "    Top-P: " << config.topP << std::endl;
    std::cout << "    Max tokens: " << config.maxTokens << std::endl;
    std::cout << "    Seed: " << config.seed << std::endl;
    std::cout << "    Auto-detect: " << (config.autoDetectQuantization ? "Yes" : "No") << std::endl;
    std::cout << "    Force quantized: " << (config.forceQuantized ? "Yes" : "No") << std::endl;
    std::cout << "    Enable speculative: " << (config.enableSpeculative ? "Yes" : "No") << std::endl;
    std::cout << "    Draft tokens: " << config.speculativeDraftTokens << std::endl;
    
    // Modify config
    config.temperature = 0.9f;
    config.maxTokens = 100;
    config.autoDetectQuantization = false;
    
    std::cout << "  Modified config:" << std::endl;
    std::cout << "    Temperature: " << config.temperature 
              << (config.temperature == 0.9f ? " ✓" : " ✗") << std::endl;
    std::cout << "    Max tokens: " << config.maxTokens 
              << (config.maxTokens == 100 ? " ✓" : " ✗") << std::endl;
    std::cout << "    Auto-detect: " << (config.autoDetectQuantization ? "Yes" : "No")
              << (!config.autoDetectQuantization ? " ✓" : " ✗") << std::endl;
    
    if (config.temperature != 0.9f || config.maxTokens != 100 || config.autoDetectQuantization) {
        std::cerr << "Configuration tests FAILED" << std::endl;
        return 1;
    }
    std::cout << std::endl;
    
    // Summary
    std::cout << "========================================" << std::endl;
    std::cout << "All Tests PASSED" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Production Integration Status:" << std::endl;
    std::cout << "  ✓ Q4_0 auto-detection working" << std::endl;
    std::cout << "  ✓ Throughput routing configured" << std::endl;
    std::cout << "  ✓ Configuration system ready" << std::endl;
    std::cout << "  ✓ Performance constants defined" << std::endl;
    std::cout << std::endl;
    std::cout << "Next Steps:" << std::endl;
    std::cout << "  1. Link with QuantizedInferenceRouter for full functionality" << std::endl;
    std::cout << "  2. Wire into RawrXD main inference path" << std::endl;
    std::cout << "  3. Add runtime performance monitoring" << std::endl;
    
    return 0;
}
