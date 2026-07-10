// Test: Quantization Format Detection
// Verifies router correctly identifies Q2_K, Q3_K, Q4_0, etc.

#include <iostream>
#include <cstring>
#include "src/inference/quantized_inference_router.hpp"

using namespace RawrXD::Inference;

int main() {
    std::cout << "=== Quantization Format Detection Test ===" << std::endl;
    
    struct TestCase {
        const char* path;
        bool expectedQuantized;
        const char* expectedType;
    };
    
    TestCase tests[] = {
        // Available models
        {"gemma3-1b-Q2_K.gguf", true, "Q2_K"},
        {"llama3.2-3b-Q2_K.gguf", true, "Q2_K"},
        {"llama3.2-3b-Q3_K_S.gguf", true, "Q3_K"},
        {"phi3-mini-Q2_K.gguf", true, "Q2_K"},
        
        // Other formats
        {"model-Q4_0.gguf", true, "Q4_0"},
        {"model-Q4_K.gguf", true, "Q4_K"},
        {"model-Q5_K.gguf", true, "Q5_K"},
        {"model-Q6_K.gguf", true, "Q6_K"},
        {"model-Q8_0.gguf", true, "Q8_0"},
        
        // Non-quantized
        {"model-f32.gguf", false, "FP32"},
        {"model-f16.gguf", false, "FP32"},
        {"dummy.gguf", false, "FP32"},
        
        // Case insensitivity
        {"MODEL-q4_0.GGUF", true, "Q4_0"},
        {"Model-Q2_K.gguf", true, "Q2_K"},
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test : tests) {
        bool isQuantized = IsQuantizedModel(test.path);
        const char* type = GetQuantizationType(test.path);
        const char* backend = GetRecommendedBackend(test.path);
        
        bool quantOk = (isQuantized == test.expectedQuantized);
        bool typeOk = (strcmp(type, test.expectedType) == 0);
        
        std::cout << "[" << (quantOk && typeOk ? "PASS" : "FAIL") << "] " 
                  << test.path << " -> " << type 
                  << " (quantized=" << (isQuantized ? "yes" : "no") << ")"
                  << " backend=" << backend;
        
        if (!quantOk) {
            std::cout << " [EXPECTED quantized=" << (test.expectedQuantized ? "yes" : "no") << "]";
        }
        if (!typeOk) {
            std::cout << " [EXPECTED type=" << test.expectedType << "]";
        }
        std::cout << std::endl;
        
        if (quantOk && typeOk) {
            passed++;
        } else {
            failed++;
        }
    }
    
    std::cout << "\n=== Results ===" << std::endl;
    std::cout << "Passed: " << passed << "/" << (passed + failed) << std::endl;
    
    return failed > 0 ? 1 : 0;
}
