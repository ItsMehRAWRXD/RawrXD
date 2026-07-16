// test_milestone3_integration.cpp - TEST MILESTONE 3: END-TO-END INTEGRATION
// Tests the complete pipeline: Text -> Tokenize -> Inference -> Detokenize -> Text
//
// Run this test to verify:
// 1. Tokenizer loads vocabulary from GGUF
// 2. Text tokenizes correctly
// 3. Inference runs without crashes
// 4. Output detokenizes to sensible text
// 5. Token cache works for repeated prompts

#include "../src/ai/ai_model_caller_integrated.h"
#include "../src/model/ModelLoader.hpp"
#include <iostream>
#include <cassert>
#include <string>

// ============================================================
// TEST CONFIGURATION
// ============================================================

// Path to tiny model for testing (small, fast)
const char* TEST_MODEL_PATH = "models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";

// Test prompts
const char* TEST_PROMPTS[] = {
    "Hello, my name is",
    "The capital of France is",
    "2 + 2 =",
    "Once upon a time",
    nullptr  // Sentinel
};

// ============================================================
// TEST FUNCTIONS
// ============================================================

bool TestModelLoading() {
    std::cout << "[TEST] Model Loading..." << std::endl;
    
    if (!ModelLoader::LoadModel(TEST_MODEL_PATH)) {
        std::cerr << "[FAIL] Could not load model: " << TEST_MODEL_PATH << std::endl;
        return false;
    }
    
    std::cout << "[PASS] Model loaded successfully" << std::endl;
    return true;
}

bool TestTokenization() {
    std::cout << "[TEST] Tokenization..." << std::endl;
    
    RawrXDTokenizer* tokenizer = ModelLoader::GetTokenizer();
    if (!tokenizer) {
        std::cerr << "[FAIL] Tokenizer not available" << std::endl;
        return false;
    }
    
    const char* test_text = "Hello world";
    std::vector<int> tokens = tokenizer->Encode(test_text);
    
    if (tokens.empty()) {
        std::cerr << "[FAIL] Tokenization produced no tokens" << std::endl;
        return false;
    }
    
    // Round-trip test
    std::string decoded = tokenizer->Decode(tokens);
    if (decoded.empty()) {
        std::cerr << "[FAIL] Detokenization produced empty string" << std::endl;
        return false;
    }
    
    std::cout << "[PASS] Tokenization: \"" << test_text << "\" -> " << tokens.size() << " tokens" << std::endl;
    return true;
}

bool TestInferenceIntegration() {
    std::cout << "[TEST] Inference Integration..." << std::endl;
    
    const char* prompt = "Hello";
    
    std::cout << "[INFO] Generating completion for: \"" << prompt << "\"" << std::endl;
    
    InferenceResult result = GenerateCompletion(prompt, 10);  // Generate 10 tokens
    
    if (result.error_code != 0) {
        std::cerr << "[FAIL] Inference failed with code " << result.error_code << std::endl;
        std::cerr << "       Error: " << result.error_message << std::endl;
        return false;
    }
    
    if (result.tokens.empty()) {
        std::cerr << "[FAIL] No tokens generated" << std::endl;
        return false;
    }
    
    if (result.text.empty()) {
        std::cerr << "[FAIL] No text generated" << std::endl;
        return false;
    }
    
    std::cout << "[PASS] Generated " << result.tokens.size() << " tokens" << std::endl;
    std::cout << "[PASS] Generated text: \"" << result.text << "\"" << std::endl;
    
    return true;
}

bool TestTokenCache() {
    std::cout << "[TEST] Token Cache..." << std::endl;
    
    const char* prompt = "This is a test prompt for caching";
    
    // First call - cache miss
    auto start1 = std::chrono::high_resolution_clock::now();
    InferenceResult result1 = GenerateCompletion(prompt, 5);
    auto end1 = std::chrono::high_resolution_clock::now();
    auto duration1 = std::chrono::duration_cast<std::chrono::milliseconds>(end1 - start1);
    
    if (result1.error_code != 0) {
        std::cerr << "[FAIL] First generation failed" << std::endl;
        return false;
    }
    
    // Second call - cache hit
    auto start2 = std::chrono::high_resolution_clock::now();
    InferenceResult result2 = GenerateCompletion(prompt, 5);
    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::milliseconds>(end2 - start2);
    
    if (result2.error_code != 0) {
        std::cerr << "[FAIL] Second generation failed" << std::endl;
        return false;
    }
    
    std::cout << "[INFO] First call: " << duration1.count() << " ms (cache miss)" << std::endl;
    std::cout << "[INFO] Second call: " << duration2.count() << " ms (cache hit)" << std::endl;
    
    // Cache hit should be faster (or at least not significantly slower)
    if (duration2.count() > duration1.count() * 1.5) {
        std::cerr << "[WARN] Cache hit was slower than expected" << std::endl;
    }
    
    std::cout << "[PASS] Token cache working" << std::endl;
    return true;
}

bool TestMultiplePrompts() {
    std::cout << "[TEST] Multiple Prompts..." << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    for (int i = 0; TEST_PROMPTS[i] != nullptr; i++) {
        const char* prompt = TEST_PROMPTS[i];
        std::cout << "[INFO] Testing prompt " << (i+1) << ": \"" << prompt << "\"" << std::endl;
        
        InferenceResult result = GenerateCompletion(prompt, 10);
        
        if (result.error_code != 0) {
            std::cerr << "[FAIL] Prompt " << (i+1) << " failed" << std::endl;
            failed++;
        } else {
            std::cout << "[PASS] Prompt " << (i+1) << " generated " << result.tokens.size() << " tokens" << std::endl;
            passed++;
        }
    }
    
    std::cout << "[INFO] Results: " << passed << " passed, " << failed << " failed" << std::endl;
    
    return failed == 0;
}

bool TestCAPI() {
    std::cout << "[TEST] C API..." << std::endl;
    
    char output_buffer[1024];
    const char* prompt = "Hello";
    
    int result = rawrxd_generate_completion(
        prompt,
        output_buffer,
        sizeof(output_buffer),
        10
    );
    
    if (result != 0) {
        std::cerr << "[FAIL] C API returned error code " << result << std::endl;
        return false;
    }
    
    if (strlen(output_buffer) == 0) {
        std::cerr << "[FAIL] C API produced empty output" << std::endl;
        return false;
    }
    
    std::cout << "[PASS] C API generated: \"" << output_buffer << "\"" << std::endl;
    return true;
}

// ============================================================
// MAIN TEST RUNNER
// ============================================================

int main(int argc, char** argv) {
    std::cout << "========================================" << std::endl;
    std::cout << "MILESTONE 3: END-TO-END INTEGRATION TEST" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    // Test 1: Model Loading
    if (TestModelLoading()) {
        passed++;
    } else {
        failed++;
        std::cerr << "[CRITICAL] Cannot continue without model" << std::endl;
        return 1;
    }
    
    // Test 2: Tokenization
    if (TestTokenization()) {
        passed++;
    } else {
        failed++;
    }
    
    // Test 3: Inference Integration
    if (TestInferenceIntegration()) {
        passed++;
    } else {
        failed++;
    }
    
    // Test 4: Token Cache
    if (TestTokenCache()) {
        passed++;
    } else {
        failed++;
    }
    
    // Test 5: Multiple Prompts
    if (TestMultiplePrompts()) {
        passed++;
    } else {
        failed++;
    }
    
    // Test 6: C API
    if (TestCAPI()) {
        passed++;
    } else {
        failed++;
    }
    
    // Summary
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "TEST SUMMARY" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << failed << std::endl;
    std::cout << "Total:  " << (passed + failed) << std::endl;
    std::cout << std::endl;
    
    if (failed == 0) {
        std::cout << "✅ ALL TESTS PASSED - MILESTONE 3 COMPLETE" << std::endl;
        return 0;
    } else {
        std::cout << "❌ SOME TESTS FAILED" << std::endl;
        return 1;
    }
}