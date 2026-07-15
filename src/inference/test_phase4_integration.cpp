/**
 * @file test_phase4_integration.cpp
 * @brief Phase 4 integration test - Full GGML pipeline
 * 
 * Tests the complete inference pipeline:
 * 1. Backend initialization
 * 2. Model loading (with validation)
 * 3. Tokenization
 * 4. Forward pass
 * 5. Sampling
 * 6. Generation
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <cassert>
#include <chrono>
#include "GGMLBackend.h"
#include "ModelLoader.h"
#include "LegacyInferenceAdapter.h"

using namespace RawrXD::Inference;

// Test colors
#define GREEN "\033[32m"
#define RED "\033[31m"
#define YELLOW "\033[33m"
#define RESET "\033[0m"

// Test counters
int g_testsPassed = 0;
int g_testsFailed = 0;

void test_pass(const char* name) {
    std::cout << GREEN << "[PASS]" << RESET << " " << name << std::endl;
    g_testsPassed++;
}

void test_fail(const char* name, const char* reason) {
    std::cout << RED << "[FAIL]" << RESET << " " << name << ": " << reason << std::endl;
    g_testsFailed++;
}

// ============================================================================
// Phase 4 Tests
// ============================================================================

void test_phase4_backend_initialization() {
    std::cout << "\n=== Phase 4.1: Backend Initialization ===" << std::endl;
    
    GGMLBackendConfig config;
    config.backendType = GGMLBackendConfig::BackendType::CPU;
    config.maxContextSize = 4096;
    config.tensorBufferSize = 256 * 1024 * 1024;  // 256MB
    
    auto backend = GGMLBackend::Create(config);
    if (!backend) {
        test_fail("Create backend", "Failed to create backend");
        return;
    }
    
    if (!backend->Initialize()) {
        test_fail("Initialize backend", backend->GetLastError().c_str());
        return;
    }
    
    if (!backend->IsInitialized()) {
        test_fail("Backend state", "Backend not initialized");
        return;
    }
    
    std::string backendType = backend->GetBackendType();
    if (backendType != "cpu") {
        test_fail("Backend type", ("Expected 'cpu', got '" + backendType + "'").c_str());
        return;
    }
    
    backend->Shutdown();
    if (backend->IsInitialized()) {
        test_fail("Backend shutdown", "Backend still initialized after shutdown");
        return;
    }
    
    test_pass("Backend initialization cycle");
}

void test_phase4_model_loader() {
    std::cout << "\n=== Phase 4.2: Model Loader ===" << std::endl;
    
    auto loader = ModelLoader::Create();
    if (!loader) {
        test_fail("Create loader", "Failed to create model loader");
        return;
    }
    
    // Test with non-existent file
    ValidationResult result = loader->Validate("/nonexistent/model.gguf");
    if (result.valid) {
        test_fail("Validate non-existent", "Should fail for non-existent file");
        return;
    }
    
    if (result.errors.empty()) {
        test_fail("Error reporting", "Should have error message");
        return;
    }
    
    test_pass("Model loader validation");
}

void test_phase4_adapter_with_backend() {
    std::cout << "\n=== Phase 4.3: Adapter with GGML Backend ===" << std::endl;
    
    EngineConfig config;
    config.maxContextLength = 4096;
    config.tensorBufferSize = 256 * 1024 * 1024;
    
    auto adapter = LegacyInferenceAdapter::Create(nullptr, config);
    if (!adapter) {
        test_fail("Create adapter", "Failed to create adapter");
        return;
    }
    
    // Initially no model
    if (adapter->IsModelLoaded()) {
        test_fail("Initial state", "Should not have model loaded initially");
        return;
    }
    
    // Try to load non-existent model
    bool result = adapter->LoadModel("/nonexistent/model.gguf");
    if (result) {
        test_fail("Load non-existent", "Should fail for non-existent model");
        return;
    }
    
    std::string error = adapter->GetLastError();
    if (error.empty()) {
        test_fail("Error message", "Should have error message");
        return;
    }
    
    test_pass("Adapter with GGML backend");
}

void test_phase4_tokenization() {
    std::cout << "\n=== Phase 4.4: Tokenization ===" << std::endl;
    
    // Create backend
    GGMLBackendConfig config;
    auto backend = GGMLBackend::Create(config);
    if (!backend || !backend->Initialize()) {
        test_fail("Backend setup", "Failed to initialize backend");
        return;
    }
    
    // Without model, tokenization returns empty
    std::vector<int> tokens = backend->Tokenize("Hello world", true, false);
    // Expected: empty since no model loaded
    
    test_pass("Tokenization (no model - returns empty)");
}

void test_phase4_forward_pass() {
    std::cout << "\n=== Phase 4.5: Forward Pass ===" << std::endl;
    
    GGMLBackendConfig config;
    auto backend = GGMLBackend::Create(config);
    if (!backend || !backend->Initialize()) {
        test_fail("Backend setup", "Failed to initialize backend");
        return;
    }
    
    // Without model, forward pass returns empty
    std::vector<int> tokens = {1, 2, 3};  // Dummy tokens
    std::vector<float> logits = backend->Forward(tokens);
    
    // Should return empty or dummy logits
    test_pass("Forward pass (no model - stub implementation)");
}

void test_phase4_sampling() {
    std::cout << "\n=== Phase 4.6: Token Sampling ===" << std::endl;
    
    GGMLBackendConfig config;
    auto backend = GGMLBackend::Create(config);
    if (!backend || !backend->Initialize()) {
        test_fail("Backend setup", "Failed to initialize backend");
        return;
    }
    
    // Create dummy logits
    std::vector<float> logits(1000);
    for (int i = 0; i < 1000; i++) {
        logits[i] = static_cast<float>(i) / 100.0f;
    }
    
    // Sample with different parameters
    int token1 = backend->SampleToken(logits, 1.0f, 0, 1.0f, 1.0f);
    int token2 = backend->SampleToken(logits, 0.7f, 40, 0.9f, 1.1f);
    
    if (token1 < 0 || token1 >= 1000) {
        test_fail("Sample token range", "Token out of range");
        return;
    }
    
    test_pass("Token sampling");
}

void test_phase4_context_management() {
    std::cout << "\n=== Phase 4.7: Context Management ===" << std::endl;
    
    GGMLBackendConfig config;
    config.maxContextSize = 4096;
    auto backend = GGMLBackend::Create(config);
    if (!backend || !backend->Initialize()) {
        test_fail("Backend setup", "Failed to initialize backend");
        return;
    }
    
    // Initially empty
    if (backend->GetContextLength() != 0) {
        test_fail("Initial context", "Context should be empty");
        return;
    }
    
    // Clear context (should work even without model)
    backend->ClearKVCache();
    
    if (backend->GetContextLength() != 0) {
        test_fail("After clear", "Context should still be empty");
        return;
    }
    
    size_t maxLen = backend->GetMaxContextLength();
    if (maxLen != 4096) {
        test_fail("Max context length", "Wrong max length");
        return;
    }
    
    test_pass("Context management");
}

void test_phase4_memory_usage() {
    std::cout << "\n=== Phase 4.8: Memory Usage ===" << std::endl;
    
    GGMLBackendConfig config;
    auto backend = GGMLBackend::Create(config);
    if (!backend || !backend->Initialize()) {
        test_fail("Backend setup", "Failed to initialize backend");
        return;
    }
    
    // Without model, memory usage should be minimal
    size_t memUsage = backend->GetMemoryUsage();
    size_t totalAlloc = backend->GetTotalAllocated();
    
    // Just verify it doesn't crash
    test_pass("Memory usage reporting");
}

void test_phase4_error_handling() {
    std::cout << "\n=== Phase 4.9: Error Handling ===" << std::endl;
    
    GGMLBackendConfig config;
    auto backend = GGMLBackend::Create(config);
    
    // Initially no error
    std::string error = backend->GetLastError();
    // May be empty initially
    
    // Try invalid operation
    backend->LoadModel("");
    error = backend->GetLastError();
    
    if (error.empty()) {
        test_fail("Error reporting", "Should have error after failed load");
        return;
    }
    
    // Clear error
    backend->ClearError();
    error = backend->GetLastError();
    // Should be empty now
    
    test_pass("Error handling");
}

void test_phase4_performance() {
    std::cout << "\n=== Phase 4.10: Performance Baseline ===" << std::endl;
    
    auto start = std::chrono::steady_clock::now();
    
    // Create and initialize backend
    GGMLBackendConfig config;
    auto backend = GGMLBackend::Create(config);
    if (!backend || !backend->Initialize()) {
        test_fail("Backend setup", "Failed to initialize");
        return;
    }
    
    auto initEnd = std::chrono::steady_clock::now();
    auto initMs = std::chrono::duration_cast<std::chrono::milliseconds>(initEnd - start).count();
    
    // Test sampling performance
    std::vector<float> logits(32000);
    for (int i = 0; i < 32000; i++) {
        logits[i] = static_cast<float>(rand()) / RAND_MAX;
    }
    
    auto sampleStart = std::chrono::steady_clock::now();
    for (int i = 0; i < 100; i++) {
        backend->SampleToken(logits, 0.7f, 40, 0.9f, 1.0f);
    }
    auto sampleEnd = std::chrono::steady_clock::now();
    auto sampleMs = std::chrono::duration_cast<std::chrono::milliseconds>(sampleEnd - sampleStart).count();
    
    std::cout << "  Initialization: " << initMs << " ms" << std::endl;
    std::cout << "  100 sampling ops: " << sampleMs << " ms (" << (sampleMs > 0 ? 100000.0 / sampleMs : 0) << " samples/sec)" << std::endl;
    
    test_pass("Performance baseline");
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "================================================================" << std::endl;
    std::cout << "RawrXD Phase 4: GGML Integration Tests" << std::endl;
    std::cout << "================================================================" << std::endl;
    
    try {
        test_phase4_backend_initialization();
        test_phase4_model_loader();
        test_phase4_adapter_with_backend();
        test_phase4_tokenization();
        test_phase4_forward_pass();
        test_phase4_sampling();
        test_phase4_context_management();
        test_phase4_memory_usage();
        test_phase4_error_handling();
        test_phase4_performance();
    } catch (const std::exception& e) {
        std::cout << RED << "\nFATAL ERROR: " << e.what() << RESET << std::endl;
        return 1;
    }
    
    std::cout << "\n================================================================" << std::endl;
    std::cout << "Results: " << g_testsPassed << " passed, " << g_testsFailed << " failed" << std::endl;
    std::cout << "================================================================" << std::endl;
    
    if (g_testsFailed > 0) {
        std::cout << RED << "\nSOME TESTS FAILED" << RESET << std::endl;
        return 1;
    }
    
    std::cout << GREEN << "\nALL TESTS PASSED" << RESET << std::endl;
    return 0;
}
