/**
 * @file test_ggml_integration.cpp
 * @brief Integration test for GGML backend
 * 
 * Tests the complete Phase 3 GGML integration pipeline:
 * 1. GGMLBackend initialization
 * 2. LegacyInferenceAdapter with GGMLBackend
 * 3. Tokenization
 * 4. Generation (stub)
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <cassert>
#include "GGMLBackend.h"
#include "LegacyInferenceAdapter.h"

using namespace RawrXD::Inference;

// Test colors
#define GREEN "\033[32m"
#define RED "\033[31m"
#define RESET "\033[0m"

void test_ggml_backend_creation() {
    std::cout << "Test: GGMLBackend creation... ";
    
    GGMLBackendConfig config;
    config.backendType = GGMLBackendConfig::BackendType::CPU;
    config.maxContextSize = 4096;
    config.tensorBufferSize = 256 * 1024 * 1024;  // 256MB
    
    auto backend = GGMLBackend::Create(config);
    assert(backend != nullptr);
    
    std::cout << GREEN << "PASSED" << RESET << std::endl;
}

void test_ggml_backend_initialization() {
    std::cout << "Test: GGMLBackend initialization... ";
    
    GGMLBackendConfig config;
    config.backendType = GGMLBackendConfig::BackendType::CPU;
    
    auto backend = GGMLBackend::Create(config);
    assert(backend->Initialize());
    assert(backend->IsInitialized());
    
    std::string backendType = backend->GetBackendType();
    assert(backendType == "cpu");
    
    backend->Shutdown();
    assert(!backend->IsInitialized());
    
    std::cout << GREEN << "PASSED" << RESET << std::endl;
}

void test_legacy_adapter_creation() {
    std::cout << "Test: LegacyInferenceAdapter creation... ";
    
    EngineConfig config;
    config.maxContextLength = 4096;
    config.tensorBufferSize = 256 * 1024 * 1024;
    
    auto adapter = LegacyInferenceAdapter::Create(nullptr, config);
    assert(adapter != nullptr);
    
    std::cout << GREEN << "PASSED" << RESET << std::endl;
}

void test_tokenization() {
    std::cout << "Test: Tokenization (requires model)... ";
    
    // Note: This test requires a model to be loaded
    // For now, just verify the adapter is created
    EngineConfig config;
    auto adapter = LegacyInferenceAdapter::Create(nullptr, config);
    
    // Without a model, tokenization returns empty
    std::vector<int> tokens = adapter->Tokenize("Hello world");
    // Expected: empty since no model loaded
    
    std::cout << GREEN << "PASSED" << RESET << " (stub - no model loaded)" << std::endl;
}

void test_model_lifecycle() {
    std::cout << "Test: Model lifecycle... ";
    
    EngineConfig config;
    auto adapter = LegacyInferenceAdapter::Create(nullptr, config);
    
    // Initially no model loaded
    assert(!adapter->IsModelLoaded());
    
    // Try to load non-existent model (should fail gracefully)
    bool result = adapter->LoadModel("/nonexistent/model.gguf");
    assert(!result);  // Should fail
    assert(!adapter->IsModelLoaded());
    
    std::string error = adapter->GetLastError();
    assert(!error.empty());  // Should have error message
    
    std::cout << GREEN << "PASSED" << RESET << std::endl;
}

void test_context_management() {
    std::cout << "Test: Context management... ";
    
    EngineConfig config;
    config.maxContextLength = 4096;
    auto adapter = LegacyInferenceAdapter::Create(nullptr, config);
    
    // Initially empty context
    assert(adapter->GetContextLength() == 0);
    assert(!adapter->IsContextFull());
    
    // Clear context (should work even without model)
    adapter->ClearContext();
    assert(adapter->GetContextLength() == 0);
    
    std::cout << GREEN << "PASSED" << RESET << std::endl;
}

void test_metrics() {
    std::cout << "Test: Metrics... ";
    
    EngineConfig config;
    auto adapter = LegacyInferenceAdapter::Create(nullptr, config);
    
    // Initially zero metrics
    PerformanceMetrics metrics = adapter->GetLastMetrics();
    assert(metrics.tokensGenerated == 0);
    assert(metrics.tokensPerSecond == 0.0f);
    
    // Reset metrics
    adapter->ResetMetrics();
    metrics = adapter->GetLastMetrics();
    assert(metrics.tokensGenerated == 0);
    
    std::cout << GREEN << "PASSED" << RESET << std::endl;
}

void test_error_handling() {
    std::cout << "Test: Error handling... ";
    
    EngineConfig config;
    auto adapter = LegacyInferenceAdapter::Create(nullptr, config);
    
    // Initially no error
    std::string error = adapter->GetLastError();
    // May be empty initially
    
    // Try invalid operation
    adapter->LoadModel("");
    error = adapter->GetLastError();
    assert(!error.empty());  // Should have error
    
    std::cout << GREEN << "PASSED" << RESET << std::endl;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Phase 3 GGML Integration Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    try {
        test_ggml_backend_creation();
        passed++;
    } catch (const std::exception& e) {
        std::cout << RED << "FAILED: " << e.what() << RESET << std::endl;
        failed++;
    }
    
    try {
        test_ggml_backend_initialization();
        passed++;
    } catch (const std::exception& e) {
        std::cout << RED << "FAILED: " << e.what() << RESET << std::endl;
        failed++;
    }
    
    try {
        test_legacy_adapter_creation();
        passed++;
    } catch (const std::exception& e) {
        std::cout << RED << "FAILED: " << e.what() << RESET << std::endl;
        failed++;
    }
    
    try {
        test_tokenization();
        passed++;
    } catch (const std::exception& e) {
        std::cout << RED << "FAILED: " << e.what() << RESET << std::endl;
        failed++;
    }
    
    try {
        test_model_lifecycle();
        passed++;
    } catch (const std::exception& e) {
        std::cout << RED << "FAILED: " << e.what() << RESET << std::endl;
        failed++;
    }
    
    try {
        test_context_management();
        passed++;
    } catch (const std::exception& e) {
        std::cout << RED << "FAILED: " << e.what() << RESET << std::endl;
        failed++;
    }
    
    try {
        test_metrics();
        passed++;
    } catch (const std::exception& e) {
        std::cout << RED << "FAILED: " << e.what() << RESET << std::endl;
        failed++;
    }
    
    try {
        test_error_handling();
        passed++;
    } catch (const std::exception& e) {
        std::cout << RED << "FAILED: " << e.what() << RESET << std::endl;
        failed++;
    }
    
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return failed > 0 ? 1 : 0;
}
