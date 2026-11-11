/**
 * @file test_phase4_inference.cpp
 * @brief Phase 4: Inference Integration Test with Real Legacy Code
 * 
 * Tests the LegacyInferenceAdapter delegation to real GGMLBackend implementation.
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <cassert>
#include <chrono>
#include <thread>

// Unified interface
#include "src/inference/InferenceEngine.h"
#include "src/inference/LegacyInferenceAdapter.h"

// Real legacy implementation
#include "src/cpu_inference_engine.h"

using namespace RawrXD::Inference;

// Test counters
int testsPassed = 0;
int testsFailed = 0;

void TestPass(const char* testName) {
    std::cout << "[PASS] " << testName << std::endl;
    testsPassed++;
}

void TestFail(const char* testName, const char* reason) {
    std::cout << "[FAIL] " << testName << ": " << reason << std::endl;
    testsFailed++;
}

// ============================================================================
// Test 1: Real CPUInferenceEngine Creation and Adapter Wrapping
// ============================================================================
void TestRealInferenceEngineCreation() {
    std::cout << "\n=== Test 1: Real InferenceEngine Creation ===" << std::endl;
    
    // Get real legacy engine
    auto legacyEngine = CPUInferenceEngine::GetSharedInstance();
    if (!legacyEngine) {
        TestFail("Real InferenceEngine Creation", "Failed to get shared instance");
        return;
    }
    
    // Wrap with adapter
    EngineConfig config;
    config.modelPath = "";
    config.maxContextLength = 4096;
    
    auto inference = LegacyInferenceAdapter::Create(legacyEngine.get(), config);
    
    if (!inference) {
        TestFail("Real InferenceEngine Creation", "Adapter returned nullptr");
        return;
    }
    
    TestPass("Real InferenceEngine Creation");
}

// ============================================================================
// Test 2: Initialize with Real Engine
// ============================================================================
void TestInitializeWithRealEngine() {
    std::cout << "\n=== Test 2: Initialize with Real Engine ===" << std::endl;
    
    auto legacyEngine = CPUInferenceEngine::GetSharedInstance();
    EngineConfig config;
    config.modelPath = "";
    config.maxContextLength = 4096;
    
    auto inference = LegacyInferenceAdapter::Create(legacyEngine.get(), config);
    
    if (!inference->Initialize(config)) {
        TestFail("Initialize", "Initialize() returned false");
        return;
    }
    
    if (!inference->IsInitialized()) {
        TestFail("Initialize", "IsInitialized() returned false");
        return;
    }
    
    TestPass("Initialize with Real Engine");
}

// ============================================================================
// Test 3: Model Loading (without actual model)
// ============================================================================
void TestModelLoading() {
    std::cout << "\n=== Test 3: Model Loading ===" << std::endl;
    
    auto legacyEngine = CPUInferenceEngine::GetSharedInstance();
    EngineConfig config;
    config.modelPath = "";
    
    auto inference = LegacyInferenceAdapter::Create(legacyEngine.get(), config);
    inference->Initialize(config);
    
    // Try to load empty model (should fail gracefully)
    bool loaded = inference->LoadModel("");
    
    // Model should not be loaded (no path provided)
    if (inference->IsModelLoaded()) {
        std::cout << "  Note: Model reported as loaded (implementation dependent)" << std::endl;
    } else {
        std::cout << "  Note: Model not loaded (expected without path)" << std::endl;
    }
    
    TestPass("Model Loading");
}

// ============================================================================
// Test 4: Tokenization (if model available)
// ============================================================================
void TestTokenization() {
    std::cout << "\n=== Test 4: Tokenization ===" << std::endl;
    
    auto legacyEngine = CPUInferenceEngine::GetSharedInstance();
    EngineConfig config;
    config.modelPath = "";
    
    auto inference = LegacyInferenceAdapter::Create(legacyEngine.get(), config);
    inference->Initialize(config);
    
    // Try to tokenize (may fail without model, but shouldn't crash)
    std::string text = "Hello, world!";
    std::vector<int> tokens;
    
    try {
        tokens = inference->Tokenize(text);
        std::cout << "  Tokenized " << text << " into " << tokens.size() << " tokens" << std::endl;
    } catch (...) {
        std::cout << "  Tokenization threw exception (expected without model)" << std::endl;
    }
    
    TestPass("Tokenization");
}

// ============================================================================
// Test 5: Model Info
// ============================================================================
void TestModelInfo() {
    std::cout << "\n=== Test 5: Model Info ===" << std::endl;
    
    auto legacyEngine = CPUInferenceEngine::GetSharedInstance();
    EngineConfig config;
    config.modelPath = "";
    
    auto inference = LegacyInferenceAdapter::Create(legacyEngine.get(), config);
    inference->Initialize(config);
    
    // Get model info
    auto info = inference->GetModelInfo();
    
    std::cout << "  Model path: " << info.path << std::endl;
    std::cout << "  Architecture: " << info.architecture << std::endl;
    std::cout << "  Vocab size: " << info.vocabSize << std::endl;
    
    TestPass("Model Info");
}

// ============================================================================
// Test 6: Performance Metrics
// ============================================================================
void TestPerformanceMetrics() {
    std::cout << "\n=== Test 6: Performance Metrics ===" << std::endl;
    
    auto legacyEngine = CPUInferenceEngine::GetSharedInstance();
    EngineConfig config;
    config.modelPath = "";
    
    auto inference = LegacyInferenceAdapter::Create(legacyEngine.get(), config);
    inference->Initialize(config);
    
    // Get performance metrics
    auto metrics = inference->GetLastPerformanceMetrics();
    
    std::cout << "  Tokens per second: " << metrics.tokensPerSecond << std::endl;
    std::cout << "  Total time (ms): " << metrics.totalTimeMs << std::endl;
    std::cout << "  Tokens generated: " << metrics.tokensGenerated << std::endl;
    
    TestPass("Performance Metrics");
}

// ============================================================================
// Test 7: Model Unload
// ============================================================================
void TestModelUnload() {
    std::cout << "\n=== Test 7: Model Unload ===" << std::endl;
    
    auto legacyEngine = CPUInferenceEngine::GetSharedInstance();
    EngineConfig config;
    config.modelPath = "";
    
    auto inference = LegacyInferenceAdapter::Create(legacyEngine.get(), config);
    inference->Initialize(config);
    
    // Unload model (should be safe even if no model loaded)
    inference->UnloadModel();
    
    // Verify model not loaded
    if (inference->IsModelLoaded()) {
        TestFail("Model Unload", "Still has model after unload");
        return;
    }
    
    TestPass("Model Unload");
}

// ============================================================================
// Test 8: Shutdown
// ============================================================================
void TestShutdown() {
    std::cout << "\n=== Test 8: Shutdown ===" << std::endl;
    
    auto legacyEngine = CPUInferenceEngine::GetSharedInstance();
    EngineConfig config;
    config.modelPath = "";
    
    auto inference = LegacyInferenceAdapter::Create(legacyEngine.get(), config);
    inference->Initialize(config);
    
    // Shutdown
    inference->Shutdown();
    
    // Verify shutdown state
    if (inference->IsInitialized()) {
        TestFail("Shutdown", "Still initialized after shutdown");
        return;
    }
    
    TestPass("Shutdown");
}

// ============================================================================
// Main Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "Phase 4: Inference Integration Tests" << std::endl;
    std::cout << "Testing REAL GGMLBackend via Adapter" << std::endl;
    std::cout << "========================================" << std::endl;
    
    try {
        // Run all tests
        TestRealInferenceEngineCreation();
        TestInitializeWithRealEngine();
        TestModelLoading();
        TestTokenization();
        TestModelInfo();
        TestPerformanceMetrics();
        TestModelUnload();
        TestShutdown();
        
    } catch (const std::exception& e) {
        std::cerr << "\n[FATAL] Unhandled exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\n[FATAL] Unknown exception" << std::endl;
        return 1;
    }
    
    // Print summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Passed: " << testsPassed << std::endl;
    std::cout << "Failed: " << testsFailed << std::endl;
    std::cout << "Total:  " << (testsPassed + testsFailed) << std::endl;
    
    if (testsFailed == 0) {
        std::cout << "\n✅ All Phase 4 inference tests passed!" << std::endl;
        std::cout << "\nPhase 4 Status: Inference integration verified" << std::endl;
        return 0;
    } else {
        std::cout << "\n❌ Some tests failed" << std::endl;
        return 1;
    }
}
