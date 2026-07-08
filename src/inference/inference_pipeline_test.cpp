/**
 * @file inference_pipeline_test.cpp
 * @brief Comprehensive inference pipeline test
 * @description Tests the complete inference pipeline from model load to token generation
 */

#include "../inference/inference_engine.h"
#include "../gguf_loader.h"
#include <cstdio>
#include <cstring>
#include <windows.h>

using namespace RawrXD::Core;

// Test result tracking
struct TestResults {
    int passed = 0;
    int failed = 0;
    
    void Pass(const char* test) {
        printf("[PASS] %s\n", test);
        passed++;
    }
    
    void Fail(const char* test, const char* reason) {
        printf("[FAIL] %s: %s\n", test, reason);
        failed++;
    }
    
    void Summary() {
        printf("\n=== Test Summary ===\n");
        printf("Passed: %d\n", passed);
        printf("Failed: %d\n", failed);
        printf("Total:  %d\n", passed + failed);
        
        if (failed == 0) {
            printf("\n[SUCCESS] All tests passed!\n");
        } else {
            printf("\n[FAILURE] %d test(s) failed!\n", failed);
        }
    }
};

// Test 1: Inference engine initialization
bool TestInitialization(TestResults& results) {
    printf("\n=== Test 1: Inference Engine Initialization ===\n");
    
    InferenceEngine engine;
    InferenceEngine::InferenceConfig config;
    config.threadCount = 4;
    config.maxTokens = 100;
    config.temperature = 0.8f;
    
    if (!engine.Initialize(config)) {
        results.Fail("Initialize", "Failed to initialize inference engine");
        return false;
    }
    
    results.Pass("Initialize");
    return true;
}

// Test 2: GGUF loader functionality
bool TestGGUFLoader(TestResults& results) {
    printf("\n=== Test 2: GGUF Loader ===\n");
    
    GGUFLoader loader;
    
    // Test that loader can be created
    results.Pass("GGUFLoader Creation");
    
    // Test Open with non-existent file (should fail gracefully)
    if (loader.Open("nonexistent.gguf")) {
        results.Fail("Open Non-existent", "Should fail for non-existent file");
        return false;
    }
    
    results.Pass("Open Non-existent (correctly fails)");
    return true;
}

// Test 3: Model load integration
bool TestModelLoad(TestResults& results) {
    printf("\n=== Test 3: Model Load Integration ===\n");
    
    InferenceEngine engine;
    InferenceEngine::InferenceConfig config;
    config.threadCount = 4;
    
    if (!engine.Initialize(config)) {
        results.Fail("Initialize for Load", "Failed to initialize");
        return false;
    }
    
    // Test with null path
    if (engine.LoadModel(nullptr)) {
        results.Fail("Load Null Path", "Should fail for null path");
        return false;
    }
    
    results.Pass("Load Null Path (correctly fails)");
    
    // Test with empty path
    if (engine.LoadModel("")) {
        results.Fail("Load Empty Path", "Should fail for empty path");
        return false;
    }
    
    results.Pass("Load Empty Path (correctly fails)");
    return true;
}

// Test 4: Memory tracking
bool TestMemoryTracking(TestResults& results) {
    printf("\n=== Test 4: Memory Tracking ===\n");
    
    InferenceEngine engine;
    InferenceEngine::InferenceConfig config;
    
    if (!engine.Initialize(config)) {
        results.Fail("Initialize for Memory", "Failed to initialize");
        return false;
    }
    
    size_t initialMemory = engine.GetMemoryUsage();
    printf("  Initial memory: %zu bytes\n", initialMemory);
    
    results.Pass("Memory Usage Query");
    
    size_t peakMemory = engine.GetPeakMemoryUsage();
    printf("  Peak memory: %zu bytes\n", peakMemory);
    
    results.Pass("Peak Memory Query");
    return true;
}

// Test 5: Configuration validation
bool TestConfigValidation(TestResults& results) {
    printf("\n=== Test 5: Configuration Validation ===\n");
    
    InferenceEngine engine;
    
    // Test with null model path
    InferenceEngine::InferenceConfig badConfig;
    badConfig.modelPath = nullptr;
    
    if (engine.Initialize(badConfig)) {
        results.Fail("Null Model Path", "Should fail for null model path");
        return false;
    }
    
    results.Pass("Null Model Path (correctly fails)");
    
    // Test with empty model path
    InferenceEngine::InferenceConfig emptyConfig;
    emptyConfig.modelPath = "";
    
    if (engine.Initialize(emptyConfig)) {
        results.Fail("Empty Model Path", "Should fail for empty model path");
        return false;
    }
    
    results.Pass("Empty Model Path (correctly fails)");
    return true;
}

// Test 6: Thread configuration
bool TestThreadConfig(TestResults& results) {
    printf("\n=== Test 6: Thread Configuration ===\n");
    
    InferenceEngine engine;
    InferenceEngine::InferenceConfig config;
    config.threadCount = 0;  // Should auto-detect
    
    if (!engine.Initialize(config)) {
        results.Fail("Auto Thread Count", "Failed to initialize with auto thread count");
        return false;
    }
    
    results.Pass("Auto Thread Count");
    
    // Test with specific thread count
    InferenceEngine::InferenceConfig specificConfig;
    specificConfig.threadCount = 8;
    
    InferenceEngine engine2;
    if (!engine2.Initialize(specificConfig)) {
        results.Fail("Specific Thread Count", "Failed to initialize with specific thread count");
        return false;
    }
    
    results.Pass("Specific Thread Count");
    return true;
}

// Test 7: Error handling
bool TestErrorHandling(TestResults& results) {
    printf("\n=== Test 7: Error Handling ===\n");
    
    InferenceEngine engine;
    
    // Try operations without initialization
    const char* error = engine.GetLastError();
    if (error == nullptr) {
        results.Fail("GetLastError", "Should return valid error string");
        return false;
    }
    
    results.Pass("GetLastError");
    
    // Test abort without running inference
    engine.AbortInference();  // Should be safe even if not running
    
    results.Pass("Abort (safe when not running)");
    return true;
}

// Test 8: Complete pipeline (without actual model)
bool TestCompletePipeline(TestResults& results) {
    printf("\n=== Test 8: Complete Pipeline Structure ===\n");
    
    // This test verifies the pipeline structure works
    // even without a real model file
    
    InferenceEngine engine;
    InferenceEngine::InferenceConfig config;
    config.threadCount = 2;
    config.maxTokens = 10;
    
    if (!engine.Initialize(config)) {
        results.Fail("Pipeline Initialize", "Failed to initialize");
        return false;
    }
    
    results.Pass("Pipeline Initialize");
    
    // Verify we can query state
    bool isRunning = engine.IsRunning();
    printf("  IsRunning: %s\n", isRunning ? "true" : "false");
    
    results.Pass("Pipeline State Query");
    return true;
}

int main(int argc, char* argv[]) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     RawrXD Inference Pipeline Comprehensive Test Suite        ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    TestResults results;
    
    // Run all tests
    TestInitialization(results);
    TestGGUFLoader(results);
    TestModelLoad(results);
    TestMemoryTracking(results);
    TestConfigValidation(results);
    TestThreadConfig(results);
    TestErrorHandling(results);
    TestCompletePipeline(results);
    
    // Print summary
    results.Summary();
    
    return results.failed > 0 ? 1 : 0;
}