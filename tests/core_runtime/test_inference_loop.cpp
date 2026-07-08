// =============================================================================
// RawrXD-CoreRuntime Test: Inference Loop Validation
// =============================================================================
// PURPOSE: Verify CoreRuntime works without any UI dependencies
// This is the "truth baseline" test - if this fails, system is broken
// =============================================================================

#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/inference_engine.h"
#include <cstdio>
#include <cassert>
#include <string>

using namespace RawrXD::Core;

// =============================================================================
// Test: Basic Initialization
// =============================================================================

bool test_basic_initialization() {
    printf("[TEST] Basic initialization...\n");
    
    auto engine = CreateInferenceEngine();
    assert(engine != nullptr);
    
    InferenceConfig config;
    config.modelPath = "test.gguf";
    config.maxTokens = 100;
    
    bool result = engine->Initialize(config);
    assert(result);
    
    printf("[PASS] Basic initialization\n");
    return true;
}

// =============================================================================
// Test: Inference Execution
// =============================================================================

bool test_inference_execution() {
    printf("[TEST] Inference execution...\n");
    
    auto engine = CreateInferenceEngine();
    
    InferenceConfig config;
    config.modelPath = "test.gguf";
    config.maxTokens = 10;
    config.onToken = [](const char* token, uint32_t tokenId) -> bool {
        printf("  Token[%u]: %s\n", tokenId, token);
        return true;  // Continue generation
    };
    
    engine->Initialize(config);
    engine->LoadModel("test.gguf");
    
    auto result = engine->RunInference("Hello, world!");
    
    assert(result.status == InferenceResult::Status::Success);
    assert(result.tokensGenerated == 10);
    assert(result.elapsedMicroseconds > 0);
    
    printf("[PASS] Inference execution (%u tokens, %llu us)\n", 
           result.tokensGenerated, result.elapsedMicroseconds);
    return true;
}

// =============================================================================
// Test: Memory Tracking
// =============================================================================

bool test_memory_tracking() {
    printf("[TEST] Memory tracking...\n");
    
    auto engine = CreateInferenceEngine();
    
    size_t initialUsage = engine->GetMemoryUsage();
    assert(initialUsage == 0);
    
    InferenceConfig config;
    config.modelPath = "test.gguf";
    engine->Initialize(config);
    engine->LoadModel("test.gguf");
    
    size_t afterLoad = engine->GetMemoryUsage();
    assert(afterLoad > initialUsage);
    
    size_t peakUsage = engine->GetPeakMemoryUsage();
    assert(peakUsage >= afterLoad);
    
    printf("[PASS] Memory tracking (current: %zu, peak: %zu)\n", 
           afterLoad, peakUsage);
    return true;
}

// =============================================================================
// Test: AVX-512 Detection
// =============================================================================

bool test_avx512_detection() {
    printf("[TEST] AVX-512 detection...\n");
    
    auto engine = CreateInferenceEngine();
    
    // Just verify the call works - actual detection depends on hardware
    bool hasAVX512 = engine->IsUsingAVX512();
    printf("  AVX-512 available: %s\n", hasAVX512 ? "YES" : "NO");
    
    printf("[PASS] AVX-512 detection\n");
    return true;
}

// =============================================================================
// Test: Version String
// =============================================================================

bool test_version_string() {
    printf("[TEST] Version string...\n");
    
    const char* version = InferenceEngine::GetVersion();
    assert(version != nullptr);
    assert(std::strlen(version) > 0);
    assert(std::strstr(version, "CoreRuntime") != nullptr);
    
    printf("[PASS] Version: %s\n", version);
    return true;
}

// =============================================================================
// External test functions from other test files
// =============================================================================

extern bool test_gguf_loader();
extern bool test_task_graph();
extern bool test_memory_pool();

// =============================================================================
// Main Test Runner
// =============================================================================

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    printf("\n");
    printf("============================================================\n");
    printf("RawrXD-CoreRuntime Test Suite\n");
    printf("============================================================\n");
    printf("\n");
    
    int passed = 0;
    int failed = 0;
    
    #define RUN_TEST(name) \
        do { \
            if (test_##name()) { \
                passed++; \
            } else { \
                failed++; \
                printf("[FAIL] " #name "\n"); \
            } \
        } while(0)
    
    RUN_TEST(basic_initialization);
    RUN_TEST(inference_execution);
    RUN_TEST(memory_tracking);
    RUN_TEST(avx512_detection);
    RUN_TEST(version_string);
    RUN_TEST(gguf_loader);
    RUN_TEST(task_graph);
    RUN_TEST(memory_pool);
    
    printf("\n");
    printf("============================================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);
    printf("============================================================\n");
    printf("\n");
    
    return failed > 0 ? 1 : 0;
}
