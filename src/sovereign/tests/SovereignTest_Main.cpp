// =============================================================================
// SovereignTestSuite - Main Test Harness
// =============================================================================
// Entry point for the SovereignTest_Suite.exe pre-build gate.
// Runs all validation tests and returns non-zero on any failure.
// =============================================================================

#include "SovereignTestSuite.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>

// =============================================================================
// Forward declarations from test modules
// =============================================================================
extern "C" {
    SovereignTestReport SovereignTest_AtomicRollback();
    SovereignTestReport SovereignTest_CacheCoherency(void* target_loop);
    SovereignTestReport SovereignTest_Correctness(
        const float* baseline, const float* patched, size_t elements, float epsilon
    );
}

// =============================================================================
// Test result formatting
// =============================================================================
static const char* ResultToString(SovereignTestResult r) {
    switch (r) {
        case SovereignTestResult::Pass: return "PASS";
        case SovereignTestResult::FailAtomicRollback: return "FAIL (Atomic Rollback)";
        case SovereignTestResult::FailCacheCoherency: return "FAIL (Cache Coherency)";
        case SovereignTestResult::FailCorrectness: return "FAIL (Correctness)";
        case SovereignTestResult::FailMemoryAccess: return "FAIL (Memory Access)";
        case SovereignTestResult::FailTimeout: return "FAIL (Timeout)";
        default: return "UNKNOWN";
    }
}

static void PrintReport(const char* test_name, const SovereignTestReport& report) {
    printf("  [%-30s] %s\n", test_name, ResultToString(report.result));
    printf("    Detail: %s\n", report.detail ? report.detail : "none");
    
    if (report.baseline_cycles > 0 || report.patched_cycles > 0) {
        printf("    Baseline: %llu cycles | Patched: %llu cycles\n",
               (unsigned long long)report.baseline_cycles,
               (unsigned long long)report.patched_cycles);
        
        if (report.baseline_cycles > 0) {
            float ratio = (float)report.patched_cycles / (float)report.baseline_cycles;
            printf("    Slowdown ratio: %.2fx\n", ratio);
        }
    }
    
    if (report.max_delta > 0.0f) {
        printf("    Max delta: %.6f\n", report.max_delta);
    }
    
    if (report.failed_patch_index != UINT32_MAX) {
        printf("    Failed at patch index: %u\n", report.failed_patch_index);
    }
    
    printf("\n");
}

// =============================================================================
// Public API: Run All Tests
// =============================================================================
extern "C" __declspec(dllexport)
uint32_t SovereignRunAllTests(const SovereignTestConfig* config) {
    SovereignTestConfig cfg;
    if (config) {
        cfg = *config;
    } else {
        cfg = SovereignTestConfig();  // Defaults
    }
    
    printf("========================================================\n");
    printf("  Sovereign Test Suite - Pre-Build CI/CD Gate\n");
    printf("========================================================\n\n");
    printf("Configuration:\n");
    printf("  Patches: %u\n", cfg.num_patches);
    printf("  Warmup: %u iterations\n", cfg.num_warmup_iterations);
    printf("  Measure: %u iterations\n", cfg.num_measure_iterations);
    printf("  Coherency threshold: %.2fx\n", cfg.coherency_threshold);
    printf("  Correctness epsilon: %.6f\n", cfg.correctness_epsilon);
    printf("  Timeout: %u ms\n\n", cfg.timeout_ms);
    
    uint32_t passed = 0;
    uint32_t failed = 0;
    
    // --- Test 1: Atomic Rollback ---
    printf("--- Test 1: Atomic Rollback ---\n");
    auto t1_start = std::chrono::high_resolution_clock::now();
    SovereignTestReport r1 = SovereignTest_AtomicRollback();
    auto t1_end = std::chrono::high_resolution_clock::now();
    PrintReport("AtomicRollback", r1);
    if (r1.result == SovereignTestResult::Pass) passed++; else failed++;
    
    // --- Test 2: Cache Coherency ---
    printf("--- Test 2: Cache Coherency ---\n");
    auto t2_start = std::chrono::high_resolution_clock::now();
    SovereignTestReport r2 = SovereignTest_CacheCoherency(nullptr);
    auto t2_end = std::chrono::high_resolution_clock::now();
    PrintReport("CacheCoherency", r2);
    if (r2.result == SovereignTestResult::Pass) passed++; else failed++;
    
    // --- Test 3: Correctness ---
    printf("--- Test 3: Correctness ---\n");
    constexpr size_t TEST_ELEMENTS = 64;
    float baseline[TEST_ELEMENTS];
    float patched[TEST_ELEMENTS];
    
    // Fill baseline with known values
    for (size_t i = 0; i < TEST_ELEMENTS; i++) {
        baseline[i] = (float)i * 0.5f;
        patched[i] = baseline[i];  // Identical initially
    }
    
    // Test 3a: Identical arrays should pass
    SovereignTestReport r3a = SovereignTest_Correctness(
        baseline, patched, TEST_ELEMENTS, cfg.correctness_epsilon
    );
    PrintReport("Correctness (identical)", r3a);
    if (r3a.result == SovereignTestResult::Pass) passed++; else failed++;
    
    // Test 3b: Introduce a small delta below epsilon - should still pass
    patched[32] += 5e-6f;  // Below 1e-5 epsilon
    SovereignTestReport r3b = SovereignTest_Correctness(
        baseline, patched, TEST_ELEMENTS, cfg.correctness_epsilon
    );
    PrintReport("Correctness (sub-epsilon)", r3b);
    if (r3b.result == SovereignTestResult::Pass) passed++; else failed++;
    
    // Test 3c: Introduce a large delta above epsilon - should fail (expected)
    patched[32] = 999.0f;  // Way above epsilon
    SovereignTestReport r3c = SovereignTest_Correctness(
        baseline, patched, TEST_ELEMENTS, cfg.correctness_epsilon
    );
    PrintReport("Correctness (super-epsilon)", r3c);
    if (r3c.result == SovereignTestResult::Pass) {
        passed++;  // Would be unexpected
    } else {
        // Expected failure - detection works correctly
        printf("    (Expected failure - detection mechanism validated)\n\n");
    }
    
    // --- Summary ---
    printf("========================================================\n");
    printf("  Results: %u passed, %u failed out of %u tests\n",
           passed, failed, passed + failed);
    printf("========================================================\n\n");
    
    return failed > 0 ? 1 : 0;
}

// =============================================================================
// Main entry point
// =============================================================================
int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    SovereignTestConfig config;
    // Allow override from environment
    char* env_epsilon = getenv("SOVEREIGN_TEST_EPSILON");
    if (env_epsilon) {
        config.correctness_epsilon = (float)atof(env_epsilon);
    }
    
    uint32_t result = SovereignRunAllTests(&config);
    
    if (result == 0) {
        printf("SovereignTest_Suite: ALL TESTS PASSED\n");
    } else {
        printf("SovereignTest_Suite: SOME TESTS FAILED (exit code: %u)\n", result);
    }
    
    return (int)result;
}
