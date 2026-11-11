// =============================================================================
// SovereignTestSuite - Pre-Build CI/CD Gate for Hot-Patcher Validation
// Architecture: x64 MASM + C++20 (Zero-dependency, beaconism pattern)
// =============================================================================
// Validates:
//   1. Atomic rollback on partial patch failure (11x batch)
//   2. Cache coherency after FlushInstructionCache (TSC-monitored)
//   3. Patch correctness (output comparison vs baseline)
// =============================================================================
#pragma once
#ifndef SOVEREIGN_TEST_SUITE_H
#define SOVEREIGN_TEST_SUITE_H

#include <cstdint>
#include <cstddef>
#include <functional>

// Test result codes
enum class SovereignTestResult : uint32_t {
    Pass = 0,
    FailAtomicRollback = 1,
    FailCacheCoherency = 2,
    FailCorrectness = 3,
    FailMemoryAccess = 4,
    FailTimeout = 5
};

// Test configuration
struct SovereignTestConfig {
    uint32_t num_patches = 11;           // 11x batch size
    uint32_t num_warmup_iterations = 100;
    uint32_t num_measure_iterations = 1000;
    float    coherency_threshold = 1.5f;  // Max allowed slowdown after patch
    float    correctness_epsilon = 1e-5f; // Max allowed float delta
    uint32_t timeout_ms = 5000;           // Test timeout
};

// Single test result
struct SovereignTestReport {
    SovereignTestResult result;
    const char* detail;
    uint64_t baseline_cycles;
    uint64_t patched_cycles;
    float    max_delta;
    uint32_t failed_patch_index;
};

// =============================================================================
// Test Suite API (beaconism pattern - direct linkage, no CRT dependency)
// =============================================================================
extern "C" {

// Run all tests in sequence. Returns 0 on pass, non-zero on failure.
__declspec(dllexport) uint32_t SovereignRunAllTests(const SovereignTestConfig* config);

// Individual test entry points
__declspec(dllexport) SovereignTestReport SovereignTest_AtomicRollback();
__declspec(dllexport) SovereignTestReport SovereignTest_CacheCoherency(void* target_loop);
__declspec(dllexport) SovereignTestReport SovereignTest_Correctness(
    const float* baseline, const float* patched, size_t elements, float epsilon
);

// Utility: TSC-based cycle counter with serializing fence
__declspec(dllexport) uint64_t SovereignReadTSC();

} // extern "C"

#endif // SOVEREIGN_TEST_SUITE_H
