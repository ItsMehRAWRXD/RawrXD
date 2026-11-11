// =============================================================================
// SovereignTestSuite - Patch Correctness Comparator
// =============================================================================
// Compares baseline output against patched output with high-precision float
// validation. Used to verify that hot-patching does not corrupt kernel output.
// =============================================================================

#include "SovereignTestSuite.hpp"
#include <cstring>
#include <cmath>

// =============================================================================
// Public API: Test Correctness
// Compares two float arrays element-by-element within epsilon tolerance
// =============================================================================
extern "C" __declspec(dllexport)
SovereignTestReport SovereignTest_Correctness(
    const float* baseline,
    const float* patched,
    size_t elements,
    float epsilon
) {
    SovereignTestReport report = {};
    report.baseline_cycles = 0;
    report.patched_cycles = 0;
    report.max_delta = 0.0f;
    report.failed_patch_index = UINT32_MAX;
    
    if (!baseline || !patched || elements == 0) {
        report.result = SovereignTestResult::FailCorrectness;
        report.detail = "Correctness: FAIL - null pointer or zero elements";
        return report;
    }
    
    if (epsilon <= 0.0f) {
        epsilon = 1e-5f;  // Default tolerance
    }
    
    float max_delta = 0.0f;
    size_t fail_index = 0;
    
    for (size_t i = 0; i < elements; i++) {
        float delta = std::abs(baseline[i] - patched[i]);
        if (delta > max_delta) {
            max_delta = delta;
            fail_index = i;
        }
    }
    
    report.max_delta = max_delta;
    
    if (max_delta > epsilon) {
        report.result = SovereignTestResult::FailCorrectness;
        report.failed_patch_index = (uint32_t)fail_index;
        report.detail = "Correctness: FAIL - output mismatch detected";
    } else {
        report.result = SovereignTestResult::Pass;
        report.detail = "Correctness: PASS - outputs match within tolerance";
    }
    
    return report;
}
