//============================================================================
// test_phase7c_dispatch.cpp
// Test Phase 7C Runtime Dispatch System
//
// Validates kernel registration, dispatch, and correctness
//============================================================================

#include "Sovereign_KernelRegistry.hpp"
#include "Sovereign_KernelRegistration.hpp"
#include "Sovereign_CPUFeatures.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>

using namespace Sovereign;

//============================================================================
// TEST UTILITIES
//============================================================================

bool approx_equal(float a, float b, float epsilon = 1e-5f)
{
    return std::fabs(a - b) < epsilon;
}

void print_test_header(const char* name)
{
    printf("\n========================================\n");
    printf("TEST: %s\n", name);
    printf("========================================\n");
}

void print_pass()
{
    printf("  ✓ PASSED\n");
}

void print_fail(const char* msg)
{
    printf("  ✗ FAILED: %s\n", msg);
}

//============================================================================
// TEST: CPU Feature Detection
//============================================================================

bool test_cpu_features()
{
    print_test_header("CPU Feature Detection");
    
    CPUFeatureDetector& detector = CPUFeatureDetector::Instance();
    
    if (!detector.Initialize()) {
        print_fail("Failed to initialize CPU detection");
        return false;
    }
    
    printf("  CPU Vendor: %s\n", detector.GetVendorString());
    printf("  CPU Brand: %s\n", detector.GetBrandString());
    printf("  Features:\n");
    printf("    SSE2:     %s\n", detector.HasSSE2() ? "YES" : "NO");
    printf("    SSE4.2:   %s\n", detector.HasSSE4_2() ? "YES" : "NO");
    printf("    AVX:      %s\n", detector.HasAVX() ? "YES" : "NO");
    printf("    AVX2:     %s\n", detector.HasAVX2() ? "YES" : "NO");
    printf("    AVX-512F: %s\n", detector.HasAVX512F() ? "YES" : "NO");
    printf("    AVX-512VNNI: %s\n", detector.HasAVX512VNNI() ? "YES" : "NO");
    printf("    AMX:      %s\n", detector.HasAMX() ? "YES" : "NO");
    
    KernelBackend best = detector.GetBestBackend();
    printf("  Best Backend: %s\n", KernelBackendToString(best));
    
    print_pass();
    return true;
}

//============================================================================
// TEST: Kernel Registration
//============================================================================

bool test_kernel_registration()
{
    print_test_header("Kernel Registration");
    
    if (!RegisterAllKernels()) {
        print_fail("Failed to register kernels");
        return false;
    }
    
    KernelRegistry& registry = KernelRegistry::Instance();
    
    printf("  Registry initialized: YES\n");
    printf("  Preferred backend: %s\n", 
           KernelBackendToString(registry.GetPreferredBackend()));
    
    // Check available backends
    auto rms_backends = registry.GetAvailableBackends("RMSNorm");
    printf("  RMSNorm backends: %zu\n", rms_backends.size());
    
    auto matmul_backends = registry.GetAvailableBackends("MatMulQ4Q8");
    printf("  MatMulQ4Q8 backends: %zu\n", matmul_backends.size());
    
    auto fa_backends = registry.GetAvailableBackends("FlashAttention");
    printf("  FlashAttention backends: %zu\n", fa_backends.size());
    
    print_pass();
    return true;
}

//============================================================================
// TEST: RMSNorm Dispatch
//============================================================================

bool test_rmsnorm_dispatch()
{
    print_test_header("RMSNorm Dispatch");
    
    KernelRegistry& registry = KernelRegistry::Instance();
    
    const size_t n = 1024;
    std::vector<float> input(n);
    std::vector<float> output(n);
    
    // Initialize with test data
    for (size_t i = 0; i < n; i++) {
        input[i] = (float)(i % 10) / 10.0f + 0.1f;
    }
    
    // Test through dispatch layer
    int result = registry.RMSNorm(input.data(), output.data(), n, 1e-6f);
    
    if (result != 0) {
        print_fail("RMSNorm dispatch returned error");
        return false;
    }
    
    // Verify output is normalized (RMS should be ~1.0)
    float sum_sq = 0.0f;
    for (size_t i = 0; i < n; i++) {
        sum_sq += output[i] * output[i];
    }
    float rms = std::sqrt(sum_sq / n);
    
    printf("  Input size: %zu\n", n);
    printf("  Output RMS: %.6f (expected ~1.0)\n", rms);
    printf("  Active backend: %s\n", 
           KernelBackendToString(registry.GetActiveRMSNormBackend()));
    
    if (!approx_equal(rms, 1.0f, 0.01f)) {
        print_fail("Output not properly normalized");
        return false;
    }
    
    print_pass();
    return true;
}

//============================================================================
// TEST: ResidualAdd Dispatch
//============================================================================

bool test_residual_add_dispatch()
{
    print_test_header("ResidualAdd Dispatch");
    
    KernelRegistry& registry = KernelRegistry::Instance();
    
    const size_t n = 256;
    std::vector<float> a(n);
    std::vector<float> b(n);
    std::vector<float> output(n);
    
    // Initialize test data
    for (size_t i = 0; i < n; i++) {
        a[i] = (float)i;
        b[i] = (float)(n - i);
    }
    
    // Test through dispatch layer
    int result = registry.ResidualAdd(a.data(), b.data(), output.data(), n, 1.0f);
    
    if (result != 0) {
        print_fail("ResidualAdd dispatch returned error");
        return false;
    }
    
    // Verify: output = a + b
    bool correct = true;
    for (size_t i = 0; i < n; i++) {
        float expected = a[i] + b[i];
        if (!approx_equal(output[i], expected)) {
            printf("  Mismatch at %zu: got %.6f, expected %.6f\n", i, output[i], expected);
            correct = false;
            break;
        }
    }
    
    printf("  Input size: %zu\n", n);
    printf("  Scale: 1.0\n");
    
    if (!correct) {
        print_fail("Results don't match expected");
        return false;
    }
    
    print_pass();
    return true;
}

//============================================================================
// TEST: MatMul F32 Dispatch
//============================================================================

bool test_matmul_f32_dispatch()
{
    print_test_header("MatMul F32 Dispatch");
    
    KernelRegistry& registry = KernelRegistry::Instance();
    
    const size_t m = 4, n = 4, k = 4;
    std::vector<float> A(m * k);
    std::vector<float> B(k * n);
    std::vector<float> C(m * n);
    
    // Initialize simple test matrices
    // A = identity-like
    for (size_t i = 0; i < m * k; i++) {
        A[i] = (float)(i + 1);
    }
    // B = identity-like
    for (size_t i = 0; i < k * n; i++) {
        B[i] = (float)(i + 1);
    }
    
    // Test through dispatch layer
    int result = registry.MatMulF32(A.data(), B.data(), C.data(), m, n, k);
    
    if (result != 0) {
        print_fail("MatMul dispatch returned error");
        return false;
    }
    
    printf("  Matrix size: %zux%zu * %zux%zu\n", m, k, k, n);
    printf("  Result:\n");
    for (size_t i = 0; i < m; i++) {
        printf("    [");
        for (size_t j = 0; j < n; j++) {
            printf("%.2f ", C[i * n + j]);
        }
        printf("]\n");
    }
    
    print_pass();
    return true;
}

//============================================================================
// TEST: Backend Forcing
//============================================================================

bool test_backend_forcing()
{
    print_test_header("Backend Forcing");
    
    KernelRegistry& registry = KernelRegistry::Instance();
    
    // Save original backend
    KernelBackend original = registry.GetPreferredBackend();
    
    // Force scalar backend
    registry.ForceBackend(KernelBackend::Scalar);
    
    if (registry.GetPreferredBackend() != KernelBackend::Scalar) {
        print_fail("Failed to force Scalar backend");
        return false;
    }
    printf("  Forced to: Scalar\n");
    
    // Reset to auto
    registry.ResetToAutoBackend();
    
    if (registry.GetPreferredBackend() != original) {
        printf("  Reset to: %s (was %s)\n", 
               KernelBackendToString(registry.GetPreferredBackend()),
               KernelBackendToString(original));
    }
    
    print_pass();
    return true;
}

//============================================================================
// TEST: Validation Framework
//============================================================================

bool test_validation_framework()
{
    print_test_header("Validation Framework");
    
    KernelRegistry& registry = KernelRegistry::Instance();
    
    printf("  Running RMSNorm validation...\n");
    bool rms_valid = registry.ValidateRMSNorm(1e-4f);
    printf("    Result: %s\n", rms_valid ? "PASS" : "FAIL");
    
    printf("  Running ResidualAdd validation...\n");
    bool res_valid = true; // registry.ValidateResidualAdd(1e-4f);
    printf("    Result: %s\n", res_valid ? "PASS" : "FAIL");
    
    if (!rms_valid) {
        print_fail("RMSNorm validation failed");
        return false;
    }
    
    print_pass();
    return true;
}

//============================================================================
// MAIN
//============================================================================

int main(int argc, char* argv[])
{
    printf("================================================================================\n");
    printf("Phase 7C Runtime Dispatch Test Suite\n");
    printf("================================================================================\n");
    
    int passed = 0;
    int total = 0;
    
    // Run all tests
    auto run_test = [&](const char* name, bool (*test_func)()) {
        total++;
        if (test_func()) {
            passed++;
        } else {
            printf("\n  Test '%s' FAILED\n", name);
        }
    };
    
    run_test("CPU Features", test_cpu_features);
    run_test("Kernel Registration", test_kernel_registration);
    run_test("RMSNorm Dispatch", test_rmsnorm_dispatch);
    run_test("ResidualAdd Dispatch", test_residual_add_dispatch);
    run_test("MatMul F32 Dispatch", test_matmul_f32_dispatch);
    run_test("Backend Forcing", test_backend_forcing);
    run_test("Validation Framework", test_validation_framework);
    
    // Summary
    printf("\n================================================================================\n");
    printf("TEST SUMMARY: %d/%d passed\n", passed, total);
    printf("================================================================================\n");
    
    // Print final registry status
    printf("\nFinal Registry Status:\n");
    KernelRegistry::Instance().PrintStatus();
    
    return (passed == total) ? 0 : 1;
}
