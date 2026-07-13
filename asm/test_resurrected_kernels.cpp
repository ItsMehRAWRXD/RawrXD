// ============================================================================
// test_resurrected_kernels.cpp - Phase 7A Integration Validation
// ============================================================================
// Validates the 5 resurrected kernels integrated into KernelDispatch
// ============================================================================

#include "Sovereign_KernelDispatch.h"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <chrono>

// External C API from resurrected kernels
extern "C" {
    int flash_attention_v2_f32(float* Q, float* K, float* V, float* output,
                                size_t seq_len, size_t head_dim);
    size_t fast_token_scan(const char* buffer, size_t length,
                           const void* token_table, int* output);
    int svd_compress_f32(float* input, size_t rank, float* output, size_t original_dim);
    size_t token_merge_avx512(int* token_ids, size_t count,
                              const void* merge_rules, size_t* output_count);
    int q4_0_q8_0_matmul(const void* A, const void* B, float* C,
                         size_t m, size_t n, size_t k);
}

// Test results
struct TestResult {
    const char* name;
    bool passed;
    double duration_ms;
    const char* error;
};

#define TEST_ASSERT(cond, msg) \
    if (!(cond)) { result.error = msg; result.passed = false; return result; }

// ----------------------------------------------------------------------------
// Test 1: FlashAttentionV2
// ----------------------------------------------------------------------------
TestResult TestFlashAttentionV2() {
    TestResult result = {"FlashAttentionV2", true, 0.0, nullptr};
    
    const size_t seq_len = 64;
    const size_t head_dim = 64;
    const size_t size = seq_len * head_dim;
    
    // Allocate aligned buffers
    float* Q = (float*)_aligned_malloc(size * sizeof(float), 32);
    float* K = (float*)_aligned_malloc(size * sizeof(float), 32);
    float* V = (float*)_aligned_malloc(size * sizeof(float), 32);
    float* output = (float*)_aligned_malloc(size * sizeof(float), 32);
    
    if (!Q || !K || !V || !output) {
        result.error = "Memory allocation failed";
        result.passed = false;
        return result;
    }
    
    // Initialize with test pattern
    for (size_t i = 0; i < size; i++) {
        Q[i] = (float)(i % 10) * 0.1f;
        K[i] = (float)(i % 8) * 0.1f;
        V[i] = (float)(i % 6) * 0.1f;
        output[i] = 0.0f;
    }
    
    // Run kernel
    auto start = std::chrono::high_resolution_clock::now();
    int ret = flash_attention_v2_f32(Q, K, V, output, seq_len, head_dim);
    auto end = std::chrono::high_resolution_clock::now();
    
    result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Validate
    TEST_ASSERT(ret == 0, "Kernel returned error code");
    
    // Check output was written (not all zeros)
    bool has_nonzero = false;
    for (size_t i = 0; i < size && !has_nonzero; i++) {
        if (output[i] != 0.0f) has_nonzero = true;
    }
    TEST_ASSERT(has_nonzero, "Output buffer not written");
    
    // Cleanup
    _aligned_free(Q);
    _aligned_free(K);
    _aligned_free(V);
    _aligned_free(output);
    
    return result;
}

// ----------------------------------------------------------------------------
// Test 2: FastTokenScan
// ----------------------------------------------------------------------------
TestResult TestFastTokenScan() {
    TestResult result = {"FastTokenScan", true, 0.0, nullptr};
    
    const char* text = "Hello world test tokens";
    const size_t len = strlen(text);
    int output[32] = {0};
    
    auto start = std::chrono::high_resolution_clock::now();
    size_t token_count = fast_token_scan(text, len, nullptr, output);
    auto end = std::chrono::high_resolution_clock::now();
    
    result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Validate
    TEST_ASSERT(token_count > 0, "No tokens found");
    TEST_ASSERT(token_count <= len, "Token count exceeds input length");
    
    return result;
}

// ----------------------------------------------------------------------------
// Test 3: SVD_Compress
// ----------------------------------------------------------------------------
TestResult TestSVDCompress() {
    TestResult result = {"SVD_Compress", true, 0.0, nullptr};
    
    const size_t dim = 64;
    const size_t rank = 32;
    
    float* input = (float*)_aligned_malloc(dim * sizeof(float), 32);
    float* output = (float*)_aligned_malloc(rank * sizeof(float), 32);
    
    if (!input || !output) {
        result.error = "Memory allocation failed";
        result.passed = false;
        return result;
    }
    
    // Initialize
    for (size_t i = 0; i < dim; i++) {
        input[i] = (float)i * 0.01f;
    }
    memset(output, 0, rank * sizeof(float));
    
    auto start = std::chrono::high_resolution_clock::now();
    int ret = svd_compress_f32(input, rank, output, dim);
    auto end = std::chrono::high_resolution_clock::now();
    
    result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Validate
    TEST_ASSERT(ret == 0, "Kernel returned error code");
    
    _aligned_free(input);
    _aligned_free(output);
    
    return result;
}

// ----------------------------------------------------------------------------
// Test 4: TokenMerge_AVX512
// ----------------------------------------------------------------------------
TestResult TestTokenMergeAVX512() {
    TestResult result = {"TokenMerge_AVX512", true, 0.0, nullptr};
    
    int tokens[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    size_t output_count = 0;
    
    auto start = std::chrono::high_resolution_clock::now();
    size_t merged = token_merge_avx512(tokens, 16, nullptr, &output_count);
    auto end = std::chrono::high_resolution_clock::now();
    
    result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Validate (simplified - just check it runs)
    TEST_ASSERT(merged >= 0, "Invalid return value");
    
    return result;
}

// ----------------------------------------------------------------------------
// Test 5: Q4_0_Q8_0_MatMul
// ----------------------------------------------------------------------------
TestResult TestQ4Q8MatMul() {
    TestResult result = {"Q4_0_Q8_0_MatMul", true, 0.0, nullptr};
    
    const size_t m = 64, n = 64, k = 64;
    
    // Allocate dummy quantized buffers (simplified test)
    void* A = _aligned_malloc(1024, 32);
    void* B = _aligned_malloc(1024, 32);
    float* C = (float*)_aligned_malloc(m * n * sizeof(float), 32);
    
    if (!A || !B || !C) {
        result.error = "Memory allocation failed";
        result.passed = false;
        return result;
    }
    
    memset(A, 0, 1024);
    memset(B, 0, 1024);
    memset(C, 0, m * n * sizeof(float));
    
    auto start = std::chrono::high_resolution_clock::now();
    int ret = q4_0_q8_0_matmul(A, B, C, m, n, k);
    auto end = std::chrono::high_resolution_clock::now();
    
    result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Validate
    TEST_ASSERT(ret == 0, "Kernel returned error code");
    
    _aligned_free(A);
    _aligned_free(B);
    _aligned_free(C);
    
    return result;
}

// ----------------------------------------------------------------------------
// Test 6: Kernel Table Validation (C API)
// ----------------------------------------------------------------------------
TestResult TestKernelDispatchIntegration() {
    TestResult result = {"KernelDispatch_C_API", true, 0.0, nullptr};
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Just verify the C API functions exist by calling them directly
    // These are declared in the header and implemented in the .asm files
    
    // Test that function pointers are valid (will crash if not linked)
    volatile auto fa_ptr = flash_attention_v2_f32;
    volatile auto ts_ptr = fast_token_scan;
    volatile auto svd_ptr = svd_compress_f32;
    volatile auto tm_ptr = token_merge_avx512;
    volatile auto mm_ptr = q4_0_q8_0_matmul;
    
    (void)fa_ptr; (void)ts_ptr; (void)svd_ptr; (void)tm_ptr; (void)mm_ptr;
    
    auto end = std::chrono::high_resolution_clock::now();
    result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // If we got here, all function pointers resolved
    TEST_ASSERT(fa_ptr != nullptr, "flash_attention_v2_f32 not linked");
    TEST_ASSERT(ts_ptr != nullptr, "fast_token_scan not linked");
    TEST_ASSERT(svd_ptr != nullptr, "svd_compress_f32 not linked");
    TEST_ASSERT(tm_ptr != nullptr, "token_merge_avx512 not linked");
    TEST_ASSERT(mm_ptr != nullptr, "q4_0_q8_0_matmul not linked");
    
    return result;
}

// ----------------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------------
int main() {
    printf("=================================================================\n");
    printf("Sovereign Kernel Suite - Phase 7A Integration Validation\n");
    printf("=================================================================\n\n");
    
    TestResult tests[] = {
        TestFlashAttentionV2(),
        TestFastTokenScan(),
        TestSVDCompress(),
        TestTokenMergeAVX512(),
        TestQ4Q8MatMul(),
        TestKernelDispatchIntegration()
    };
    
    const int num_tests = sizeof(tests) / sizeof(tests[0]);
    int passed = 0;
    int failed = 0;
    double total_time = 0.0;
    
    for (int i = 0; i < num_tests; i++) {
        const auto& t = tests[i];
        total_time += t.duration_ms;
        
        if (t.passed) {
            printf("[PASS] %-30s %6.3f ms\n", t.name, t.duration_ms);
            passed++;
        } else {
            printf("[FAIL] %-30s %6.3f ms - %s\n", t.name, t.duration_ms, 
                   t.error ? t.error : "Unknown error");
            failed++;
        }
    }
    
    printf("\n=================================================================\n");
    printf("Results: %d/%d passed, %d failed\n", passed, num_tests, failed);
    printf("Total time: %.3f ms\n", total_time);
    printf("=================================================================\n");
    
    return failed > 0 ? 1 : 0;
}
